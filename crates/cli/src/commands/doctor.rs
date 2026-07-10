//! `rbgp doctor`: live red/green triage checks plus one redacted
//! `rustbgpd-doctor-<ts>.tar.gz` support bundle.
//!
//! Hard rules: the raw daemon config file is never copied (the config
//! section is the daemon's own secret-redacted `GetEffectiveConfig`
//! dump) and no bearer-token material is collected. Log collection is
//! opt-in via `--log-file`; the daemon logs to stdout/journald and the
//! manifest records that instead of shelling out to journalctl.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::commands::watch::bgp_event_json_value;
use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonNeighbor};
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::{
    GetEffectiveConfigRequest, GetGlobalRequest, HealthRequest, ListNeighborsRequest,
    ListPolicyEventsRequest, ListSessionEventsRequest, MetricsRequest,
};

/// Bounded recent slice pulled from each event history for triage. The
/// daemon clamps to its own 4096-event ceiling; this keeps the bundle small.
const EVENT_HISTORY_LIMIT: u32 = 256;

/// Keys in the shipped `BgpEvent` JSON whose values are free text that
/// could echo operator/peer-supplied strings (e.g. RFC 8203 shutdown
/// reasons). Redacted the same way `tcp_ao_detail`/metrics are.
const EVENT_FREE_TEXT_KEYS: &[&str] = &["summary", "reason", "shutdown_reason", "target"];

/// A non-Established peer that transitioned longer ago than this (or has
/// no recent transition event at all) is red, not merely "settling".
const STUCK_PEER_SECS: u64 = 120;

/// Established peers that have flapped at least this often get a red
/// check (hold-time expiry loops and unstable transport look like this).
const FLAP_FAIL_THRESHOLD: u64 = 5;

/// Daemon soft `nofile` limits below this are flagged: each peer costs
/// sockets plus per-session file handles, and the systemd default of
/// 1024 exhausts quickly at scale.
const NOFILE_SOFT_MIN: u64 = 4096;

/// Number of lines tailed from `--log-file` into `logs/tail-1000.jsonl`.
const LOG_TAIL_LINES: usize = 1000;

/// At most this many panic reports are swept into `crashes/` and each is
/// size-capped, so a pathological crash directory cannot bloat the bundle.
const MAX_CRASH_REPORTS: usize = 10;
const MAX_CRASH_BYTES: u64 = 64 * 1024;

/// Where the daemon keeps runtime state when the effective config is not
/// available (daemon down). Mirrors the config default.
const DEFAULT_STATE_DIR: &str = "/var/lib/rustbgpd";

pub(crate) struct DoctorOptions<'a> {
    /// Bundle output path. Defaults to `rustbgpd-doctor-<unix-seconds>.tar.gz`.
    pub output: Option<&'a Path>,
    /// Daemon log file to tail into the bundle (the daemon itself logs to
    /// stdout/journald; only an operator-named file is ever read).
    pub log_file: Option<&'a Path>,
    pub daemon_address: &'a str,
    pub token_file_configured: bool,
    pub json: bool,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Serialize)]
struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
}

/// Records checks and prints them live (human mode) as they are produced.
struct Reporter {
    json: bool,
    checks: Vec<Check>,
}

impl Reporter {
    fn record(&mut self, name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) {
        let check = Check {
            name: name.into(),
            status,
            detail: detail.into(),
        };
        if !self.json {
            use owo_colors::{OwoColorize, Stream::Stdout};
            let marker = match check.status {
                CheckStatus::Ok => format!("  {}", "ok".if_supports_color(Stdout, |s| s.green())),
                CheckStatus::Warn => {
                    format!("{}", "warn".if_supports_color(Stdout, |s| s.yellow()))
                }
                CheckStatus::Fail => format!("{}", "FAIL".if_supports_color(Stdout, |s| s.red())),
            };
            println!("{marker}  {}", check.detail);
        }
        self.checks.push(check);
    }

    fn any_fail(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }
}

/// Bundle contents buffered in memory (every section is small and
/// bounded), then written as one gzipped tarball under a single root
/// directory so extraction never splatters files into the cwd.
struct Bundle {
    files: Vec<(String, Vec<u8>)>,
}

impl Bundle {
    fn add(&mut self, rel_path: &str, bytes: Vec<u8>) {
        self.files.push((rel_path.to_string(), bytes));
    }

    fn add_json<T: Serialize>(&mut self, rel_path: &str, value: &T) -> Result<(), CliError> {
        self.add(rel_path, serde_json::to_vec_pretty(value)?);
        Ok(())
    }

    fn write_tar_gz(&self, path: &Path, root: &str) -> Result<(), CliError> {
        let file = fs::File::create(path)?;
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mtime = now_unix_seconds();
        for (rel_path, bytes) in &self.files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(mtime);
            tar.append_data(&mut header, format!("{root}/{rel_path}"), bytes.as_slice())?;
        }
        tar.into_inner()?.finish()?.flush()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct ManifestV2<'a> {
    /// Bundle layout version. 2 = tar.gz with manifest/config/peers/
    /// logs/crashes/system (v1 was a bare directory of seven files).
    format: u32,
    generated_at_unix_seconds: u64,
    cli_version: &'a str,
    /// `None` when the daemon was unreachable or predates the
    /// `daemon_version` health field.
    daemon_version: Option<String>,
    daemon_address: &'a str,
    token_file_configured: bool,
    redaction: &'static str,
    /// Section name -> "collected"/"unavailable: `<reason>`" so a bundle
    /// from a down daemon says exactly what is missing and why.
    sections: BTreeMap<&'static str, String>,
    files: Vec<String>,
    checks: &'a [Check],
    note: &'static str,
}

#[derive(Serialize)]
struct HealthSnapshot {
    healthy: bool,
    uptime_seconds: u64,
    active_peers: u32,
    total_routes: u32,
    daemon_version: String,
}

#[derive(Serialize)]
struct GlobalSnapshot {
    asn: u32,
    router_id: String,
    listen_port: u32,
    tcp_ao_support: String,
    tcp_ao_detail: String,
}

#[derive(Serialize)]
struct EnvironmentSnapshot<'a> {
    os: &'a str,
    arch: &'a str,
    kernel_release: String,
    current_dir: String,
    daemon_address: &'a str,
    token_file_configured: bool,
}

#[derive(Serialize)]
struct EventsSnapshot {
    session: Vec<serde_json::Value>,
    policy: Vec<serde_json::Value>,
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn tcp_ao_support_label(value: i32) -> &'static str {
    match crate::proto::TcpAoSupport::try_from(value) {
        Ok(crate::proto::TcpAoSupport::Supported) => "supported",
        Ok(crate::proto::TcpAoSupport::Unsupported) => "unsupported",
        Ok(crate::proto::TcpAoSupport::ProbeFailed) => "probe_failed",
        Ok(crate::proto::TcpAoSupport::Unspecified) | Err(_) => "unknown",
    }
}

fn redact_text(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("bearer")
            {
                "[REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Redact the free-text leaf fields of one serialized `BgpEvent` in place,
/// mirroring how `tcp_ao_detail`/metrics are scrubbed. State names, ASNs,
/// timestamps, and other structured fields are left untouched.
fn redact_event(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        for key in EVENT_FREE_TEXT_KEYS {
            if let Some(serde_json::Value::String(text)) = object.get_mut(*key) {
                *text = redact_text(text);
            }
        }
    }
    value
}

/// Last N lines of a log text, redacted line-wise.
fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// `[global] runtime_state_dir` from the daemon's effective-config TOML.
fn parse_state_dir(effective_toml: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(effective_toml).ok()?;
    Some(
        value
            .get("global")?
            .get("runtime_state_dir")?
            .as_str()?
            .to_string(),
    )
}

/// Parse the soft/hard "Max open files" row of a `/proc/<pid>/limits`
/// dump. "unlimited" maps to `u64::MAX`.
fn parse_max_open_files(limits: &str) -> Option<(u64, u64)> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    let mut fields = line.trim_start_matches("Max open files").split_whitespace();
    let parse = |token: &str| {
        if token == "unlimited" {
            Some(u64::MAX)
        } else {
            token.parse::<u64>().ok()
        }
    };
    let soft = parse(fields.next()?)?;
    let hard = parse(fields.next()?)?;
    Some((soft, hard))
}

/// Local rustbgpd processes found by `/proc/<pid>/comm`, with their
/// rlimit dumps. Empty on non-Linux hosts, remote daemons, or when the
/// daemon runs in another namespace — the manifest records that.
fn local_daemon_limits() -> Vec<(u32, String)> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim_end() != "rustbgpd" {
            continue;
        }
        if let Ok(limits) = fs::read_to_string(format!("/proc/{pid}/limits")) {
            found.push((pid, limits));
        }
    }
    found.sort_by_key(|(pid, _)| *pid);
    found
}

/// Pure rlimit check: red when the soft `nofile` limit is below
/// [`NOFILE_SOFT_MIN`].
fn nofile_check(pid: u32, soft: u64, hard: u64) -> Check {
    let (status, verdict) = if soft < NOFILE_SOFT_MIN {
        (CheckStatus::Fail, "low — peers exhaust fds at scale")
    } else {
        (CheckStatus::Ok, "ok")
    };
    Check {
        name: format!("daemon.rlimit.nofile.{pid}"),
        status,
        detail: format!("daemon pid {pid} rlimit nofile soft {soft} hard {hard}: {verdict}"),
    }
}

/// Pure per-peer session checks: state (with time-in-state derived from
/// the most recent session event) and flap count.
fn peer_checks(
    address: &str,
    state: &str,
    stale: bool,
    uptime_seconds: u64,
    flap_count: u64,
    last_transition_unix: Option<u64>,
    now: u64,
) -> Vec<Check> {
    let mut checks = Vec::new();
    if stale {
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status: CheckStatus::Warn,
            detail: format!("peer {address} state read timed out (stale) — session task busy"),
        });
    } else if state == "Established" {
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status: CheckStatus::Ok,
            detail: format!(
                "peer {address} Established for {}",
                output::format_duration(uptime_seconds)
            ),
        });
    } else {
        let (status, since) = match last_transition_unix {
            Some(ts) => {
                let elapsed = now.saturating_sub(ts);
                let status = if elapsed >= STUCK_PEER_SECS {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Warn
                };
                (status, format!("for {}", output::format_duration(elapsed)))
            }
            // No recent transition event: it has been stuck at least as
            // long as the event window covers.
            None => (
                CheckStatus::Fail,
                "with no recent state transition".to_string(),
            ),
        };
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status,
            detail: format!("peer {address} in {state} {since}"),
        });
    }
    if flap_count >= FLAP_FAIL_THRESHOLD {
        checks.push(Check {
            name: format!("peer.{address}.flaps"),
            status: CheckStatus::Fail,
            detail: format!(
                "peer {address} flapped {flap_count} times (possible hold-time expiry loop)"
            ),
        });
    }
    checks
}

/// Most recent session-event timestamp per peer, for time-in-state.
fn last_transition_by_peer(events: &[serde_json::Value]) -> HashMap<String, u64> {
    let mut map: HashMap<String, u64> = HashMap::new();
    for event in events {
        let Some(peer) = event.get("peer_address").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(ts) = event
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let entry = map.entry(peer.to_string()).or_insert(0);
        *entry = (*entry).max(ts);
    }
    map
}

/// Sweep bounded panic reports (written by the daemon's panic hook under
/// `<runtime_state_dir>/crash/`) into the bundle. Returns the collected
/// file names, newest first.
fn sweep_crash_reports(crash_dir: &Path, bundle: &mut Bundle) -> Vec<String> {
    let Ok(entries) = fs::read_dir(crash_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("panic-") && n.ends_with(".toml"))
        .collect();
    // Timestamped names: lexicographic sort is chronological. Newest first.
    names.sort_by(|a, b| b.cmp(a));
    names.truncate(MAX_CRASH_REPORTS);
    let mut collected = Vec::new();
    for name in names {
        let path = crash_dir.join(&name);
        if path
            .metadata()
            .map(|m| m.len() > MAX_CRASH_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        if let Ok(contents) = fs::read_to_string(&path) {
            bundle.add(
                &format!("crashes/{name}"),
                redact_text(&contents).into_bytes(),
            );
            collected.push(name);
        }
    }
    collected
}

pub(crate) async fn run(
    connection: Result<Connection, CliError>,
    opts: &DoctorOptions<'_>,
) -> Result<i32, CliError> {
    let now = now_unix_seconds();
    let bundle_path = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("rustbgpd-doctor-{now}.tar.gz")));
    // Root directory inside the tar: the bundle file name without
    // extensions, so `tar xzf` yields exactly one directory.
    let root = bundle_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".tar.gz").trim_end_matches(".tgz"))
        .filter(|n| !n.is_empty())
        .map_or_else(|| format!("rustbgpd-doctor-{now}"), str::to_string);

    let mut reporter = Reporter {
        json: opts.json,
        checks: Vec::new(),
    };
    let mut bundle = Bundle { files: Vec::new() };
    let mut sections: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut daemon_version: Option<String> = None;
    let mut state_dir: Option<String> = None;

    // ---- daemon-backed sections -------------------------------------
    match connection {
        Ok(connection) => {
            reporter.record(
                "daemon.reachable",
                CheckStatus::Ok,
                format!("daemon reachable at {}", opts.daemon_address),
            );
            let mut control = ControlServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            let mut global = GlobalServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            let mut neighbor = NeighborServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            let mut events = EventServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );

            // system/health.json + the healthy check.
            match control.get_health(HealthRequest {}).await {
                Ok(resp) => {
                    let health = resp.into_inner();
                    if !health.daemon_version.is_empty() {
                        daemon_version = Some(health.daemon_version.clone());
                    }
                    reporter.record(
                        "daemon.healthy",
                        if health.healthy {
                            CheckStatus::Ok
                        } else {
                            CheckStatus::Fail
                        },
                        format!(
                            "daemon {} (uptime {}, {} active peers, {} routes)",
                            if health.healthy {
                                "healthy"
                            } else {
                                "reports UNHEALTHY"
                            },
                            output::format_duration(health.uptime_seconds),
                            health.active_peers,
                            health.total_routes
                        ),
                    );
                    bundle.add_json(
                        "system/health.json",
                        &HealthSnapshot {
                            healthy: health.healthy,
                            uptime_seconds: health.uptime_seconds,
                            active_peers: health.active_peers,
                            total_routes: health.total_routes,
                            daemon_version: health.daemon_version,
                        },
                    )?;
                }
                Err(e) => {
                    reporter.record(
                        "daemon.healthy",
                        CheckStatus::Fail,
                        format!("health RPC failed: {e}"),
                    );
                }
            }

            // system/global.json.
            match global.get_global(GetGlobalRequest {}).await {
                Ok(resp) => {
                    let global_state = resp.into_inner();
                    bundle.add_json(
                        "system/global.json",
                        &GlobalSnapshot {
                            asn: global_state.asn,
                            router_id: global_state.router_id,
                            listen_port: global_state.listen_port,
                            tcp_ao_support: tcp_ao_support_label(global_state.tcp_ao_support)
                                .to_string(),
                            tcp_ao_detail: redact_text(&global_state.tcp_ao_detail),
                        },
                    )?;
                }
                Err(e) => {
                    sections.insert("system", format!("partial: global RPC failed: {e}"));
                }
            }

            // system/metrics.prom.
            match control.get_metrics(MetricsRequest {}).await {
                Ok(resp) => {
                    bundle.add(
                        "system/metrics.prom",
                        redact_text(&resp.into_inner().prometheus_text).into_bytes(),
                    );
                }
                Err(e) => {
                    sections.insert("system", format!("partial: metrics RPC failed: {e}"));
                }
            }

            // config/effective.toml: the daemon's own redacted, normalized
            // dump (same RPC as `rbgp config effective`). Never the raw file.
            let mut config_client = ConfigServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            match config_client
                .get_effective_config(GetEffectiveConfigRequest {})
                .await
            {
                Ok(resp) => {
                    let toml_text = resp.into_inner().toml;
                    state_dir = parse_state_dir(&toml_text);
                    bundle.add("config/effective.toml", toml_text.into_bytes());
                    sections.insert(
                        "config",
                        "collected (daemon-redacted effective config)".to_string(),
                    );
                }
                Err(e) => {
                    sections.insert(
                        "config",
                        format!("unavailable: effective-config RPC failed: {e}"),
                    );
                }
            }

            // peers/: neighbors + recent session/policy events, then the
            // per-peer red/green checks.
            let session_events = match events
                .list_session_events(ListSessionEventsRequest {
                    neighbor_address: String::new(),
                    event_types: Vec::new(),
                    limit: EVENT_HISTORY_LIMIT,
                })
                .await
            {
                Ok(resp) => resp
                    .into_inner()
                    .events
                    .iter()
                    .map(|e| bgp_event_json_value(e).map(redact_event))
                    .collect::<Result<Vec<_>, _>>()?,
                Err(_) => Vec::new(),
            };
            let policy_events = match events
                .list_policy_events(ListPolicyEventsRequest {
                    neighbor_address: String::new(),
                    event_types: Vec::new(),
                    limit: EVENT_HISTORY_LIMIT,
                })
                .await
            {
                Ok(resp) => resp
                    .into_inner()
                    .events
                    .iter()
                    .map(|e| bgp_event_json_value(e).map(redact_event))
                    .collect::<Result<Vec<_>, _>>()?,
                Err(_) => Vec::new(),
            };
            match neighbor.list_neighbors(ListNeighborsRequest {}).await {
                Ok(resp) => {
                    let neighbors = resp.into_inner();
                    let transitions = last_transition_by_peer(&session_events);
                    let snapshots: Vec<JsonNeighbor> = neighbors
                        .neighbors
                        .iter()
                        .map(|n| {
                            let cfg = n.config.as_ref();
                            JsonNeighbor {
                                address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
                                interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
                                remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
                                state: output::format_state_with_stale(n.state, n.stale)
                                    .to_string(),
                                stale: n.stale,
                                uptime_seconds: n.uptime_seconds,
                                prefixes_received: n.prefixes_received,
                                prefixes_sent: n.prefixes_sent,
                                messages_received: n.messages_received,
                                messages_sent: n.messages_sent,
                                flap_count: n.flap_count,
                                route_reflector_client: n.route_reflector_client,
                                description: redact_text(
                                    &cfg.map(|c| c.description.clone()).unwrap_or_default(),
                                ),
                            }
                        })
                        .collect();
                    if snapshots.is_empty() {
                        reporter.record(
                            "peers.configured",
                            CheckStatus::Warn,
                            "no neighbors configured",
                        );
                    }
                    for snapshot in &snapshots {
                        for check in peer_checks(
                            &snapshot.address,
                            &snapshot.state,
                            snapshot.stale,
                            snapshot.uptime_seconds,
                            snapshot.flap_count,
                            transitions.get(&snapshot.address).copied(),
                            now,
                        ) {
                            reporter.record(check.name, check.status, check.detail);
                        }
                    }
                    bundle.add_json("peers/neighbors.json", &snapshots)?;
                    bundle.add_json(
                        "peers/events.json",
                        &EventsSnapshot {
                            session: session_events,
                            policy: policy_events,
                        },
                    )?;
                    sections.insert("peers", "collected".to_string());
                }
                Err(e) => {
                    sections.insert("peers", format!("unavailable: neighbor RPC failed: {e}"));
                }
            }
            sections
                .entry("system")
                .or_insert_with(|| "collected".to_string());
        }
        Err(e) => {
            reporter.record(
                "daemon.reachable",
                CheckStatus::Fail,
                format!("daemon unreachable: {e}"),
            );
            sections.insert("config", "unavailable: daemon unreachable".to_string());
            sections.insert("peers", "unavailable: daemon unreachable".to_string());
            sections.insert(
                "system",
                "partial: daemon unreachable (host facts only)".to_string(),
            );
        }
    }

    // ---- system/environment.json (always available) ------------------
    bundle.add_json(
        "system/environment.json",
        &EnvironmentSnapshot {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.trim_end().to_string())
                .unwrap_or_default(),
            current_dir: std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
            daemon_address: opts.daemon_address,
            token_file_configured: opts.token_file_configured,
        },
    )?;

    // ---- daemon rlimits (local processes only) ------------------------
    let daemon_limits = local_daemon_limits();
    if daemon_limits.is_empty() {
        sections.insert(
            "rlimits",
            "unavailable: no local rustbgpd process found".to_string(),
        );
    } else {
        for (pid, limits) in &daemon_limits {
            match parse_max_open_files(limits) {
                Some((soft, hard)) => {
                    let check = nofile_check(*pid, soft, hard);
                    reporter.record(check.name, check.status, check.detail);
                }
                None => reporter.record(
                    format!("daemon.rlimit.nofile.{pid}"),
                    CheckStatus::Warn,
                    format!("daemon pid {pid}: could not parse Max open files from /proc limits"),
                ),
            }
            bundle.add(
                &format!("system/daemon-limits-{pid}.txt"),
                limits.clone().into_bytes(),
            );
        }
        sections.insert("rlimits", "collected".to_string());
    }

    // ---- crashes/ ------------------------------------------------------
    let crash_dir = PathBuf::from(state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIR)).join("crash");
    let crash_reports = sweep_crash_reports(&crash_dir, &mut bundle);
    if crash_reports.is_empty() {
        reporter.record(
            "crashes.recent",
            CheckStatus::Ok,
            format!("no panic reports in {}", crash_dir.display()),
        );
        sections.insert(
            "crashes",
            format!("collected (0 reports in {})", crash_dir.display()),
        );
    } else {
        reporter.record(
            "crashes.recent",
            CheckStatus::Fail,
            format!(
                "{} panic report(s) collected from {} — the daemon has crashed recently",
                crash_reports.len(),
                crash_dir.display()
            ),
        );
        sections.insert(
            "crashes",
            format!(
                "collected ({} reports from {})",
                crash_reports.len(),
                crash_dir.display()
            ),
        );
    }

    // ---- logs/ -----------------------------------------------------------
    match opts.log_file {
        Some(log_file) => match fs::read_to_string(log_file) {
            Ok(contents) => {
                bundle.add(
                    "logs/tail-1000.jsonl",
                    redact_text(&tail_lines(&contents, LOG_TAIL_LINES)).into_bytes(),
                );
                sections.insert(
                    "logs",
                    format!(
                        "collected (last {LOG_TAIL_LINES} lines of {})",
                        log_file.display()
                    ),
                );
            }
            Err(e) => {
                sections.insert(
                    "logs",
                    format!("unavailable: cannot read {}: {e}", log_file.display()),
                );
            }
        },
        None => {
            sections.insert(
                "logs",
                "unavailable: daemon logs to stdout/journald; pass --log-file if stdout \
                 is redirected to a file"
                    .to_string(),
            );
        }
    }

    // ---- manifest.json + tarball ------------------------------------
    let mut files: Vec<String> = bundle.files.iter().map(|(p, _)| p.clone()).collect();
    files.push("manifest.json".to_string());
    files.sort();
    let sections_summary = sections.clone();
    bundle.add_json(
        "manifest.json",
        &ManifestV2 {
            format: 2,
            generated_at_unix_seconds: now,
            cli_version: env!("CARGO_PKG_VERSION"),
            daemon_version,
            daemon_address: opts.daemon_address,
            token_file_configured: opts.token_file_configured,
            redaction: "config is the daemon's secret-redacted effective dump; metrics, \
                        event free text, descriptions, crash reports, and log lines are \
                        scrubbed client-side for password/secret/token/bearer material",
            sections,
            files,
            checks: &reporter.checks,
            note: "No daemon config file or bearer token material is copied. Route \
                   contents are not collected; when route-level divergence against an \
                   incumbent is suspected, run `rbgp diff advertised` separately and \
                   attach its report if appropriate.",
        },
    )?;
    bundle.write_tar_gz(&bundle_path, &root)?;

    let failed = reporter.any_fail();
    if opts.json {
        output::print_json_line(&serde_json::json!({
            "bundle": bundle_path.display().to_string(),
            "ok": !failed,
            "checks": serde_json::to_value(&reporter.checks)?,
            "sections": serde_json::to_value(&sections_summary)?,
        }))?;
    } else {
        println!("Support bundle written: {}", bundle_path.display());
    }
    Ok(if failed { 2 } else { 0 })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    // ---- pure-logic checks -------------------------------------------

    #[test]
    fn redact_text_replaces_sensitive_lines() {
        let redacted = redact_text("ok 1\napi_token=secret\npassword = nope\nok 2");
        assert_eq!(redacted, "ok 1\n[REDACTED]\n[REDACTED]\nok 2");
    }

    #[test]
    fn redact_event_scrubs_free_text_but_keeps_structured_fields() {
        let event = serde_json::json!({
            "event_type": "session_lost",
            "new_state": "Idle",
            "reason": "shutdown bearer token leaked here",
            "summary": "peer down",
        });
        let redacted = redact_event(event);
        assert_eq!(redacted["reason"], "[REDACTED]");
        assert_eq!(redacted["summary"], "peer down");
        assert_eq!(redacted["event_type"], "session_lost");
        assert_eq!(redacted["new_state"], "Idle");
    }

    #[test]
    fn established_peer_is_green() {
        let checks = peer_checks("10.0.0.2", "Established", false, 3600, 0, None, 1_000_000);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].status == CheckStatus::Ok);
        assert!(checks[0].detail.contains("Established"));
    }

    #[test]
    fn peer_stuck_in_connect_past_threshold_is_red_with_duration() {
        let now = 1_000_000;
        let transitioned = now - (4 * 3600 + 12 * 60); // 4h12m ago
        let checks = peer_checks("10.0.0.2", "Connect", false, 0, 0, Some(transitioned), now);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].status == CheckStatus::Fail);
        assert!(
            checks[0].detail.contains("in Connect for 04:12:00"),
            "{}",
            checks[0].detail
        );
    }

    #[test]
    fn peer_in_connect_just_after_transition_is_warn_not_red() {
        let now = 1_000_000;
        let checks = peer_checks(
            "10.0.0.2",
            "Connect",
            false,
            0,
            0,
            Some(now - STUCK_PEER_SECS + 1),
            now,
        );
        assert!(checks[0].status == CheckStatus::Warn);
    }

    #[test]
    fn peer_in_connect_with_no_transition_event_is_red() {
        let checks = peer_checks("10.0.0.2", "Connect", false, 0, 0, None, 1_000_000);
        assert!(checks[0].status == CheckStatus::Fail);
        assert!(checks[0].detail.contains("no recent state transition"));
    }

    #[test]
    fn flapping_peer_gets_extra_red_check() {
        let checks = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            60,
            FLAP_FAIL_THRESHOLD,
            None,
            1_000_000,
        );
        assert_eq!(checks.len(), 2);
        assert!(checks[1].status == CheckStatus::Fail);
        assert!(checks[1].detail.contains("flapped 5 times"));
    }

    #[test]
    fn stale_peer_is_warn() {
        let checks = peer_checks("10.0.0.2", "Stale", true, 0, 0, None, 1_000_000);
        assert!(checks[0].status == CheckStatus::Warn);
        assert!(checks[0].detail.contains("stale"));
    }

    #[test]
    fn low_nofile_soft_limit_is_red() {
        let check = nofile_check(42, 1024, 524_288);
        assert!(check.status == CheckStatus::Fail);
        assert!(check.detail.contains("soft 1024"));
        assert!(nofile_check(42, 4096, 524_288).status == CheckStatus::Ok);
    }

    #[test]
    fn parse_max_open_files_reads_proc_limits_format() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max cpu time              unlimited            unlimited            seconds\n\
                      Max open files            1024                 524288               files\n";
        assert_eq!(parse_max_open_files(limits), Some((1024, 524_288)));
        let unlimited =
            "Max open files            unlimited            unlimited            files\n";
        assert_eq!(parse_max_open_files(unlimited), Some((u64::MAX, u64::MAX)));
        assert_eq!(parse_max_open_files("no such row"), None);
    }

    #[test]
    fn tail_lines_keeps_only_the_last_n() {
        let text = (1..=5)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(tail_lines(&text, 2), "line 4\nline 5");
        assert_eq!(tail_lines(&text, 10), text);
    }

    #[test]
    fn parse_state_dir_reads_global_runtime_state_dir() {
        let toml = "[global]\nasn = 65000\nruntime_state_dir = \"/tmp/x\"\n";
        assert_eq!(parse_state_dir(toml), Some("/tmp/x".to_string()));
        assert_eq!(parse_state_dir("[global]\nasn = 65000\n"), None);
        assert_eq!(parse_state_dir("not toml ["), None);
    }

    #[test]
    fn last_transition_by_peer_takes_newest_event() {
        let events = vec![
            serde_json::json!({"peer_address": "10.0.0.2", "timestamp": "100"}),
            serde_json::json!({"peer_address": "10.0.0.2", "timestamp": "250"}),
            serde_json::json!({"peer_address": "10.0.0.3", "timestamp": "50"}),
            serde_json::json!({"peer_address": "", "timestamp": "999"}),
        ];
        let map = last_transition_by_peer(&events);
        assert_eq!(map.get("10.0.0.2"), Some(&250));
        assert_eq!(map.get("10.0.0.3"), Some(&50));
    }

    // ---- bundle integration ------------------------------------------

    /// Extract a produced tar.gz into (root-relative path -> contents).
    fn extract_bundle(path: &Path) -> Vec<(String, String)> {
        let file = fs::File::open(path).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let mut out = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let full = entry.path().unwrap().to_string_lossy().to_string();
            let rel = full
                .split_once('/')
                .map(|(_, rest)| rest.to_string())
                .expect("all entries live under one root directory");
            let mut contents = String::new();
            entry.read_to_string(&mut contents).unwrap();
            out.push((rel, contents));
        }
        out
    }

    fn find<'a>(files: &'a [(String, String)], rel: &str) -> &'a str {
        &files
            .iter()
            .find(|(p, _)| p == rel)
            .unwrap_or_else(|| panic!("bundle missing {rel}"))
            .1
    }

    fn neighbor(
        address: &str,
        state: i32,
        flaps: u64,
        description: &str,
    ) -> rustbgpd_api::proto::NeighborState {
        rustbgpd_api::proto::NeighborState {
            config: Some(rustbgpd_api::proto::NeighborConfig {
                address: address.to_string(),
                remote_asn: 65002,
                description: description.to_string(),
                hold_time: 90,
                ..Default::default()
            }),
            state,
            uptime_seconds: 3600,
            flap_count: flaps,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn doctor_bundle_has_v2_layout_and_manifest() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));
        *server.state.list_neighbors_response.lock().await =
            vec![neighbor("10.0.0.2", 6, 0, "core peer")];
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        let code = run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
            },
        )
        .await
        .unwrap();
        // Exit code is 0 or 2 depending on host facts (e.g. a real local
        // rustbgpd with a low rlimit); the contract-level cases are pinned
        // by the pure-logic tests and the daemon-down test below.
        assert!(code == 0 || code == 2);

        let files = extract_bundle(&bundle_path);
        for expected in [
            "manifest.json",
            "config/effective.toml",
            "peers/neighbors.json",
            "peers/events.json",
            "system/environment.json",
            "system/health.json",
            "system/global.json",
            "system/metrics.prom",
        ] {
            find(&files, expected);
        }

        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_eq!(manifest["format"], 2);
        assert_eq!(manifest["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["daemon_version"], "0.0.0-mock");
        assert_eq!(manifest["sections"]["peers"], "collected");
        assert!(
            manifest["sections"]["logs"]
                .as_str()
                .unwrap()
                .contains("stdout/journald"),
            "logs section records the stdout-only default"
        );
        assert!(
            manifest["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| { c["name"] == "daemon.reachable" && c["status"] == "ok" })
        );
        assert!(
            manifest["note"]
                .as_str()
                .unwrap()
                .contains("No daemon config file or bearer token material is copied.")
        );

        // The effective config is the daemon dump, verbatim.
        assert!(find(&files, "config/effective.toml").contains("asn = 65000"));
        assert!(find(&files, "peers/neighbors.json").contains("10.0.0.2"));
    }

    #[tokio::test]
    async fn doctor_flags_stuck_peer_and_exits_red() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));
        // State 2 = Connect, no session events => stuck with no recent
        // transition => red.
        *server.state.list_neighbors_response.lock().await =
            vec![neighbor("10.0.0.9", 2, 0, "stuck peer")];
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        let code = run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 2, "stuck peer must produce the red exit code");

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert!(manifest["checks"].as_array().unwrap().iter().any(|c| {
            c["name"] == "peer.10.0.0.9.session"
                && c["status"] == "fail"
                && c["detail"].as_str().unwrap().contains("in Connect")
        }));
    }

    /// LAN-324 scope item 5: a seeded `md5_password` value and a bearer
    /// token must never appear anywhere in a produced bundle. Secrets are
    /// pushed through every client-side collection path (metrics text,
    /// neighbor description, event free text, crash reports, the log
    /// tail), the tar is extracted, and every file is grepped.
    #[tokio::test]
    async fn seeded_secrets_never_appear_anywhere_in_the_bundle() {
        const MD5_SECRET: &str = "hunter2-md5-seekrit";
        const BEARER_SECRET: &str = "tok-sekrit-bearer-value";

        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        // Crash report a hostile/buggy panic message could have produced.
        let crash_dir = state_dir.path().join("crash");
        fs::create_dir_all(&crash_dir).unwrap();
        fs::write(
            crash_dir.join("panic-0000000001-000.toml"),
            format!(
                "message = \"config md5_password {MD5_SECRET} echoed\"\nlocation = \"x:1:1\"\n"
            ),
        )
        .unwrap();
        // The daemon redacts the effective config itself; what doctor must
        // guarantee is that the raw file (with the real md5_password) is
        // never read. Serve the daemon-redacted form.
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n\n[[neighbors]]\naddress = \"192.0.2.2\"\nmd5_password = \"<redacted>\"\n",
            state_dir.path().display()
        ));
        *server.state.metrics_text.lock().await = Some(format!(
            "bgp_peers_total 1\ndebug_password_echo{{password=\"{MD5_SECRET}\"}} 1\n"
        ));
        *server.state.list_neighbors_response.lock().await = vec![neighbor(
            "192.0.2.2",
            6,
            0,
            &format!("md5_password={MD5_SECRET} for this peer"),
        )];
        *server.state.session_events.lock().await = vec![rustbgpd_api::proto::BgpEvent {
            timestamp: "100".to_string(),
            peer_address: "192.0.2.2".to_string(),
            summary: format!("peer offered bearer {BEARER_SECRET}"),
            ..Default::default()
        }];
        // Operator-tailed log file carrying a token line.
        let log_file = state_dir.path().join("daemon.jsonl");
        fs::write(
            &log_file,
            format!("{{\"msg\":\"ok\"}}\n{{\"msg\":\"auth\",\"token\":\"{BEARER_SECRET}\"}}\n"),
        )
        .unwrap();

        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");
        run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: Some(&log_file),
                daemon_address: &server.addr,
                token_file_configured: true,
                json: true,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        // The seeded material took its intended paths...
        find(&files, "crashes/panic-0000000001-000.toml");
        find(&files, "logs/tail-1000.jsonl");
        // ...and no file in the bundle carries either secret.
        for (path, contents) in &files {
            assert!(
                !contents.contains(MD5_SECRET),
                "md5 secret leaked into {path}:\n{contents}"
            );
            assert!(
                !contents.contains(BEARER_SECRET),
                "bearer token leaked into {path}:\n{contents}"
            );
        }
    }

    #[tokio::test]
    async fn doctor_against_down_daemon_still_produces_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");
        let absent = dir.path().join("nobody-home.sock");
        let addr = format!("unix://{}", absent.display());
        let connection = connect(&addr, None).await;
        assert!(connection.is_err(), "precondition: daemon is down");

        let code = run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &addr,
                token_file_configured: false,
                json: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 2, "unreachable daemon is a red check");

        let files = extract_bundle(&bundle_path);
        find(&files, "system/environment.json");
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_eq!(manifest["daemon_version"], serde_json::Value::Null);
        assert_eq!(
            manifest["sections"]["config"],
            "unavailable: daemon unreachable"
        );
        assert_eq!(
            manifest["sections"]["peers"],
            "unavailable: daemon unreachable"
        );
        assert!(
            manifest["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| { c["name"] == "daemon.reachable" && c["status"] == "fail" })
        );
        // No daemon-backed files sneak in.
        assert!(!files.iter().any(|(p, _)| p == "config/effective.toml"));
        assert!(!files.iter().any(|(p, _)| p == "peers/neighbors.json"));
    }
}
