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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::commands::config::confirmation_status_label;
use crate::commands::watch::bgp_event_json_value;
use crate::connection::{
    Connection, EFFECTIVE_CONFIG_RPC_TIMEOUT, LocalProcess, READ_RPC_TIMEOUT, proc_start_ticks,
    rpc_with_timeout,
};
use crate::error::CliError;
use crate::output::{self, JsonNeighbor, outln};
use crate::proto::bfd_service_client::BfdServiceClient;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    BfdSession, BfdSessionState, ConfigTransactionConfirmationStatus,
    ConfigTransactionStatusResponse, GetBfdSessionsRequest, GetConfigTransactionStatusRequest,
    GetEffectiveConfigRequest, GetGlobalRequest, GetValidationPolicyPostureRequest,
    GetValidationPolicyPostureResponse, HealthRequest, ListDynamicNeighborsRequest,
    ListNeighborsRequest, ListPolicyEventsRequest, ListSessionEventsRequest, MetricsRequest,
    ValidationPolicyDimensionPosture, ValidationPolicyDisposition,
};

/// Bounded recent slice pulled from each event history for triage. The
/// daemon clamps to its own 4096-event ceiling; this keeps the bundle small.
const EVENT_HISTORY_LIMIT: u32 = 256;

/// Keys in the shipped `BgpEvent` JSON whose values are free text that
/// could echo operator/peer-supplied strings (e.g. RFC 8203 shutdown
/// reasons). Redacted the same way `tcp_ao_detail`/metrics are.
const EVENT_FREE_TEXT_KEYS: &[&str] = &["summary", "reason", "shutdown_reason", "target"];

/// A non-Established peer with a retained transition older than this is
/// red, not merely "settling". Missing history cannot prove the age.
const STUCK_PEER_SECS: u64 = 120;

/// Established peers that have flapped at least this often get an
/// additional check. It is red only when retained history also proves
/// recent instability; the counter itself covers the daemon lifetime.
const FLAP_REPORT_THRESHOLD: u64 = 5;

/// A retained session loss within this window correlates a high lifetime
/// flap count with instability that is still current.
const RECENT_FLAP_SECS: u64 = 120;

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

/// Daemon config file default, mirrored from the daemon's CLI. Used as
/// the probe-target source when the daemon (and thus its effective-config
/// RPC) is down and no local daemon process names another path.
const DEFAULT_CONFIG_PATH: &str = "/etc/rustbgpd/config.toml";

/// Per-endpoint TCP probe budget. Every first-deploy probe is bounded by
/// this so a config full of dead endpoints cannot hang doctor.
const PROBE_TIMEOUT_SECS: u64 = 2;

/// Free-space thresholds for `runtime_state_dir`: below WARN the check is
/// yellow, below FAIL it is red (journal/MRT/crash/event-history writes
/// are about to start failing).
const STATE_DIR_DISK_WARN_BYTES: u64 = 1024 * 1024 * 1024;
const STATE_DIR_DISK_FAIL_BYTES: u64 = 100 * 1024 * 1024;

pub(crate) struct DoctorOptions<'a> {
    /// Bundle output path. Defaults to `rustbgpd-doctor-<unix-seconds>.tar.gz`
    /// under [`default_bundle_dir`].
    pub output: Option<&'a Path>,
    /// Daemon log file to tail into the bundle (the daemon itself logs to
    /// stdout/journald; only an operator-named file is ever read).
    pub log_file: Option<&'a Path>,
    pub daemon_address: &'a str,
    pub token_file_configured: bool,
    pub json: bool,
    /// `--pre-upgrade CONFIG`: add the read-only pre-upgrade checks against
    /// the config file the upgraded daemon will boot. `None` keeps doctor's
    /// ordinary check and RPC set unchanged.
    pub pre_upgrade: Option<&'a Path>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
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

impl Check {
    fn human_text(&self) -> String {
        use owo_colors::{OwoColorize, Stream::Stdout};
        let marker = match self.status {
            CheckStatus::Ok => format!("  {}", "ok".if_supports_color(Stdout, |s| s.green())),
            CheckStatus::Warn => {
                format!("{}", "warn".if_supports_color(Stdout, |s| s.yellow()))
            }
            CheckStatus::Fail => format!("{}", "FAIL".if_supports_color(Stdout, |s| s.red())),
        };
        format!("{marker}  {}", self.detail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionHistoryEvidence {
    /// The history RPC failed, so even the bounded recent window is unknown.
    Unavailable,
    /// The history RPC succeeded. Timestamps and administrative state may
    /// still be absent because the 256-event fleet-wide window did not retain
    /// this peer.
    Retained {
        last_transition_unix: Option<u64>,
        last_loss_unix: Option<u64>,
        latest_admin_state: Option<RetainedAdminState>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedAdminState {
    Enabled,
    Disabled,
}

/// Records checks and prints them live (human mode) as they are produced.
struct Reporter {
    json: bool,
    checks: Vec<Check>,
}

impl Reporter {
    fn record(
        &mut self,
        name: impl Into<String>,
        status: CheckStatus,
        detail: impl Into<String>,
    ) -> Result<(), CliError> {
        let check = Check {
            name: name.into(),
            status,
            detail: detail.into(),
        };
        if !self.json {
            outln!("{}", check.human_text())?;
        }
        self.checks.push(check);
        Ok(())
    }

    fn any_fail(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }
}

/// Bundle contents buffered in memory, then written as one gzipped tarball
/// under a single root directory so extraction never splatters files into
/// the cwd. Most sections are small; the bounded effective config can be up
/// to 384 MiB and is moved into the bundle exactly once after its checks and
/// deployment probes have borrowed it.
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
        let file = fs::File::create(path).map_err(|error| {
            CliError::Argument(format!(
                "cannot write support bundle to {}: {error}\n  \
                 hint: pass --output <FILE> to write it somewhere writable",
                path.display()
            ))
        })?;
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
struct DynamicNeighborSnapshot {
    prefix: String,
    peer_group: String,
    remote_asn: u32,
    description: String,
}

/// Doctor-only join of the redacted support projection and live fields used
/// for diagnosis. Keeping these values in one record prevents scoped peers
/// from being paired with another neighbor's hold-down state.
struct NeighborDoctorRecord {
    support: JsonNeighbor,
    identity: String,
    update_group: String,
    max_prefix_restart_remaining_millis: Option<u64>,
}

impl From<&crate::proto::DynamicNeighborRange> for DynamicNeighborSnapshot {
    fn from(range: &crate::proto::DynamicNeighborRange) -> Self {
        Self {
            prefix: range.prefix.clone(),
            peer_group: range.peer_group.clone(),
            remote_asn: range.remote_asn,
            description: redact_text(&range.description),
        }
    }
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

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct BfdSnapshot {
    peer_address: String,
    state: String,
    diagnostic: String,
    strict: bool,
    /// `None` is serialized as JSON null so a bundle from an older daemon does
    /// not silently conflate unknown with a known non-AdminDown cause.
    remote_administrative_down: Option<bool>,
}

impl From<&BfdSession> for BfdSnapshot {
    fn from(session: &BfdSession) -> Self {
        Self {
            peer_address: session.peer_address.clone(),
            state: bfd_state_label(session.state).to_string(),
            diagnostic: session.diagnostic.clone(),
            strict: session.strict,
            remote_administrative_down: session.remote_administrative_down,
        }
    }
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

fn bfd_state_label(value: i32) -> &'static str {
    match BfdSessionState::try_from(value) {
        Ok(BfdSessionState::AdminDown) => "admin-down",
        Ok(BfdSessionState::Down) => "down",
        Ok(BfdSessionState::Init) => "init",
        Ok(BfdSessionState::Up) => "up",
        Ok(BfdSessionState::Unspecified) | Err(_) => "unspecified",
    }
}

fn validation_axis_check(response: &GetValidationPolicyPostureResponse, rpki: bool) -> Check {
    let (name, label, advice, aggregate) = if rpki {
        (
            "rpki.invalid_route_policy",
            "RPKI-invalid",
            "review `reject-rpki-invalid` in examples/route-server/config.toml",
            response.rpki_invalid.as_ref(),
        )
    } else {
        (
            "aspa.invalid_route_policy",
            "ASPA-invalid",
            "review `reject-aspa-invalid` in examples/route-server/hygiene.rpol",
            response.aspa_invalid.as_ref(),
        )
    };
    let enforced = response.complete
        && response.omitted == 0
        && !response.scopes.is_empty()
        && dimension_is_enforced(aggregate)
        && response.scopes.iter().all(|scope| {
            dimension_is_enforced(if rpki {
                scope.rpki_invalid.as_ref()
            } else {
                scope.aspa_invalid.as_ref()
            })
        });
    Check {
        name: name.to_string(),
        status: if enforced {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        detail: if enforced {
            format!(
                "compiled import-policy disposition proves every reported scope denies {label} \
                 routes; this does not prove validation readiness/currentness, traffic, intent, \
                 FIB state, or runtime enforcement"
            )
        } else {
            format!(
                "compiled import-policy disposition does not prove every reported scope denies \
                 {label} routes; {advice}. This advisory does not report validation \
                 readiness/currentness, traffic, intent, FIB state, or runtime enforcement"
            )
        },
    }
}

fn dimension_is_enforced(dimension: Option<&ValidationPolicyDimensionPosture>) -> bool {
    dimension.is_some_and(|dimension| {
        ValidationPolicyDisposition::try_from(dimension.disposition)
            == Ok(ValidationPolicyDisposition::Enforced)
    })
}

fn validation_policy_posture_checks(
    result: Result<GetValidationPolicyPostureResponse, tonic::Status>,
) -> [Check; 2] {
    match result {
        Ok(response) => [
            validation_axis_check(&response, true),
            validation_axis_check(&response, false),
        ],
        Err(status) => {
            let detail = if status.code() == tonic::Code::Unimplemented {
                "serving daemon predates GetValidationPolicyPosture; upgrade it to evaluate the \
                 compiled-policy disposition"
                    .to_string()
            } else {
                format!(
                    "GetValidationPolicyPosture RPC unavailable ({}); compiled-policy \
                     disposition was not evaluated",
                    status.code()
                )
            };
            [true, false].map(|rpki| {
                let name = if rpki {
                    "rpki.invalid_route_policy"
                } else {
                    "aspa.invalid_route_policy"
                };
                Check {
                    name: name.to_string(),
                    status: CheckStatus::Warn,
                    detail: detail.clone(),
                }
            })
        }
    }
}

/// ADR-0112 policy-requirement check for one neighbor, both directions.
///
/// - `not_required` passes silently: enforcement off, or an iBGP session. The
///   compatibility default is off, so warning here would turn every current
///   deployment yellow for using the default.
/// - `missing` fails and names the direction. The reserved internal deny is
///   installed there; the session is up and exchanging keepalives while no
///   route crosses that direction, in any negotiated family.
/// - `unknown` warns rather than passes. A daemon that predates the field
///   sends nothing, and "no evidence" must not read as "no problem".
///
/// Deliberately not wired to readiness. A peer missing operator policy is a
/// configuration state to repair; `/readyz` answers whether this process can
/// serve traffic, and depooling a healthy route reflector over one peer's
/// config widens the blast radius instead of narrowing it.
fn rfc8212_policy_check(address: &str, import: i32, export: i32) -> Check {
    use crate::commands::neighbor::rfc8212_policy_status_label as label;

    let (import, export) = (label(import), label(export));
    let missing: Vec<&str> = [("import", import), ("export", export)]
        .into_iter()
        .filter_map(|(direction, status)| (status == "missing").then_some(direction))
        .collect();
    let (status, verdict) = if missing.is_empty() {
        if import == "unknown" || export == "unknown" {
            (
                CheckStatus::Warn,
                "RFC 8212 policy status is unknown; the serving daemon does not expose it"
                    .to_string(),
            )
        } else if import == "not_required" && export == "not_required" {
            (
                CheckStatus::Ok,
                "RFC 8212 explicit policy is not required (enforcement disabled, or iBGP)"
                    .to_string(),
            )
        } else {
            (
                CheckStatus::Ok,
                format!("RFC 8212 explicit policy present (import: {import}, export: {export})"),
            )
        }
    } else {
        (
            CheckStatus::Fail,
            format!(
                "RFC 8212 explicit policy missing on {}; the reserved internal deny is installed \
                 and no route crosses that direction — configure an explicit policy or disable \
                 [global] ebgp_requires_policy",
                missing.join(" and ")
            ),
        )
    };
    Check {
        name: format!("peer.{address}.rfc8212_policy"),
        status,
        detail: format!("neighbor {address}: {verdict}"),
    }
}

fn bfd_check(session: &BfdSnapshot) -> Check {
    let (status, verdict) = match session.state.as_str() {
        "up" if session.remote_administrative_down != Some(true) => {
            (CheckStatus::Ok, "BFD session is Up".to_string())
        }
        "up" => (
            CheckStatus::Warn,
            "BFD session is Up but the remote AdminDown cause is inconsistent or unknown"
                .to_string(),
        ),
        "down" if session.remote_administrative_down == Some(true) => (
            CheckStatus::Warn,
            "peer administratively disabled BFD; BGP is permitted by RFC 5882 section 4.1"
                .to_string(),
        ),
        "down" if session.remote_administrative_down.is_none() => (
            CheckStatus::Fail,
            format!(
                "BFD session is Down ({}) and the remote AdminDown cause is unknown; serving daemon predates field 5",
                session.diagnostic
            ),
        ),
        "down" => (
            CheckStatus::Fail,
            format!("BFD session is Down ({})", session.diagnostic),
        ),
        "init" => (
            CheckStatus::Warn,
            "BFD session is still initializing".to_string(),
        ),
        "admin-down" => (
            CheckStatus::Warn,
            "local BFD session is administratively down".to_string(),
        ),
        _ => (
            CheckStatus::Warn,
            "BFD session state is unknown".to_string(),
        ),
    };
    Check {
        name: format!("peer.{}.bfd", session.peer_address),
        status,
        detail: format!("neighbor {}: {verdict}", session.peer_address),
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
fn config_state_dir(value: &toml::Value) -> Option<String> {
    Some(
        value
            .get("global")?
            .get("runtime_state_dir")?
            .as_str()?
            .to_string(),
    )
}

fn deploy_config_source<'a>(
    effective_toml: Option<&'a str>,
    local_config_source: Option<&'a (String, String)>,
) -> Option<(&'a str, &'a str)> {
    effective_toml
        .map(|toml_text| (toml_text, "effective config"))
        .or_else(|| {
            local_config_source.map(|(toml_text, source)| (toml_text.as_str(), source.as_str()))
        })
}

fn tcp_ao_configured_targets(value: &toml::Value) -> Vec<String> {
    let mut targets = Vec::new();
    for (table, identity) in [("neighbors", "address"), ("dynamic_neighbors", "prefix")] {
        if let Some(rows) = value.get(table).and_then(toml::Value::as_array) {
            for row in rows {
                if row.get("tcp_ao").is_some()
                    && let Some(target) = row.get(identity).and_then(toml::Value::as_str)
                {
                    targets.push(target.to_string());
                }
            }
        }
    }
    targets.sort();
    targets
}

fn tcp_ao_capability_checks(document: &toml::Value, support: i32) -> Vec<Check> {
    tcp_ao_configured_targets(document)
        .into_iter()
        .map(|target| {
            let (status, verdict) = match crate::proto::TcpAoSupport::try_from(support) {
                Ok(crate::proto::TcpAoSupport::Supported) => {
                    (CheckStatus::Ok, "kernel TCP-AO support available")
                }
                Ok(crate::proto::TcpAoSupport::Unsupported) => (
                    CheckStatus::Fail,
                    "config requires TCP-AO but the kernel reports it unsupported",
                ),
                Ok(crate::proto::TcpAoSupport::ProbeFailed) => (
                    CheckStatus::Warn,
                    "config requires TCP-AO but the kernel capability probe failed",
                ),
                Ok(crate::proto::TcpAoSupport::Unspecified) | Err(_) => (
                    CheckStatus::Warn,
                    "config requires TCP-AO but kernel capability is unknown",
                ),
            };
            Check {
                name: format!("peer.{target}.tcp_ao_capability"),
                status,
                detail: format!("neighbor {target}: {verdict}"),
            }
        })
        .collect()
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

/// Limits belong only to the process observed on this connection's UDS stream.
/// TCP, inaccessible procfs, and changed process identities provide no local evidence.
fn local_daemon_limits(connection: Option<&Connection>) -> Option<(u32, String)> {
    let connection = connection?;
    let process = connection.local_process()?;
    let limits = process.read_file("limits")?;
    (connection.local_process() == Some(process)).then_some((process.pid, limits))
}

/// Pure rlimit check: red when the soft `nofile` limit is below
/// [`NOFILE_SOFT_MIN`]. The remediation line is tailored to the detected
/// run context so "raise the limit" names the file to edit.
fn nofile_check(pid: u32, soft: u64, hard: u64, run_context: &str) -> Check {
    let remedy = match run_context {
        "systemd" => "set LimitNOFILE= in the systemd unit and restart",
        "container" => "raise the container runtime's nofile ulimit (e.g. docker --ulimit nofile=)",
        _ => "raise the service's nofile ulimit",
    };
    let (status, verdict) = if soft < NOFILE_SOFT_MIN {
        (
            CheckStatus::Fail,
            format!("low — peers exhaust fds at scale; {remedy}"),
        )
    } else {
        (CheckStatus::Ok, "ok".to_string())
    };
    Check {
        name: format!("daemon.rlimit.nofile.{pid}"),
        status,
        detail: format!("daemon pid {pid} rlimit nofile soft {soft} hard {hard}: {verdict}"),
    }
}

/// Pure per-peer session checks: state (with time-in-state derived from
/// the most recent session event), slow-peer health, and flap count.
#[expect(clippy::too_many_arguments, reason = "snapshot fields")]
fn peer_checks(
    address: &str,
    state: &str,
    stale: bool,
    max_prefix_restart_remaining_millis: Option<u64>,
    slow_peer: bool,
    update_group: &str,
    uptime_seconds: u64,
    flap_count: u64,
    session_evidence: SessionHistoryEvidence,
    now: u64,
    last_error: &str,
) -> Vec<Check> {
    let mut checks = Vec::new();
    if stale {
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status: CheckStatus::Warn,
            detail: format!("peer {address} state read timed out (stale) — session task busy"),
        });
    } else if let Some(remaining) = max_prefix_restart_remaining_millis {
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status: CheckStatus::Warn,
            detail: format!(
                "peer {address} is intentionally held down after max-prefix shutdown; automatic restart countdown has {remaining}ms remaining (state {state})"
            ),
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
    } else if matches!(
        session_evidence,
        SessionHistoryEvidence::Retained {
            latest_admin_state: Some(RetainedAdminState::Disabled),
            ..
        }
    ) {
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status: CheckStatus::Ok,
            detail: format!("peer {address} administratively disabled (state {state})"),
        });
    } else {
        let (status, since) = match session_evidence {
            SessionHistoryEvidence::Retained {
                last_transition_unix: Some(ts),
                ..
            } => {
                let elapsed = now.saturating_sub(ts);
                let status = if elapsed >= STUCK_PEER_SECS {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Warn
                };
                (status, format!("for {}", output::format_duration(elapsed)))
            }
            SessionHistoryEvidence::Retained {
                last_transition_unix: None,
                ..
            } => (
                CheckStatus::Warn,
                format!(
                    "for an unknown duration (no transition retained in the bounded {EVENT_HISTORY_LIMIT}-event fleet history)"
                ),
            ),
            SessionHistoryEvidence::Unavailable => (
                CheckStatus::Warn,
                "for an unknown duration (session-event history unavailable)".to_string(),
            ),
        };
        let cause = if last_error.is_empty() {
            String::new()
        } else {
            format!("; last error: {last_error}")
        };
        checks.push(Check {
            name: format!("peer.{address}.session"),
            status,
            detail: format!("peer {address} in {state} {since}{cause}"),
        });
    }
    if slow_peer {
        let detail = if update_group == "slow_peer" {
            format!(
                "peer {address} is flagged slow and already isolated from shared update groups: outbound queue persistently backlogged; inspect bgp_peer_outbound_queue_depth{{peer=\"{address}\"}} and troubleshoot the member's receive path"
            )
        } else {
            format!(
                "peer {address} is flagged slow: outbound queue persistently backlogged; inspect bgp_peer_outbound_queue_depth{{peer=\"{address}\"}} and enable slow_peer_isolation for chronic single-peer lag"
            )
        };
        checks.push(Check {
            name: format!("peer.{address}.slow_peer"),
            status: CheckStatus::Warn,
            detail,
        });
    }
    if flap_count >= FLAP_REPORT_THRESHOLD {
        let last_loss_unix = match session_evidence {
            SessionHistoryEvidence::Retained { last_loss_unix, .. } => last_loss_unix,
            SessionHistoryEvidence::Unavailable => None,
        };
        let recent_loss_age = last_loss_unix
            .filter(|ts| *ts <= now)
            .map(|ts| now.saturating_sub(ts))
            .filter(|age| *age < RECENT_FLAP_SECS);
        let (status, evidence) = if let Some(age) = recent_loss_age {
            (
                CheckStatus::Fail,
                format!(
                    "; retained history shows a session loss {} ago",
                    output::format_duration(age)
                ),
            )
        } else {
            let evidence = match session_evidence {
                SessionHistoryEvidence::Unavailable => {
                    "; recent correlation is unknown because session-event history is unavailable"
                        .to_string()
                }
                SessionHistoryEvidence::Retained { .. } => format!(
                    "; no session loss within the last {} is retained in the bounded history",
                    output::format_duration(RECENT_FLAP_SECS)
                ),
            };
            (CheckStatus::Warn, evidence)
        };
        checks.push(Check {
            name: format!("peer.{address}.flaps"),
            status,
            detail: format!(
                "peer {address} flapped {flap_count} times during this daemon lifetime{evidence}"
            ),
        });
    }
    checks
}

/// A blocking outbound family is intentionally withholding routes. Rows that
/// are merely limited (or unlimited) are capacity inventory, not failures.
fn outbound_prefix_limit_checks(
    identity: &str,
    rows: &[crate::proto::OutboundPrefixLimitState],
) -> Vec<Check> {
    rows.iter()
        .filter(|row| row.blocking)
        .map(|row| {
            let limit = row
                .limit
                .map_or_else(|| "unlimited".to_string(), |limit| limit.to_string());
            let reason = row
                .reason
                .as_deref()
                .filter(|reason| !reason.is_empty())
                .unwrap_or("unknown (daemon omitted reason)");
            Check {
                name: format!(
                    "peer.{identity}.outbound_prefix_limit.{}",
                    row.family
                ),
                status: CheckStatus::Fail,
                detail: format!(
                    "peer {identity} family {} is intentionally withholding routes: usage {}, limit {limit}, reason {reason}",
                    row.family, row.usage
                ),
            }
        })
        .collect()
}

/// Most recent session-event timestamp per peer, for time-in-state.
fn last_transition_by_peer(events: &[serde_json::Value]) -> HashMap<String, u64> {
    last_event_by_peer(events, |_| true)
}

/// Most recent retained session-loss timestamp per peer, used to
/// distinguish current instability from an old daemon-lifetime counter.
fn last_loss_by_peer(events: &[serde_json::Value]) -> HashMap<String, u64> {
    last_event_by_peer(events, |event| {
        event.get("event_type").and_then(|v| v.as_str()) == Some("session_lost")
    })
}

/// Latest retained operator intent per peer.
///
/// The daemon returns the retained vector oldest-to-newest. Fold that order
/// directly: lifecycle events are stamped only to whole seconds, and unrelated
/// later FSM events must not erase the most recent enable/disable intent.
fn latest_admin_state_by_peer(events: &[serde_json::Value]) -> HashMap<String, RetainedAdminState> {
    let mut map = HashMap::new();
    for event in events {
        let state = match event.get("event_type").and_then(|v| v.as_str()) {
            Some("peer_enabled") => RetainedAdminState::Enabled,
            Some("peer_disabled") => RetainedAdminState::Disabled,
            _ => continue,
        };
        let Some(peer) = event
            .get("peer_address")
            .and_then(|v| v.as_str())
            .filter(|peer| !peer.is_empty())
        else {
            continue;
        };
        map.insert(peer.to_string(), state);
    }
    map
}

fn peer_identity(address: &str, interface: &str) -> String {
    if interface.is_empty() {
        address.to_string()
    } else {
        format!("{address}%{interface}")
    }
}

#[derive(Default)]
struct GtsmInventory {
    static_peers: HashMap<String, Option<u8>>,
    peer_groups: HashMap<String, Option<u8>>,
}

#[derive(Default)]
struct AdminEnabledInventory {
    peers: HashMap<String, Option<bool>>,
}

fn configured_gtsm_hops(row: &toml::Value) -> Option<u8> {
    if row.get("ttl_security").and_then(toml::Value::as_bool) != Some(true) {
        return None;
    }
    match row.get("ttl_security_hops") {
        None => Some(1),
        Some(value) => value
            .as_integer()
            .and_then(|hops| u8::try_from(hops).ok())
            .filter(|hops| *hops != 0),
    }
}

fn insert_unique(map: &mut HashMap<String, Option<u8>>, key: String, hops: u8) {
    match map.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(Some(hops));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.insert(None);
        }
    }
}

fn gtsm_inventory(value: &toml::Value) -> GtsmInventory {
    let mut inventory = GtsmInventory::default();
    for row in value
        .get("neighbors")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(hops) = configured_gtsm_hops(row) else {
            continue;
        };
        let Some(address) = row.get("address").and_then(toml::Value::as_str) else {
            continue;
        };
        let interface = row
            .get("interface")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        insert_unique(
            &mut inventory.static_peers,
            peer_identity(address, interface),
            hops,
        );
    }
    for (name, row) in value
        .get("peer_groups")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(toml::map::Map::iter)
    {
        if let Some(hops) = configured_gtsm_hops(row) {
            insert_unique(&mut inventory.peer_groups, name.clone(), hops);
        }
    }
    inventory
}

fn parse_metric_labels(input: &str) -> Option<HashMap<String, String>> {
    let mut labels = HashMap::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (name, after_name) = rest.split_once('=')?;
        if name.is_empty() || !after_name.starts_with('"') {
            return None;
        }
        let mut value = String::new();
        let mut escaped = false;
        let mut end = None;
        for (offset, ch) in after_name[1..].char_indices() {
            if escaped {
                value.push(match ch {
                    'n' => '\n',
                    '\\' => '\\',
                    '"' => '"',
                    _ => return None,
                });
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                end = Some(offset + 2);
                break;
            } else {
                value.push(ch);
            }
        }
        let end = end?;
        if labels.insert(name.to_string(), value).is_some() {
            return None;
        }
        rest = &after_name[end..];
        if rest.is_empty() {
            break;
        }
        rest = rest.strip_prefix(',')?;
    }
    Some(labels)
}

fn admin_enabled_inventory(metrics: &str) -> Option<AdminEnabledInventory> {
    let mut inventory = AdminEnabledInventory::default();
    for line in metrics.lines() {
        let Some(rest) = line.strip_prefix("bgp_peer_admin_enabled{") else {
            continue;
        };
        let (label_text, value_text) = rest.split_once("} ")?;
        let labels = parse_metric_labels(label_text)?;
        let peer = labels.get("peer")?.clone();
        let interface = labels.get("interface")?.clone();
        let enabled = match value_text {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        let key = peer_identity(&peer, &interface);
        match inventory.peers.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(enabled));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    (!inventory.peers.is_empty()).then_some(inventory)
}

fn gtsm_advisory_check(
    record: &NeighborDoctorRecord,
    session_evidence: SessionHistoryEvidence,
    inventory: Option<&GtsmInventory>,
    admin_enabled: Option<&AdminEnabledInventory>,
) -> Option<Check> {
    if record.support.stale
        || record.support.state == "Established"
        || record.support.flap_count != 0
        || record.max_prefix_restart_remaining_millis.is_some()
        || matches!(
            session_evidence,
            SessionHistoryEvidence::Retained {
                latest_admin_state: Some(RetainedAdminState::Disabled),
                ..
            }
        )
    {
        return None;
    }
    let inventory = inventory?;
    let hops = if record.support.is_dynamic {
        let peer_group = &record.support.accepted_dynamic_range.as_ref()?.peer_group;
        inventory.peer_groups.get(peer_group).copied().flatten()?
    } else {
        inventory
            .static_peers
            .get(&record.identity)
            .copied()
            .flatten()?
    };
    if admin_enabled?.peers.get(&record.identity) != Some(&Some(true)) {
        return None;
    }
    Some(Check {
        name: format!("peer.{}.ttl_security", record.identity),
        status: CheckStatus::Warn,
        detail: format!(
            "peer {} has ttl_security enabled (ttl_security_hops={hops}) and has not established during the current session-task lifetime; GTSM drops occur in the kernel before BGP and produce no NOTIFICATION. Confirm the peer transmits TTL/Hop Limit 255 and that ttl_security_hops covers the actual path; this is an advisory, not a diagnosis.",
            record.identity
        ),
    })
}

fn last_event_by_peer(
    events: &[serde_json::Value],
    include: impl Fn(&serde_json::Value) -> bool,
) -> HashMap<String, u64> {
    let mut map: HashMap<String, u64> = HashMap::new();
    for event in events {
        if !include(event) {
            continue;
        }
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

// ---- first-deploy probes (LAN-482) ----------------------------------
//
// All probes are read-only: TCP connects that are immediately dropped, a
// test-bind that is immediately released, statvfs/access, and /proc
// reads. Each network touch is bounded by [`PROBE_TIMEOUT_SECS`].

/// Read a documented key path without projecting the daemon's config schema.
/// The effective document is parsed once and shared by all doctor checks.
fn config_value<'a>(document: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    path.iter().try_fold(document, |value, key| value.get(*key))
}

fn config_rows<'a>(document: &'a toml::Value, path: &[&str]) -> &'a [toml::Value] {
    config_value(document, path)
        .and_then(toml::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn config_addresses(document: &toml::Value, path: &[&str]) -> Vec<String> {
    config_rows(document, path)
        .iter()
        .filter_map(|row| row.get("address").and_then(toml::Value::as_str))
        .map(str::to_string)
        .collect()
}

fn config_listen_port(document: &toml::Value) -> Option<u16> {
    config_value(document, &["global", "listen_port"])
        .and_then(toml::Value::as_integer)
        .and_then(|port| u16::try_from(port).ok())
}

fn rpki_vrp_table_check(configured_caches: &[String], metrics: Option<&str>) -> Option<Check> {
    if configured_caches.is_empty() {
        return None;
    }
    let Some(metrics) = metrics else {
        return Some(Check {
            name: "rpki.vrp_table".to_string(),
            status: CheckStatus::Warn,
            detail: "RPKI caches are configured but the metrics snapshot is unavailable; \
                     rerun doctor after the metrics RPC succeeds"
                .to_string(),
        });
    };
    let count = crate::commands::control::rpki_vrp_count_sum(metrics);
    let readiness = crate::commands::control::rpki_cache_end_of_data_readiness(metrics);
    let configured = configured_caches
        .iter()
        .map(|cache| cache.parse::<std::net::SocketAddr>())
        .collect::<Result<Vec<_>, _>>();
    let (status, detail) = match (count, readiness, configured) {
        (None, _, _) => (
            CheckStatus::Warn,
            "RPKI caches are configured but bgp_rpki_vrp_count is absent or malformed; \
             inspect /metrics and RTR synchronization"
                .to_string(),
        ),
        (_, None, _) => (
            CheckStatus::Warn,
            "RPKI caches are configured but bgp_rpki_cache_end_of_data_ready is malformed; \
             inspect /metrics and RTR synchronization"
                .to_string(),
        ),
        (_, _, Err(_)) => (
            CheckStatus::Warn,
            "A configured RPKI cache address is invalid; expected IP:port or [IPv6]:port"
                .to_string(),
        ),
        (Some(count), Some(readiness), Ok(configured)) => {
            let not_ready = configured
                .iter()
                .filter(|cache| readiness.get(cache) == Some(&false))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let missing = configured
                .iter()
                .filter(|cache| !readiness.contains_key(cache))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if count > 0 && not_ready.is_empty() && missing.is_empty() {
                (
                    CheckStatus::Ok,
                    format!(
                        "RPKI VRP table contains {count} IPv4+IPv6 entries; every configured cache has retained accepted complete End-of-Data readiness"
                    ),
                )
            } else {
                let mut reasons = Vec::new();
                if count == 0 {
                    reasons.push("merged VRP count is 0".to_string());
                }
                if !not_ready.is_empty() {
                    reasons.push(format!("not ready: {}", not_ready.join(", ")));
                }
                if !missing.is_empty() {
                    reasons.push(format!("readiness missing: {}", missing.join(", ")));
                }
                (
                    CheckStatus::Warn,
                    format!(
                        "RPKI merged-table prerequisites are incomplete ({})",
                        reasons.join("; ")
                    ),
                )
            }
        }
    };
    Some(Check {
        name: "rpki.vrp_table".to_string(),
        status,
        detail,
    })
}

/// One bounded TCP connect, immediately dropped on success.
async fn probe_tcp(addr: String) -> Result<(), String> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(addr.as_str()),
    )
    .await
    {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("timed out after {PROBE_TIMEOUT_SECS}s")),
    }
}

struct ProbeSpec {
    name: String,
    label: String,
    addr: String,
    advice: &'static str,
    cli_vantage: bool,
}

struct ProbeTaskIdentity {
    name: String,
    label: String,
    addr: String,
}

struct ProbeTask {
    identity: ProbeTaskIdentity,
    handle: tokio::task::JoinHandle<Check>,
}

async fn run_probe(spec: ProbeSpec) -> Check {
    let vantage = spec
        .cli_vantage
        .then_some(" from the rbgp CLI network vantage");
    match probe_tcp(spec.addr.clone()).await {
        Ok(()) => Check {
            name: spec.name,
            status: CheckStatus::Ok,
            detail: format!(
                "{} {} reachable{}",
                spec.label,
                spec.addr,
                vantage.unwrap_or_default()
            ),
        },
        Err(e) => Check {
            name: spec.name,
            status: if spec.cli_vantage {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            detail: format!(
                "{} {} unreachable{} ({e}) — {}{}",
                spec.label,
                spec.addr,
                vantage.unwrap_or_default(),
                if spec.cli_vantage {
                    "this is not daemon-side connectivity evidence; "
                } else {
                    ""
                },
                spec.advice
            ),
        },
    }
}

async fn collect_probe_tasks(tasks: Vec<ProbeTask>) -> (Vec<Check>, bool) {
    let mut checks = Vec::with_capacity(tasks.len());
    let mut task_failed = false;
    for task in tasks {
        match task.handle.await {
            Ok(check) => checks.push(check),
            Err(error) => {
                task_failed = true;
                checks.push(Check {
                    name: task.identity.name,
                    status: CheckStatus::Fail,
                    detail: format!(
                        "{} {} reachability probe task failed ({error}); \
                         doctor could not determine reachability",
                        task.identity.label, task.identity.addr
                    ),
                });
            }
        }
    }
    (checks, task_failed)
}

/// The management host is a fallback only for remote wildcard listeners.
fn daemon_probe_host(daemon_address: &str) -> Option<String> {
    let uri = if daemon_address.starts_with("http://") || daemon_address.starts_with("https://") {
        daemon_address.to_string()
    } else {
        format!("http://{daemon_address}")
    };
    tonic::codegen::http::Uri::try_from(uri)
        .ok()?
        .host()
        .map(|host| host.trim_matches(['[', ']']).to_string())
}

fn local_daemon(daemon_address: &str) -> bool {
    daemon_address.starts_with("unix://")
        || daemon_probe_host(daemon_address).is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
}

/// Explicit addresses come from `[global].listen_addresses`, including when
/// management uses a Unix socket. Omitted addresses mean tolerant dual wildcard
/// listeners: either family can serve if the other is unavailable.
fn listener_probe_hosts(document: &toml::Value, daemon_address: &str) -> Vec<String> {
    if config_value(document, &["global", "listen_addresses"]).is_some() {
        return config_rows(document, &["global", "listen_addresses"])
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect();
    }
    if local_daemon(daemon_address) {
        vec!["127.0.0.1".to_string(), "::1".to_string()]
    } else {
        daemon_probe_host(daemon_address).into_iter().collect()
    }
}

async fn listener_reachability_check(
    document: &toml::Value,
    daemon_address: &str,
    port: u16,
) -> Check {
    let local = local_daemon(daemon_address);
    let explicit = config_value(document, &["global", "listen_addresses"]).is_some();
    let hosts = listener_probe_hosts(document, daemon_address);
    let mut tasks = Vec::new();
    let mut checks = Vec::new();
    for host in hosts {
        let ip = host.parse::<std::net::IpAddr>().ok();
        let addr = ip.map_or_else(
            || format!("{host}:{port}"),
            |ip| std::net::SocketAddr::new(ip, port).to_string(),
        );
        if !local && ip.is_some_and(|ip| ip.is_loopback()) {
            checks.push(Check {
                name: "bgp.listener".to_string(),
                status: CheckStatus::Warn,
                detail: format!("BGP listener {addr} is daemon-local; a remote CLI cannot probe this bind — run doctor on the daemon host"),
            });
            continue;
        }
        let spec = ProbeSpec {
            name: "bgp.listener".to_string(),
            label: "BGP listener".to_string(),
            addr,
            advice: if local {
                "check the daemon log for listener bind errors (a port below 1024 needs CAP_NET_BIND_SERVICE)"
            } else {
                "run doctor on the daemon host to verify listener binds; remote routing or filtering can prevent this CLI probe"
            },
            cli_vantage: !local,
        };
        tasks.push(ProbeTask {
            identity: ProbeTaskIdentity {
                name: spec.name.clone(),
                label: spec.label.clone(),
                addr: spec.addr.clone(),
            },
            handle: tokio::spawn(run_probe(spec)),
        });
    }
    let (results, task_failed) = collect_probe_tasks(tasks).await;
    checks.extend(results);
    listener_probe_summary(checks, task_failed, explicit)
}

fn listener_probe_summary(checks: Vec<Check>, task_failed: bool, explicit: bool) -> Check {
    let status = if checks.is_empty() || task_failed {
        CheckStatus::Fail
    } else if !explicit && checks.iter().any(|check| check.status == CheckStatus::Ok) {
        CheckStatus::Ok
    } else if checks.iter().any(|check| check.status == CheckStatus::Fail) {
        CheckStatus::Fail
    } else if checks.iter().any(|check| check.status == CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };
    let detail = if checks.is_empty() {
        "BGP listener addresses unavailable in config; cannot verify a bind".to_string()
    } else {
        let details = checks
            .into_iter()
            .map(|check| check.detail)
            .collect::<Vec<_>>()
            .join("; ");
        if !explicit && status == CheckStatus::Ok {
            format!(
                "{details}; default wildcard mode requires at least one reachable address family"
            )
        } else {
            details
        }
    };
    Check {
        name: "bgp.listener".to_string(),
        status,
        detail,
    }
}

/// TCP reachability probes for the BGP listener (daemon-up only) and
/// every configured RTR cache / BMP collector / gNMI dial-out collector.
/// Probes run concurrently; results keep config order.
async fn reachability_checks(
    daemon_reachable: bool,
    daemon_address: &str,
    document: &toml::Value,
) -> Vec<Check> {
    let mut specs = Vec::new();
    for addr in config_addresses(document, &["rpki", "cache_servers"]) {
        specs.push(ProbeSpec {
            name: format!("rpki.cache.{addr}.reachable_from_cli"),
            label: "RTR cache".to_string(),
            addr,
            advice: "inspect the daemon-side rpki.vrp_table check and RTR logs for actual \
                     cache state; troubleshoot the CLI path only when rbgp and rustbgpd are \
                     expected to share a network vantage",
            cli_vantage: true,
        });
    }
    for addr in config_addresses(document, &["bmp", "collectors"]) {
        specs.push(ProbeSpec {
            name: format!("bmp.collector.{addr}.reachable_from_cli"),
            label: "BMP collector".to_string(),
            addr,
            advice: "inspect rustbgpd and collector logs for actual export state; troubleshoot \
                     the CLI path only when rbgp and rustbgpd are expected to share a network \
                     vantage",
            cli_vantage: true,
        });
    }
    for row in config_rows(document, &["gnmi_dialout", "targets"]) {
        let (Some(name), Some(addr)) = (
            row.get("name").and_then(toml::Value::as_str),
            row.get("address").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        specs.push(ProbeSpec {
            name: format!("gnmi_dialout.{name}.reachable_from_cli"),
            label: format!("gNMI dial-out collector {name}"),
            addr: addr.to_string(),
            advice: "inspect the daemon-side gnmi_dialout_connected metric and logs for actual \
                     dial-out state; troubleshoot the CLI path only when rbgp and rustbgpd are \
                     expected to share a network vantage",
            cli_vantage: true,
        });
    }
    let tasks = specs
        .into_iter()
        .map(|spec| {
            let identity = ProbeTaskIdentity {
                name: spec.name.clone(),
                label: spec.label.clone(),
                addr: spec.addr.clone(),
            };
            ProbeTask {
                identity,
                handle: tokio::spawn(run_probe(spec)),
            }
        })
        .collect();
    let mut checks = Vec::new();
    if daemon_reachable && let Some(port) = config_listen_port(document) {
        checks.push(listener_reachability_check(document, daemon_address, port).await);
    }
    checks.extend(collect_probe_tasks(tasks).await.0);
    checks
}

/// Daemon-down listener check: test-bind the BGP listen port and release
/// it, mapping bind errors to first-deploy advice.
fn listener_bind_check(port: u16) -> Check {
    bind_check_from_result(
        port,
        std::net::TcpListener::bind(("0.0.0.0", port)).map(drop),
    )
}

fn bind_check_from_result(port: u16, result: std::io::Result<()>) -> Check {
    let name = "bgp.listener".to_string();
    let (status, detail) = match result {
        Ok(()) => (
            CheckStatus::Ok,
            format!("BGP listen port {port} is bindable (daemon not running; test-bind released)"),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => (
            CheckStatus::Warn,
            format!(
                "BGP listen port {port} is already in use — another process (possibly a \
                 rustbgpd this doctor run could not reach) holds it"
            ),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (
            CheckStatus::Fail,
            format!(
                "cannot bind BGP listen port {port}: permission denied — grant the daemon \
                 CAP_NET_BIND_SERVICE (systemd: AmbientCapabilities=CAP_NET_BIND_SERVICE) \
                 or use a port >= 1024"
            ),
        ),
        Err(e) => (
            CheckStatus::Fail,
            format!("cannot bind BGP listen port {port}: {e}"),
        ),
    };
    Check {
        name,
        status,
        detail,
    }
}

/// Free bytes available to unprivileged writers on the filesystem
/// holding `path`.
fn disk_free_bytes(path: &Path) -> Option<u64> {
    let vfs = nix::sys::statvfs::statvfs(path).ok()?;
    Some(vfs.blocks_available().saturating_mul(vfs.fragment_size()))
}

fn dir_writable(path: &Path) -> bool {
    nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok()
}

/// Directory a defaulted (no `--output`) bundle lands in: the working
/// directory when it is writable — the historical behavior — else the
/// daemon's runtime state dir, else the temp dir. The container image
/// runs as a nonroot user with `/` as its working directory, so an
/// unqualified `rbgp doctor` must not fail on an unwritable cwd right
/// when someone is trying to file a report.
fn default_bundle_dir(cwd: &Path, state_dir: Option<&str>) -> PathBuf {
    [
        cwd.to_path_buf(),
        PathBuf::from(state_dir.unwrap_or(DEFAULT_STATE_DIR)),
    ]
    .into_iter()
    .find(|dir| dir_writable(dir))
    .unwrap_or_else(std::env::temp_dir)
}

fn human_bytes(bytes: u64) -> String {
    #[allow(
        clippy::cast_precision_loss,
        reason = "human-readable GiB display does not need integer precision"
    )]
    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    if gib >= 1.0 {
        format!("{gib:.1} GiB")
    } else {
        format!("{} MiB", bytes / (1024 * 1024))
    }
}

/// State-dir health: existence, writability (for the invoking user), and
/// free disk space against the yellow/red thresholds.
fn state_dir_checks(dir: &Path) -> Vec<Check> {
    if !dir.is_dir() {
        return vec![Check {
            name: "state_dir.writable".to_string(),
            status: CheckStatus::Warn,
            detail: format!(
                "runtime state dir {} does not exist yet — the daemon creates it at startup; \
                 ensure the parent directory is writable by the daemon user",
                dir.display()
            ),
        }];
    }
    let mut checks = Vec::new();
    checks.push(if dir_writable(dir) {
        Check {
            name: "state_dir.writable".to_string(),
            status: CheckStatus::Ok,
            detail: format!("runtime state dir {} is writable", dir.display()),
        }
    } else {
        Check {
            name: "state_dir.writable".to_string(),
            status: CheckStatus::Fail,
            detail: format!(
                "runtime state dir {} is not writable by this user — commit-confirm journal, \
                 MRT dumps, crash reports, and event-history writes fail without it; check \
                 ownership (and ReadWritePaths= under systemd)",
                dir.display()
            ),
        }
    });
    checks.push(match disk_free_bytes(dir) {
        None => Check {
            name: "state_dir.disk".to_string(),
            status: CheckStatus::Warn,
            detail: format!("could not stat free space on {}", dir.display()),
        },
        Some(free) => {
            let (status, verdict) = if free < STATE_DIR_DISK_FAIL_BYTES {
                (
                    CheckStatus::Fail,
                    "critically low — state writes are about to fail; free space or move \
                     runtime_state_dir",
                )
            } else if free < STATE_DIR_DISK_WARN_BYTES {
                (
                    CheckStatus::Warn,
                    "low — journal, MRT dumps, crash reports, and the event-history DB write \
                     here",
                )
            } else {
                (CheckStatus::Ok, "ok")
            };
            Check {
                name: "state_dir.disk".to_string(),
                status,
                detail: format!(
                    "free space on {}: {} — {verdict}",
                    dir.display(),
                    human_bytes(free)
                ),
            }
        }
    });
    checks
}

/// "systemd" / "container" / "unknown" from pid-1 facts. Container wins
/// over systemd-inside-a-container: the remediation surface is the
/// container runtime, not the inner unit.
fn classify_run_context(pid1_comm: &str, in_container: bool) -> &'static str {
    if in_container {
        "container"
    } else if pid1_comm == "systemd" {
        "systemd"
    } else {
        "unknown"
    }
}

fn detect_run_context() -> &'static str {
    let pid1_comm = fs::read_to_string("/proc/1/comm").unwrap_or_default();
    let cgroup = fs::read_to_string("/proc/1/cgroup").unwrap_or_default();
    let in_container = Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || ["docker", "containerd", "kubepods", "lxc"]
            .iter()
            .any(|marker| cgroup.contains(marker));
    classify_run_context(pid1_comm.trim_end(), in_container)
}

/// Config-file path from a daemon's `/proc/<pid>/cmdline`: the first
/// non-flag argument after argv0, mirroring the daemon's own CLI.
fn parse_cmdline_config_path(cmdline: &[u8]) -> Option<String> {
    cmdline
        .split(|b| *b == 0)
        .skip(1)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).to_string())
        .find(|arg| !arg.starts_with('-'))
}

fn proc_cmdline_config_path(process: LocalProcess) -> Option<PathBuf> {
    let bytes = process.read_file("cmdline")?;
    let path = parse_cmdline_config_path(bytes.as_bytes())
        .map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from);
    Some(process_config_path(process.pid, &path))
}

/// Traverse the peer's procfs magic links directly: resolving them into host
/// paths first would lose the peer's mount namespace.
fn process_config_path(pid: u32, path: &Path) -> PathBuf {
    if let Ok(relative) = path.strip_prefix("/") {
        PathBuf::from(format!("/proc/{pid}/root")).join(relative)
    } else {
        PathBuf::from(format!("/proc/{pid}/cwd")).join(path)
    }
}

/// A connected UDS peer may identify its config; an unreachable local UDS
/// may use the packaged file only as first-deploy input. TCP has no local source.
fn local_config_path(connection: Option<&Connection>, daemon_address: &str) -> Option<PathBuf> {
    if !daemon_address.starts_with("unix://") {
        return None;
    }
    let Some(connection) = connection else {
        return Some(PathBuf::from(DEFAULT_CONFIG_PATH));
    };
    let process = connection.local_process()?;
    let path = proc_cmdline_config_path(process)?;
    (connection.local_process() == Some(process)).then_some(path)
}

/// Process start time (unix seconds) from `/proc/<pid>/stat` field 22
/// plus the boot time; `stat` is the raw file contents.
fn parse_proc_start_unix(stat: &str, btime: u64, clk_tck: u64) -> Option<u64> {
    // The comm field (2) may contain spaces; fields 3+ follow the last ')'.
    let starttime = proc_start_ticks(stat)?;
    Some(btime + starttime / clk_tck.max(1))
}

fn proc_start_unix(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let btime = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse::<u64>()
        .ok()?;
    // /proc/<pid>/stat starttime is in USER_HZ ticks, ABI-fixed at 100
    // on Linux regardless of the kernel HZ.
    parse_proc_start_unix(&stat, btime, 100)
}

fn mtime_unix(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// File the daemon writes under `runtime_state_dir` holding the config file's
/// mtime as of its own last read or write of that file. Written by the
/// daemon's `config_persister` — keep the name in step with it.
const LAST_PERSIST_FILE: &str = "config-last-persist";

/// The daemon's own record of the config file as it last read or wrote it.
fn last_persist_unix(state_dir: &Path) -> Option<u64> {
    fs::read_to_string(state_dir.join(LAST_PERSIST_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The timestamp a config-file mtime is judged against.
///
/// Process start is the wrong reference: the daemon rewrites its own config
/// file on every runtime mutation (`rbgp neighbor add`, a config transaction,
/// gNMI Set), and a container entrypoint may seed the file after the process
/// has started. Both leave an mtime past process start with nothing pending,
/// so the check warned permanently on every deployment that used the
/// documented runtime-mutation workflow.
///
/// The daemon's own last-persist marker is the honest reference — it advances
/// exactly when the daemon reads or writes the file, and not when an operator
/// edits it. Process start remains the fallback for a daemon that wrote no
/// marker (no writable state dir, or an older build).
fn config_freshness_reference(state_dir: &Path, pid: u32) -> Option<u64> {
    last_persist_unix(state_dir).or_else(|| proc_start_unix(pid))
}

/// Pure freshness verdict: warn when the config mtime is newer than the
/// daemon's marker without claiming that the file contents diverge.
fn config_freshness_check(
    pid: u32,
    config_path: &str,
    config_mtime_unix: u64,
    daemon_sync_unix: u64,
) -> Check {
    let (status, detail) = if config_mtime_unix > daemon_sync_unix {
        (
            CheckStatus::Warn,
            format!(
                "config {config_path} is newer than daemon pid {pid}'s last config-file marker — \
                 on-disk changes may be pending; validate with `rustbgpd --check \
                 {config_path}` and reload with SIGHUP (systemctl reload rustbgpd)"
            ),
        )
    } else {
        (
            CheckStatus::Ok,
            format!(
                "config {config_path} is not newer than daemon pid {pid}'s last config-file \
                 marker; this does not prove effective runtime agreement"
            ),
        )
    };
    Check {
        name: format!("daemon.config_freshness.{pid}"),
        status,
        detail,
    }
}

/// `daemon.authz.reachable`: the `GetHealth` probe outcome viewed through
/// an authorization lens. `GetHealth` is the least-privileged RPC doctor
/// issues (`sensitive_read`, within every role's ceiling), so a
/// PERMISSION_DENIED there means this connection's identity cannot use the
/// gRPC surface at all, and the check surfaces the daemon's actionable
/// denial message as a first-class FAIL instead of a generic RPC error.
/// Transport/handler failures stay owned by `daemon.healthy` (skip).
fn authz_reachable_check(health_error: Option<&tonic::Status>) -> Option<Check> {
    let name = "daemon.authz.reachable".to_string();
    match health_error {
        None => Some(Check {
            name,
            status: CheckStatus::Ok,
            detail: "GetHealth (sensitive_read) permitted on this connection".to_string(),
        }),
        Some(status) if status.code() == tonic::Code::PermissionDenied => Some(Check {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "daemon denied GetHealth (sensitive_read): {}",
                status.message()
            ),
        }),
        Some(status) if status.code() == tonic::Code::Unauthenticated => Some(Check {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "daemon rejected this connection's credentials on GetHealth: {}",
                status.message()
            ),
        }),
        Some(_) => None,
    }
}

/// `daemon.authz.identity`: what this connection looks like from the
/// client side. The daemon does not expose the resolved principal/role
/// over any RPC, so the check reports the transport and credential shape
/// it can prove locally and says so honestly; the daemon's `grpc_authz`
/// log records the authoritative per-request mapping.
fn authz_identity_check(daemon_address: &str, token_file_configured: bool) -> Check {
    let transport = if daemon_address.starts_with("unix://") {
        "a unix socket"
    } else if token_file_configured {
        "TCP with a bearer token"
    } else {
        "TCP without a bearer token"
    };
    Check {
        name: "daemon.authz.identity".to_string(),
        status: CheckStatus::Ok,
        detail: format!(
            "connected via {transport}; the daemon assigns the principal from its listener \
             config and does not expose the resolved principal/role over RPC — its \
             grpc_authz log records the authoritative mapping"
        ),
    }
}

/// `daemon.authz.enforcement`: enforcement mode as already exposed by the
/// daemon's own redacted effective-config dump. An older daemon whose dump
/// lacks `[security.grpc]` yields `None` (check skipped), never a FAIL.
fn authz_enforcement_check(value: &toml::Value) -> Option<Check> {
    let grpc = value.get("security")?.get("grpc")?;
    let enforcement = grpc.get("enforcement")?.as_str()?;
    let mapped_roles = grpc
        .get("roles")
        .and_then(toml::Value::as_table)
        .map_or(0, toml::map::Map::len);
    let (status, detail) = match enforcement {
        "tier" => (
            CheckStatus::Ok,
            format!(
                "per-principal tier enforcement is active \
                 ({mapped_roles} principal(s) mapped in [security.grpc.roles])"
            ),
        ),
        "legacy" => (
            CheckStatus::Warn,
            "enforcement = \"legacy\": principal roles are audit-only and the listener \
             max_tier authorizes calls; migrate to enforcement = \"tier\" \
             (see docs/reference/configuration.md)"
                .to_string(),
        ),
        other => (
            CheckStatus::Warn,
            format!("unrecognized [security.grpc] enforcement mode \"{other}\""),
        ),
    };
    Some(Check {
        name: "daemon.authz.enforcement".to_string(),
        status,
        detail,
    })
}

/// RFC 8212 posture resolved from one TOML document with the documented
/// omitted-versus-explicit rules: an omitted `config_epoch` is epoch 1; an
/// omitted `[global] ebgp_requires_policy` resolves to `false` at epoch 1
/// and `true` at epoch 2; an explicit boolean keeps its stated value in every
/// epoch. Resolution only reads; nothing here rewrites a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rfc8212Posture {
    epoch: u8,
    epoch_source: &'static str,
    policy: bool,
    policy_source: &'static str,
}

impl Rfc8212Posture {
    const fn effective(self) -> (u8, bool) {
        (self.epoch, self.policy)
    }
}

impl std::fmt::Display for Rfc8212Posture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "config_epoch = {} ({}), ebgp_requires_policy = {} ({})",
            self.epoch, self.epoch_source, self.policy, self.policy_source
        )
    }
}

fn rfc8212_posture(document: &toml::Value) -> Result<Rfc8212Posture, String> {
    let (epoch, epoch_source) = match document.get("config_epoch") {
        None => (1, "omitted"),
        Some(toml::Value::Integer(1)) => (1, "explicit"),
        Some(toml::Value::Integer(2)) => (2, "explicit"),
        Some(_) => return Err("config_epoch must be 1 or 2".to_string()),
    };
    let raw = document
        .get("global")
        .and_then(|global| global.get("ebgp_requires_policy"));
    let (policy, policy_source) = match raw {
        None if epoch == 2 => (true, "epoch_2_default"),
        None => (false, "legacy_omission"),
        Some(toml::Value::Boolean(value)) => (*value, "explicit"),
        Some(_) => {
            return Err("[global] ebgp_requires_policy must be a boolean".to_string());
        }
    };
    Ok(Rfc8212Posture {
        epoch,
        epoch_source,
        policy,
        policy_source,
    })
}

/// Evidence gathered for `--pre-upgrade`. Missing evidence fails closed; the
/// checks never confirm, abort, rewrite, or stop anything.
struct PreUpgradeEvidence<'a> {
    /// `None` when the daemon was unreachable; `Some(Err)` when the status
    /// RPC itself failed (denied, unimplemented, timed out, ...).
    transaction: Option<&'a Result<ConfigTransactionStatusResponse, tonic::Status>>,
    /// The daemon's effective config, or the reason it is unavailable.
    effective_config: Result<&'a toml::Value, &'a str>,
    /// The daemon's metrics scrape, or the reason it is unavailable.
    metrics: Result<&'a str, &'a str>,
}

/// Wording every green pre-upgrade check carries: a live observation is not
/// quiescence and grants no permission to mutate later.
const PRE_UPGRADE_NOT_A_FENCE: &str =
    "this is an observation at one instant, not a fence: a transaction can start after it";
const INCOMPLETE_EVIDENCE: &str = "evidence incomplete, never a green upgrade verdict";
const SETTLEMENT_ACTIVE_METRIC: &str = "bgp_runtime_config_settlement_active";

fn pre_upgrade_checks(
    candidate_path: &Path,
    evidence: &PreUpgradeEvidence<'_>,
    observed_at: u64,
) -> Vec<Check> {
    vec![
        upgrade_transaction_check(evidence.transaction, observed_at),
        upgrade_settlement_check(evidence.metrics, observed_at),
        upgrade_posture_check(candidate_path, evidence.effective_config, observed_at),
    ]
}

/// `upgrade.transaction`: the same RPC as `rbgp config status`. Only an
/// empty "none" record or a terminal outcome is green; pending, applying,
/// rollback-failed, ambiguous, unrecognized, and unavailable states are red
/// with the confirm/abort/wait action spelled out.
fn upgrade_transaction_check(
    status: Option<&Result<ConfigTransactionStatusResponse, tonic::Status>>,
    observed_at: u64,
) -> Check {
    let name = "upgrade.transaction";
    let fail = |detail: String| Check {
        name: name.to_string(),
        status: CheckStatus::Fail,
        detail,
    };
    let response = match status {
        None => {
            return fail(format!(
                "config transaction status unavailable: daemon unreachable — {INCOMPLETE_EVIDENCE}"
            ));
        }
        Some(Err(error)) => {
            return fail(match error.code() {
                tonic::Code::PermissionDenied => format!(
                    "daemon denied GetConfigTransactionStatus (sensitive_read): {} — \
                     {INCOMPLETE_EVIDENCE}; rerun with a principal permitted to read \
                     transaction status",
                    error.message()
                ),
                tonic::Code::Unauthenticated => format!(
                    "daemon rejected this connection's credentials on \
                     GetConfigTransactionStatus: {} — {INCOMPLETE_EVIDENCE}; rerun with valid \
                     credentials",
                    error.message()
                ),
                tonic::Code::Unimplemented => format!(
                    "daemon does not implement GetConfigTransactionStatus — \
                     {INCOMPLETE_EVIDENCE}; that release predates transaction status, so \
                     follow its own documented upgrade procedure"
                ),
                _ => format!(
                    "GetConfigTransactionStatus failed: {error} — {INCOMPLETE_EVIDENCE}; rerun \
                     once the daemon answers"
                ),
            });
        }
        Some(Ok(response)) => response,
    };
    let Some(confirmation) = response.confirmation.as_ref() else {
        return fail(format!(
            "daemon returned no confirmation record — {INCOMPLETE_EVIDENCE}"
        ));
    };
    let id = confirmation.confirm_id.as_str();
    let label = confirmation_status_label(confirmation.status);
    let human = confirmation.human_text.trim();
    let never_mutates = "this check never confirms, aborts, or rewrites anything";
    use ConfigTransactionConfirmationStatus as Confirmation;
    let (status, detail) = match Confirmation::try_from(confirmation.status)
        .unwrap_or(Confirmation::Unspecified)
    {
        Confirmation::None if id.is_empty() => (
            CheckStatus::Ok,
            format!(
                "no confirmed config transaction is pending as of unix {observed_at}; \
                 {PRE_UPGRADE_NOT_A_FENCE}"
            ),
        ),
        Confirmation::None => (
            CheckStatus::Fail,
            format!(
                "confirmed transaction {id} has an ambiguous outcome and config mutations are \
                 fenced: {human} Restart rustbgpd to boot-revert, then rerun this check"
            ),
        ),
        Confirmation::Pending if confirmation.deadline_unix_seconds == 0 => (
            CheckStatus::Fail,
            format!(
                "confirmed transaction {id} is still applying: {human} Wait for the apply to \
                 finish, then confirm it (`rbgp config confirm {id}`) or abort it (`rbgp \
                 config abort {id}`) before the coordinated stop; {never_mutates}"
            ),
        ),
        Confirmation::Pending => (
            CheckStatus::Fail,
            format!(
                "confirmed transaction {id} is pending until unix {}: confirm it (`rbgp config \
                 confirm {id}`) or abort it (`rbgp config abort {id}`) before the coordinated \
                 stop; {never_mutates}",
                confirmation.deadline_unix_seconds
            ),
        ),
        Confirmation::AbortFailed | Confirmation::AutoRevertFailed => (
            CheckStatus::Fail,
            format!(
                "confirmed transaction {id} is {label}: {human} Retry `rbgp config abort {id}`, \
                 confirm with `rbgp config confirm {id}`, or restart rustbgpd to boot-revert, \
                 then rerun this check"
            ),
        ),
        Confirmation::Confirmed | Confirmation::Aborted | Confirmation::AutoReverted => (
            CheckStatus::Ok,
            format!(
                "last confirmed transaction {id} is terminal ({label}); nothing is pending as \
                 of unix {observed_at}; {PRE_UPGRADE_NOT_A_FENCE}"
            ),
        ),
        Confirmation::Unspecified => (
            CheckStatus::Fail,
            format!(
                "unrecognized confirmation status {} — evidence ambiguous, never a green \
                 upgrade verdict",
                confirmation.status
            ),
        ),
    };
    Check {
        name: name.to_string(),
        status,
        detail,
    }
}

/// `upgrade.settlement`: the settlement watchdog's gauge from the metrics
/// scrape doctor already collects. The daemon emits the gauge only while an
/// owner is live or recovery-fenced, so an absent series on a successful
/// scrape is the idle state; a failed scrape is missing evidence.
fn upgrade_settlement_check(metrics: Result<&str, &str>, observed_at: u64) -> Check {
    let name = "upgrade.settlement".to_string();
    let text = match metrics {
        Ok(text) => text,
        Err(reason) => {
            return Check {
                name,
                status: CheckStatus::Fail,
                detail: format!(
                    "runtime-config settlement evidence unavailable: {reason} — \
                     {INCOMPLETE_EVIDENCE}"
                ),
            };
        }
    };
    let active = text.lines().find_map(|line| {
        let rest = line.strip_prefix(SETTLEMENT_ACTIVE_METRIC)?;
        let (labels, value) = match rest.strip_prefix('{').and_then(|rest| rest.split_once('}')) {
            Some((labels, value)) => (parse_metric_labels(labels).unwrap_or_default(), value),
            None => (HashMap::new(), rest.strip_prefix(' ')?),
        };
        let value: f64 = value.split_whitespace().next()?.parse().ok()?;
        (value != 0.0).then_some(labels)
    });
    let (status, detail) = match active {
        Some(labels) => {
            let label = |key: &str| labels.get(key).map_or("unknown", String::as_str);
            (
                CheckStatus::Fail,
                format!(
                    "a runtime-config settlement owner is active as of unix {observed_at} \
                     (kind={}, phase={}, fence_reason={}): a config transaction, neighbor or \
                     FIB change, or SIGHUP reload has not settled; wait until \
                     {SETTLEMENT_ACTIVE_METRIC} clears and rerun this check — a fence_reason \
                     other than none means the daemon is fencing and will exit 70 for a \
                     supervised restart",
                    label("kind"),
                    label("phase"),
                    label("fence_reason")
                ),
            )
        }
        None => (
            CheckStatus::Ok,
            format!(
                "no runtime-config settlement owner is active as of unix {observed_at} (the \
                 daemon emits {SETTLEMENT_ACTIVE_METRIC} only while an owner is live or \
                 fenced); {PRE_UPGRADE_NOT_A_FENCE}"
            ),
        ),
    };
    Check {
        name,
        status,
        detail,
    }
}

/// `upgrade.posture`: the candidate file's resolved RFC 8212 posture against
/// the live effective posture. A mismatch means the restart changes
/// behavior; the check names the offline migration but performs none.
fn upgrade_posture_check(
    candidate_path: &Path,
    effective_config: Result<&toml::Value, &str>,
    observed_at: u64,
) -> Check {
    let name = "upgrade.posture".to_string();
    let path = candidate_path.display();
    let fail = |detail: String| Check {
        name: name.clone(),
        status: CheckStatus::Fail,
        detail,
    };
    let parse = |text: &str| {
        toml::from_str::<toml::Value>(text)
            .map_err(|_| "invalid TOML; source text omitted".to_string())
            .and_then(|document| rfc8212_posture(&document))
    };
    let live = match effective_config {
        Ok(text) => text,
        Err(reason) => {
            return fail(format!(
                "live RFC 8212 posture unavailable: {reason} — {INCOMPLETE_EVIDENCE}"
            ));
        }
    };
    let live = match rfc8212_posture(live) {
        Ok(posture) => posture,
        Err(error) => {
            return fail(format!(
                "live effective config posture unreadable: {error} — {INCOMPLETE_EVIDENCE}"
            ));
        }
    };
    let candidate = match fs::read_to_string(candidate_path) {
        Ok(text) => text,
        Err(error) => {
            return fail(format!(
                "cannot read candidate config {path}: {error} — {INCOMPLETE_EVIDENCE}; pass \
                 the file the upgraded daemon will boot to --pre-upgrade and run as a user \
                 that can read it"
            ));
        }
    };
    let candidate = match parse(&candidate) {
        Ok(posture) => posture,
        Err(error) => {
            return fail(format!(
                "candidate config {path} posture unreadable: {error}; fix the file, then \
                 repeat the candidate `rustbgpd --check --strict {path}`"
            ));
        }
    };
    if candidate.effective() == live.effective() {
        Check {
            name,
            status: CheckStatus::Ok,
            detail: format!(
                "candidate {path} resolves to {candidate}; the live daemon runs {live} — \
                 effective posture matches as of unix {observed_at}; nothing was rewritten"
            ),
        }
    } else {
        let restore = match live.effective() {
            (1, false) => format!("run `rustbgpd --migrate-config pin-legacy --offline {path}`"),
            (2, true) => format!("run `rustbgpd --migrate-config prepare-secure --offline {path}`"),
            (epoch, policy) => format!(
                "set top-level `config_epoch = {epoch}` and `[global] ebgp_requires_policy = {policy}` explicitly in {path}"
            ),
        };
        fail(format!(
            "candidate {path} resolves to {candidate} but the live daemon runs {live} — \
             restarting on this file changes the RFC 8212 posture. Decide before the \
             coordinated stop: keep the change only if every eBGP direction has explicit \
             policy (the candidate `rustbgpd --check --strict {path}` names unpoliced \
             directions), or restore the live posture in the file after the stop: \
             {restore}; repeat the candidate `rustbgpd --check --strict {path}` after \
             any rewrite. This check rewrote nothing"
        ))
    }
}

/// Machine-readable tail of a `--pre-upgrade` run: the instant the
/// observation was taken and the verdict for that instant.
#[derive(Serialize)]
struct PreUpgradeSummary {
    candidate_config: String,
    observed_at_unix_seconds: u64,
    ok: bool,
}

impl PreUpgradeSummary {
    fn human_text(&self) -> String {
        let next = if self.ok {
            format!(
                "next: coordinated stop, verify the service is inactive, then repeat the \
                 candidate `rustbgpd --check --strict {}` and any offline authority checks \
                 before install",
                self.candidate_config
            )
        } else {
            format!(
                "next: resolve the FAIL checks above, then rerun `rbgp doctor --pre-upgrade {}`",
                self.candidate_config
            )
        };
        format!(
            "Pre-upgrade observation as of unix {}: {}; {PRE_UPGRADE_NOT_A_FENCE}.\n  {next}",
            self.observed_at_unix_seconds,
            if self.ok { "no red checks" } else { "FAIL" }
        )
    }
}

fn json_report(
    bundle_path: &Path,
    failed: bool,
    checks: &[Check],
    sections: &BTreeMap<&'static str, String>,
    pre_upgrade: Option<&PreUpgradeSummary>,
) -> Result<serde_json::Value, CliError> {
    let mut report = serde_json::json!({
        "bundle": bundle_path.display().to_string(),
        "ok": !failed,
        "checks": serde_json::to_value(checks)?,
        "sections": serde_json::to_value(sections)?,
    });
    if let Some(summary) = pre_upgrade {
        report["pre_upgrade"] = serde_json::to_value(summary)?;
    }
    Ok(report)
}

pub(crate) async fn run(
    connection: Result<Connection, CliError>,
    opts: &DoctorOptions<'_>,
) -> Result<i32, CliError> {
    run_with_deadlines(
        connection,
        opts,
        READ_RPC_TIMEOUT,
        EFFECTIVE_CONFIG_RPC_TIMEOUT,
    )
    .await
}

async fn run_with_deadlines(
    connection: Result<Connection, CliError>,
    opts: &DoctorOptions<'_>,
    read_budget: Duration,
    effective_config_budget: Duration,
) -> Result<i32, CliError> {
    let now = now_unix_seconds();
    let mut reporter = Reporter {
        json: opts.json,
        checks: Vec::new(),
    };
    let mut bundle = Bundle { files: Vec::new() };
    let mut sections: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut daemon_version: Option<String> = None;
    let mut state_dir: Option<String> = None;
    let mut effective_toml: Option<String> = None;
    let mut effective_config: Option<toml::Value> = None;
    let mut metrics_text: Option<String> = None;
    let mut metrics_error: Option<String> = None;
    let mut effective_config_error: Option<String> = None;
    let mut transaction_status: Option<Result<ConfigTransactionStatusResponse, tonic::Status>> =
        None;
    let mut tcp_ao_support = crate::proto::TcpAoSupport::Unspecified.into();
    let daemon_reachable = connection.is_ok();
    let local_connection = connection.as_ref().ok().cloned();

    // ---- daemon-backed sections -------------------------------------
    match connection {
        Ok(connection) => {
            reporter.record(
                "daemon.reachable",
                CheckStatus::Ok,
                format!("daemon reachable at {}", opts.daemon_address),
            )?;
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
            let mut bfd =
                BfdServiceClient::with_interceptor(connection.channel(), connection.interceptor());
            let mut events = EventServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );
            let mut policy = PolicyServiceClient::with_interceptor(
                connection.channel(),
                connection.interceptor(),
            );

            let posture = rpc_with_timeout(
                "GetValidationPolicyPosture",
                read_budget,
                policy.get_validation_policy_posture(GetValidationPolicyPostureRequest {}),
            )
            .await
            .map(|response| response.into_inner());
            for check in validation_policy_posture_checks(posture) {
                reporter.record(check.name, check.status, check.detail)?;
            }

            // system/health.json + the healthy check. The same probe outcome
            // feeds the daemon.authz.* triage: a PERMISSION_DENIED here is an
            // authorization finding, not a health one.
            let health_result = rpc_with_timeout(
                "GetHealth",
                read_budget,
                control.get_health(HealthRequest {}),
            )
            .await;
            if let Some(check) = authz_reachable_check(health_result.as_ref().err()) {
                reporter.record(check.name, check.status, check.detail)?;
            }
            let identity = authz_identity_check(opts.daemon_address, opts.token_file_configured);
            reporter.record(identity.name, identity.status, identity.detail)?;
            match health_result {
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
                    )?;
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
                    )?;
                    sections.insert("system", format!("partial: health RPC failed: {e}"));
                }
            }

            // system/global.json.
            match rpc_with_timeout(
                "GetGlobal",
                read_budget,
                global.get_global(GetGlobalRequest {}),
            )
            .await
            {
                Ok(resp) => {
                    let global_state = resp.into_inner();
                    tcp_ao_support = global_state.tcp_ao_support;
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
            match rpc_with_timeout(
                "GetMetrics",
                read_budget,
                control.get_metrics(MetricsRequest {}),
            )
            .await
            {
                Ok(resp) => {
                    let text = resp.into_inner().prometheus_text;
                    bundle.add("system/metrics.prom", redact_text(&text).into_bytes());
                    metrics_text = Some(text);
                }
                Err(e) => {
                    sections.insert("system", format!("partial: metrics RPC failed: {e}"));
                    metrics_error = Some(format!("metrics RPC failed: {e}"));
                }
            }

            // config/effective.toml: the daemon's own redacted, normalized
            // dump (same RPC as `rbgp config effective`). Never the raw file.
            let mut config_client = connection.effective_config_client();
            match rpc_with_timeout(
                "GetEffectiveConfig",
                effective_config_budget,
                config_client.get_effective_config(GetEffectiveConfigRequest {}),
            )
            .await
            {
                Ok(resp) => {
                    let toml_text = resp.into_inner().toml;
                    match toml::from_str::<toml::Value>(&toml_text) {
                        Ok(document) => {
                            for check in tcp_ao_capability_checks(&document, tcp_ao_support) {
                                reporter.record(check.name, check.status, check.detail)?;
                            }
                            let rpki_caches =
                                config_addresses(&document, &["rpki", "cache_servers"]);
                            if let Some(check) =
                                rpki_vrp_table_check(&rpki_caches, metrics_text.as_deref())
                            {
                                reporter.record(check.name, check.status, check.detail)?;
                            }
                            if let Some(check) = authz_enforcement_check(&document) {
                                reporter.record(check.name, check.status, check.detail)?;
                            }
                            state_dir = config_state_dir(&document);
                            effective_config = Some(document);
                        }
                        Err(_) => {
                            let reason = "invalid effective-config TOML; source text omitted";
                            effective_config_error = Some(reason.to_string());
                            reporter.record(
                                "deploy.config_parse",
                                CheckStatus::Fail,
                                reason.to_string(),
                            )?;
                        }
                    }
                    effective_toml = Some(toml_text);
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
                    effective_config_error = Some(format!("effective-config RPC failed: {e}"));
                }
            }

            // --pre-upgrade only: the same RPC as `rbgp config status`, so
            // plain doctor keeps its RPC set unchanged.
            if opts.pre_upgrade.is_some() {
                let mut config = ConfigServiceClient::with_interceptor(
                    connection.channel(),
                    connection.interceptor(),
                );
                transaction_status = Some(
                    rpc_with_timeout(
                        "GetConfigTransactionStatus",
                        read_budget,
                        config.get_config_transaction_status(GetConfigTransactionStatusRequest {}),
                    )
                    .await
                    .map(|response| response.into_inner()),
                );
            }

            // peers/bfd.json: presence-aware BFD cause snapshot plus per-peer
            // red/yellow/green checks. The RPC is bounded by the same tonic
            // request path as the other daemon snapshots; no packet probing is
            // performed by doctor.
            let bfd_collected = match rpc_with_timeout(
                "GetBfdSessions",
                read_budget,
                bfd.get_bfd_sessions(GetBfdSessionsRequest {
                    peer_address: String::new(),
                }),
            )
            .await
            {
                Ok(resp) => {
                    let snapshots: Vec<BfdSnapshot> = resp
                        .into_inner()
                        .sessions
                        .iter()
                        .map(BfdSnapshot::from)
                        .collect();
                    for snapshot in &snapshots {
                        let check = bfd_check(snapshot);
                        reporter.record(check.name, check.status, check.detail)?;
                    }
                    bundle.add_json("peers/bfd.json", &snapshots)?;
                    true
                }
                Err(e) => {
                    sections.insert("peers", format!("partial: BFD RPC failed: {e}"));
                    false
                }
            };

            // peers/: snapshot neighbors before querying event history. If an
            // operator disables a peer between these RPCs, the older snapshot
            // remains harmless; if the snapshot already shows the resulting
            // non-Established state, the later history query includes the
            // disable evidence.
            let neighbor_snapshot = rpc_with_timeout(
                "ListNeighbors",
                read_budget,
                neighbor.list_neighbors(ListNeighborsRequest {}),
            )
            .await;
            let dynamic_neighbor_snapshot = match rpc_with_timeout(
                "ListDynamicNeighbors",
                read_budget,
                neighbor.list_dynamic_neighbors(ListDynamicNeighborsRequest {}),
            )
            .await
            {
                Ok(resp) => {
                    let snapshots: Vec<DynamicNeighborSnapshot> = resp
                        .into_inner()
                        .ranges
                        .iter()
                        .map(DynamicNeighborSnapshot::from)
                        .collect();
                    bundle.add_json("peers/dynamic-neighbors.json", &snapshots)?;
                    sections.insert("dynamic_neighbors", "collected".to_string());
                    Some(snapshots)
                }
                Err(e) => {
                    sections.insert(
                        "dynamic_neighbors",
                        format!(
                            "unavailable: ListDynamicNeighbors RPC failed: {}",
                            redact_text(&e.to_string())
                        ),
                    );
                    None
                }
            };
            let (session_events, session_history_available) = match rpc_with_timeout(
                "ListSessionEvents",
                read_budget,
                events.list_session_events(ListSessionEventsRequest {
                    neighbor_address: String::new(),
                    event_types: Vec::new(),
                    limit: EVENT_HISTORY_LIMIT,
                }),
            )
            .await
            {
                Ok(resp) => (
                    resp.into_inner()
                        .events
                        .iter()
                        .map(|e| bgp_event_json_value(e).map(redact_event))
                        .collect::<Result<Vec<_>, _>>()?,
                    true,
                ),
                Err(e) => {
                    sections.insert(
                        "session_events",
                        format!(
                            "partial: ListSessionEvents RPC failed: {}",
                            redact_text(&e.to_string())
                        ),
                    );
                    (Vec::new(), false)
                }
            };
            sections
                .entry("session_events")
                .or_insert_with(|| "collected".to_string());
            let policy_events = match rpc_with_timeout(
                "ListPolicyEvents",
                read_budget,
                events.list_policy_events(ListPolicyEventsRequest {
                    neighbor_address: String::new(),
                    event_types: Vec::new(),
                    limit: EVENT_HISTORY_LIMIT,
                }),
            )
            .await
            {
                Ok(resp) => resp
                    .into_inner()
                    .events
                    .iter()
                    .map(|e| bgp_event_json_value(e).map(redact_event))
                    .collect::<Result<Vec<_>, _>>()?,
                Err(e) => {
                    sections.insert(
                        "policy_events",
                        format!(
                            "partial: ListPolicyEvents RPC failed: {}",
                            redact_text(&e.to_string())
                        ),
                    );
                    Vec::new()
                }
            };
            sections
                .entry("policy_events")
                .or_insert_with(|| "collected".to_string());
            match neighbor_snapshot {
                Ok(resp) => {
                    let neighbors = resp.into_inner();
                    let admin_enabled = metrics_text.as_deref().and_then(admin_enabled_inventory);
                    let gtsm = admin_enabled
                        .as_ref()
                        .and(effective_config.as_ref())
                        .map(gtsm_inventory);
                    let transitions = last_transition_by_peer(&session_events);
                    let losses = last_loss_by_peer(&session_events);
                    let admin_states = latest_admin_state_by_peer(&session_events);
                    let mut records = Vec::with_capacity(neighbors.neighbors.len());
                    for n in &neighbors.neighbors {
                        let cfg = n.config.as_ref();
                        let identity = cfg.map_or_else(String::new, |config| {
                            peer_identity(&config.address, &config.interface)
                        });
                        let policy_check = rfc8212_policy_check(
                            &identity,
                            n.rfc8212_import_policy,
                            n.rfc8212_export_policy,
                        );
                        reporter.record(
                            policy_check.name,
                            policy_check.status,
                            policy_check.detail,
                        )?;
                        for check in
                            outbound_prefix_limit_checks(&identity, &n.outbound_prefix_limits)
                        {
                            reporter.record(check.name, check.status, check.detail)?;
                        }
                        records.push(NeighborDoctorRecord {
                            support: JsonNeighbor {
                                address: cfg.map(|c| c.address.clone()).unwrap_or_default(),
                                interface: cfg.map(|c| c.interface.clone()).unwrap_or_default(),
                                remote_asn: cfg.map(|c| c.remote_asn).unwrap_or(0),
                                state: output::format_state_with_stale(n.state, n.stale)
                                    .to_string(),
                                stale: n.stale,
                                slow_peer: n.slow_peer,
                                uptime_seconds: n.uptime_seconds,
                                prefixes_received: n.prefixes_received,
                                prefixes_sent: n.prefixes_sent,
                                messages_received: n.messages_received,
                                messages_sent: n.messages_sent,
                                flap_count: n.flap_count,
                                last_error: redact_text(&n.last_error),
                                is_dynamic: n.is_dynamic,
                                accepted_dynamic_range: output::json_accepted_dynamic_range(
                                    n.accepted_dynamic_range.as_ref(),
                                ),
                                route_reflector_client: n.route_reflector_client,
                                description: redact_text(
                                    &cfg.map(|c| c.description.clone()).unwrap_or_default(),
                                ),
                            },
                            identity,
                            update_group: n.update_group.clone(),
                            max_prefix_restart_remaining_millis: n
                                .max_prefix_restart_remaining_millis,
                        });
                    }
                    if records.is_empty() {
                        match dynamic_neighbor_snapshot.as_ref() {
                            Some(ranges) if ranges.is_empty() => reporter.record(
                                "peers.configured",
                                CheckStatus::Warn,
                                "no active neighbor sessions and no dynamic-neighbor ranges configured",
                            )?,
                            Some(ranges) => reporter.record(
                                "peers.configured",
                                CheckStatus::Ok,
                                format!(
                                    "no active neighbor sessions; {} dynamic-neighbor range{} configured for future acceptance",
                                    ranges.len(),
                                    if ranges.len() == 1 { "" } else { "s" }
                                ),
                            )?,
                            None => reporter.record(
                                "peers.configured",
                                CheckStatus::Warn,
                                "no active neighbor sessions; dynamic-neighbor range inventory unavailable",
                            )?,
                        }
                    }
                    for record in &records {
                        let session_evidence = if session_history_available {
                            SessionHistoryEvidence::Retained {
                                last_transition_unix: transitions.get(&record.identity).copied(),
                                last_loss_unix: losses.get(&record.identity).copied(),
                                latest_admin_state: admin_states.get(&record.identity).copied(),
                            }
                        } else {
                            SessionHistoryEvidence::Unavailable
                        };
                        for check in peer_checks(
                            &record.identity,
                            &record.support.state,
                            record.support.stale,
                            record.max_prefix_restart_remaining_millis,
                            record.support.slow_peer,
                            &record.update_group,
                            record.support.uptime_seconds,
                            record.support.flap_count,
                            session_evidence,
                            now,
                            &record.support.last_error,
                        ) {
                            reporter.record(check.name, check.status, check.detail)?;
                        }
                        if let Some(check) = gtsm_advisory_check(
                            record,
                            session_evidence,
                            gtsm.as_ref(),
                            admin_enabled.as_ref(),
                        ) {
                            reporter.record(check.name, check.status, check.detail)?;
                        }
                    }
                    bundle.add_json(
                        "peers/neighbors.json",
                        &records
                            .iter()
                            .map(|record| &record.support)
                            .collect::<Vec<_>>(),
                    )?;
                    if bfd_collected {
                        sections.insert("peers", "collected".to_string());
                    }
                }
                Err(e) => {
                    sections.insert(
                        "peers",
                        if bfd_collected {
                            format!("partial: BFD collected; neighbor RPC failed: {e}")
                        } else {
                            format!("unavailable: BFD and neighbor RPCs failed: {e}")
                        },
                    );
                }
            }
            // Event history was collected independently of the neighbor snapshot.
            // Keep it even when that snapshot failed or timed out.
            bundle.add_json(
                "peers/events.json",
                &EventsSnapshot {
                    session: session_events,
                    policy: policy_events,
                },
            )?;
            sections
                .entry("system")
                .or_insert_with(|| "collected".to_string());
        }
        Err(e) => {
            reporter.record(
                "daemon.reachable",
                CheckStatus::Fail,
                format!("daemon unreachable: {e}"),
            )?;
            sections.insert("config", "unavailable: daemon unreachable".to_string());
            sections.insert("peers", "unavailable: daemon unreachable".to_string());
            sections.insert(
                "dynamic_neighbors",
                "unavailable: daemon unreachable".to_string(),
            );
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

    // ---- run context (informs remediation advice) ---------------------
    let run_context = detect_run_context();
    reporter.record(
        "host.run_context",
        CheckStatus::Ok,
        format!("run context: {run_context}"),
    )?;

    // ---- daemon rlimits (local processes only) ------------------------
    if let Some((pid, limits)) = local_daemon_limits(local_connection.as_ref()) {
        match parse_max_open_files(&limits) {
            Some((soft, hard)) => {
                let check = nofile_check(pid, soft, hard, run_context);
                reporter.record(check.name, check.status, check.detail)?;
            }
            None => reporter.record(
                format!("daemon.rlimit.nofile.{pid}"),
                CheckStatus::Warn,
                format!("daemon pid {pid}: could not parse Max open files from /proc limits"),
            )?,
        }
        bundle.add(
            &format!("system/daemon-limits-{pid}.txt"),
            limits.into_bytes(),
        );
        sections.insert("rlimits", "collected".to_string());
    } else {
        sections.insert(
            "rlimits",
            "unavailable: connected daemon has no verified local UDS process limits".to_string(),
        );
    }

    // ---- first-deploy probes (LAN-482) --------------------------------
    // Effective config is authoritative. Local fallback files are used only
    // for a verified UDS peer, or first-deploy input when that UDS is down.
    let local_config_source: Option<(String, String)> = if effective_toml.is_none() {
        let process = local_connection
            .as_ref()
            .and_then(Connection::local_process);
        local_config_path(local_connection.as_ref(), opts.daemon_address).and_then(|path| {
            let text = fs::read_to_string(&path).ok()?;
            (local_connection
                .as_ref()
                .and_then(Connection::local_process)
                == process)
                .then(|| (text, path.display().to_string()))
        })
    } else {
        None
    };
    let config_source =
        deploy_config_source(effective_toml.as_deref(), local_config_source.as_ref());
    let local_document = local_config_source
        .as_ref()
        .map(|(text, _)| toml::from_str::<toml::Value>(text));
    let document = effective_config.as_ref().or_else(|| {
        local_document
            .as_ref()
            .and_then(|result| result.as_ref().ok())
    });
    match config_source {
        Some((_, source)) => {
            if let Some(document) = document {
                if !daemon_reachable && let Some(port) = config_listen_port(document) {
                    let check = listener_bind_check(port);
                    reporter.record(check.name, check.status, check.detail)?;
                }
                for check in
                    reachability_checks(daemon_reachable, opts.daemon_address, document).await
                {
                    reporter.record(check.name, check.status, check.detail)?;
                }
                if state_dir.is_none() {
                    state_dir = config_state_dir(document);
                }
                let dir = PathBuf::from(state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIR));
                for check in state_dir_checks(&dir) {
                    reporter.record(check.name, check.status, check.detail)?;
                }
                sections.insert("probes", format!("collected (targets from {source})"));
            } else {
                if local_document.is_some() {
                    reporter.record(
                        "deploy.config_parse",
                        CheckStatus::Fail,
                        "invalid local config TOML; source text omitted".to_string(),
                    )?;
                }
                sections.insert("probes", "skipped: invalid config document".to_string());
            }
        }
        None => {
            reporter.record(
                "deploy.config_source",
                CheckStatus::Warn,
                format!(
                    "first-deploy probes skipped: daemon config unavailable and \
                     {DEFAULT_CONFIG_PATH} is not readable"
                ),
            )?;
            sections.insert("probes", "skipped: no config source".to_string());
        }
    }

    // ---- pre-upgrade diagnostics (opt-in, read-only) --------------------
    let mut pre_upgrade_observed_at = None;
    if let Some(candidate) = opts.pre_upgrade {
        let observed_at = now_unix_seconds();
        let unreachable = "daemon unreachable";
        let evidence = PreUpgradeEvidence {
            transaction: transaction_status.as_ref(),
            effective_config: effective_config
                .as_ref()
                .ok_or(effective_config_error.as_deref().unwrap_or(unreachable)),
            metrics: metrics_text
                .as_deref()
                .ok_or(metrics_error.as_deref().unwrap_or(unreachable)),
        };
        for check in pre_upgrade_checks(candidate, &evidence, observed_at) {
            reporter.record(check.name, check.status, check.detail)?;
        }
        sections.insert(
            "pre_upgrade",
            format!("collected (observed at unix {observed_at}; an observation, not a fence)"),
        );
        pre_upgrade_observed_at = Some(observed_at);
    }

    // Checks and probes above only borrow the potentially large document;
    // transfer its allocation directly into the bundle after the last read.
    if let Some(toml_text) = effective_toml.take() {
        bundle.add("config/effective.toml", toml_text.into_bytes());
    }

    // ---- config freshness (local daemon processes only) ---------------
    let freshness_state_dir = PathBuf::from(state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIR));
    if let Some(connection) = local_connection.as_ref()
        && let Some(process) = connection.local_process()
        && let Some(config_path) = proc_cmdline_config_path(process)
        && let (Some(mtime), Some(reference)) = (
            mtime_unix(&config_path),
            config_freshness_reference(
                &process_config_path(process.pid, &freshness_state_dir),
                process.pid,
            ),
        )
        && connection.local_process() == Some(process)
    {
        let check = config_freshness_check(
            process.pid,
            &config_path.display().to_string(),
            mtime,
            reference,
        );
        reporter.record(check.name, check.status, check.detail)?;
    }

    // ---- crashes/ ------------------------------------------------------
    let crash_dir = PathBuf::from(state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIR)).join("crash");
    let crash_reports = sweep_crash_reports(&crash_dir, &mut bundle);
    if crash_reports.is_empty() {
        reporter.record(
            "crashes.recent",
            CheckStatus::Ok,
            format!("no panic reports in {}", crash_dir.display()),
        )?;
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
        )?;
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
    // Defaulted after the state dir is known, so the fallback can use it.
    let bundle_path = opts.output.map_or_else(
        || {
            default_bundle_dir(Path::new("."), state_dir.as_deref())
                .join(format!("rustbgpd-doctor-{now}.tar.gz"))
        },
        PathBuf::from,
    );
    // Root directory inside the tar: the bundle file name without
    // extensions, so `tar xzf` yields exactly one directory.
    let root = bundle_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".tar.gz").trim_end_matches(".tgz"))
        .filter(|n| !n.is_empty())
        .map_or_else(|| format!("rustbgpd-doctor-{now}"), str::to_string);
    bundle.write_tar_gz(&bundle_path, &root)?;

    let failed = reporter.any_fail();
    let pre_upgrade =
        opts.pre_upgrade
            .zip(pre_upgrade_observed_at)
            .map(|(candidate, observed_at)| PreUpgradeSummary {
                candidate_config: candidate.display().to_string(),
                observed_at_unix_seconds: observed_at,
                ok: !failed,
            });
    if opts.json {
        output::print_json_line(&json_report(
            &bundle_path,
            failed,
            &reporter.checks,
            &sections_summary,
            pre_upgrade.as_ref(),
        )?)?;
    } else {
        outln!("Support bundle written: {}", bundle_path.display())?;
        if let Some(summary) = &pre_upgrade {
            outln!("{}", summary.human_text())?;
        }
    }
    Ok(if failed { 2 } else { 0 })
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use tonic::Code;

    fn gtsm_record(address: &str, interface: &str) -> NeighborDoctorRecord {
        NeighborDoctorRecord {
            support: JsonNeighbor {
                address: address.to_string(),
                interface: interface.to_string(),
                remote_asn: 65001,
                state: "Active".to_string(),
                stale: false,
                slow_peer: false,
                uptime_seconds: 0,
                prefixes_received: 0,
                prefixes_sent: 0,
                messages_received: 0,
                messages_sent: 0,
                flap_count: 0,
                last_error: String::new(),
                is_dynamic: false,
                accepted_dynamic_range: None,
                route_reflector_client: false,
                description: String::new(),
            },
            identity: peer_identity(address, interface),
            update_group: String::new(),
            max_prefix_restart_remaining_millis: None,
        }
    }

    fn gtsm_config() -> &'static str {
        r#"
[peer_groups.dynamic]
ttl_security = true
ttl_security_hops = 9

[[neighbors]]
address = "192.0.2.1"
ttl_security = true

[[neighbors]]
address = "fe80::1"
interface = "eth0"
ttl_security = true
ttl_security_hops = 3
"#
    }

    fn admin_metric(peer: &str, interface: &str, value: u8) -> String {
        format!("bgp_peer_admin_enabled{{interface=\"{interface}\",peer=\"{peer}\"}} {value}")
    }

    fn gtsm_check(
        record: &NeighborDoctorRecord,
        history: SessionHistoryEvidence,
        config: Option<&str>,
        metrics: Option<&str>,
    ) -> Option<Check> {
        let inventory = config
            .and_then(|text| toml::from_str(text).ok())
            .as_ref()
            .map(gtsm_inventory);
        let admin_enabled = metrics.and_then(admin_enabled_inventory);
        gtsm_advisory_check(record, history, inventory.as_ref(), admin_enabled.as_ref())
    }

    #[test]
    fn gtsm_advisory_static_and_dynamic_identity_and_detail_are_exact() {
        let static_record = gtsm_record("fe80::1", "eth0");
        let metric = admin_metric("fe80::1", "eth0", 1);
        let check = gtsm_check(
            &static_record,
            SessionHistoryEvidence::Unavailable,
            Some(gtsm_config()),
            Some(&metric),
        )
        .unwrap();
        assert_eq!(check.name, "peer.fe80::1%eth0.ttl_security");
        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(
            check.detail,
            "peer fe80::1%eth0 has ttl_security enabled (ttl_security_hops=3) and has not established during the current session-task lifetime; GTSM drops occur in the kernel before BGP and produce no NOTIFICATION. Confirm the peer transmits TTL/Hop Limit 255 and that ttl_security_hops covers the actual path; this is an advisory, not a diagnosis."
        );

        let mut dynamic = gtsm_record("198.51.100.8", "");
        dynamic.support.is_dynamic = true;
        dynamic.support.accepted_dynamic_range = Some(output::JsonAcceptedDynamicRange {
            prefix: "198.51.100.0/24".to_string(),
            peer_group: "dynamic".to_string(),
        });
        let metric = admin_metric("198.51.100.8", "", 1);
        let check = gtsm_check(
            &dynamic,
            SessionHistoryEvidence::Unavailable,
            Some(gtsm_config()),
            Some(&metric),
        )
        .unwrap();
        assert!(check.detail.contains("ttl_security_hops=9"));
    }

    #[test]
    fn gtsm_advisory_suppresses_ineligible_session_states() {
        let metric = admin_metric("192.0.2.1", "", 1);
        let inventory = gtsm_inventory(&toml::from_str(gtsm_config()).unwrap());
        let history =
            retained_session_evidence_with_admin(None, None, Some(RetainedAdminState::Enabled));
        let eligible = gtsm_record("192.0.2.1", "");
        let admin_enabled = admin_enabled_inventory(&metric).unwrap();
        assert!(
            gtsm_advisory_check(&eligible, history, Some(&inventory), Some(&admin_enabled))
                .is_some()
        );

        for variant in 0..5 {
            let mut record = gtsm_record("192.0.2.1", "");
            match variant {
                0 => record.support.state = "Established".to_string(),
                1 => record.support.stale = true,
                2 => record.support.flap_count = 1,
                3 => record.max_prefix_restart_remaining_millis = Some(0),
                4 => record.max_prefix_restart_remaining_millis = Some(10),
                _ => unreachable!(),
            }
            assert!(
                gtsm_advisory_check(&record, history, Some(&inventory), Some(&admin_enabled))
                    .is_none(),
                "variant {variant} must be absent"
            );
        }
        let disabled =
            retained_session_evidence_with_admin(None, None, Some(RetainedAdminState::Disabled));
        assert!(
            gtsm_advisory_check(&eligible, disabled, Some(&inventory), Some(&admin_enabled))
                .is_none()
        );
    }

    #[test]
    fn gtsm_advisory_requires_unique_authoritative_admin_metric() {
        let record = gtsm_record("192.0.2.1", "");
        let history = SessionHistoryEvidence::Unavailable;
        for metrics in [
            None,
            Some("unrelated 1"),
            Some("bgp_peer_admin_enabled{interface=\"\",peer=\"192.0.2.1\"} 0"),
            Some("bgp_peer_admin_enabled{interface=\"\",peer=\"192.0.2.1\"} nope"),
            Some("bgp_peer_admin_enabled{peer=\"192.0.2.1\"} 1"),
            Some("bgp_peer_admin_enabled{interface=\"\",peer=\"192.0.2.1\" 1"),
            Some("bgp_peer_admin_enabled{interface=\"eth0\",peer=\"192.0.2.1\"} 1"),
            Some(
                "bgp_peer_admin_enabled{interface=\"\",peer=\"192.0.2.1\"} 1\nbgp_peer_admin_enabled{interface=\"\",peer=\"192.0.2.1\"} 1",
            ),
        ] {
            assert!(
                gtsm_check(&record, history, Some(gtsm_config()), metrics).is_none(),
                "metric evidence must suppress: {metrics:?}"
            );
        }
        assert!(admin_enabled_inventory("unrelated 1").is_none());
    }

    #[test]
    fn gtsm_advisory_suppresses_unconfigured_ambiguous_and_unattributed_dynamic_peers() {
        let metric = admin_metric("192.0.2.9", "", 1);
        let record = gtsm_record("192.0.2.9", "");
        assert!(
            gtsm_check(
                &record,
                SessionHistoryEvidence::Unavailable,
                Some(gtsm_config()),
                Some(&metric)
            )
            .is_none()
        );

        let duplicate = format!(
            "{}\n[[neighbors]]\naddress = \"192.0.2.1\"\nttl_security = true\n",
            gtsm_config()
        );
        let duplicate_record = gtsm_record("192.0.2.1", "");
        let duplicate_metric = admin_metric("192.0.2.1", "", 1);
        assert!(
            gtsm_check(
                &duplicate_record,
                SessionHistoryEvidence::Unavailable,
                Some(&duplicate),
                Some(&duplicate_metric)
            )
            .is_none()
        );

        let mut dynamic = gtsm_record("198.51.100.8", "");
        dynamic.support.is_dynamic = true;
        let dynamic_metric = admin_metric("198.51.100.8", "", 1);
        assert!(
            gtsm_check(
                &dynamic,
                SessionHistoryEvidence::Unavailable,
                Some(gtsm_config()),
                Some(&dynamic_metric)
            )
            .is_none()
        );

        let malformed_then_valid = format!("[[neighbors]]\nttl_security = true\n{}", gtsm_config());
        let valid_record = gtsm_record("192.0.2.1", "");
        let valid_metric = admin_metric("192.0.2.1", "", 1);
        assert!(
            gtsm_check(
                &valid_record,
                SessionHistoryEvidence::Unavailable,
                Some(&malformed_then_valid),
                Some(&valid_metric)
            )
            .is_some()
        );
    }

    #[test]
    fn gtsm_admin_metric_inventory_is_built_once_outside_the_peer_loop() {
        let production = include_str!("doctor.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            production
                .matches(".and_then(admin_enabled_inventory)")
                .count(),
            1
        );
        let collection = production
            .split("let admin_enabled =")
            .nth(1)
            .unwrap()
            .split("let transitions =")
            .next()
            .unwrap();
        assert!(
            collection.find("admin_enabled_inventory").unwrap()
                < collection.find("gtsm_inventory").unwrap()
        );
        let advisory = production
            .split("fn gtsm_advisory_check")
            .nth(1)
            .unwrap()
            .split("fn last_event_by_peer")
            .next()
            .unwrap();
        assert!(!advisory.contains("metrics.lines()"));
    }

    /// The effective config can approach 384 MiB. Reintroducing either the
    /// bundle copy or the probe-source copy adds `toml_text.clone()` to the
    /// production half and makes this structural allocation fence red.
    #[test]
    fn effective_config_is_borrowed_for_probes_then_moved_into_bundle() {
        let source = include_str!("doctor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("toml_text.clone()").count(), 0);
        assert_eq!(production.matches("effective_toml.clone()").count(), 0);
        assert_eq!(
            production
                .matches(
                    "deploy_config_source(effective_toml.as_deref(), local_config_source.as_ref())"
                )
                .count(),
            1
        );
        assert_eq!(production.matches("effective_toml.take()").count(), 1);
        assert_eq!(production.matches("toml_text.into_bytes()").count(), 1);
    }

    #[test]
    fn deploy_probe_config_prefers_effective_and_preserves_local_fallback() {
        // Removing the local fallback makes the second assertion red;
        // reversing precedence makes the first assertion red.
        let local = ("local".to_string(), "/etc/rustbgpd/config.toml".to_string());
        assert_eq!(
            deploy_config_source(Some("effective"), Some(&local)),
            Some(("effective", "effective config"))
        );
        assert_eq!(
            deploy_config_source(None, Some(&local)),
            Some(("local", "/etc/rustbgpd/config.toml"))
        );
        assert_eq!(deploy_config_source(None, None), None);
    }

    /// Load-bearing proof: removing the remote-AdminDown branch makes the
    /// permitted warning red; defaulting absent presence to false makes the
    /// older-daemon Down assertion red; requiring field presence while Up
    /// makes the healthy rolling-upgrade assertion red.
    #[test]
    fn bfd_checks_distinguish_remote_admin_down_and_unknown_presence() {
        assert_eq!(
            bfd_state_label(BfdSessionState::AdminDown as i32),
            "admin-down"
        );
        assert_eq!(
            bfd_state_label(BfdSessionState::Unspecified as i32),
            "unspecified"
        );

        let remote_disabled = BfdSnapshot {
            peer_address: "192.0.2.1".to_string(),
            state: "down".to_string(),
            diagnostic: "none".to_string(),
            strict: true,
            remote_administrative_down: Some(true),
        };
        let check = bfd_check(&remote_disabled);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("BGP is permitted"));

        let old_daemon = BfdSnapshot {
            remote_administrative_down: None,
            ..remote_disabled
        };
        let check = bfd_check(&old_daemon);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("cause is unknown"));
        assert!(check.detail.contains("predates field 5"));

        let old_healthy = BfdSnapshot {
            state: "up".to_string(),
            diagnostic: "none".to_string(),
            ..old_daemon
        };
        assert_eq!(bfd_check(&old_healthy).status, CheckStatus::Ok);

        let impossible_healthy = BfdSnapshot {
            remote_administrative_down: Some(true),
            ..old_healthy
        };
        assert_eq!(bfd_check(&impossible_healthy).status, CheckStatus::Warn);
    }

    fn json_type(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
    }

    fn assert_json_type(
        value: &serde_json::Value,
        expected: &serde_json::Value,
        contract_id: &str,
        key: &str,
    ) {
        let allowed: Vec<&str> = match expected {
            serde_json::Value::String(value) => vec![value.as_str()],
            serde_json::Value::Array(values) => {
                values.iter().map(|value| value.as_str().unwrap()).collect()
            }
            _ => panic!("invalid {contract_id} type floor for {key:?}"),
        };
        assert!(
            allowed.contains(&json_type(value)),
            "{contract_id} field {key:?} changed JSON type: expected {allowed:?}, got {}",
            json_type(value)
        );
    }

    fn assert_json_shape(value: &serde_json::Value, shape: &serde_json::Value, contract_id: &str) {
        let object = value.as_object().expect("representative JSON is an object");
        for (key, expected) in shape["required_json_types"].as_object().unwrap() {
            let field = object
                .get(key)
                .unwrap_or_else(|| panic!("required {contract_id} field {key:?} is absent"));
            assert_json_type(field, expected, contract_id, key);
        }
        for (key, expected) in shape["optional_json_types"].as_object().unwrap() {
            if let Some(field) = object.get(key) {
                assert_json_type(field, expected, contract_id, key);
            }
        }
    }

    fn assert_inventory_json_contract(value: &serde_json::Value, contract_id: &str) {
        let inventory_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/reference/v1-stable-surface.json"
        );
        let inventory: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(inventory_path).unwrap()).unwrap();
        let contract = inventory["cli"]["test_pinned_json_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["id"] == contract_id)
            .unwrap_or_else(|| panic!("missing JSON contract {contract_id}"));
        assert_json_shape(value, contract, contract_id);
        for nested in contract["nested_json_contracts"].as_array().unwrap() {
            match nested["path"].as_str().unwrap() {
                "checks[]" => {
                    for check in value["checks"].as_array().unwrap() {
                        assert_json_shape(check, nested, contract_id);
                    }
                }
                path => panic!("unhandled {contract_id} nested contract path {path}"),
            }
        }
    }

    // ---- pure-logic checks -------------------------------------------

    #[test]
    fn redact_text_replaces_sensitive_lines() {
        let redacted = redact_text("ok 1\napi_token=secret\npassword = nope\nok 2");
        assert_eq!(redacted, "ok 1\n[REDACTED]\n[REDACTED]\nok 2");
    }

    #[test]
    fn tcp_ao_capability_lint_fails_each_protected_target_when_unsupported() {
        let config = r#"
[[neighbors]]
address = "192.0.2.1"
tcp_ao = { key = "<redacted>", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
[[dynamic_neighbors]]
prefix = "198.51.100.0/24"
tcp_ao = { key = "<redacted>", send_id = 3, recv_id = 4, algorithm = "hmac(sha256)" }
"#;
        let checks = tcp_ao_capability_checks(
            &toml::from_str(config).unwrap(),
            crate::proto::TcpAoSupport::Unsupported.into(),
        );
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|check| check.status == CheckStatus::Fail));
        assert_eq!(checks[0].name, "peer.192.0.2.1.tcp_ao_capability");
        assert_eq!(checks[1].name, "peer.198.51.100.0/24.tcp_ao_capability");
    }

    #[test]
    fn tcp_ao_capability_lint_distinguishes_supported_and_unknown() {
        let config = r#"[[neighbors]]
address = "192.0.2.1"
tcp_ao = { key = "<redacted>", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
        let supported = tcp_ao_capability_checks(
            &toml::from_str(config).unwrap(),
            crate::proto::TcpAoSupport::Supported.into(),
        );
        assert_eq!(supported[0].status, CheckStatus::Ok);
        let unknown = tcp_ao_capability_checks(
            &toml::from_str(config).unwrap(),
            crate::proto::TcpAoSupport::ProbeFailed.into(),
        );
        assert_eq!(unknown[0].status, CheckStatus::Warn);
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

    fn retained_session_evidence(
        last_transition_unix: Option<u64>,
        last_loss_unix: Option<u64>,
    ) -> SessionHistoryEvidence {
        retained_session_evidence_with_admin(last_transition_unix, last_loss_unix, None)
    }

    fn retained_session_evidence_with_admin(
        last_transition_unix: Option<u64>,
        last_loss_unix: Option<u64>,
        latest_admin_state: Option<RetainedAdminState>,
    ) -> SessionHistoryEvidence {
        SessionHistoryEvidence::Retained {
            last_transition_unix,
            last_loss_unix,
            latest_admin_state,
        }
    }

    #[test]
    fn established_peer_is_green() {
        let checks = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            None,
            false,
            "",
            3600,
            0,
            retained_session_evidence(None, None),
            1_000_000,
            "",
        );
        assert_eq!(checks.len(), 1);
        assert!(checks[0].status == CheckStatus::Ok);
        assert!(checks[0].detail.contains("Established"));
    }

    /// Load-bearing max-prefix hold-down proof: deleting the countdown branch
    /// turns both intentional warnings back into the identical fixture's
    /// retained-age failure. Matching only positive values makes the zero
    /// assertion red. The stale and disabled assertions pin their precedence.
    #[test]
    fn max_prefix_restart_countdown_is_intentional_at_zero_and_nonzero() {
        let evidence = || {
            retained_session_evidence_with_admin(Some(1), None, Some(RetainedAdminState::Enabled))
        };
        let diagnose = |stale, countdown, evidence| {
            peer_checks(
                "10.0.0.2", "Connect", stale, countdown, false, "", 0, 0, evidence, 1_000_000, "",
            )
        };

        let running = diagnose(false, Some(30_000), evidence());
        assert_eq!(running[0].status, CheckStatus::Warn);
        assert!(running[0].detail.contains("intentionally held down"));
        assert!(running[0].detail.contains("30000ms remaining"));

        let expired = diagnose(false, Some(0), evidence());
        assert_eq!(expired[0].status, CheckStatus::Warn);
        assert!(expired[0].detail.contains("0ms remaining"));

        let absent = diagnose(false, None, evidence());
        assert_eq!(absent[0].status, CheckStatus::Fail);
        assert!(absent[0].detail.contains("in Connect"));

        let stale = diagnose(true, Some(30_000), evidence());
        assert_eq!(stale[0].status, CheckStatus::Warn);
        assert!(stale[0].detail.contains("state read timed out (stale)"));

        let disabled = diagnose(
            false,
            None,
            retained_session_evidence_with_admin(Some(1), None, Some(RetainedAdminState::Disabled)),
        );
        assert_eq!(disabled[0].status, CheckStatus::Ok);
        assert!(disabled[0].detail.contains("administratively disabled"));
    }

    /// Load-bearing blocking predicate and scope proof: removing the
    /// `blocking` filter drops the first check; broadening it to every row
    /// creates checks for eth1. Replacing the scoped identity with the bare
    /// address makes the exact name assertions red.
    #[test]
    fn outbound_prefix_checks_report_only_blocking_scoped_families() {
        let blocking = crate::proto::OutboundPrefixLimitState {
            family: "ipv4_unicast".to_string(),
            usage: 100,
            limit: Some(100),
            headroom: Some(0),
            blocking: true,
            reason: Some("outbound_prefix_limit_reached".to_string()),
        };
        let mut nonblocking = blocking.clone();
        nonblocking.blocking = false;
        nonblocking.reason = None;
        let unlimited = crate::proto::OutboundPrefixLimitState {
            family: "ipv6_unicast".to_string(),
            usage: 7,
            limit: None,
            headroom: None,
            blocking: false,
            reason: None,
        };

        let eth0 = outbound_prefix_limit_checks("fe80::1%eth0", std::slice::from_ref(&blocking));
        assert_eq!(eth0.len(), 1);
        assert_eq!(
            eth0[0].name,
            "peer.fe80::1%eth0.outbound_prefix_limit.ipv4_unicast"
        );
        assert_eq!(eth0[0].status, CheckStatus::Fail);
        assert!(eth0[0].detail.contains("usage 100, limit 100"));
        assert!(
            eth0[0]
                .detail
                .contains("reason outbound_prefix_limit_reached")
        );
        assert!(eth0[0].detail.contains("intentionally withholding routes"));

        let mut missing_reason = blocking.clone();
        missing_reason.reason = None;
        let unknown = outbound_prefix_limit_checks("fe80::1%eth0", &[missing_reason]);
        assert!(
            unknown[0]
                .detail
                .contains("reason unknown (daemon omitted reason)")
        );
        assert!(
            !unknown[0]
                .detail
                .contains("reason outbound_prefix_limit_reached")
        );

        assert!(outbound_prefix_limit_checks("fe80::1%eth1", &[nonblocking, unlimited]).is_empty());
        assert!(outbound_prefix_limit_checks("fe80::1%eth1", &[]).is_empty());
    }

    /// ADR-0112 doctor contract, all four dispositions in one place.
    ///
    /// Load-bearing three ways: warning on the compatibility default would
    /// turn every current deployment yellow; passing an enabled missing
    /// direction would hide the exact configuration error this feature
    /// exists to surface; and passing `unknown` would report "no problem"
    /// from a daemon that reported nothing at all.
    #[test]
    fn rfc8212_policy_check_separates_default_missing_and_unknown() {
        use crate::proto::Rfc8212PolicyStatus as S;

        let not_required =
            rfc8212_policy_check("10.0.0.1", S::NotRequired as i32, S::NotRequired as i32);
        assert_eq!(not_required.name, "peer.10.0.0.1.rfc8212_policy");
        assert_eq!(not_required.status, CheckStatus::Ok);
        assert!(not_required.detail.contains("not required"));

        let present = rfc8212_policy_check("10.0.0.1", S::Present as i32, S::Present as i32);
        assert_eq!(present.status, CheckStatus::Ok);

        let missing_export = rfc8212_policy_check("10.0.0.2", S::Present as i32, S::Missing as i32);
        assert_eq!(missing_export.status, CheckStatus::Fail);
        assert!(
            missing_export.detail.contains("export")
                && !missing_export.detail.contains("import and export"),
            "the failing direction must be named: {}",
            missing_export.detail
        );

        let missing_both = rfc8212_policy_check("10.0.0.3", S::Missing as i32, S::Missing as i32);
        assert_eq!(missing_both.status, CheckStatus::Fail);
        assert!(missing_both.detail.contains("import and export"));

        // Zero is what a daemon that predates the field sends.
        let unknown = rfc8212_policy_check("10.0.0.4", 0, 0);
        assert_eq!(unknown.status, CheckStatus::Warn);
        assert!(unknown.detail.contains("unknown"));
    }

    /// Load-bearing mutation proof: weakening the retained-age threshold,
    /// or treating every retained timestamp as merely unknown, makes the
    /// genuinely old transition assertion red.
    #[test]
    fn peer_stuck_in_connect_past_threshold_is_red_with_duration() {
        let now = 1_000_000;
        let transitioned = now - (4 * 3600 + 12 * 60); // 4h12m ago
        let checks = peer_checks(
            "10.0.0.2",
            "Connect",
            false,
            None,
            false,
            "",
            0,
            0,
            retained_session_evidence(Some(transitioned), None),
            now,
            "",
        );
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
            None,
            false,
            "",
            0,
            0,
            retained_session_evidence(Some(now - STUCK_PEER_SECS + 1), None),
            now,
            "",
        );
        assert!(checks[0].status == CheckStatus::Warn);
    }

    /// LAN-668 destructive red proof: removing the retained disabled branch
    /// makes the session assertion red. Slow-peer and flap checks remain
    /// independently present instead of being swallowed by that verdict.
    #[test]
    fn administratively_disabled_peer_is_green_without_hiding_other_checks() {
        let now = 1_000_000;
        let checks = peer_checks(
            "10.0.0.2",
            "Idle",
            false,
            None,
            true,
            "",
            0,
            FLAP_REPORT_THRESHOLD,
            retained_session_evidence_with_admin(
                Some(1),
                Some(now - 30),
                Some(RetainedAdminState::Disabled),
            ),
            now,
            "",
        );

        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0].status, CheckStatus::Ok);
        assert!(
            checks[0]
                .detail
                .contains("administratively disabled (state Idle)")
        );
        assert_eq!(checks[1].name, "peer.10.0.0.2.slow_peer");
        assert_eq!(checks[1].status, CheckStatus::Warn);
        assert_eq!(checks[2].name, "peer.10.0.0.2.flaps");
        assert_eq!(checks[2].status, CheckStatus::Fail);
        assert!(checks[2].detail.contains("session loss 00:00:30 ago"));
    }

    /// LAN-668 destructive red proof: a later retained `PeerEnabled` must
    /// supersede disabled intent. Treating any historical disable as current
    /// would incorrectly turn this genuinely old Active session green.
    #[test]
    fn enabled_peer_stuck_in_active_remains_red() {
        let checks = peer_checks(
            "10.0.0.2",
            "Active",
            false,
            None,
            false,
            "",
            0,
            0,
            retained_session_evidence_with_admin(Some(1), None, Some(RetainedAdminState::Enabled)),
            1_000_000,
            "",
        );

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].detail.contains("in Active"));
    }

    /// Load-bearing mutation proof: changing the missing-timestamp branch
    /// back to `Fail` makes the status assertion red. The bounded fleet
    /// history cannot establish how long this peer has been in Connect.
    #[test]
    fn peer_in_connect_with_no_retained_transition_warns_age_unknown() {
        let checks = peer_checks(
            "10.0.0.2",
            "Connect",
            false,
            None,
            false,
            "",
            0,
            0,
            retained_session_evidence(None, None),
            1_000_000,
            "",
        );
        assert!(checks[0].status == CheckStatus::Warn);
        assert!(checks[0].detail.contains("unknown duration"));
        assert!(checks[0].detail.contains("bounded 256-event fleet history"));
    }

    /// Load-bearing mutation proof: making every daemon-lifetime count red
    /// again changes this warning to failure despite no retained recent loss.
    #[test]
    fn lifetime_flap_count_without_recent_loss_warns() {
        let checks = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            None,
            false,
            "",
            60,
            FLAP_REPORT_THRESHOLD,
            retained_session_evidence(None, None),
            1_000_000,
            "",
        );
        assert_eq!(checks.len(), 2);
        assert!(checks[1].status == CheckStatus::Warn);
        assert!(checks[1].detail.contains("during this daemon lifetime"));
        assert!(
            checks[1]
                .detail
                .contains("is retained in the bounded history")
        );
    }

    /// Load-bearing mutation proof: removing the recent-loss correlation,
    /// or downgrading its branch to warning, makes the red assertion fail.
    #[test]
    fn lifetime_flap_count_with_recent_retained_loss_is_red() {
        let now = 1_000_000;
        let checks = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            None,
            false,
            "",
            60,
            FLAP_REPORT_THRESHOLD,
            retained_session_evidence(Some(now - 30), Some(now - 30)),
            now,
            "",
        );
        assert_eq!(checks.len(), 2);
        assert!(checks[1].status == CheckStatus::Fail);
        assert!(checks[1].detail.contains("session loss 00:00:30 ago"));
    }

    #[test]
    fn stale_peer_is_warn() {
        let checks = peer_checks(
            "10.0.0.2",
            "Stale",
            true,
            None,
            false,
            "",
            0,
            0,
            retained_session_evidence_with_admin(Some(1), None, Some(RetainedAdminState::Disabled)),
            1_000_000,
            "",
        );
        // LAN-668 red proof: retained disabled intent must not turn a stale
        // timeout placeholder green.
        assert!(checks[0].status == CheckStatus::Warn);
        assert!(checks[0].detail.contains("stale"));
    }

    /// Load-bearing mutation proof: deleting the `if slow_peer` branch removes
    /// the named warning, while treating every slow peer as isolated changes
    /// the exact remediation for this ordinary update group.
    #[test]
    fn established_slow_peer_warns_with_queue_remediation() {
        let expected = r#"peer 10.0.0.2 is flagged slow: outbound queue persistently backlogged; inspect bgp_peer_outbound_queue_depth{peer="10.0.0.2"} and enable slow_peer_isolation for chronic single-peer lag"#;
        let checks = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            None,
            true,
            "group:7",
            3600,
            0,
            retained_session_evidence(None, None),
            1_000_000,
            "",
        );

        assert_eq!(checks.len(), 2);
        assert!(checks[0].status == CheckStatus::Ok);
        assert_eq!(checks[1].name, "peer.10.0.0.2.slow_peer");
        assert!(checks[1].status == CheckStatus::Warn);
        assert_eq!(checks[1].detail, expected);

        let ungrouped = peer_checks(
            "10.0.0.2",
            "Established",
            false,
            None,
            true,
            "",
            3600,
            0,
            retained_session_evidence(None, None),
            1_000_000,
            "",
        );
        assert_eq!(ungrouped[1].detail, expected);
    }

    #[test]
    fn low_nofile_soft_limit_is_red_with_context_advice() {
        let check = nofile_check(42, 1024, 524_288, "systemd");
        assert!(check.status == CheckStatus::Fail);
        assert!(check.detail.contains("soft 1024"));
        assert!(check.detail.contains("LimitNOFILE"), "{}", check.detail);
        let container = nofile_check(42, 1024, 524_288, "container");
        assert!(container.detail.contains("ulimit"), "{}", container.detail);
        assert!(nofile_check(42, 4096, 524_288, "unknown").status == CheckStatus::Ok);
    }

    /// Subprocess fixture: two independently limited UDS peers, deliberately
    /// named rustbgpd so the former host-wide discovery would select both.
    #[cfg(target_os = "linux")]
    #[test]
    fn local_identity_fixture() {
        let Some(socket) = std::env::var_os("RUSTBGPD_DOCTOR_IDENTITY_SOCKET") else {
            return;
        };
        fs::write("/proc/self/comm", "rustbgpd").unwrap();
        let path = PathBuf::from(socket);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let _server = crate::test_support::spawn_mock_uds_server(&path, None).await;
                fs::write(path.with_extension("ready"), "ready").unwrap();
                std::future::pending::<()>().await;
            });
    }

    #[cfg(target_os = "linux")]
    struct IdentityFixture(std::process::Child);

    #[cfg(target_os = "linux")]
    impl Drop for IdentityFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "linux")]
    async fn spawn_identity_fixture(path: &Path, nofile: u64) -> IdentityFixture {
        let _ = fs::remove_file(path.with_extension("ready"));
        let child = std::process::Command::new("sh")
            .args(["-c", "ulimit -n \"$1\"; exec \"$2\" --exact commands::doctor::tests::local_identity_fixture --nocapture", "doctor-identity-fixture"])
            .arg(nofile.to_string())
            .arg(std::env::current_exe().unwrap())
            .env("RUSTBGPD_DOCTOR_IDENTITY_SOCKET", path)
            .stdout(std::process::Stdio::null())
            .spawn().unwrap();
        let mut fixture = IdentityFixture(child);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.with_extension("ready").exists() {
                assert!(
                    fixture.0.try_wait().unwrap().is_none(),
                    "identity fixture exited before binding"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        fixture
    }

    #[test]
    fn process_config_paths_stay_in_the_connected_process_filesystem() {
        assert_eq!(
            process_config_path(42, Path::new("/etc/rustbgpd/config.toml")),
            PathBuf::from("/proc/42/root/etc/rustbgpd/config.toml"),
        );
        assert_eq!(
            process_config_path(42, Path::new("configs/router.toml")),
            PathBuf::from("/proc/42/cwd/configs/router.toml"),
        );
    }

    #[tokio::test]
    async fn local_config_fallback_requires_a_local_down_endpoint_or_verified_process() {
        assert_eq!(
            local_config_path(None, "unix:///missing.sock"),
            Some(PathBuf::from(DEFAULT_CONFIG_PATH))
        );
        assert!(local_config_path(None, "http://192.0.2.1:50051").is_none());
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        assert!(local_config_path(Some(&connection), &server.addr).is_none());
        // Even an address presented as UDS cannot turn unavailable transport
        // identity into evidence that the packaged file belongs to its daemon.
        assert!(local_config_path(Some(&connection), "unix:///unknown.sock").is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connected_process_limits_ignore_other_daemons_and_follow_reconnect() {
        let dir = tempfile::tempdir().unwrap();
        let selected_path = dir.path().join("selected.sock");
        let good = spawn_identity_fixture(&selected_path, 4096).await;
        let bad_path = dir.path().join("other.sock");
        let bad = spawn_identity_fixture(&bad_path, 1024).await;
        let connection = connect(&format!("unix://{}", selected_path.display()), None)
            .await
            .unwrap();
        let (pid, limits) = local_daemon_limits(Some(&connection)).unwrap();
        assert_eq!(pid, good.0.id());
        let (soft, hard) = parse_max_open_files(&limits).unwrap();
        assert_eq!(soft, 4096);
        assert!(nofile_check(pid, soft, hard, "unknown").status == CheckStatus::Ok);

        let other = connect(&format!("unix://{}", bad_path.display()), None)
            .await
            .unwrap();
        let (pid, limits) = local_daemon_limits(Some(&other)).unwrap();
        assert_eq!(pid, bad.0.id());
        let (soft, hard) = parse_max_open_files(&limits).unwrap();
        assert_eq!(soft, 1024);
        assert!(nofile_check(pid, soft, hard, "unknown").status == CheckStatus::Fail);
        let tcp = crate::test_support::spawn_mock_server(None).await;
        let tcp_connection = connect(&tcp.addr, None).await.unwrap();
        assert!(local_daemon_limits(Some(&tcp_connection)).is_none());
        assert!(local_daemon_limits(None).is_none());

        drop(good);
        assert!(local_daemon_limits(Some(&connection)).is_none());
        let replacement = spawn_identity_fixture(&selected_path, 1024).await;
        let mut client =
            GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let _ = client.get_global(crate::proto::GetGlobalRequest {}).await;
                if connection
                    .local_process()
                    .is_some_and(|process| process.pid == replacement.0.id())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let (pid, limits) = local_daemon_limits(Some(&connection)).unwrap();
        assert_eq!(pid, replacement.0.id());
        let (soft, hard) = parse_max_open_files(&limits).unwrap();
        assert_eq!(soft, 1024);
        assert!(nofile_check(pid, soft, hard, "unknown").status == CheckStatus::Fail);
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
        assert_eq!(
            config_state_dir(&toml::from_str(toml).unwrap()),
            Some("/tmp/x".to_string())
        );
        assert_eq!(
            config_state_dir(&toml::from_str("[global]\nasn = 65000\n").unwrap()),
            None
        );
        assert!(toml::from_str::<toml::Value>("not toml [").is_err());
    }

    #[test]
    fn authz_reachable_maps_denial_to_fail_with_server_message() {
        let ok = authz_reachable_check(None).unwrap();
        assert_eq!(ok.name, "daemon.authz.reachable");
        assert_eq!(ok.status, CheckStatus::Ok);

        let denied = tonic::Status::permission_denied(
            "principal \"ci-bot\" has no [security.grpc.roles] entry",
        );
        let check = authz_reachable_check(Some(&denied)).unwrap();
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("principal \"ci-bot\""));

        let unauthenticated = tonic::Status::unauthenticated("invalid bearer token");
        let check = authz_reachable_check(Some(&unauthenticated)).unwrap();
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("invalid bearer token"));

        // Transport/handler failures are daemon.healthy's finding.
        assert!(authz_reachable_check(Some(&tonic::Status::internal("boom"))).is_none());
    }

    #[test]
    fn authz_identity_reports_transport_and_names_the_limitation() {
        let uds = authz_identity_check("unix:///run/rustbgpd/grpc.sock", false);
        assert_eq!(uds.name, "daemon.authz.identity");
        assert_eq!(uds.status, CheckStatus::Ok);
        assert!(uds.detail.contains("unix socket"));
        assert!(
            uds.detail
                .contains("not expose the resolved principal/role")
        );

        let tcp_token = authz_identity_check("127.0.0.1:50051", true);
        assert!(tcp_token.detail.contains("TCP with a bearer token"));

        let tcp_plain = authz_identity_check("127.0.0.1:50051", false);
        assert!(tcp_plain.detail.contains("TCP without a bearer token"));
    }

    #[test]
    fn authz_enforcement_reads_effective_config_and_skips_when_absent() {
        let tier = "[security.grpc]\nenforcement = \"tier\"\n\
                    [security.grpc.roles]\nadmin = \"operator\"\n";
        let check = authz_enforcement_check(&toml::from_str(tier).unwrap()).unwrap();
        assert_eq!(check.name, "daemon.authz.enforcement");
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(check.detail.contains("1 principal(s) mapped"));

        let legacy = "[security.grpc]\nenforcement = \"legacy\"\n";
        let check = authz_enforcement_check(&toml::from_str(legacy).unwrap()).unwrap();
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("audit-only"));

        // Older daemons without the section in the dump: skip, never FAIL.
        assert!(
            authz_enforcement_check(&toml::from_str("[global]\nasn = 65000\n").unwrap()).is_none()
        );
        assert!(toml::from_str::<toml::Value>("not toml [").is_err());
    }

    #[test]
    fn session_evidence_maps_keep_latest_transition_and_latest_actual_loss() {
        let events = vec![
            serde_json::json!({
                "peer_address": "10.0.0.2",
                "timestamp": "100",
                "event_type": "session_lost"
            }),
            serde_json::json!({
                "peer_address": "10.0.0.2",
                "timestamp": "250",
                "event_type": "session_established"
            }),
            serde_json::json!({
                "peer_address": "10.0.0.3",
                "timestamp": "50",
                "event_type": "session_state_changed"
            }),
            serde_json::json!({"peer_address": "", "timestamp": "999"}),
        ];
        let transitions = last_transition_by_peer(&events);
        assert_eq!(transitions.get("10.0.0.2"), Some(&250));
        assert_eq!(transitions.get("10.0.0.3"), Some(&50));

        let losses = last_loss_by_peer(&events);
        // Load-bearing mutation proof: dropping the event-type filter makes
        // the newer establishment overwrite the actual loss timestamp.
        assert_eq!(losses.get("10.0.0.2"), Some(&100));
        // A peer with only non-loss events must not acquire fabricated loss
        // evidence; treating all session events as losses makes this red.
        assert!(!losses.contains_key("10.0.0.3"));
    }

    #[test]
    fn retained_admin_state_uses_vector_order_and_keeps_scoped_peers_distinct() {
        let events = vec![
            serde_json::json!({
                "peer_address": "fe80::1%eth0",
                "timestamp": "100",
                "event_type": "peer_disabled"
            }),
            serde_json::json!({
                "peer_address": "fe80::1%eth0",
                "timestamp": "100",
                "event_type": "peer_enabled"
            }),
            serde_json::json!({
                "peer_address": "fe80::1%eth1",
                "timestamp": "100",
                "event_type": "peer_enabled"
            }),
            serde_json::json!({
                "peer_address": "fe80::1%eth1",
                "timestamp": "100",
                "event_type": "peer_disabled"
            }),
            serde_json::json!({
                "peer_address": "fe80::1%eth1",
                "timestamp": "101",
                "event_type": "session_state_changed"
            }),
        ];

        let states = latest_admin_state_by_peer(&events);
        // Equal-second events are resolved by retained vector order. Sorting
        // or taking max by the second-resolution timestamp makes this red.
        assert_eq!(
            states.get("fe80::1%eth0"),
            Some(&RetainedAdminState::Enabled)
        );
        // LAN-668 destructive red proof: replacing `PeerDisabled` above with
        // a normal transition must make this disabled assertion red. A later
        // FSM event must not erase retained operator intent.
        assert_eq!(
            states.get("fe80::1%eth1"),
            Some(&RetainedAdminState::Disabled)
        );
        assert_eq!(peer_identity("fe80::1", "eth1"), "fe80::1%eth1");
    }

    // ---- first-deploy probes (LAN-482) --------------------------------

    #[test]
    fn deploy_targets_parses_all_probe_sections() {
        let config = r#"
[global]
asn = 65000
listen_port = 10179

[rpki]
[[rpki.cache_servers]]
address = "rtr.example.net:8282"

[bmp]
[[bmp.collectors]]
address = "127.0.0.1:11019"

[gnmi_dialout]
[[gnmi_dialout.targets]]
name = "central"
address = "collector.example.net:57400"
paths = ["x"]
"#;
        let document = toml::from_str(config).unwrap();
        assert_eq!(config_listen_port(&document), Some(10179));
        assert_eq!(
            config_addresses(&document, &["rpki", "cache_servers"]),
            vec!["rtr.example.net:8282"]
        );
        assert_eq!(
            config_addresses(&document, &["bmp", "collectors"]),
            vec!["127.0.0.1:11019"]
        );
        let collector = &config_rows(&document, &["gnmi_dialout", "targets"])[0];
        assert_eq!(collector["name"].as_str(), Some("central"));
        assert_eq!(
            collector["address"].as_str(),
            Some("collector.example.net:57400")
        );
        // Unknown future tables survive the generic document unchanged.
        let future = toml::from_str("[future.probes]\naddress = '192.0.2.1:1234'\n").unwrap();
        assert_eq!(
            config_value(&future, &["future", "probes", "address"]).and_then(toml::Value::as_str),
            Some("192.0.2.1:1234")
        );
        assert_eq!(config_listen_port(&future), None);
        assert!(config_addresses(&future, &["rpki", "cache_servers"]).is_empty());
    }

    /// Red proofs: zero-as-OK and dropping the configured guard fail below.
    #[test]
    fn rpki_vrp_table_check_distinguishes_configuration_and_snapshot_state() {
        let caches = vec!["192.0.2.1:8282".to_string()];
        assert!(rpki_vrp_table_check(&[], None).is_none());

        let nonzero = rpki_vrp_table_check(
            &caches,
            Some(
                "bgp_rpki_vrp_count{af=\"ipv4\"} 1\n\
                 bgp_rpki_vrp_count{af=\"ipv6\"} 2\n\
                 bgp_rpki_cache_end_of_data_ready{cache=\"192.0.2.1:8282\"} 1",
            ),
        )
        .unwrap();
        assert_eq!(nonzero.status, CheckStatus::Ok);

        let zero = rpki_vrp_table_check(
            &caches,
            Some("bgp_rpki_vrp_count{af=\"ipv4\"} 0\nbgp_rpki_vrp_count{af=\"ipv6\"} 0"),
        )
        .unwrap();
        assert_eq!(zero.status, CheckStatus::Warn);
        assert!(zero.detail.contains("merged VRP count is 0"));
        assert!(!zero.detail.contains("cache readiness is incomplete"));
        assert_eq!(
            rpki_vrp_table_check(&caches, Some("unrelated_metric 1"))
                .unwrap()
                .status,
            CheckStatus::Warn
        );
        assert_eq!(
            rpki_vrp_table_check(&caches, None).unwrap().status,
            CheckStatus::Warn
        );
    }

    #[test]
    fn rpki_vrp_table_requires_every_configured_cache_ready() {
        let caches = vec![
            "192.0.2.1:8282".to_string(),
            "[2001:db8::1]:8282".to_string(),
        ];
        let base = "bgp_rpki_vrp_count{af=\"ipv4\"} 1\n\
                    bgp_rpki_vrp_count{af=\"ipv6\"} 2\n";
        let not_ready = rpki_vrp_table_check(
            &caches,
            Some(&format!(
                "{base}bgp_rpki_cache_end_of_data_ready{{cache=\"192.0.2.1:8282\"}} 1\n\
                 bgp_rpki_cache_end_of_data_ready{{cache=\"[2001:0db8::1]:8282\"}} 0\n\
                 bgp_rpki_cache_end_of_data_ready{{cache=\"198.51.100.9:8282\"}} 1"
            )),
        )
        .unwrap();
        assert_eq!(not_ready.status, CheckStatus::Warn);
        assert!(not_ready.detail.contains("not ready: [2001:db8::1]:8282"));
        assert!(!not_ready.detail.contains("198.51.100.9"));

        let missing = rpki_vrp_table_check(
            &caches,
            Some(&format!(
                "{base}bgp_rpki_cache_end_of_data_ready{{cache=\"192.0.2.1:8282\"}} 1"
            )),
        )
        .unwrap();
        assert_eq!(missing.status, CheckStatus::Warn);
        assert!(
            missing
                .detail
                .contains("readiness missing: [2001:db8::1]:8282")
        );

        let malformed = rpki_vrp_table_check(
            &caches,
            Some(&format!(
                "{base}bgp_rpki_cache_end_of_data_ready{{cache=\"bad\"}} 1"
            )),
        )
        .unwrap();
        assert_eq!(malformed.status, CheckStatus::Warn);
        assert!(malformed.detail.contains("is malformed"));

        let invalid_config = rpki_vrp_table_check(
            &["cache.example:8282".to_string()],
            Some(&format!(
                "{base}bgp_rpki_cache_end_of_data_ready{{cache=\"192.0.2.1:8282\"}} 1"
            )),
        )
        .unwrap();
        assert_eq!(invalid_config.status, CheckStatus::Warn);
        assert!(
            invalid_config
                .detail
                .contains("configured RPKI cache address is invalid")
        );
    }

    #[tokio::test]
    async fn reachability_probe_distinguishes_listener_from_cli_vantage() {
        // The ordinary suite uses an alternate loopback bind. The owned lab
        // sets this to its non-loopback interface and runs the same assertions.
        let bind_ip = doctor_listener_test_ip();
        let listener = tokio::net::TcpListener::bind((bind_ip, 0)).await.unwrap();
        let live = listener.local_addr().unwrap();
        let dead_socket = tokio::net::TcpSocket::new_v4().unwrap();
        dead_socket
            .bind(std::net::SocketAddr::new(bind_ip, 0))
            .unwrap();
        let dead = dead_socket.local_addr().unwrap();
        let targets = toml::from_str(&format!(
            "[global]\nlisten_port = {}\nlisten_addresses = ['{bind_ip}']\n\
             [[rpki.cache_servers]]\naddress = '{live}'\n\
             [[bmp.collectors]]\naddress = '{dead}'\n\
             [[gnmi_dialout.targets]]\nname = 'central'\naddress = '{dead}'\n",
            dead.port()
        ))
        .unwrap();
        let checks = reachability_checks(true, "unix:///run/rustbgpd/grpc.sock", &targets).await;
        let healthy = toml::from_str(&format!(
            "[global]\nlisten_port = {}\nlisten_addresses = ['{bind_ip}']",
            live.port()
        ))
        .unwrap();
        let healthy_checks =
            reachability_checks(true, "unix:///run/rustbgpd/grpc.sock", &healthy).await;
        assert_eq!(
            healthy_checks[0].status,
            CheckStatus::Ok,
            "{}",
            healthy_checks[0].detail
        );
        assert!(healthy_checks[0].detail.contains(&live.to_string()));
        assert!(!healthy_checks[0].detail.contains("127.0.0.1:"));
        let non_loopback = toml::from_str(include_str!(
            "../../tests/fixtures/doctor/explicit-listener.toml"
        ))
        .unwrap();
        assert_eq!(
            listener_probe_hosts(&non_loopback, "unix:///run/rustbgpd/grpc.sock"),
            ["192.0.2.10"]
        );
        assert_eq!(checks.len(), 4);
        // Load-bearing proof: weakening the authoritative daemon-listener
        // probe to the dependency warning semantics makes this red.
        assert_eq!(checks[0].name, "bgp.listener");
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert_eq!(
            checks[1].name,
            format!("rpki.cache.{live}.reachable_from_cli")
        );
        assert_eq!(checks[1].status, CheckStatus::Ok);
        assert!(
            checks[1]
                .detail
                .contains("reachable from the rbgp CLI network vantage"),
            "{}",
            checks[1].detail
        );
        assert_eq!(
            checks[2].name,
            format!("bmp.collector.{dead}.reachable_from_cli")
        );
        assert_eq!(checks[2].status, CheckStatus::Warn);
        assert!(
            checks[2]
                .detail
                .contains("unreachable from the rbgp CLI network vantage"),
            "{}",
            checks[2].detail
        );
        assert_eq!(checks[3].name, "gnmi_dialout.central.reachable_from_cli");
        assert_eq!(checks[3].status, CheckStatus::Warn);
        assert!(
            checks[3].detail.contains("dial-out"),
            "{}",
            checks[3].detail
        );
    }

    /// Load-bearing proof: silently collecting only `Ok` join results removes
    /// the final two rows and makes the ordered name assertion red.
    #[tokio::test]
    async fn reachability_collector_keeps_failed_task_evidence_in_probe_order() {
        let task = |name: &str, label: &str, addr: &str, handle: tokio::task::JoinHandle<Check>| {
            ProbeTask {
                identity: ProbeTaskIdentity {
                    name: name.to_string(),
                    label: label.to_string(),
                    addr: addr.to_string(),
                },
                handle,
            }
        };

        let ok = tokio::spawn(async {
            Check {
                name: "probe.ok".to_string(),
                status: CheckStatus::Ok,
                detail: "probe ok reachable".to_string(),
            }
        });
        let panicked = tokio::spawn(async {
            panic!("deliberate reachability probe failure");
        });
        let cancelled = tokio::spawn(std::future::pending::<Check>());
        cancelled.abort();

        let checks = collect_probe_tasks(vec![
            task("probe.ok", "probe", "ok", ok),
            task("probe.panic", "panic target", "192.0.2.1:179", panicked),
            task(
                "probe.cancelled",
                "cancelled target",
                "192.0.2.2:179",
                cancelled,
            ),
        ])
        .await
        .0;

        assert_eq!(
            checks
                .iter()
                .map(|check| check.name.as_str())
                .collect::<Vec<_>>(),
            vec!["probe.ok", "probe.panic", "probe.cancelled"]
        );
        assert_eq!(checks[0].status, CheckStatus::Ok);
        for check in &checks[1..] {
            assert_eq!(check.status, CheckStatus::Fail);
            assert!(check.detail.contains("task failed"), "{}", check.detail);
        }
        assert!(
            checks[1].detail.contains("panic target 192.0.2.1:179")
                && checks[1].detail.contains("panicked"),
            "{}",
            checks[1].detail
        );
        assert!(
            checks[2].detail.contains("cancelled target 192.0.2.2:179")
                && checks[2].detail.contains("cancelled"),
            "{}",
            checks[2].detail
        );
    }

    #[test]
    fn listener_test_bind_maps_bind_errors_to_advice() {
        // Free port: bindable. The port has to be genuinely released —
        // `listener_bind_check` is itself the binder, so holding it would
        // test the opposite branch. That leaves the one window this file
        // cannot close (LAN-941): the two statements between the release
        // and the check, with no await or sleep between them.
        let free = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let ok = listener_bind_check(free);
        assert_eq!(ok.status, CheckStatus::Ok);
        assert!(ok.detail.contains("bindable"), "{}", ok.detail);

        // Held port: warn, not fail (a daemon we could not reach may hold it).
        let held = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let busy = listener_bind_check(held.local_addr().unwrap().port());
        assert_eq!(busy.status, CheckStatus::Warn);
        assert!(busy.detail.contains("already in use"), "{}", busy.detail);

        // Privileged-port EACCES carries the capability advice.
        let denied = bind_check_from_result(
            179,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        assert_eq!(denied.status, CheckStatus::Fail);
        assert!(
            denied.detail.contains("CAP_NET_BIND_SERVICE"),
            "{}",
            denied.detail
        );
    }

    #[test]
    fn state_dir_checks_cover_ok_missing_and_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        let checks = state_dir_checks(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].name, "state_dir.writable");
        assert_eq!(checks[0].status, CheckStatus::Ok);
        assert_eq!(checks[1].name, "state_dir.disk");
        assert_ne!(checks[1].status, CheckStatus::Fail);

        let missing = state_dir_checks(&dir.path().join("nope"));
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].status, CheckStatus::Warn);
        assert!(missing[0].detail.contains("does not exist"));

        // access(W_OK) always succeeds for root, so only assert the
        // unwritable path as an unprivileged user.
        if !nix::unistd::geteuid().is_root() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
            let unwritable = state_dir_checks(dir.path());
            assert_eq!(unwritable[0].status, CheckStatus::Fail);
            assert!(unwritable[0].detail.contains("not writable"));
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn default_bundle_dir_falls_back_past_an_unwritable_working_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        assert_eq!(
            default_bundle_dir(cwd.path(), Some(&state.path().display().to_string())),
            cwd.path()
        );

        // access(W_OK) always succeeds for root, so the fallback rungs
        // are only observable as an unprivileged user.
        if !nix::unistd::geteuid().is_root() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(cwd.path(), fs::Permissions::from_mode(0o555)).unwrap();
            assert_eq!(
                default_bundle_dir(cwd.path(), Some(&state.path().display().to_string())),
                state.path()
            );
            assert_eq!(
                default_bundle_dir(cwd.path(), Some("/nonexistent-state-dir")),
                std::env::temp_dir()
            );
            fs::set_permissions(cwd.path(), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn doctor_listener_test_ip() -> std::net::IpAddr {
        std::env::var("RBGPD_DOCTOR_TEST_BIND_IP").map_or_else(
            |_| "127.0.0.2".parse().unwrap(),
            |ip| {
                let ip: std::net::IpAddr = ip.parse().unwrap();
                assert!(
                    !ip.is_loopback() && !ip.is_unspecified(),
                    "lab address must be non-loopback"
                );
                ip
            },
        )
    }

    #[tokio::test]
    async fn listener_default_keeps_failed_probe_task_even_when_other_family_reachable() {
        let task = ProbeTask {
            identity: ProbeTaskIdentity {
                name: "bgp.listener".to_string(),
                label: "BGP listener".to_string(),
                addr: "[::1]:179".to_string(),
            },
            handle: tokio::spawn(async { panic!("deliberately failed listener probe task") }),
        };
        let reachable = Check {
            name: "bgp.listener".to_string(),
            status: CheckStatus::Ok,
            detail: "BGP listener 127.0.0.1:179 reachable".to_string(),
        };
        let (mut checks, task_failed) = collect_probe_tasks(vec![task]).await;
        checks.push(reachable);
        let check = listener_probe_summary(checks, task_failed, false);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("probe task failed"));
        assert!(check.detail.contains("127.0.0.1:179 reachable"));
    }

    #[test]
    fn listener_default_accepts_either_family_but_explicit_requires_every_bind() {
        let result = |status, detail: &str| Check {
            name: "bgp.listener".to_string(),
            status,
            detail: detail.to_string(),
        };
        let one_family = || {
            vec![
                result(CheckStatus::Ok, "BGP listener 127.0.0.1:179 reachable"),
                result(CheckStatus::Fail, "BGP listener [::1]:179 unreachable"),
            ]
        };
        assert_eq!(
            listener_probe_summary(one_family(), false, false).status,
            CheckStatus::Ok
        );
        assert_eq!(
            listener_probe_summary(one_family(), false, true).status,
            CheckStatus::Fail
        );
        let neither_family = vec![
            result(CheckStatus::Fail, "BGP listener 127.0.0.1:179 unreachable"),
            result(CheckStatus::Fail, "BGP listener [::1]:179 unreachable"),
        ];
        assert_eq!(
            listener_probe_summary(neither_family, false, false).status,
            CheckStatus::Fail
        );
    }

    #[tokio::test]
    async fn listener_implicit_port_ipv6_management_keeps_missing_local_bind_red() {
        let explicit = toml::from_str("[global]\nlisten_addresses = ['::1']").unwrap();
        for endpoint in ["http://[::1]", "https://[::1]", "[::1]", "http://[::1]/"] {
            assert!(local_daemon(endpoint), "{endpoint}");
            assert_eq!(daemon_probe_host(endpoint).as_deref(), Some("::1"));
            // Port zero has no listener; no IPv6 family support is required.
            let check = listener_reachability_check(&explicit, endpoint, 0).await;
            assert_eq!(
                check.status,
                CheckStatus::Fail,
                "{endpoint}: {}",
                check.detail
            );
            assert!(check.detail.contains("[::1]:0 unreachable"));
        }
    }

    #[tokio::test]
    async fn listener_ipv6_only_formats_endpoint_and_remote_loopback_is_not_cli_local() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let explicit = toml::from_str("[global]\nlisten_addresses = ['::1']").unwrap();
        let check =
            listener_reachability_check(&explicit, "unix:///run/rustbgpd/grpc.sock", port).await;
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(check.detail.contains(&format!("[::1]:{port}")));
        let check = listener_reachability_check(&explicit, "https://192.0.2.10:50051", port).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("remote CLI cannot probe this bind"));
    }

    #[test]
    fn listener_probe_host_follows_the_daemon_address() {
        let explicit =
            toml::from_str("[global]\nlisten_addresses = ['192.0.2.10', '2001:db8::10']").unwrap();
        for endpoint in [
            "unix:///run/rustbgpd/grpc.sock",
            "http://10.0.0.5:50051",
            "https://rr1.example.net:50051",
        ] {
            assert_eq!(
                listener_probe_hosts(&explicit, endpoint),
                ["192.0.2.10", "2001:db8::10"]
            );
        }
        let wildcard = toml::from_str("[global]").unwrap();
        assert_eq!(
            listener_probe_hosts(&wildcard, "unix:///run/rustbgpd/grpc.sock"),
            ["127.0.0.1", "::1"]
        );
        assert_eq!(
            listener_probe_hosts(&wildcard, "http://[::1]:50051"),
            ["127.0.0.1", "::1"]
        );
        assert_eq!(
            listener_probe_hosts(&wildcard, "http://10.0.0.5:50051"),
            ["10.0.0.5"]
        );
        assert_eq!(
            listener_probe_hosts(&wildcard, "https://rr1.example.net:50051"),
            ["rr1.example.net"]
        );
    }

    #[test]
    fn run_context_classification() {
        assert_eq!(classify_run_context("systemd", false), "systemd");
        assert_eq!(classify_run_context("systemd", true), "container");
        assert_eq!(classify_run_context("init", true), "container");
        assert_eq!(classify_run_context("bash", false), "unknown");
    }

    #[test]
    fn cmdline_config_path_takes_first_non_flag_argument() {
        assert_eq!(
            parse_cmdline_config_path(b"rustbgpd\0/etc/rustbgpd/prod.toml\0"),
            Some("/etc/rustbgpd/prod.toml".to_string())
        );
        assert_eq!(
            parse_cmdline_config_path(b"rustbgpd\0--check\0/n/c.toml\0"),
            Some("/n/c.toml".to_string())
        );
        assert_eq!(parse_cmdline_config_path(b"rustbgpd\0"), None);
    }

    #[test]
    fn proc_start_time_parses_stat_field_22_past_comm_spaces() {
        // comm with spaces and parens: fields resume after the last ')'.
        let stat = "1234 (rust bgpd (x)) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 0 0";
        // starttime = 5000 ticks at 100 Hz = 50s after btime.
        assert_eq!(parse_proc_start_unix(stat, 1_000_000, 100), Some(1_000_050));
        assert_eq!(parse_proc_start_unix("garbage", 0, 100), None);
    }

    #[test]
    fn config_modified_after_daemon_start_is_yellow_with_reload_advice() {
        let stale = config_freshness_check(7, "/etc/rustbgpd/config.toml", 2_000, 1_000);
        assert_eq!(stale.status, CheckStatus::Warn);
        assert!(stale.detail.contains("SIGHUP"), "{}", stale.detail);
        assert!(stale.detail.contains("--check"), "{}", stale.detail);
        let fresh = config_freshness_check(7, "/etc/rustbgpd/config.toml", 1_000, 1_000);
        assert_eq!(fresh.status, CheckStatus::Ok);
        assert!(
            fresh.detail.contains("config-file marker"),
            "{}",
            fresh.detail
        );
        assert!(
            fresh
                .detail
                .contains("does not prove effective runtime agreement"),
            "{}",
            fresh.detail
        );
        assert!(!fresh.detail.contains("last applied"), "{}", fresh.detail);
    }

    /// The regression: the daemon rewrites its own config file on every
    /// runtime mutation, so a mtime past process start is not evidence of an
    /// operator edit. The check must judge against the daemon's own
    /// last-persist marker — and must still warn when the file really did
    /// move past it.
    #[test]
    fn freshness_reference_prefers_the_daemon_last_persist_marker() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(LAST_PERSIST_FILE), "2000\n").unwrap();

        // The marker wins over process start: an unusable pid cannot
        // contribute a fallback, so the reference can only be the marker.
        assert_eq!(
            config_freshness_reference(dir.path(), u32::MAX),
            Some(2_000)
        );

        // A daemon-authored write leaves the config mtime AT the marker.
        let after_daemon_write =
            config_freshness_check(1, "/var/lib/rustbgpd/config.toml", 2_000, 2_000);
        assert_eq!(
            after_daemon_write.status,
            CheckStatus::Ok,
            "{}",
            after_daemon_write.detail
        );

        // A genuine external edit lands past it and must still be yellow.
        let after_external_edit =
            config_freshness_check(1, "/var/lib/rustbgpd/config.toml", 2_001, 2_000);
        assert_eq!(
            after_external_edit.status,
            CheckStatus::Warn,
            "{}",
            after_external_edit.detail
        );
        assert!(
            after_external_edit.detail.contains("SIGHUP"),
            "{}",
            after_external_edit.detail
        );
    }

    /// No marker (no writable state dir, or an older daemon) degrades to the
    /// previous behaviour rather than skipping the check.
    #[test]
    fn freshness_reference_falls_back_to_process_start_without_a_marker() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(last_persist_unix(dir.path()), None);
        assert_eq!(
            config_freshness_reference(dir.path(), std::process::id()),
            proc_start_unix(std::process::id())
        );
    }

    fn posture_dimension(disposition: i32) -> ValidationPolicyDimensionPosture {
        ValidationPolicyDimensionPosture {
            disposition,
            reason: "ignored".to_string(),
        }
    }

    fn posture_response(rpki: i32, aspa: i32) -> GetValidationPolicyPostureResponse {
        GetValidationPolicyPostureResponse {
            scopes: vec![crate::proto::ValidationPolicyScopePosture {
                scope: "192.0.2.1".to_string(),
                kind: "static_peer".to_string(),
                rpki_invalid: Some(posture_dimension(rpki)),
                aspa_invalid: Some(posture_dimension(aspa)),
            }],
            rpki_invalid: Some(posture_dimension(rpki)),
            aspa_invalid: Some(posture_dimension(aspa)),
            complete: true,
            omitted: 0,
        }
    }

    #[test]
    fn validation_posture_doctor_requires_axis_complete_enforced_proof() {
        let enforced = ValidationPolicyDisposition::Enforced as i32;
        let unknown = ValidationPolicyDisposition::Unknown as i32;
        let checks = validation_policy_posture_checks(Ok(posture_response(enforced, enforced)));
        assert!(checks.iter().all(|check| check.status == CheckStatus::Ok));
        assert_eq!(checks[0].name, "rpki.invalid_route_policy");
        assert_eq!(checks[1].name, "aspa.invalid_route_policy");

        for (rpki, aspa, expected) in [
            (enforced, unknown, [CheckStatus::Ok, CheckStatus::Warn]),
            (unknown, enforced, [CheckStatus::Warn, CheckStatus::Ok]),
        ] {
            let checks = validation_policy_posture_checks(Ok(posture_response(rpki, aspa)));
            assert_eq!(checks.map(|check| check.status), expected);
        }
        let warnings = validation_policy_posture_checks(Ok(posture_response(unknown, unknown)));
        assert!(
            warnings[0]
                .detail
                .contains("`reject-rpki-invalid` in examples/route-server/config.toml")
        );
        assert!(
            warnings[1]
                .detail
                .contains("`reject-aspa-invalid` in examples/route-server/hygiene.rpol")
        );
    }

    #[test]
    fn validation_posture_doctor_warns_on_unknown_missing_or_inconsistent_axis() {
        let enforced = ValidationPolicyDisposition::Enforced as i32;
        let mut candidates = vec![
            posture_response(ValidationPolicyDisposition::Unknown as i32, enforced),
            posture_response(ValidationPolicyDisposition::Unenforced as i32, enforced),
            posture_response(ValidationPolicyDisposition::Unspecified as i32, enforced),
            posture_response(99, enforced),
        ];
        let mut missing_aggregate = posture_response(enforced, enforced);
        missing_aggregate.rpki_invalid = None;
        candidates.push(missing_aggregate);
        let mut missing_scope = posture_response(enforced, enforced);
        missing_scope.scopes[0].rpki_invalid = None;
        candidates.push(missing_scope);
        let mut inconsistent = posture_response(enforced, enforced);
        inconsistent.scopes[0].rpki_invalid = Some(posture_dimension(
            ValidationPolicyDisposition::Unenforced as i32,
        ));
        candidates.push(inconsistent);

        for response in candidates {
            assert_eq!(
                validation_policy_posture_checks(Ok(response))[0].status,
                CheckStatus::Warn
            );
        }
    }

    #[test]
    fn validation_posture_doctor_warns_on_fleet_boundaries_and_rpc_errors() {
        let enforced = ValidationPolicyDisposition::Enforced as i32;
        let mut empty = posture_response(enforced, enforced);
        empty.scopes.clear();
        let mut incomplete = posture_response(enforced, enforced);
        incomplete.complete = false;
        let mut omitted = posture_response(enforced, enforced);
        omitted.omitted = 1;
        for response in [empty, incomplete, omitted] {
            assert!(
                validation_policy_posture_checks(Ok(response))
                    .iter()
                    .all(|check| check.status == CheckStatus::Warn)
            );
        }
        for error in [
            tonic::Status::unimplemented("old daemon"),
            tonic::Status::internal("bearer secret must not escape"),
        ] {
            let checks = validation_policy_posture_checks(Err(error));
            assert!(checks.iter().all(|check| check.status == CheckStatus::Warn));
            assert!(checks.iter().all(|check| !check.detail.contains("secret")));
        }
    }

    #[test]
    fn validation_posture_doctor_has_one_dedicated_rpc_evidence_source() {
        let source = include_str!("doctor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches(".get_validation_policy_posture(")
                .count(),
            1
        );
        let helper = production
            .split("fn validation_axis_check")
            .nth(1)
            .unwrap()
            .split("/// ADR-0112")
            .next()
            .unwrap();
        assert!(!helper.contains("effective_toml"));
        assert!(!helper.contains("metrics_text"));
        let fixture = include_str!("../test_support.rs")
            .split("async fn get_validation_policy_posture")
            .nth(1)
            .unwrap()
            .split("async fn list_policies")
            .next()
            .unwrap();
        assert!(!fixture.contains("config_effective"));
        assert!(!fixture.contains("metrics"));
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

    fn manifest_check<'a>(manifest: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        manifest["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == name)
            .unwrap_or_else(|| panic!("manifest missing check {name}"))
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
    async fn read_deadline_retains_partial_bundle_and_separate_effective_config_budget() {
        let server = spawn_mock_server(None).await;
        server.state.health_read_stall.store(true, Ordering::SeqCst);
        server
            .state
            .neighbor_read_stall
            .store(true, Ordering::SeqCst);
        server
            .state
            .session_events
            .lock()
            .await
            .push(rustbgpd_api::proto::BgpEvent {
                event_type: rustbgpd_api::proto::BgpEventType::SessionLost as i32,
                summary: "retained session history".into(),
                ..Default::default()
            });
        server
            .state
            .effective_config_delay_ms
            .store(500, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            dir.path().display()
        ));
        let bundle_path = dir.path().join("bundle.tar.gz");
        let code = run_with_deadlines(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
            Duration::from_millis(250),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(code, 2);
        let files = extract_bundle(&bundle_path);
        assert!(!files.iter().any(|(name, _)| name == "system/health.json"));
        for retained in [
            "system/global.json",
            "system/metrics.prom",
            "config/effective.toml",
            "peers/events.json",
        ] {
            find(&files, retained);
        }
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert!(
            manifest["sections"]["system"]
                .as_str()
                .unwrap()
                .contains("partial: health RPC failed")
        );
        assert!(
            manifest_check(&manifest, "daemon.healthy")["detail"]
                .as_str()
                .unwrap()
                .contains("GetHealth response timed out after 0.25s")
        );
        assert_eq!(
            manifest["sections"]["config"],
            "collected (daemon-redacted effective config)"
        );
        assert!(
            manifest["sections"]["peers"]
                .as_str()
                .unwrap()
                .contains("partial: BFD collected")
        );
        assert_eq!(manifest["sections"]["session_events"], "collected");
        assert!(
            manifest["sections"]["peers"]
                .as_str()
                .unwrap()
                .contains("ListNeighbors response timed out after 0.25s")
        );
        assert!(find(&files, "peers/events.json").contains("retained session history"));
    }

    #[tokio::test]
    async fn effective_config_deadline_keeps_successful_lightweight_evidence() {
        let server = spawn_mock_server(None).await;
        server
            .state
            .effective_config_delay_ms
            .store(500, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");
        run_with_deadlines(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        let files = extract_bundle(&bundle_path);
        find(&files, "system/health.json");
        find(&files, "peers/neighbors.json");
        assert!(
            !files
                .iter()
                .any(|(name, _)| name == "config/effective.toml")
        );
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_eq!(manifest["sections"]["system"], "collected");
        assert!(
            manifest["sections"]["config"]
                .as_str()
                .unwrap()
                .contains("GetEffectiveConfig response timed out after 0.02s")
        );
    }

    #[tokio::test]
    async fn doctor_validation_posture_warnings_are_advisory_and_use_one_rpc() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));
        let output_dir = tempfile::tempdir().unwrap();
        let bundle_path = output_dir.path().join("bundle.tar.gz");
        let code = run(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(code, 0, "policy posture warnings are advisory");
        assert_eq!(
            server
                .state
                .validation_policy_posture_calls
                .load(Ordering::SeqCst),
            1
        );
        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        for name in ["rpki.invalid_route_policy", "aspa.invalid_route_policy"] {
            assert_eq!(manifest_check(&manifest, name)["status"], "warn");
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
        let mut slow = neighbor(
            "10.0.0.2",
            rustbgpd_api::proto::SessionState::Idle as i32,
            FLAP_REPORT_THRESHOLD,
            "core peer",
        );
        slow.slow_peer = true;
        slow.update_group = "slow_peer".to_string();
        slow.is_dynamic = true;
        slow.accepted_dynamic_range = Some(rustbgpd_api::proto::AcceptedDynamicNeighborRange {
            prefix: "10.0.0.0/24".to_string(),
            peer_group: "ix-members".to_string(),
        });
        *server.state.list_neighbors_response.lock().await = vec![slow];
        *server.state.session_events.lock().await = vec![
            rustbgpd_api::proto::BgpEvent {
                timestamp: now_unix_seconds().to_string(),
                peer_address: "10.0.0.2".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::SessionLost as i32,
                summary: "recent session loss".to_string(),
                ..Default::default()
            },
            rustbgpd_api::proto::BgpEvent {
                timestamp: now_unix_seconds().to_string(),
                peer_address: "10.0.0.2".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::PeerDisabled as i32,
                summary: "peer disabled after loss".to_string(),
                ..Default::default()
            },
        ];
        *server.state.bfd_sessions.lock().await = vec![rustbgpd_api::proto::BfdSession {
            peer_address: "10.0.0.2".to_string(),
            state: rustbgpd_api::proto::BfdSessionState::Down as i32,
            diagnostic: "none".to_string(),
            strict: true,
            remote_administrative_down: Some(true),
            multihop: false,
        }];
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
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();
        // The evidenced recent loss is an unconditional red input; the
        // manifest assertion below is the load-bearing correlation proof even
        // though the independent disabled session verdict is green.
        assert_eq!(code, 2);

        let files = extract_bundle(&bundle_path);
        for expected in [
            "manifest.json",
            "config/effective.toml",
            "peers/bfd.json",
            "peers/dynamic-neighbors.json",
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
        // Pin the complete required manifest floor while allowing future
        // bundle versions to add fields without breaking v2 consumers.
        assert_inventory_json_contract(&manifest, "support-bundle-manifest/2");
        assert_eq!(manifest["format"], 2);
        assert_eq!(manifest["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["daemon_version"], "0.0.0-mock");
        assert_eq!(manifest["sections"]["peers"], "collected");
        assert_eq!(manifest["sections"]["dynamic_neighbors"], "collected");
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
        let peers: serde_json::Value =
            serde_json::from_str(find(&files, "peers/neighbors.json")).unwrap();
        let dynamic_neighbors: serde_json::Value =
            serde_json::from_str(find(&files, "peers/dynamic-neighbors.json")).unwrap();
        assert_eq!(dynamic_neighbors, serde_json::json!([]));
        // Load-bearing mutation proof: dropping any shared JsonNeighbor
        // projection from the support snapshot makes its assertion red.
        assert_eq!(peers[0]["slow_peer"], true);
        assert_eq!(peers[0]["is_dynamic"], true);
        assert_eq!(
            peers[0]["accepted_dynamic_range"],
            serde_json::json!({
                "prefix": "10.0.0.0/24",
                "peer_group": "ix-members",
            })
        );
        let bfd: serde_json::Value = serde_json::from_str(find(&files, "peers/bfd.json")).unwrap();
        // Load-bearing mutation proof: dropping the field from the doctor
        // projection or defaulting it false/null makes this primary cause
        // assertion red.
        assert_eq!(bfd[0]["remote_administrative_down"], true);
        assert!(manifest["checks"].as_array().unwrap().iter().any(|check| {
            check["name"] == "peer.10.0.0.2.bfd"
                && check["status"] == "warn"
                && check["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("BGP is permitted"))
        }));
        // Load-bearing mutation proof: dropping the live update-group handoff,
        // or disabling the isolation predicate, restores the enable-isolation
        // guidance and makes this exact already-isolated assertion red.
        let slow_check = manifest_check(&manifest, "peer.10.0.0.2.slow_peer");
        assert_eq!(slow_check["status"], "warn");
        assert_eq!(
            slow_check["detail"],
            r#"peer 10.0.0.2 is flagged slow and already isolated from shared update groups: outbound queue persistently backlogged; inspect bgp_peer_outbound_queue_depth{peer="10.0.0.2"} and troubleshoot the member's receive path"#
        );
        // LAN-668 destructive red proof: the retained disable affects only
        // the session disposition; removing its Ok branch makes this red.
        assert!(manifest["checks"].as_array().unwrap().iter().any(|check| {
            check["name"] == "peer.10.0.0.2.session"
                && check["status"] == "ok"
                && check["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("administratively disabled"))
        }));
        // Load-bearing mutation proof: dropping the event-type correlation,
        // the loss map, its handoff into `peer_checks`, or short-circuiting
        // after the disabled session verdict changes this independently
        // evidenced recent-instability verdict away from red.
        assert!(manifest["checks"].as_array().unwrap().iter().any(|check| {
            check["name"] == "peer.10.0.0.2.flaps"
                && check["status"] == "fail"
                && check["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("retained history shows a session loss"))
        }));
    }

    /// End-to-end load-bearing proof for the doctor-private neighbor record.
    /// Dropping the blocking check loses exit 2 and its exact scoped check;
    /// serializing the private wrapper instead of its redacted support
    /// projection exposes one of the forbidden internal keys.
    #[tokio::test]
    async fn doctor_reports_scoped_outbound_blocking_without_changing_bundle_shape() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));

        let mut blocked = neighbor(
            "fe80::1",
            rustbgpd_api::proto::SessionState::Connect as i32,
            0,
            "blocked peer",
        );
        blocked.config.as_mut().unwrap().interface = "eth0".to_string();
        blocked.last_error = "token=must-not-escape".to_string();
        blocked.max_prefix_restart_remaining_millis = Some(0);
        blocked.outbound_prefix_limits = vec![rustbgpd_api::proto::OutboundPrefixLimitState {
            family: "ipv4_unicast".to_string(),
            usage: 100,
            limit: Some(100),
            headroom: Some(0),
            blocking: true,
            reason: Some("outbound_prefix_limit_reached".to_string()),
        }];

        let mut unblocked = neighbor(
            "fe80::1",
            rustbgpd_api::proto::SessionState::Established as i32,
            0,
            "healthy peer",
        );
        unblocked.config.as_mut().unwrap().interface = "eth1".to_string();
        unblocked.outbound_prefix_limits = vec![rustbgpd_api::proto::OutboundPrefixLimitState {
            family: "ipv4_unicast".to_string(),
            usage: 99,
            limit: Some(100),
            headroom: Some(1),
            blocking: false,
            reason: None,
        }];
        *server.state.list_neighbors_response.lock().await = vec![blocked, unblocked];

        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");
        let code = run(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 2, "blocking outbound capacity must exit red");

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        let blocked_check = manifest_check(
            &manifest,
            "peer.fe80::1%eth0.outbound_prefix_limit.ipv4_unicast",
        );
        assert_eq!(blocked_check["status"], "fail");
        assert!(
            blocked_check["detail"]
                .as_str()
                .unwrap()
                .contains("usage 100, limit 100, reason outbound_prefix_limit_reached")
        );
        assert!(manifest["checks"].as_array().unwrap().iter().all(|check| {
            !check["name"]
                .as_str()
                .unwrap()
                .starts_with("peer.fe80::1%eth1.outbound_prefix_limit")
        }));
        assert_eq!(
            manifest_check(&manifest, "peer.fe80::1%eth0.session")["status"],
            "warn"
        );

        let peers: serde_json::Value =
            serde_json::from_str(find(&files, "peers/neighbors.json")).unwrap();
        assert_eq!(peers[0]["address"], "fe80::1");
        assert_eq!(peers[0]["interface"], "eth0");
        assert_eq!(peers[0]["last_error"], "[REDACTED]");
        for forbidden in [
            "support",
            "identity",
            "update_group",
            "max_prefix_restart_remaining_millis",
            "outbound_prefix_limits",
        ] {
            assert!(
                peers[0].get(forbidden).is_none(),
                "private doctor field {forbidden} leaked into neighbors.json"
            );
        }
    }

    /// Load-bearing zero-inventory proof: omitting the range snapshot removes
    /// the bundle file, while treating a truly unconfigured daemon as healthy
    /// weakens the existing first-deploy warning.
    #[tokio::test]
    async fn doctor_records_zero_live_neighbors_and_zero_dynamic_ranges() {
        let server = spawn_mock_server(None).await;
        *server.state.config_effective_toml.lock().await =
            Some("[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n".to_string());
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        let dynamic_neighbors: serde_json::Value =
            serde_json::from_str(find(&files, "peers/dynamic-neighbors.json")).unwrap();
        assert_eq!(dynamic_neighbors, serde_json::json!([]));
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_eq!(manifest["sections"]["dynamic_neighbors"], "collected");
        let inventory = manifest_check(&manifest, "peers.configured");
        assert_eq!(inventory["status"], "warn");
        assert_eq!(
            inventory["detail"],
            "no active neighbor sessions and no dynamic-neighbor ranges configured"
        );
    }

    /// Load-bearing dormant-range proof: deleting the range RPC projection or
    /// correlating only the empty live-neighbor list loses both the redacted
    /// range evidence and the exact configured-range count.
    #[tokio::test]
    async fn doctor_records_dormant_dynamic_neighbor_inventory() {
        let server = spawn_mock_server(None).await;
        *server.state.config_effective_toml.lock().await =
            Some("[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n".to_string());
        *server.state.list_dynamic_neighbors_response.lock().await = vec![
            rustbgpd_api::proto::DynamicNeighborRange {
                prefix: "192.0.2.0/24".to_string(),
                peer_group: "edge".to_string(),
                remote_asn: 65002,
                description: "password=must-not-escape".to_string(),
            },
            rustbgpd_api::proto::DynamicNeighborRange {
                prefix: "198.51.100.0/24".to_string(),
                peer_group: "edge".to_string(),
                remote_asn: 65003,
                description: "secondary range".to_string(),
            },
        ];
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        let dynamic_text = find(&files, "peers/dynamic-neighbors.json");
        assert!(!dynamic_text.contains("must-not-escape"));
        let dynamic_neighbors: serde_json::Value = serde_json::from_str(dynamic_text).unwrap();
        assert_eq!(dynamic_neighbors.as_array().unwrap().len(), 2);
        assert_eq!(dynamic_neighbors[0]["prefix"], "192.0.2.0/24");
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert!(
            manifest["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path == "peers/dynamic-neighbors.json")
        );
        let inventory = manifest_check(&manifest, "peers.configured");
        assert_eq!(inventory["status"], "ok");
        assert_eq!(
            inventory["detail"],
            "no active neighbor sessions; 2 dynamic-neighbor ranges configured for future acceptance"
        );
    }

    /// Load-bearing unavailable-evidence proof: converting the range RPC error
    /// to an empty vector fabricates zero inventory and drops the explicit
    /// partial-evidence receipt.
    #[tokio::test]
    async fn doctor_marks_dynamic_neighbor_inventory_rpc_unavailable() {
        let server = spawn_mock_server(None).await;
        *server.state.config_effective_toml.lock().await =
            Some("[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n".to_string());
        *server.state.list_dynamic_neighbors_error.lock().await =
            Some((Code::Unavailable, "range inventory offline".to_string()));
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connect(&server.addr, None).await,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        assert!(
            !files
                .iter()
                .any(|(path, _)| path == "peers/dynamic-neighbors.json")
        );
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert!(
            manifest["sections"]["dynamic_neighbors"]
                .as_str()
                .is_some_and(
                    |status| status.contains("unavailable: ListDynamicNeighbors RPC failed")
                )
        );
        let inventory = manifest_check(&manifest, "peers.configured");
        assert_eq!(inventory["status"], "warn");
        let detail = inventory["detail"].as_str().unwrap();
        assert!(detail.contains("no active neighbor sessions"));
        assert!(detail.contains("dynamic-neighbor range inventory unavailable"));
        assert!(!detail.contains("0 dynamic-neighbor"));
    }

    #[tokio::test]
    async fn doctor_marks_successful_empty_session_history_as_bounded_unknown() {
        let server = spawn_mock_server(None).await;
        *server.state.list_neighbors_response.lock().await = vec![neighbor(
            "10.0.0.2",
            rustbgpd_api::proto::SessionState::Connect as i32,
            0,
            "peer with no retained transition",
        )];
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        // Load-bearing mutation proof: conflating an empty successful reply
        // with an RPC failure changes either this collected source status or
        // the bounded-history wording below to "unavailable".
        assert_eq!(manifest["sections"]["session_events"], "collected");
        let peer_session = manifest["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "peer.10.0.0.2.session")
            .expect("Connect peer session check");
        assert_eq!(peer_session["status"], "warn");
        let detail = peer_session["detail"].as_str().unwrap();
        assert!(detail.contains("bounded 256-event fleet history"));
        assert!(!detail.contains("unavailable"));
    }

    /// LAN-668 bundle exit proof: retained operator intent must flow through
    /// the real RPC projection and keep an intentionally disabled peer from
    /// manufacturing the process-wide red exit code.
    #[tokio::test]
    async fn doctor_bundle_exits_green_for_scoped_administratively_disabled_peer() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));
        let mut disabled = neighbor(
            "fe80::1",
            rustbgpd_api::proto::SessionState::Idle as i32,
            0,
            "intentionally disabled",
        );
        disabled.config.as_mut().unwrap().interface = "eth0".to_string();
        *server.state.list_neighbors_response.lock().await = vec![disabled];
        *server.state.session_events.lock().await = vec![
            rustbgpd_api::proto::BgpEvent {
                timestamp: "1".to_string(),
                peer_address: "fe80::1%eth0".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::PeerDisabled as i32,
                summary: "peer disabled".to_string(),
                ..Default::default()
            },
            // A later ordinary FSM event must not erase the administrative
            // state retained immediately above.
            rustbgpd_api::proto::BgpEvent {
                timestamp: "2".to_string(),
                peer_address: "fe80::1%eth0".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::SessionStateChanged as i32,
                summary: "transitioned to Idle".to_string(),
                ..Default::default()
            },
        ];
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
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        // LAN-668 destructive red proof: replacing `PeerDisabled` above with
        // a normal transition makes the retained admin evidence disappear,
        // turning the ancient Idle transition and this bundle exit assertion
        // red.
        assert_eq!(code, 0, "an intentionally disabled peer must not exit red");
        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        let peer_session = manifest["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "peer.fe80::1%eth0.session")
            .expect("scoped disabled-peer session check");
        assert_eq!(peer_session["status"], "ok");
        assert!(
            peer_session["detail"]
                .as_str()
                .unwrap()
                .contains("administratively disabled (state Idle)")
        );
    }

    #[tokio::test]
    async fn doctor_marks_session_history_failure_without_discarding_peer_evidence() {
        let server = spawn_mock_server(None).await;
        *server.state.list_neighbors_response.lock().await = vec![neighbor(
            "10.0.0.2",
            rustbgpd_api::proto::SessionState::Connect as i32,
            0,
            "peer evidence survives",
        )];
        *server.state.session_events_error.lock().await = Some((
            Code::Unavailable,
            "upstream bearer must-not-escape".to_string(),
        ));
        *server.state.policy_events.lock().await = vec![rustbgpd_api::proto::BgpEvent {
            timestamp: "200".to_string(),
            peer_address: "10.0.0.2".to_string(),
            summary: "policy evidence survives".to_string(),
            ..Default::default()
        }];
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        let session_status = manifest["sections"]["session_events"].as_str().unwrap();
        // Load-bearing mutation proof: restoring the old `Err(_) => Vec::new()`
        // collapse makes this partial-source assertion red.
        assert!(session_status.contains("partial: ListSessionEvents RPC failed"));
        assert!(session_status.contains("[REDACTED]"));
        assert!(!session_status.contains("must-not-escape"));
        assert_eq!(manifest["sections"]["policy_events"], "collected");
        assert_eq!(manifest["sections"]["peers"], "collected");
        let peers: serde_json::Value =
            serde_json::from_str(find(&files, "peers/neighbors.json")).unwrap();
        assert_eq!(peers[0]["address"], "10.0.0.2");
        let peer_session = manifest["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "peer.10.0.0.2.session")
            .expect("Connect peer session check");
        // Load-bearing mutation proof: collapsing the failed RPC to an empty
        // event vector fabricates the old red "no transition" verdict and
        // makes both the warning and unavailable-evidence assertions red.
        assert_eq!(peer_session["status"], "warn");
        assert!(
            peer_session["detail"]
                .as_str()
                .unwrap()
                .contains("session-event history unavailable")
        );
        let events: serde_json::Value =
            serde_json::from_str(find(&files, "peers/events.json")).unwrap();
        // Load-bearing mutation proof: discarding the successful policy
        // vector while the session RPC fails makes this exact evidence
        // assertion red.
        assert_eq!(events["policy"][0]["summary"], "policy evidence survives");
    }

    #[tokio::test]
    async fn doctor_marks_policy_history_failure_independently() {
        let server = spawn_mock_server(None).await;
        *server.state.policy_events_error.lock().await =
            Some((Code::Unavailable, "policy source unavailable".to_string()));
        *server.state.session_events.lock().await = vec![rustbgpd_api::proto::BgpEvent {
            timestamp: "100".to_string(),
            peer_address: "10.0.0.2".to_string(),
            summary: "session evidence survives".to_string(),
            ..Default::default()
        }];
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: &server.addr,
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        // Load-bearing mutation proof: restoring the old `Err(_) => Vec::new()`
        // collapse makes this independently-named partial-source assertion red.
        assert!(
            manifest["sections"]["policy_events"]
                .as_str()
                .unwrap()
                .contains("partial: ListPolicyEvents RPC failed")
        );
        assert_eq!(manifest["sections"]["session_events"], "collected");
        assert_eq!(manifest["sections"]["peers"], "collected");
        let events: serde_json::Value =
            serde_json::from_str(find(&files, "peers/events.json")).unwrap();
        // Load-bearing mutation proof: discarding the successful session
        // vector while the policy RPC fails makes this exact evidence
        // assertion red.
        assert_eq!(events["session"][0]["summary"], "session evidence survives");
    }

    /// A remote-daemon run proves dependency connects describe the rbgp
    /// process's network vantage, not daemon-side reachability. Restoring
    /// `Fail` for a refused dependency makes the exit-code assertion red;
    /// removing the vantage wording makes the exact detail assertion red.
    #[tokio::test]
    async fn doctor_remote_daemon_dependency_probes_are_cli_vantage_warnings() {
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = live.local_addr().unwrap().port();
        let dead_socket = tokio::net::TcpSocket::new_v4().unwrap();
        dead_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let dead = dead_socket.local_addr().unwrap();

        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            r#"[global]
asn = 65000
router_id = "192.0.2.1"
runtime_state_dir = "{state}"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:{live_port}"
[[rpki.cache_servers]]
address = "{dead}"

[bmp]
[[bmp.collectors]]
address = "{dead}"

[gnmi_dialout]
[[gnmi_dialout.targets]]
name = "central"
address = "{dead}"
paths = ["x"]
"#,
            state = state_dir.path().display()
        ));
        *server.state.metrics_text.lock().await = Some(
            "bgp_rpki_vrp_count{af=\"ipv4\"} 0\nbgp_rpki_vrp_count{af=\"ipv6\"} 0\n".to_string(),
        );
        let connection = connect(&server.addr, None).await;
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        let code = run(
            connection,
            &DoctorOptions {
                output: Some(&bundle_path),
                log_file: None,
                daemon_address: "http://198.51.100.9:50051",
                token_file_configured: false,
                json: true,
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 0, "CLI-vantage dependency failures must not exit red");

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_eq!(
            manifest["sections"]["probes"],
            "collected (targets from effective config)"
        );
        let checks = manifest["checks"].as_array().unwrap();
        let status_of = |name: &str| -> &str {
            checks
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("missing check {name}"))["status"]
                .as_str()
                .unwrap()
        };
        let detail_of = |name: &str| -> &str {
            checks
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("missing check {name}"))["detail"]
                .as_str()
                .unwrap()
        };
        assert_eq!(
            status_of(&format!(
                "rpki.cache.127.0.0.1:{live_port}.reachable_from_cli"
            )),
            "ok"
        );
        // Red proof: removing effective-config/metrics wiring removes this check.
        assert_eq!(status_of("rpki.vrp_table"), "warn");
        assert_eq!(
            status_of(&format!("rpki.cache.{dead}.reachable_from_cli")),
            "warn"
        );
        assert_eq!(
            status_of(&format!("bmp.collector.{dead}.reachable_from_cli")),
            "warn"
        );
        assert_eq!(status_of("gnmi_dialout.central.reachable_from_cli"), "warn");
        assert_eq!(status_of("state_dir.writable"), "ok");
        assert_eq!(status_of("host.run_context"), "ok");
        assert_ne!(status_of("state_dir.disk"), "fail");
        assert_eq!(
            detail_of(&format!("rpki.cache.{dead}.reachable_from_cli")),
            format!(
                "RTR cache {dead} unreachable from the rbgp CLI network vantage \
                 (Connection refused (os error 111)) — this is not daemon-side connectivity \
                 evidence; inspect the daemon-side rpki.vrp_table check and RTR logs for \
                 actual cache state; troubleshoot the CLI path only when rbgp and rustbgpd \
                 are expected to share a network vantage"
            )
        );
        assert_eq!(
            detail_of(&format!("bmp.collector.{dead}.reachable_from_cli")),
            format!(
                "BMP collector {dead} unreachable from the rbgp CLI network vantage \
                 (Connection refused (os error 111)) — this is not daemon-side connectivity \
                 evidence; inspect rustbgpd and collector logs for actual export state; \
                 troubleshoot the CLI path only when rbgp and rustbgpd are expected to share \
                 a network vantage"
            )
        );
        assert_eq!(
            detail_of("gnmi_dialout.central.reachable_from_cli"),
            format!(
                "gNMI dial-out collector central {dead} unreachable from the rbgp CLI network \
                 vantage (Connection refused (os error 111)) — this is not daemon-side \
                 connectivity evidence; inspect the daemon-side gnmi_dialout_connected metric \
                 and logs for actual dial-out state; troubleshoot the CLI path only when rbgp \
                 and rustbgpd are expected to share a network vantage"
            )
        );
    }

    #[tokio::test]
    async fn doctor_flags_stuck_peer_and_exits_red() {
        let server = spawn_mock_server(None).await;
        let state_dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "[global]\nasn = 65000\nruntime_state_dir = \"{}\"\n",
            state_dir.path().display()
        ));
        // State 2 = Connect with a genuinely old retained transition => red.
        let mut stuck = neighbor("10.0.0.9", 2, 0, "stuck peer");
        stuck.last_error =
            "sent NOTIFICATION 2/7 (Unsupported Capability)\ntoken=must-not-escape".to_string();
        *server.state.list_neighbors_response.lock().await = vec![stuck];
        *server.state.session_events.lock().await = vec![
            rustbgpd_api::proto::BgpEvent {
                timestamp: "1".to_string(),
                peer_address: "10.0.0.9".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::PeerDisabled as i32,
                summary: "old incarnation disabled".to_string(),
                ..Default::default()
            },
            rustbgpd_api::proto::BgpEvent {
                timestamp: "1".to_string(),
                peer_address: "10.0.0.9".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::PeerEnabled as i32,
                summary: "replacement incarnation added enabled".to_string(),
                ..Default::default()
            },
            rustbgpd_api::proto::BgpEvent {
                timestamp: "1".to_string(),
                peer_address: "10.0.0.9".to_string(),
                event_type: rustbgpd_api::proto::BgpEventType::SessionStateChanged as i32,
                summary: "old transition".to_string(),
                ..Default::default()
            },
        ];
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
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();
        // LAN-668 delete/re-add red proof: deleting the replacement
        // incarnation's `PeerEnabled` publication above leaves the old
        // `PeerDisabled` current, fabricates a green session verdict, and
        // makes this expected red exit assertion fail.
        assert_eq!(code, 2, "stuck peer must produce the red exit code");

        let files = extract_bundle(&bundle_path);
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert!(manifest["checks"].as_array().unwrap().iter().any(|c| {
            c["name"] == "peer.10.0.0.9.session"
                && c["status"] == "fail"
                && c["detail"].as_str().unwrap().contains("in Connect")
                && c["detail"]
                    .as_str()
                    .unwrap()
                    .contains("Unsupported Capability")
                && c["detail"].as_str().unwrap().contains("[REDACTED]")
        }));
        let peers: serde_json::Value =
            serde_json::from_str(find(&files, "peers/neighbors.json")).unwrap();
        assert_eq!(
            peers[0]["last_error"],
            "sent NOTIFICATION 2/7 (Unsupported Capability)\n[REDACTED]"
        );
        assert!(!find(&files, "manifest.json").contains("must-not-escape"));
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
                pre_upgrade: None,
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
                pre_upgrade: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 2, "unreachable daemon is a red check");

        let files = extract_bundle(&bundle_path);
        find(&files, "system/environment.json");
        let manifest: serde_json::Value =
            serde_json::from_str(find(&files, "manifest.json")).unwrap();
        assert_inventory_json_contract(&manifest, "support-bundle-manifest/2");
        assert_eq!(manifest["daemon_version"], serde_json::Value::Null);
        assert_eq!(
            manifest["sections"]["config"],
            "unavailable: daemon unreachable"
        );
        assert_eq!(
            manifest["sections"]["peers"],
            "unavailable: daemon unreachable"
        );
        assert_eq!(
            manifest["sections"]["dynamic_neighbors"],
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

    // ---- pre-upgrade mode ---------------------------------------------

    fn mock_confirmation(
        status: rustbgpd_api::proto::ConfigTransactionConfirmationStatus,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        human_text: &str,
    ) -> rustbgpd_api::proto::ConfigTransactionConfirmation {
        rustbgpd_api::proto::ConfigTransactionConfirmation {
            status: status as i32,
            confirm_id: confirm_id.to_string(),
            timeout_seconds: 0,
            deadline_unix_seconds,
            committed_sections: Vec::new(),
            runtime_snapshot_token: String::new(),
            human_text: human_text.to_string(),
        }
    }

    fn status_response(
        status: ConfigTransactionConfirmationStatus,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        human_text: &str,
    ) -> Result<ConfigTransactionStatusResponse, tonic::Status> {
        Ok(ConfigTransactionStatusResponse {
            confirmation: Some(crate::proto::ConfigTransactionConfirmation {
                status: status as i32,
                confirm_id: confirm_id.to_string(),
                timeout_seconds: 0,
                deadline_unix_seconds,
                committed_sections: Vec::new(),
                runtime_snapshot_token: String::new(),
                human_text: human_text.to_string(),
            }),
            human_text: format!("{human_text}\n"),
        })
    }

    fn assert_detail_mentions(check: &Check, fragments: &[&str]) {
        for fragment in fragments {
            assert!(
                check.detail.contains(fragment),
                "{} detail lacks {fragment:?}: {}",
                check.name,
                check.detail
            );
        }
    }

    #[test]
    fn pre_upgrade_transaction_check_fails_closed_on_every_nonterminal_or_unavailable_state() {
        use ConfigTransactionConfirmationStatus as S;
        let quiet = "No confirmed config transaction is pending.";
        // Green: an empty "none" record or a terminal outcome, always dated
        // and never claiming quiescence.
        for (response, fragment) in [
            (
                status_response(S::None, "", 0, quiet),
                "no confirmed config transaction is pending as of unix 1700",
            ),
            (
                status_response(S::Confirmed, "deploy-1", 0, "confirmed"),
                "terminal (confirmed)",
            ),
            (
                status_response(S::Aborted, "deploy-1", 0, "aborted"),
                "terminal (aborted)",
            ),
            (
                status_response(S::AutoReverted, "deploy-1", 0, "reverted"),
                "terminal (auto_reverted)",
            ),
        ] {
            let check = upgrade_transaction_check(Some(&response), 1700);
            assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
            assert_detail_mentions(&check, &[fragment, "not a fence"]);
        }
        // Red: every nonterminal state names the exact operator action.
        let cases: [(Result<_, tonic::Status>, &[&str]); 6] = [
            (
                status_response(S::Pending, "deploy-1", 1800, "awaiting confirmation"),
                &[
                    "pending until unix 1800",
                    "rbgp config confirm deploy-1",
                    "rbgp config abort deploy-1",
                    "never confirms, aborts, or rewrites",
                ],
            ),
            (
                status_response(
                    S::Pending,
                    "deploy-1",
                    0,
                    "Confirmed config transaction is applying.",
                ),
                &[
                    "still applying",
                    "rbgp config confirm deploy-1",
                    "rbgp config abort deploy-1",
                ],
            ),
            (
                status_response(
                    S::AbortFailed,
                    "deploy-1",
                    1800,
                    "Abort rollback failed; the transaction is still pending",
                ),
                &[
                    "abort_failed",
                    "Abort rollback failed",
                    "rbgp config abort deploy-1",
                    "boot-revert",
                ],
            ),
            (
                status_response(
                    S::AutoRevertFailed,
                    "deploy-1",
                    1800,
                    "Automatic rollback failed",
                ),
                &[
                    "auto_revert_failed",
                    "rbgp config confirm deploy-1",
                    "boot-revert",
                ],
            ),
            (
                status_response(
                    S::None,
                    "deploy-1",
                    0,
                    "failed with an ambiguous outcome; config mutations are blocked",
                ),
                &[
                    "ambiguous outcome",
                    "config mutations are blocked",
                    "Restart rustbgpd to boot-revert",
                ],
            ),
            (
                status_response(S::Unspecified, "", 0, ""),
                &["unrecognized confirmation status 0", "never a green"],
            ),
        ];
        for (response, fragments) in &cases {
            let check = upgrade_transaction_check(Some(response), 1700);
            assert_eq!(check.status, CheckStatus::Fail, "{}", check.detail);
            assert_detail_mentions(&check, fragments);
        }
        // Red: missing evidence is incomplete, never green.
        let unreachable = upgrade_transaction_check(None, 1700);
        assert_eq!(unreachable.status, CheckStatus::Fail);
        assert_detail_mentions(&unreachable, &["daemon unreachable", "never a green"]);
        let empty: Result<_, tonic::Status> = Ok(ConfigTransactionStatusResponse::default());
        let no_record = upgrade_transaction_check(Some(&empty), 1700);
        assert_eq!(no_record.status, CheckStatus::Fail);
        assert_detail_mentions(&no_record, &["no confirmation record", "never a green"]);
        for (error, fragments) in [
            (
                tonic::Status::permission_denied("principal reader lacks sensitive_read"),
                vec![
                    "denied GetConfigTransactionStatus",
                    "principal reader lacks sensitive_read",
                    "never a green",
                ],
            ),
            (
                tonic::Status::unauthenticated("bad token"),
                vec!["rejected this connection's credentials", "bad token"],
            ),
            (
                tonic::Status::unimplemented("no such method"),
                vec!["does not implement GetConfigTransactionStatus", "predates"],
            ),
            (
                tonic::Status::deadline_exceeded(
                    "GetConfigTransactionStatus response timed out after 30s",
                ),
                vec!["timed out after 30s", "never a green"],
            ),
        ] {
            let failed: Result<ConfigTransactionStatusResponse, _> = Err(error);
            let check = upgrade_transaction_check(Some(&failed), 1700);
            assert_eq!(check.status, CheckStatus::Fail, "{}", check.detail);
            assert_detail_mentions(&check, &fragments);
        }
    }

    #[test]
    fn pre_upgrade_settlement_check_reads_the_watchdog_gauge() {
        let idle = "# HELP bgp_peers_total peers\nbgp_peers_total 3\n";
        let check = upgrade_settlement_check(Ok(idle), 1700);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert_detail_mentions(
            &check,
            &[
                "no runtime-config settlement owner is active as of unix 1700",
                "not a fence",
            ],
        );

        let zero = "bgp_runtime_config_settlement_active{fence_reason=\"none\",kind=\"apply\",phase=\"settled\",response_attached=\"attached\"} 0\n";
        assert_eq!(
            upgrade_settlement_check(Ok(zero), 1700).status,
            CheckStatus::Ok
        );

        let reload = "bgp_runtime_config_settlement_active{fence_reason=\"none\",kind=\"sighup_reload\",phase=\"mutating\",response_attached=\"detached\"} 1\n";
        let check = upgrade_settlement_check(Ok(reload), 1700);
        assert_eq!(check.status, CheckStatus::Fail, "{}", check.detail);
        assert_detail_mentions(
            &check,
            &[
                "kind=sighup_reload",
                "phase=mutating",
                "fence_reason=none",
                "wait until bgp_runtime_config_settlement_active clears",
            ],
        );

        let fenced = "bgp_runtime_config_settlement_active{fence_reason=\"known_divergence\",kind=\"apply\",phase=\"mutating\",response_attached=\"attached\"} 1\nbgp_runtime_config_settlement_fail_stops_total{fence_reason=\"known_divergence\",kind=\"apply\",phase=\"mutating\",response_attached=\"attached\"} 1\n";
        let check = upgrade_settlement_check(Ok(fenced), 1700);
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(&check, &["fence_reason=known_divergence", "exit 70"]);

        // A different series sharing the prefix is not the gauge.
        let lookalike = "bgp_runtime_config_settlement_active_total 1\n";
        assert_eq!(
            upgrade_settlement_check(Ok(lookalike), 1700).status,
            CheckStatus::Ok
        );

        let check = upgrade_settlement_check(Err("metrics RPC failed: status: Unavailable"), 1700);
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(&check, &["metrics RPC failed", "never a green"]);
    }

    #[test]
    fn rfc8212_posture_resolves_omitted_and_explicit_pairs() {
        let resolve = |text: &str| rfc8212_posture(&toml::from_str(text).unwrap());
        assert_eq!(
            resolve("[global]\nasn = 1\n").unwrap(),
            Rfc8212Posture {
                epoch: 1,
                epoch_source: "omitted",
                policy: false,
                policy_source: "legacy_omission"
            }
        );
        assert_eq!(
            resolve("config_epoch = 2\n[global]\nasn = 1\n").unwrap(),
            Rfc8212Posture {
                epoch: 2,
                epoch_source: "explicit",
                policy: true,
                policy_source: "epoch_2_default"
            }
        );
        assert_eq!(
            resolve("config_epoch = 2\n[global]\nebgp_requires_policy = false\n").unwrap(),
            Rfc8212Posture {
                epoch: 2,
                epoch_source: "explicit",
                policy: false,
                policy_source: "explicit"
            }
        );
        assert_eq!(
            resolve("[global]\nebgp_requires_policy = true\n").unwrap(),
            Rfc8212Posture {
                epoch: 1,
                epoch_source: "omitted",
                policy: true,
                policy_source: "explicit"
            }
        );
        assert!(
            resolve("config_epoch = 3\n")
                .unwrap_err()
                .contains("must be 1 or 2")
        );
        assert!(
            resolve("[global]\nebgp_requires_policy = \"yes\"\n")
                .unwrap_err()
                .contains("must be a boolean")
        );
        assert_eq!(
            resolve("config_epoch = 2\n").unwrap().to_string(),
            "config_epoch = 2 (explicit), ebgp_requires_policy = true (epoch_2_default)"
        );
    }

    #[test]
    fn pre_upgrade_posture_check_reports_mismatch_without_rewriting() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("config.toml");
        let live_legacy =
            "config_epoch = 1\n\n[global]\nasn = 65000\nebgp_requires_policy = false\n";

        // Staged epoch-2 file against a legacy daemon: the restart would
        // activate the secure default, so the check is red and names both
        // the policy route and the offline pin, and the file is untouched.
        let staged = "config_epoch = 2\n\n[global]\nasn = 65000\n";
        fs::write(&candidate, staged).unwrap();
        let check =
            upgrade_posture_check(&candidate, Ok(&toml::from_str(live_legacy).unwrap()), 1700);
        assert_eq!(check.status, CheckStatus::Fail, "{}", check.detail);
        assert_detail_mentions(
            &check,
            &[
                "ebgp_requires_policy = true (epoch_2_default)",
                "ebgp_requires_policy = false (explicit)",
                "changes the RFC 8212 posture",
                &format!("rustbgpd --check --strict {}", candidate.display()),
                &format!(
                    "--migrate-config pin-legacy --offline {}",
                    candidate.display()
                ),
                "rewrote nothing",
            ],
        );
        assert_eq!(
            fs::read_to_string(&candidate).unwrap(),
            staged,
            "the check must not rewrite"
        );

        // Legacy omission on disk matches a materialized epoch-1 daemon.
        fs::write(&candidate, "[global]\nasn = 65000\n").unwrap();
        let check =
            upgrade_posture_check(&candidate, Ok(&toml::from_str(live_legacy).unwrap()), 1700);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert_detail_mentions(
            &check,
            &[
                "legacy_omission",
                "matches as of unix 1700",
                "nothing was rewritten",
            ],
        );

        // An explicit epoch-2 opt-out keeps its stated meaning.
        fs::write(
            &candidate,
            "config_epoch = 2\n\n[global]\nebgp_requires_policy = false\n",
        )
        .unwrap();
        let live_optout =
            "config_epoch = 2\n\n[global]\nasn = 65000\nebgp_requires_policy = false\n";
        assert_eq!(
            upgrade_posture_check(&candidate, Ok(&toml::from_str(live_optout).unwrap()), 1700)
                .status,
            CheckStatus::Ok
        );

        // Missing or unreadable evidence is red, never green.
        let check =
            upgrade_posture_check(&candidate, Err("effective-config RPC failed: denied"), 1700);
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(
            &check,
            &["effective-config RPC failed: denied", "never a green"],
        );
        let check = upgrade_posture_check(
            &candidate,
            Err("invalid effective-config TOML; source text omitted"),
            1700,
        );
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(&check, &["invalid effective-config TOML"]);
        let check = upgrade_posture_check(
            &dir.path().join("absent.toml"),
            Ok(&toml::from_str(live_legacy).unwrap()),
            1700,
        );
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(
            &check,
            &[
                "cannot read candidate config",
                "--pre-upgrade",
                "never a green",
            ],
        );
        fs::write(&candidate, "config_epoch = 3\n").unwrap();
        let check =
            upgrade_posture_check(&candidate, Ok(&toml::from_str(live_legacy).unwrap()), 1700);
        assert_eq!(check.status, CheckStatus::Fail);
        assert_detail_mentions(&check, &["must be 1 or 2", "rustbgpd --check --strict"]);
    }

    #[test]
    fn pre_upgrade_mismatch_restores_every_supported_live_tuple() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("config.toml");
        for (epoch, policy) in [(1, false), (1, true), (2, false), (2, true)] {
            fs::write(
                &candidate,
                format!(
                    "config_epoch = {epoch}\n[global]\nebgp_requires_policy = {}\n",
                    !policy
                ),
            )
            .unwrap();
            let live =
                format!("config_epoch = {epoch}\n[global]\nebgp_requires_policy = {policy}\n");
            let check =
                upgrade_posture_check(&candidate, Ok(&toml::from_str(&live).unwrap()), 1700);
            assert_eq!(check.status, CheckStatus::Fail);
            match (epoch, policy) {
                (1, false) => assert!(
                    check
                        .detail
                        .contains("--migrate-config pin-legacy --offline")
                ),
                (2, true) => assert!(
                    check
                        .detail
                        .contains("--migrate-config prepare-secure --offline")
                ),
                _ => {
                    assert!(!check.detail.contains("--migrate-config"));
                    assert!(check.detail.contains(&format!("config_epoch = {epoch}` and `[global] ebgp_requires_policy = {policy}` explicitly")));
                }
            }
            assert!(check.detail.contains("after any rewrite"));
        }
    }

    #[tokio::test]
    async fn pre_upgrade_candidate_errors_redact_source_from_every_report() {
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        let secret = "dummy-secret-do-not-report";
        let documents = [
            format!("[global]\nmd5_password = \"{secret}\\q\"\n"),
            format!("config_epoch = \"{secret}\"\n"),
            format!("[global]\nebgp_requires_policy = {{ secret = \"{secret}\" }}\n"),
        ];
        for (index, document) in documents.iter().enumerate() {
            fs::write(&candidate, document).unwrap();
            let bundle_path = dir.path().join(format!("redacted-{index}.tar.gz"));
            let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;
            assert_eq!(code, 2);
            let reported = manifest_check(&manifest, "upgrade.posture");
            assert_eq!(reported["status"], "fail");
            let check = Check {
                name: "upgrade.posture".to_string(),
                status: CheckStatus::Fail,
                detail: reported["detail"].as_str().unwrap().to_string(),
            };
            let human = check.human_text();
            assert!(human.contains("FAIL"));
            assert!(!human.contains(secret));
            let json = json_report(&bundle_path, true, &[check], &BTreeMap::new(), None).unwrap();
            assert_eq!(json["ok"], false);
            assert!(!json.to_string().contains(secret));
            for (path, contents) in extract_bundle(&bundle_path) {
                assert!(!contents.contains(secret), "secret leaked into {path}");
            }
            assert_eq!(fs::read_to_string(&candidate).unwrap(), *document);
        }
    }

    #[test]
    fn json_report_adds_pre_upgrade_only_in_that_mode() {
        let bundle = Path::new("/tmp/bundle.tar.gz");
        let checks = vec![Check {
            name: "daemon.reachable".to_string(),
            status: CheckStatus::Ok,
            detail: "ok".to_string(),
        }];
        let sections = BTreeMap::from([("config", "collected".to_string())]);
        let plain = json_report(bundle, false, &checks, &sections, None).unwrap();
        let mut keys: Vec<_> = plain.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["bundle", "checks", "ok", "sections"],
            "plain doctor JSON is unchanged"
        );

        let summary = PreUpgradeSummary {
            candidate_config: "/etc/rustbgpd/config.toml".to_string(),
            observed_at_unix_seconds: 1700,
            ok: true,
        };
        let report = json_report(bundle, false, &checks, &sections, Some(&summary)).unwrap();
        assert_eq!(report["pre_upgrade"]["observed_at_unix_seconds"], 1700);
        assert_eq!(
            report["pre_upgrade"]["candidate_config"],
            "/etc/rustbgpd/config.toml"
        );
        assert_eq!(report["pre_upgrade"]["ok"], true);
        let text = summary.human_text();
        assert!(text.contains("as of unix 1700"), "{text}");
        assert!(text.contains("not a fence"), "{text}");
        assert!(text.contains("coordinated stop"), "{text}");
        assert!(!text.to_lowercase().contains("safe to upgrade"), "{text}");
        let red = PreUpgradeSummary {
            ok: false,
            ..summary
        }
        .human_text();
        assert!(
            red.contains("FAIL") && red.contains("rerun `rbgp doctor --pre-upgrade"),
            "{red}"
        );
    }

    /// A mock daemon whose ordinary doctor checks are green, so the exit
    /// codes below are decided by the pre-upgrade checks alone. Mirrors the
    /// disabled-peer seeding of the plain green bundle test.
    async fn green_pre_upgrade_lab() -> (
        crate::test_support::MockServerHandle,
        tempfile::TempDir,
        PathBuf,
    ) {
        let server = spawn_mock_server(None).await;
        let dir = tempfile::tempdir().unwrap();
        *server.state.config_effective_toml.lock().await = Some(format!(
            "config_epoch = 1\n\n[global]\nasn = 65000\nebgp_requires_policy = false\nruntime_state_dir = \"{}\"\n",
            dir.path().display()
        ));
        let mut disabled = neighbor(
            "fe80::1",
            rustbgpd_api::proto::SessionState::Idle as i32,
            0,
            "intentionally disabled",
        );
        disabled.config.as_mut().unwrap().interface = "eth0".to_string();
        *server.state.list_neighbors_response.lock().await = vec![disabled];
        *server.state.session_events.lock().await = vec![rustbgpd_api::proto::BgpEvent {
            timestamp: "1".to_string(),
            peer_address: "fe80::1%eth0".to_string(),
            event_type: rustbgpd_api::proto::BgpEventType::PeerDisabled as i32,
            summary: "peer disabled".to_string(),
            ..Default::default()
        }];
        let candidate = dir.path().join("config.toml");
        fs::write(
            &candidate,
            "[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n",
        )
        .unwrap();
        (server, dir, candidate)
    }

    #[tokio::test]
    async fn malformed_effective_document_keeps_bundle_but_cannot_pass_pre_upgrade() {
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        let malformed = "invalid = = TOML";
        *server.state.config_effective_toml.lock().await = Some(malformed.to_string());
        let bundle_path = dir.path().join("malformed.tar.gz");
        let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;
        assert_eq!(code, 2);
        let check = manifest_check(&manifest, "deploy.config_parse");
        assert_eq!(check["status"], "fail");
        assert!(!check["detail"].as_str().unwrap().contains(malformed));
        assert_eq!(
            manifest_check(&manifest, "upgrade.posture")["status"],
            "fail"
        );
        assert_eq!(
            manifest["sections"]["probes"],
            "skipped: invalid config document"
        );
        assert_eq!(
            find(&extract_bundle(&bundle_path), "config/effective.toml"),
            malformed
        );
    }

    #[tokio::test]
    async fn pre_upgrade_explicit_listener_passes_and_failed_bind_stays_red() {
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        let bind_ip = doctor_listener_test_ip();
        let listener = tokio::net::TcpListener::bind((bind_ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        // Reserve a distinct non-listening socket before either doctor run.
        // Releasing and reacquiring the live port races other tests and TCP state.
        let unbound = tokio::net::TcpSocket::new_v4().unwrap();
        unbound.bind(std::net::SocketAddr::new(bind_ip, 0)).unwrap();
        let dead = unbound.local_addr().unwrap();
        server
            .state
            .config_effective_toml
            .lock()
            .await
            .as_mut()
            .unwrap()
            .push_str(&format!(
                "listen_port = {}\nlisten_addresses = ['{bind_ip}']\n",
                address.port()
            ));
        let (code, manifest) = run_doctor(
            &server.addr,
            &dir.path().join("healthy.tar.gz"),
            Some(&candidate),
        )
        .await;
        assert_eq!(code, 0, "{manifest}");
        let check = manifest_check(&manifest, "bgp.listener");
        assert_eq!(check["status"], "ok", "{check}");
        assert!(
            check["detail"]
                .as_str()
                .unwrap()
                .contains(&address.to_string())
        );
        assert!(!check["detail"].as_str().unwrap().contains("127.0.0.1:"));
        {
            let mut effective = server.state.config_effective_toml.lock().await;
            let text = effective.as_mut().unwrap();
            *text = text.replace(
                &format!("listen_port = {}\n", address.port()),
                &format!("listen_port = {}\n", dead.port()),
            );
        }
        let (code, manifest) = run_doctor(
            &server.addr,
            &dir.path().join("failed.tar.gz"),
            Some(&candidate),
        )
        .await;
        assert_eq!(code, 2, "{manifest}");
        assert_eq!(manifest_check(&manifest, "bgp.listener")["status"], "fail");
        assert!(
            upgrade_checks(&manifest)
                .iter()
                .all(|(_, status, _)| status == "ok")
        );
    }

    async fn run_doctor(
        addr: &str,
        bundle_path: &Path,
        pre_upgrade: Option<&Path>,
    ) -> (i32, serde_json::Value) {
        let code = run(
            connect(addr, None).await,
            &DoctorOptions {
                output: Some(bundle_path),
                log_file: None,
                daemon_address: addr,
                token_file_configured: false,
                json: true,
                pre_upgrade,
            },
        )
        .await
        .unwrap();
        let files = extract_bundle(bundle_path);
        let manifest = serde_json::from_str(find(&files, "manifest.json")).unwrap();
        (code, manifest)
    }

    fn upgrade_checks(manifest: &serde_json::Value) -> Vec<(String, String, String)> {
        manifest["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|check| check["name"].as_str().unwrap().starts_with("upgrade."))
            .map(|check| {
                (
                    check["name"].as_str().unwrap().to_string(),
                    check["status"].as_str().unwrap().to_string(),
                    check["detail"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn assert_upgrade_check(
        manifest: &serde_json::Value,
        name: &str,
        status: &str,
        fragments: &[&str],
    ) {
        let check = manifest_check(manifest, name);
        assert_eq!(check["status"], status, "{name}: {}", check["detail"]);
        let detail = check["detail"].as_str().unwrap();
        for fragment in fragments {
            assert!(
                detail.contains(fragment),
                "{name} detail lacks {fragment:?}: {detail}"
            );
        }
        assert!(
            !detail.to_lowercase().contains("safe to upgrade")
                && !detail.to_lowercase().contains("quiescen"),
            "{name} must never claim quiescence: {detail}"
        );
    }

    #[tokio::test]
    async fn pre_upgrade_pending_confirmation_exits_red_with_confirm_abort_guidance() {
        use rustbgpd_api::proto::ConfigTransactionConfirmationStatus as S;
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        *server.state.config_status_confirmation.lock().await = Some(mock_confirmation(
            S::Pending,
            "deploy-20260907-1",
            now_unix_seconds() + 600,
            "Confirmed config transaction is awaiting confirmation.",
        ));
        let before = fs::read(&candidate).unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;

        assert_eq!(
            code, 2,
            "a pending confirmation is a red pre-upgrade verdict"
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "fail",
            &[
                "deploy-20260907-1 is pending until unix",
                "rbgp config confirm deploy-20260907-1",
                "rbgp config abort deploy-20260907-1",
                "before the coordinated stop",
            ],
        );
        assert_upgrade_check(&manifest, "upgrade.settlement", "ok", &["as of unix"]);
        assert_upgrade_check(
            &manifest,
            "upgrade.posture",
            "ok",
            &["legacy_omission", "matches"],
        );
        // Nothing was resolved on the operator's behalf.
        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&candidate).unwrap(), before, "no file rewrite");
        assert!(
            manifest["sections"]["pre_upgrade"]
                .as_str()
                .unwrap()
                .contains("an observation, not a fence")
        );
    }

    #[tokio::test]
    async fn pre_upgrade_unavailable_evidence_is_red() {
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        *server.state.config_status_error.lock().await =
            Some((Code::Unimplemented, "unknown method".to_string()));
        server
            .state
            .metrics_failures_remaining
            .store(1, Ordering::SeqCst);
        *server.state.config_effective_error.lock().await = Some((
            Code::Unavailable,
            "effective config export busy".to_string(),
        ));
        let bundle_path = dir.path().join("bundle.tar.gz");

        let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;

        assert_eq!(code, 2);
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "fail",
            &[
                "does not implement GetConfigTransactionStatus",
                "never a green",
            ],
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.settlement",
            "fail",
            &["metrics RPC failed", "never a green"],
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.posture",
            "fail",
            &[
                "effective-config RPC failed",
                "effective config export busy",
                "never a green",
            ],
        );
        assert!(
            upgrade_checks(&manifest)
                .iter()
                .all(|(_, status, _)| status == "fail"),
            "missing evidence never yields a green upgrade check"
        );
    }

    #[tokio::test]
    async fn pre_upgrade_permission_denied_is_red() {
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        *server.state.config_status_error.lock().await = Some((
            Code::PermissionDenied,
            "principal reader lacks sensitive_read".to_string(),
        ));
        *server.state.config_effective_error.lock().await = Some((
            Code::PermissionDenied,
            "principal reader lacks sensitive_read".to_string(),
        ));
        let bundle_path = dir.path().join("bundle.tar.gz");

        let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;

        assert_eq!(code, 2);
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "fail",
            &[
                "denied GetConfigTransactionStatus (sensitive_read)",
                "principal reader lacks sensitive_read",
                "rerun with a principal permitted",
            ],
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.posture",
            "fail",
            &[
                "does not have permission",
                "principal reader lacks sensitive_read",
                "never a green",
            ],
        );
    }

    #[tokio::test]
    async fn pre_upgrade_rejected_credentials_are_red() {
        let server = spawn_mock_server(Some("expected-token")).await;
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("config.toml");
        fs::write(&candidate, "[global]\nasn = 65000\n").unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");

        // No token: every RPC is Unauthenticated, so every upgrade check is red.
        let (code, manifest) = run_doctor(&server.addr, &bundle_path, Some(&candidate)).await;

        assert_eq!(code, 2);
        let checks = upgrade_checks(&manifest);
        assert_eq!(checks.len(), 3, "{checks:?}");
        assert!(
            checks.iter().all(|(_, status, _)| status == "fail"),
            "{checks:?}"
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "fail",
            &["rejected this connection's credentials", "never a green"],
        );
    }

    #[tokio::test]
    async fn pre_upgrade_refused_connection_is_red() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("config.toml");
        fs::write(&candidate, "[global]\nasn = 65000\n").unwrap();
        let bundle_path = dir.path().join("bundle.tar.gz");
        let addr = format!("unix://{}", dir.path().join("nobody-home.sock").display());

        let (code, manifest) = run_doctor(&addr, &bundle_path, Some(&candidate)).await;

        assert_eq!(code, 2);
        for name in [
            "upgrade.transaction",
            "upgrade.settlement",
            "upgrade.posture",
        ] {
            assert_upgrade_check(
                &manifest,
                name,
                "fail",
                &["daemon unreachable", "never a green"],
            );
        }
        assert!(manifest["sections"]["pre_upgrade"].is_string());
    }

    #[tokio::test]
    async fn pre_upgrade_observation_is_stale_once_a_transaction_starts() {
        use rustbgpd_api::proto::ConfigTransactionConfirmationStatus as S;
        let (server, dir, candidate) = green_pre_upgrade_lab().await;
        let first = dir.path().join("first.tar.gz");
        let second = dir.path().join("second.tar.gz");

        // A green observation at one instant...
        let (code, manifest) = run_doctor(&server.addr, &first, Some(&candidate)).await;
        assert_eq!(code, 0, "{:?}", manifest["checks"]);
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "ok",
            &[
                "no confirmed config transaction is pending as of unix",
                "not a fence",
            ],
        );
        assert_upgrade_check(&manifest, "upgrade.settlement", "ok", &["not a fence"]);
        assert_upgrade_check(&manifest, "upgrade.posture", "ok", &["matches as of unix"]);

        // ...grants nothing: a transaction that starts afterwards makes the
        // same command red, so the earlier observation is stale.
        *server.state.config_status_confirmation.lock().await = Some(mock_confirmation(
            S::Pending,
            "late-window",
            now_unix_seconds() + 600,
            "Confirmed config transaction is awaiting confirmation.",
        ));
        let (code, manifest) = run_doctor(&server.addr, &second, Some(&candidate)).await;
        assert_eq!(
            code, 2,
            "a transaction starting after the observation invalidates it"
        );
        assert_upgrade_check(
            &manifest,
            "upgrade.transaction",
            "fail",
            &[
                "late-window is pending",
                "rbgp config confirm late-window",
                "rbgp config abort late-window",
            ],
        );
        assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn plain_doctor_ignores_a_healthy_pending_confirmation_window() {
        use rustbgpd_api::proto::ConfigTransactionConfirmationStatus as S;
        let (server, dir, _candidate) = green_pre_upgrade_lab().await;
        *server.state.config_status_confirmation.lock().await = Some(mock_confirmation(
            S::Pending,
            "deploy-20260907-1",
            now_unix_seconds() + 600,
            "Confirmed config transaction is awaiting confirmation.",
        ));
        let bundle_path = dir.path().join("bundle.tar.gz");

        let (code, manifest) = run_doctor(&server.addr, &bundle_path, None).await;

        assert_eq!(
            code, 0,
            "a healthy pending-confirm window is not a plain doctor failure"
        );
        assert!(
            upgrade_checks(&manifest).is_empty(),
            "no upgrade checks outside the mode"
        );
        assert!(manifest["sections"].get("pre_upgrade").is_none());
        assert_eq!(
            server.state.config_status_calls.load(Ordering::SeqCst),
            0,
            "plain doctor issues no transaction status RPC"
        );
    }
}
