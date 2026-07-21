//! Parameterized fixed-scenario differential corpus for update groups.
//!
//! The small corpus runs fixed schedules in normal PR CI. Seeds vary fixture
//! identities, not operation ordering. The ignored extension sweeps those same
//! schedules under hard parameter/operation caps on a weekly hosted runner.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustbgpd_wire::{
    AddressPrefixOrf, Afi, Ipv4Prefix, OrfAction, OrfMatch, Prefix, RtcNlri, Safi,
};

use super::update_groups_oracle::{
    NormAnnounce, NormMsg, NormVpnAnnounce, Oracle, OraclePeerFeatures, Streams, deny_prefix_chain,
    deny_prefixes_chain, fold, fold_vpn, ibgp_route, peer_context_permit_chain, pfx, rtc_default,
    vpn_nlri, vpn_route, vpn_rtc_sendable,
};
use crate::route::RtcRibRouteKey;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEFT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const RIGHT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const PR_SEEDS: [u64; 3] = [0x51_7A, 0xC0_FF_EE, 0x05EE_D357];
const DEFAULT_SEED_START: u64 = 0x3570_0000;
const DEFAULT_SEED_COUNT: usize = 24;
const DEFAULT_MAX_OPS: usize = 64;
const SEED_COUNT_CAP: usize = 64;
const MIN_MAX_OPS: usize = 18;
const MAX_OPS_CAP: usize = 64;
const SEED_START_ENV: &str = "RUSTBGPD_UPDATE_GROUP_SEED_START";
const SEED_COUNT_ENV: &str = "RUSTBGPD_UPDATE_GROUP_SEED_COUNT";
const MAX_OPS_ENV: &str = "RUSTBGPD_UPDATE_GROUP_MAX_OPS";
const SCENARIO_ENV: &str = "RUSTBGPD_UPDATE_GROUP_SCENARIO";
const OP_INDICES_ENV: &str = "RUSTBGPD_UPDATE_GROUP_OP_INDICES";
const MINIMIZE_ENV: &str = "RUSTBGPD_UPDATE_GROUP_MINIMIZE";
const MINIMIZE_EVALUATIONS_ENV: &str = "RUSTBGPD_UPDATE_GROUP_MINIMIZE_EVALUATIONS";
const FORCE_FAILURE_OP_ENV: &str = "RUSTBGPD_UPDATE_GROUP_FORCE_FAILURE_OP";
const MINIMIZER_CHILD_ENV: &str = "RUSTBGPD_UPDATE_GROUP_MINIMIZER_CHILD";
const EMPTY_OPS_SENTINEL: &str = "none";
const DEFAULT_MINIMIZE_EVALUATIONS: usize = 64;
const MINIMIZE_EVALUATIONS_CAP: usize = 256;
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(20);
const FAILURE_FINGERPRINT_MARKER: &str = "UPDATE_GROUP_FAILURE_FINGERPRINT=";
const EXTENDED_TEST_NAME: &str =
    "manager::tests::update_groups_fault_corpus::deterministic_fault_corpus_extended";
const TIMEOUT_FIXTURE_TEST_NAME: &str =
    "manager::tests::update_groups_fault_corpus::minimizer_timeout_fixture";
const TIMEOUT_FIXTURE_ENV: &str = "RUSTBGPD_UPDATE_GROUP_TIMEOUT_FIXTURE";
const TEST_RT: u64 = 0x0002_FDE8_0000_002A;
static CHILD_LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExtendedConfig {
    seed_start: u64,
    seed_count: usize,
    max_ops: usize,
    scenario: Option<String>,
    op_indices: Option<Vec<usize>>,
    minimize: bool,
    minimize_evaluations: usize,
    force_failure_op: Option<usize>,
    minimizer_child: bool,
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = value.strip_prefix("0x").unwrap_or(value);
    if value.starts_with("0x") {
        u64::from_str_radix(parsed, 16)
    } else {
        value.parse()
    }
    .map_err(|error| format!("invalid {name}={value:?}: {error}"))
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    usize::try_from(parse_u64(name, value)?)
        .map_err(|error| format!("invalid {name}={value:?}: {error}"))
}

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("{name} must be 0 or 1, got {value:?}")),
    }
}

fn parse_op_indices(value: &str) -> Result<Vec<usize>, String> {
    if value == EMPTY_OPS_SENTINEL {
        return Ok(Vec::new());
    }
    if value.is_empty() {
        return Err(format!("{OP_INDICES_ENV} must not be empty"));
    }
    let indices = value
        .split(',')
        .map(|value| parse_usize(OP_INDICES_ENV, value))
        .collect::<Result<Vec<_>, _>>()?;
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!(
            "{OP_INDICES_ENV} must be strictly increasing without duplicates"
        ));
    }
    Ok(indices)
}

fn parse_extended_config(get: impl Fn(&str) -> Option<String>) -> Result<ExtendedConfig, String> {
    let seed_start = get(SEED_START_ENV)
        .map(|value| parse_u64(SEED_START_ENV, &value))
        .transpose()?
        .unwrap_or(DEFAULT_SEED_START);
    let seed_count = get(SEED_COUNT_ENV)
        .map(|value| parse_u64(SEED_COUNT_ENV, &value))
        .transpose()?
        .map_or(Ok(DEFAULT_SEED_COUNT), |value| {
            usize::try_from(value)
                .map_err(|error| format!("invalid {SEED_COUNT_ENV}={value}: {error}"))
        })?;
    let max_ops = get(MAX_OPS_ENV)
        .map(|value| parse_u64(MAX_OPS_ENV, &value))
        .transpose()?
        .map_or(Ok(DEFAULT_MAX_OPS), |value| {
            usize::try_from(value)
                .map_err(|error| format!("invalid {MAX_OPS_ENV}={value}: {error}"))
        })?;
    let scenario = get(SCENARIO_ENV)
        .map(|value| {
            if value.is_empty() {
                Err(format!("{SCENARIO_ENV} must not be empty"))
            } else {
                Ok(value)
            }
        })
        .transpose()?;
    let op_indices = get(OP_INDICES_ENV)
        .map(|value| parse_op_indices(&value))
        .transpose()?;
    let minimize = get(MINIMIZE_ENV)
        .map(|value| parse_bool(MINIMIZE_ENV, &value))
        .transpose()?
        .unwrap_or(false);
    let minimize_evaluations = get(MINIMIZE_EVALUATIONS_ENV)
        .map(|value| parse_usize(MINIMIZE_EVALUATIONS_ENV, &value))
        .transpose()?
        .unwrap_or(DEFAULT_MINIMIZE_EVALUATIONS);
    let force_failure_op = get(FORCE_FAILURE_OP_ENV)
        .map(|value| parse_usize(FORCE_FAILURE_OP_ENV, &value))
        .transpose()?;
    let minimizer_child = get(MINIMIZER_CHILD_ENV)
        .map(|value| parse_bool(MINIMIZER_CHILD_ENV, &value))
        .transpose()?
        .unwrap_or(false);
    if !(1..=SEED_COUNT_CAP).contains(&seed_count) {
        return Err(format!(
            "{SEED_COUNT_ENV} must be in 1..={SEED_COUNT_CAP}, got {seed_count}"
        ));
    }
    if !(MIN_MAX_OPS..=MAX_OPS_CAP).contains(&max_ops) {
        return Err(format!(
            "{MAX_OPS_ENV} must be in {MIN_MAX_OPS}..={MAX_OPS_CAP}, got {max_ops}"
        ));
    }
    if !(1..=MINIMIZE_EVALUATIONS_CAP).contains(&minimize_evaluations) {
        return Err(format!(
            "{MINIMIZE_EVALUATIONS_ENV} must be in 1..={MINIMIZE_EVALUATIONS_CAP}, got {minimize_evaluations}"
        ));
    }
    if scenario.is_some() && seed_count != 1 {
        return Err(format!(
            "{SCENARIO_ENV} requires {SEED_COUNT_ENV}=1 for exact replay"
        ));
    }
    if op_indices.is_some() && scenario.is_none() {
        return Err(format!("{OP_INDICES_ENV} requires {SCENARIO_ENV}"));
    }
    if minimize && scenario.is_none() {
        return Err(format!("{MINIMIZE_ENV}=1 requires {SCENARIO_ENV}"));
    }
    if force_failure_op.is_some() && !minimize && !minimizer_child {
        return Err(format!("{FORCE_FAILURE_OP_ENV} requires {MINIMIZE_ENV}=1"));
    }
    if minimizer_child && (scenario.is_none() || op_indices.is_none() || minimize) {
        return Err(format!(
            "{MINIMIZER_CHILD_ENV}=1 requires an exact scenario/operation replay and {MINIMIZE_ENV}=0"
        ));
    }
    let last_offset = u64::try_from(seed_count - 1).expect("seed count is capped at 64");
    seed_start
        .checked_add(last_offset)
        .ok_or_else(|| format!("{SEED_START_ENV} + {SEED_COUNT_ENV} overflows u64"))?;
    Ok(ExtendedConfig {
        seed_start,
        seed_count,
        max_ops,
        scenario,
        op_indices,
        minimize,
        minimize_evaluations,
        force_failure_op,
        minimizer_child,
    })
}

#[derive(Clone, Copy, Debug)]
enum ComparisonMode {
    ExactStream,
    SemanticFold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FamilySet {
    Unicast,
    VpnRtc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PolicySpec {
    Permit,
    DenyOne(Ipv4Prefix),
    DenyMany(Vec<Ipv4Prefix>),
    PeerContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MembershipExpectation {
    SharedGroup,
    SeparateSharedGroupFrom(Ipv4Addr),
    PeerContextFallback,
    AddPathFallback,
    OrfFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    PeerUp {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
        families: FamilySet,
    },
    PeerDown {
        peer: Ipv4Addr,
        generation: u64,
    },
    PeerUpAddPath {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
        send_max: u32,
    },
    PeerUpOrf {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
    },
    AddPathLimit {
        peer: Ipv4Addr,
        generation: u64,
        limit: u32,
    },
    OrfPermitExact {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
        accepted: bool,
    },
    OrfRemoveAll {
        peer: Ipv4Addr,
        generation: u64,
    },
    Announce {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
        local_pref: u32,
    },
    Withdraw {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
    },
    VpnAnnounce {
        peer: Ipv4Addr,
        generation: u64,
        id: u8,
    },
    ReplacePolicy {
        peer: Ipv4Addr,
        policy: PolicySpec,
    },
    AssertMembership {
        peer: Ipv4Addr,
        expectation: MembershipExpectation,
    },
    AssertAnnouncedPaths {
        peer: Ipv4Addr,
        prefix: Ipv4Prefix,
        expected: usize,
    },
    AssertLocRibAbsent(Ipv4Prefix),
    RtcDefaultAnnounce {
        peer: Ipv4Addr,
        generation: u64,
    },
    RtcDefaultWithdraw {
        peer: Ipv4Addr,
        generation: u64,
    },
    DrainOne(Ipv4Addr),
    DrainAvailable,
    AdvanceRetry,
    Quiesce,
}

#[derive(Clone, Debug)]
struct Schedule {
    name: &'static str,
    seed: u64,
    comparison: ComparisonMode,
    require_vpn_churn: bool,
    ops: Vec<Op>,
}

#[derive(Clone, Debug)]
struct ReplaySchedule {
    schedule: Schedule,
    retained_indices: Vec<usize>,
}

impl ReplaySchedule {
    fn full(schedule: Schedule) -> Self {
        let retained_indices = (0..schedule.ops.len()).collect();
        Self {
            schedule,
            retained_indices,
        }
    }

    fn retaining(&self, indices: &[usize]) -> Result<Self, String> {
        if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("operation indices must be strictly increasing".to_owned());
        }
        if let Some(index) = indices
            .iter()
            .find(|index| **index >= self.schedule.ops.len())
        {
            return Err(format!(
                "operation index {index} is out of range for scenario {} (0..{})",
                self.schedule.name,
                self.schedule.ops.len()
            ));
        }
        Ok(Self {
            schedule: self.schedule.clone(),
            retained_indices: indices.to_vec(),
        })
    }

    fn ops(&self) -> impl Iterator<Item = (usize, &Op)> {
        self.retained_indices
            .iter()
            .map(|index| (*index, &self.schedule.ops[*index]))
    }

    fn replay(&self) -> String {
        let ops = self
            .ops()
            .map(|(index, op)| format!("{index}:{op:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "scenario={} seed={:#x} mode={:?} ops=[{}]",
            self.schedule.name, self.schedule.seed, self.schedule.comparison, ops
        )
    }

    fn replay_command(&self) -> String {
        let indices = self.indices_value();
        format!(
            "{SEED_START_ENV}={:#x} {SEED_COUNT_ENV}=1 {SCENARIO_ENV}={} \
             {OP_INDICES_ENV}={indices} cargo test -p rustbgpd-rib --lib \
             {EXTENDED_TEST_NAME} -- --ignored --exact --nocapture",
            self.schedule.seed, self.schedule.name
        )
    }

    fn indices_value(&self) -> String {
        if self.retained_indices.is_empty() {
            EMPTY_OPS_SENTINEL.to_owned()
        } else {
            self.retained_indices
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    fn satisfies_minimizer_dependencies(&self) -> bool {
        let retained = self
            .retained_indices
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        self.schedule.ops.iter().enumerate().all(|(index, op)| {
            let session_boundary = matches!(
                op,
                Op::PeerUp { .. } | Op::PeerUpAddPath { .. } | Op::PeerUpOrf { .. }
            );
            if session_boundary && !retained.contains(&index) {
                return false;
            }
            let assertion = matches!(
                op,
                Op::AssertMembership { .. }
                    | Op::AssertAnnouncedPaths { .. }
                    | Op::AssertLocRibAbsent(_)
            );
            !assertion
                || !retained.contains(&index)
                || index
                    .checked_sub(1)
                    .is_some_and(|prior| retained.contains(&prior))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailureFingerprint(String);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Evaluation {
    Passed,
    Failed {
        fingerprint: FailureFingerprint,
        detail: String,
    },
    UnclassifiedFailure {
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Reduction {
    retained_indices: Vec<usize>,
    evaluations: usize,
    complete_single_deletion_pass: bool,
}

fn failure_fingerprint(detail: &str) -> FailureFingerprint {
    let headline = detail.lines().next().unwrap_or("non-string panic");
    if headline.starts_with("forced fault-corpus failure at original op ") {
        return FailureFingerprint(headline.to_owned());
    }
    let normalized = normalize_join_error_task_id(headline);
    let mut delimiters = vec!["scenario=", ": {", ": Err("];
    if !normalized.contains("JoinError::Panic(") {
        delimiters.push(" on an Err value:");
    }
    let stable = delimiters
        .into_iter()
        .filter_map(|delimiter| normalized.find(delimiter))
        .min()
        .map_or(normalized.as_str(), |end| &normalized[..end])
        .trim_end_matches([' ', ':']);
    FailureFingerprint(stable.to_owned())
}

fn normalize_join_error_task_id(headline: &str) -> String {
    let mut normalized = headline.to_owned();
    let prefix = "JoinError::Panic(Id(";
    let Some(start) = normalized.find(prefix) else {
        return normalized;
    };
    let digits_start = start + prefix.len();
    let Some(relative_end) = normalized[digits_start..].find(')') else {
        return normalized;
    };
    let end = digits_start + relative_end;
    if normalized[digits_start..end]
        .chars()
        .all(|character| character.is_ascii_digit())
    {
        normalized.replace_range(digits_start..end, "_");
    }
    normalized
}

fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn preserves_failure(evaluation: &Evaluation, target: &FailureFingerprint) -> bool {
    matches!(
        evaluation,
        Evaluation::Failed { fingerprint, .. } if fingerprint == target
    )
}

fn failure_marker(output: &str) -> Option<FailureFingerprint> {
    output.lines().rev().find_map(|line| {
        line.strip_prefix(FAILURE_FINGERPRINT_MARKER)
            .map(|value| FailureFingerprint(value.to_owned()))
    })
}

fn classify_nonzero_child(exit: &str, output: String) -> Evaluation {
    match failure_marker(&output) {
        Some(fingerprint) => Evaluation::Failed {
            fingerprint,
            detail: output,
        },
        None => Evaluation::UnclassifiedFailure {
            detail: format!("child {exit} without {FAILURE_FINGERPRINT_MARKER}\n{output}"),
        },
    }
}

fn minimization_target(evaluation: Evaluation) -> Result<(FailureFingerprint, String), String> {
    match evaluation {
        Evaluation::Passed => Err("configured minimization case no longer fails".to_owned()),
        Evaluation::Failed {
            fingerprint,
            detail,
        } => Ok((fingerprint, detail)),
        Evaluation::UnclassifiedFailure { detail } => Err(format!(
            "original child failure was unclassified; refusing to minimize:\n{detail}"
        )),
    }
}

fn minimize_failure<F>(
    initial: Vec<usize>,
    target: &FailureFingerprint,
    evaluation_cap: usize,
    mut evaluate: F,
) -> Reduction
where
    F: FnMut(Vec<usize>) -> Evaluation,
{
    let mut current = initial;
    let mut evaluations = 0;
    let mut partitions = 2;

    while current.len() >= 2 && evaluations < evaluation_cap {
        let chunk_size = current.len().div_ceil(partitions);
        let mut reduced = false;
        for start in (0..current.len()).step_by(chunk_size) {
            if evaluations == evaluation_cap {
                break;
            }
            let end = (start + chunk_size).min(current.len());
            let mut candidate = current[..start].to_vec();
            candidate.extend_from_slice(&current[end..]);
            evaluations += 1;
            if preserves_failure(&evaluate(candidate.clone()), target) {
                current = candidate;
                partitions = partitions.saturating_sub(1).max(2);
                reduced = true;
                eprintln!(
                    "update-group minimizer: best-so-far ops={current:?} evaluations={evaluations}/{evaluation_cap}"
                );
                break;
            }
        }
        if reduced {
            continue;
        }
        if partitions >= current.len() {
            break;
        }
        partitions = (partitions * 2).min(current.len());
    }

    let complete_single_deletion_pass = loop {
        let mut reduced = false;
        let mut completed_pass = true;
        for position in 0..current.len() {
            if evaluations == evaluation_cap {
                completed_pass = false;
                break;
            }
            let mut candidate = current.clone();
            candidate.remove(position);
            evaluations += 1;
            if preserves_failure(&evaluate(candidate.clone()), target) {
                current = candidate;
                reduced = true;
                eprintln!(
                    "update-group minimizer: best-so-far ops={current:?} evaluations={evaluations}/{evaluation_cap}"
                );
                break;
            }
        }
        if !completed_pass {
            break false;
        }
        if !reduced {
            break true;
        }
    };

    Reduction {
        retained_indices: current,
        evaluations,
        complete_single_deletion_pass,
    }
}

fn child_log_path() -> PathBuf {
    let sequence = CHILD_LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "rustbgpd-update-group-minimizer-{}-{sequence}.log",
        std::process::id()
    ))
}

struct ReapingChild {
    child: Child,
    reaped: bool,
}

impl ReapingChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<ExitStatus> {
        let kill = self.child.kill();
        match self.child.wait() {
            Ok(status) => {
                // A failed kill can mean the process exited between try_wait
                // and kill. A successful wait still proves it was reaped.
                self.reaped = true;
                Ok(status)
            }
            Err(wait_error) => {
                if let Err(kill_error) = kill {
                    return Err(std::io::Error::new(
                        wait_error.kind(),
                        format!("kill failed ({kill_error}); wait failed ({wait_error})"),
                    ));
                }
                Err(wait_error)
            }
        }
    }
}

impl Drop for ReapingChild {
    fn drop(&mut self) {
        if !self.reaped {
            // This guard covers every early return after spawn, including a
            // try_wait error. Both calls are best effort because Drop cannot
            // report an I/O failure; the main timeout path reports failures.
            let _ = self.child.kill();
            if self.child.wait().is_ok() {
                self.reaped = true;
            }
        }
    }
}

fn wait_for_child(
    child: &mut ReapingChild,
    timeout: Duration,
) -> Result<Option<ExitStatus>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("poll isolated fault-corpus candidate: {error}"))?
        {
            Some(status) => return Ok(Some(status)),
            None if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(remaining.min(Duration::from_millis(20)));
            }
            None => {
                child.terminate_and_reap().map_err(|error| {
                    format!("terminate timed-out fault-corpus candidate: {error}")
                })?;
                return Ok(None);
            }
        }
    }
}

fn evaluate_isolated_candidate(
    schedule: &ReplaySchedule,
    max_ops: usize,
    force_failure_op: Option<usize>,
) -> Result<Evaluation, String> {
    let executable = env::current_exe()
        .map_err(|error| format!("locate current fault-corpus test executable: {error}"))?;
    let log_path = child_log_path();
    let log = File::create(&log_path)
        .map_err(|error| format!("create candidate log {}: {error}", log_path.display()))?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("clone candidate log {}: {error}", log_path.display()))?;

    let mut command = Command::new(executable);
    command
        .arg(EXTENDED_TEST_NAME)
        .args(["--ignored", "--exact", "--nocapture"])
        .env(SEED_START_ENV, format!("{:#x}", schedule.schedule.seed))
        .env(SEED_COUNT_ENV, "1")
        .env(MAX_OPS_ENV, max_ops.to_string())
        .env(SCENARIO_ENV, schedule.schedule.name)
        .env(OP_INDICES_ENV, schedule.indices_value())
        .env(MINIMIZE_ENV, "0")
        .env(MINIMIZER_CHILD_ENV, "1")
        .env_remove(MINIMIZE_EVALUATIONS_ENV)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    if let Some(index) = force_failure_op {
        command.env(FORCE_FAILURE_OP_ENV, index.to_string());
    } else {
        command.env_remove(FORCE_FAILURE_OP_ENV);
    }

    let mut child = ReapingChild::new(
        command
            .spawn()
            .map_err(|error| format!("spawn isolated fault-corpus candidate: {error}"))?,
    );
    let status = wait_for_child(&mut child, CANDIDATE_TIMEOUT)?;

    let mut output = String::new();
    File::open(&log_path)
        .and_then(|mut log| log.read_to_string(&mut output))
        .map_err(|error| format!("read candidate log {}: {error}", log_path.display()))?;
    fs::remove_file(&log_path)
        .map_err(|error| format!("remove candidate log {}: {error}", log_path.display()))?;

    let Some(status) = status else {
        return Ok(Evaluation::Failed {
            fingerprint: FailureFingerprint("candidate-timeout".to_owned()),
            detail: format!(
                "candidate exceeded {}s wall-clock deadline\n{output}",
                CANDIDATE_TIMEOUT.as_secs()
            ),
        });
    };
    if status.success() {
        if !output.lines().any(|line| line.trim() == "running 1 test") {
            return Err(format!(
                "exact ignored test {EXTENDED_TEST_NAME} did not run\n{output}"
            ));
        }
        return Ok(Evaluation::Passed);
    }

    Ok(classify_nonzero_child(
        &format!("exited with {status}"),
        output,
    ))
}

fn unicast() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast)]
}

fn sentinel() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 255, 255, 0), 24)
}

fn seed_octet(seed: u64, lane: usize) -> u8 {
    // SplitMix64's stable finalizer makes every fixture lane depend on the
    // whole seed; consecutive extended-corpus seeds therefore do not leave
    // the high-byte lanes unchanged.
    let lane = u64::try_from(lane).expect("fixture lanes fit in u64");
    let mut mixed = seed ^ lane.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (mixed ^ (mixed >> 31)).to_le_bytes()[0] | 1
}

fn distinct_seed_octet(seed: u64, lane: usize, other: u8) -> u8 {
    let candidate = seed_octet(seed, lane);
    if candidate == other {
        candidate.wrapping_add(2)
    } else {
        candidate
    }
}

fn distinct_seed_octet_from(seed: u64, lane: usize, others: &[u8]) -> u8 {
    let mut candidate = seed_octet(seed, lane);
    while others.contains(&candidate) {
        candidate = candidate.wrapping_add(2);
    }
    candidate
}

fn policy(spec: &PolicySpec) -> Option<rustbgpd_policy::PolicyChain> {
    match spec {
        PolicySpec::Permit => None,
        PolicySpec::DenyOne(prefix) => Some(deny_prefix_chain(*prefix)),
        PolicySpec::DenyMany(prefixes) => Some(deny_prefixes_chain(prefixes)),
        PolicySpec::PeerContext => Some(peer_context_permit_chain()),
    }
}

#[derive(Clone, Debug, PartialEq)]
enum SemanticEffect {
    SessionStart {
        peer: IpAddr,
        generation: u64,
    },
    Announce {
        peer: IpAddr,
        route: NormAnnounce,
    },
    Withdraw {
        peer: IpAddr,
        key: (Prefix, u32),
    },
    UnknownWithdrawBeforeTerminalRoute {
        peer: IpAddr,
        key: (Prefix, u32),
    },
    VpnAnnounce {
        peer: IpAddr,
        route: NormVpnAnnounce,
    },
    VpnWithdraw {
        peer: IpAddr,
        key: (String, u32),
    },
    UnknownVpnWithdrawBeforeTerminalRoute {
        peer: IpAddr,
        key: (String, u32),
    },
}

fn semantic_effects(streams: &Streams) -> Vec<SemanticEffect> {
    let terminal = fold(streams);
    let terminal_vpn = fold_vpn(streams);
    let mut effects = Vec::new();
    for (peer, messages) in streams {
        let mut state: HashMap<(Prefix, u32), NormAnnounce> = HashMap::new();
        let mut vpn_state: HashMap<String, NormVpnAnnounce> = HashMap::new();
        for message in messages {
            if let Some(generation) = message.session_start {
                state.clear();
                vpn_state.clear();
                effects.push(SemanticEffect::SessionStart {
                    peer: *peer,
                    generation,
                });
            }
            for key in &message.withdraw {
                if state.remove(key).is_some() {
                    effects.push(SemanticEffect::Withdraw {
                        peer: *peer,
                        key: *key,
                    });
                } else if terminal
                    .get(peer)
                    .is_some_and(|routes| routes.contains_key(key))
                {
                    effects.push(SemanticEffect::UnknownWithdrawBeforeTerminalRoute {
                        peer: *peer,
                        key: *key,
                    });
                }
            }
            for route in &message.announce {
                let key = (route.0, route.1);
                if state.get(&key) != Some(route) {
                    state.insert(key, route.clone());
                    effects.push(SemanticEffect::Announce {
                        peer: *peer,
                        route: route.clone(),
                    });
                }
            }
            for key in &message.vpn_withdraw {
                if vpn_state.remove(&key.0).is_some() {
                    effects.push(SemanticEffect::VpnWithdraw {
                        peer: *peer,
                        key: key.clone(),
                    });
                } else if terminal_vpn
                    .get(peer)
                    .is_some_and(|routes| routes.contains_key(&key.0))
                {
                    effects.push(SemanticEffect::UnknownVpnWithdrawBeforeTerminalRoute {
                        peer: *peer,
                        key: key.clone(),
                    });
                }
            }
            for route in &message.vpn_announce {
                if vpn_state.get(&route.0) != Some(route) {
                    vpn_state.insert(route.0.clone(), route.clone());
                    effects.push(SemanticEffect::VpnAnnounce {
                        peer: *peer,
                        route: route.clone(),
                    });
                }
            }
        }
    }
    effects
}

async fn apply_vpn_announce(oracle: &mut Oracle, peer: Ipv4Addr, generation: u64, id: u8) {
    oracle
        .vpn_routes_generation(
            peer,
            generation,
            vec![vpn_route(
                vpn_nlri(id, 16_000 + u32::from(id)),
                peer,
                100,
                vec![TEST_RT],
            )],
            vec![],
        )
        .await;
}

async fn assert_membership(
    oracle: &mut Oracle,
    peer: Ipv4Addr,
    expectation: MembershipExpectation,
    force_ungrouped: bool,
) {
    let label = oracle.group_label(peer).await;
    match expectation {
        MembershipExpectation::SharedGroup if force_ungrouped => assert!(
            !label.starts_with("group:"),
            "forced oracle unexpectedly grouped {peer}: {label}"
        ),
        MembershipExpectation::SharedGroup => assert!(
            label.starts_with("group:"),
            "grouped path did not group {peer}: {label}"
        ),
        MembershipExpectation::SeparateSharedGroupFrom(other) if force_ungrouped => {
            let other_label = oracle.group_label(other).await;
            assert!(
                !label.starts_with("group:") && !other_label.starts_with("group:"),
                "forced oracle unexpectedly grouped comparison peers: \
                 {peer}={label}, {other}={other_label}"
            );
        }
        MembershipExpectation::SeparateSharedGroupFrom(other) => {
            let other_label = oracle.group_label(other).await;
            assert!(
                label.starts_with("group:")
                    && other_label.starts_with("group:")
                    && label != other_label,
                "policy regroup did not split shared update groups: \
                 {peer}={label}, {other}={other_label}"
            );
        }
        MembershipExpectation::PeerContextFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "policy_peer_context"),
            "peer-context transition did not reach per-peer path for {peer}: {label}"
        ),
        MembershipExpectation::AddPathFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "add_path_send"),
            "Add-Path transition did not reach per-peer path for {peer}: {label}"
        ),
        MembershipExpectation::OrfFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "orf_installed"),
            "ORF transition did not reach per-peer path for {peer}: {label}"
        ),
    }
}

fn announced_paths(messages: &[NormMsg], prefix: Ipv4Prefix) -> HashSet<(u32, IpAddr)> {
    messages
        .iter()
        .flat_map(|message| &message.announce)
        .filter_map(|route| (route.0 == Prefix::V4(prefix)).then_some((route.1, route.3)))
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive fault-script interpreter keeps every operation's behavior in one auditable match"
)]
async fn apply(oracle: &mut Oracle, op: &Op, force_ungrouped: bool) {
    match op {
        Op::PeerUp {
            peer,
            generation,
            capacity,
            families,
        } => {
            let sendable = match families {
                FamilySet::Unicast => unicast(),
                FamilySet::VpnRtc => vpn_rtc_sendable(),
            };
            oracle
                .peer_up_families_generation(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    sendable,
                )
                .await;
        }
        Op::PeerDown { peer, generation } => {
            oracle.peer_down_generation(*peer, *generation).await;
        }
        Op::PeerUpAddPath {
            peer,
            generation,
            capacity,
            send_max,
        } => {
            oracle
                .peer_up_families_generation_with_features(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    unicast(),
                    OraclePeerFeatures {
                        add_path_send_max: *send_max,
                        ..OraclePeerFeatures::default()
                    },
                )
                .await;
        }
        Op::PeerUpOrf {
            peer,
            generation,
            capacity,
        } => {
            oracle
                .peer_up_families_generation_with_features(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    unicast(),
                    OraclePeerFeatures {
                        negotiated_orf_recv: unicast(),
                        ..OraclePeerFeatures::default()
                    },
                )
                .await;
        }
        Op::AddPathLimit {
            peer,
            generation,
            limit,
        } => {
            oracle
                .peer_add_path_limits(*peer, *generation, *limit)
                .await;
        }
        Op::OrfPermitExact {
            peer,
            generation,
            prefix,
            accepted,
        } => {
            let result = oracle
                .peer_orf_update(
                    *peer,
                    *generation,
                    vec![AddressPrefixOrf {
                        action: OrfAction::Add,
                        match_: OrfMatch::Permit,
                        sequence: 10,
                        min_len: 0,
                        max_len: 0,
                        prefix: Some(Prefix::V4(*prefix)),
                    }],
                )
                .await;
            assert_eq!(
                result.is_ok(),
                *accepted,
                "ORF generation acceptance mismatch: {result:?}"
            );
        }
        Op::OrfRemoveAll { peer, generation } => {
            oracle
                .peer_orf_update(
                    *peer,
                    *generation,
                    vec![AddressPrefixOrf {
                        action: OrfAction::RemoveAll,
                        match_: OrfMatch::Permit,
                        sequence: 0,
                        min_len: 0,
                        max_len: 0,
                        prefix: None,
                    }],
                )
                .await
                .expect("current-session ORF Remove-All must be accepted");
        }
        Op::Announce {
            peer,
            generation,
            prefix,
            local_pref,
        } => {
            oracle
                .routes_generation(
                    *peer,
                    *generation,
                    vec![ibgp_route(*prefix, *peer, *local_pref, vec![])],
                    vec![],
                )
                .await;
        }
        Op::Withdraw {
            peer,
            generation,
            prefix,
        } => {
            oracle
                .routes_generation(*peer, *generation, vec![], vec![*prefix])
                .await;
        }
        Op::VpnAnnounce {
            peer,
            generation,
            id,
        } => {
            apply_vpn_announce(oracle, *peer, *generation, *id).await;
        }
        Op::ReplacePolicy { peer, policy: spec } => {
            oracle.replace_policy(*peer, policy(spec)).await;
        }
        Op::AssertMembership { peer, expectation } => {
            assert_membership(oracle, *peer, *expectation, force_ungrouped).await;
        }
        Op::AssertAnnouncedPaths {
            peer,
            prefix,
            expected,
        } => {
            let messages = oracle.drain_peer_available(*peer).await;
            let paths = announced_paths(&messages, *prefix);
            assert_eq!(
                paths.len(),
                *expected,
                "unexpected newly announced Add-Path identities for {prefix}: {paths:?}"
            );
        }
        Op::AssertLocRibAbsent(prefix) => {
            let routes = oracle.best_routes().await;
            assert!(
                routes
                    .iter()
                    .all(|route| route.prefix != Prefix::V4(*prefix)),
                "stale-session replacement route reached the Loc-RIB: {prefix}"
            );
        }
        Op::RtcDefaultAnnounce { peer, generation } => {
            oracle
                .rtc_routes_full_generation(*peer, *generation, vec![rtc_default(*peer)], vec![])
                .await;
            oracle.quiesce().await;
        }
        Op::RtcDefaultWithdraw { peer, generation } => {
            oracle
                .rtc_routes_full_generation(
                    *peer,
                    *generation,
                    vec![],
                    vec![RtcRibRouteKey {
                        nlri: RtcNlri::DEFAULT,
                        path_id: 0,
                    }],
                )
                .await;
            oracle.quiesce().await;
        }
        Op::DrainOne(peer) => {
            let _ = oracle.drain_one(*peer).await;
        }
        Op::DrainAvailable => oracle.drain_available(),
        Op::AdvanceRetry => {
            tokio::time::advance(Duration::from_secs(2)).await;
            oracle.quiesce().await;
        }
        Op::Quiesce => oracle.quiesce().await,
    }
}

async fn run_path(
    schedule: &ReplaySchedule,
    force_ungrouped: bool,
    max_ops: usize,
    force_failure_op: Option<usize>,
) -> Streams {
    assert!(
        schedule.retained_indices.len() <= max_ops,
        "operation cap {max_ops} exceeded: {}",
        schedule.replay()
    );
    let mut oracle = Oracle::spawn(force_ungrouped, Some(Ipv4Addr::new(192, 0, 2, 1)));
    for (index, op) in schedule.ops() {
        eprintln!(
            "update-group replay: scenario={} seed={:#x} op={index} {op:?}",
            schedule.schedule.name, schedule.schedule.seed
        );
        assert!(
            force_ungrouped || force_failure_op != Some(index),
            "forced fault-corpus failure at original op {index}"
        );
        apply(&mut oracle, op, force_ungrouped).await;
    }
    if !force_ungrouped {
        let left = oracle.group_label(LEFT).await;
        let right = oracle.group_label(RIGHT).await;
        assert!(
            left.starts_with("group:") && left == right,
            "scenario did not exercise a shared update group ({left:?}/{right:?}): {}",
            schedule.replay()
        );
    }

    // Every schedule ends with a current-generation sentinel from SOURCE.
    // Its delivery proves that the manager remains live after the injected
    // faults rather than merely comparing two empty or prematurely-ended runs.
    oracle
        .routes_generation(
            SOURCE,
            2,
            vec![ibgp_route(sentinel(), SOURCE, 250, vec![])],
            vec![],
        )
        .await;
    let health = oracle.terminal_health().await;
    assert_eq!(
        health,
        (0, 0, 0, 0, 0, 0),
        "terminal dirty/force/regroup/residue health is not clean: {}",
        schedule.replay()
    );
    let streams = oracle.finish().await; // Awaiting the handle proves manager completion.
    validate_terminal_stream(&streams).unwrap_or_else(|error| {
        panic!(
            "incomplete outbound stream ({error}): {}",
            schedule.replay()
        )
    });
    if schedule.schedule.require_vpn_churn {
        let left = streams
            .get(&IpAddr::V4(LEFT))
            .expect("LEFT is registered in every schedule");
        assert!(
            left.iter().any(|message| !message.vpn_announce.is_empty())
                && left.iter().any(|message| !message.vpn_withdraw.is_empty()),
            "RTC membership did not produce both VPN announce and withdraw traffic: {}",
            schedule.replay()
        );
        assert!(
            fold_vpn(&streams)
                .get(&IpAddr::V4(LEFT))
                .is_none_or(std::collections::HashMap::is_empty),
            "final RTC withdrawal must leave LEFT with no advertised VPN route: {}",
            schedule.replay()
        );
    }
    streams
}

fn validate_terminal_stream(streams: &Streams) -> Result<(), String> {
    let terminal = fold(streams);
    for peer in [LEFT, RIGHT] {
        let key = (Prefix::V4(sentinel()), 0);
        if !terminal
            .get(&IpAddr::V4(peer))
            .is_some_and(|routes| routes.contains_key(&key))
        {
            return Err(format!(
                "terminal sentinel absent from final session state for {peer}"
            ));
        }
    }
    Ok(())
}

async fn run_schedule(schedule: ReplaySchedule, max_ops: usize, force_failure_op: Option<usize>) {
    let grouped = run_path(&schedule, false, max_ops, force_failure_op).await;
    let ungrouped = run_path(&schedule, true, max_ops, force_failure_op).await;
    match schedule.schedule.comparison {
        ComparisonMode::ExactStream => assert_eq!(
            grouped,
            ungrouped,
            "exact stream mismatch: {}",
            schedule.replay()
        ),
        ComparisonMode::SemanticFold => assert_eq!(
            semantic_effects(&grouped),
            semantic_effects(&ungrouped),
            "normalized semantic-effect mismatch: {}",
            schedule.replay()
        ),
    }
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "folded advertised-state mismatch: {}",
        schedule.replay()
    );
    assert_eq!(
        fold_vpn(&grouped),
        fold_vpn(&ungrouped),
        "folded VPN advertised-state mismatch: {}",
        schedule.replay()
    );
}

async fn run_schedule_reporting_failure(
    schedule: ReplaySchedule,
    max_ops: usize,
    force_failure_op: Option<usize>,
) {
    let seed = schedule.schedule.seed;
    let scenario = schedule.schedule.name;
    match tokio::spawn(run_schedule(schedule, max_ops, force_failure_op)).await {
        Ok(()) => {}
        Err(error) if error.is_panic() => {
            let payload = error.into_panic();
            let detail = panic_detail(payload.as_ref());
            let fingerprint = failure_fingerprint(&detail);
            eprintln!("UPDATE_GROUP_FAILURE_CASE seed={seed:#x} scenario={scenario}");
            eprintln!("{FAILURE_FINGERPRINT_MARKER}{}", fingerprint.0);
            std::panic::resume_unwind(payload);
        }
        Err(error) => panic!("fault-corpus schedule task was cancelled: {error}"),
    }
}

fn saturation_schedule(seed: u64) -> Schedule {
    let first = pfx(seed_octet(seed, 0), 0);
    let second = pfx(distinct_seed_octet(seed, 1, seed_octet(seed, 0)), 1);
    Schedule {
        name: "saturation-drain-virtual-retry",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 110,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix: first,
            },
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainAvailable,
        ],
    }
}

fn dirty_policy_schedule(seed: u64) -> Schedule {
    let first = pfx(seed_octet(seed, 2), 2);
    let second = pfx(distinct_seed_octet(seed, 3, seed_octet(seed, 2)), 3);
    Schedule {
        name: "dirty-policy-regroup-transitions",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyOne(first),
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyMany(vec![first, second]),
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::PeerContext,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::PeerContextFallback,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::Permit,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainAvailable,
        ],
    }
}

fn stale_generation_rtc_schedule(seed: u64) -> Schedule {
    let live_octet = seed_octet(seed, 4);
    let stale_octet = distinct_seed_octet(seed, 5, live_octet);
    let live = pfx(live_octet, 4);
    let stale = pfx(stale_octet, 5);
    assert_ne!(
        live, stale,
        "stale-generation probe must not alias the current route"
    );
    Schedule {
        name: "stale-generation-rtc-membership-churn",
        seed,
        comparison: ComparisonMode::ExactStream,
        require_vpn_churn: true,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 1,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 1,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 1,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 1,
                prefix: stale,
                local_pref: 200,
            },
            Op::PeerDown {
                peer: SOURCE,
                generation: 1,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: live,
                local_pref: 100,
            },
            Op::RtcDefaultAnnounce {
                peer: LEFT,
                generation: 1,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::RtcDefaultWithdraw {
                peer: LEFT,
                generation: 2,
            },
            Op::RtcDefaultAnnounce {
                peer: LEFT,
                generation: 2,
            },
            Op::VpnAnnounce {
                peer: SOURCE,
                generation: 2,
                id: seed_octet(seed, 6),
            },
            Op::RtcDefaultWithdraw {
                peer: LEFT,
                generation: 2,
            },
            Op::Quiesce,
        ],
    }
}

fn add_path_membership_schedule(seed: u64) -> Schedule {
    let prefix = pfx(seed_octet(seed, 0), 7);
    Schedule {
        name: "add-path-membership-and-limit-churn",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix,
                local_pref: 200,
            },
            Op::Announce {
                peer: LEFT,
                generation: 2,
                prefix,
                local_pref: 100,
            },
            Op::PeerUpAddPath {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
                send_max: 2,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::AddPathFallback,
            },
            // Removing initial Add-Path fanout or rank compaction makes these
            // operation-boundary counts fail instead of merely comparing two
            // equally incomplete terminal folds.
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 2,
            },
            // The predecessor generation cannot narrow the active session's
            // cap or trigger its replay.
            Op::AddPathLimit {
                peer: RIGHT,
                generation: 2,
                limit: 1,
            },
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 0,
            },
            Op::AddPathLimit {
                peer: RIGHT,
                generation: 3,
                limit: 1,
            },
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 1,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 4,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 3,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::Quiesce,
        ],
    }
}

fn orf_membership_schedule(seed: u64) -> Schedule {
    let first_octet = seed_octet(seed, 1);
    let second_octet = distinct_seed_octet(seed, 2, first_octet);
    let third_octet = distinct_seed_octet_from(seed, 3, &[first_octet, second_octet]);
    let first = pfx(first_octet, 8);
    let second = pfx(second_octet, 9);
    let third = pfx(third_octet, 10);
    Schedule {
        name: "orf-membership-generation-and-filter-churn",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            Op::PeerUpOrf {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::OrfFallback,
            },
            Op::OrfPermitExact {
                peer: RIGHT,
                generation: 2,
                prefix: first,
                accepted: false,
            },
            Op::OrfPermitExact {
                peer: RIGHT,
                generation: 3,
                prefix: first,
                accepted: true,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: third,
                local_pref: 100,
            },
            Op::OrfRemoveAll {
                peer: RIGHT,
                generation: 3,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix: first,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 4,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 3,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::Quiesce,
        ],
    }
}

fn replacement_during_resync_schedule(seed: u64) -> Schedule {
    let first_octet = seed_octet(seed, 4);
    let second_octet = distinct_seed_octet(seed, 5, first_octet);
    let stale_octet = distinct_seed_octet_from(seed, 6, &[first_octet, second_octet]);
    let first = pfx(first_octet, 11);
    let second = pfx(second_octet, 12);
    let stale = pfx(stale_octet, 13);
    Schedule {
        name: "session-replacement-during-dirty-resync",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            // Replace the dirty transport before its virtual-time retry.
            Op::PeerUp {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 2,
            },
            Op::Announce {
                peer: RIGHT,
                generation: 2,
                prefix: stale,
                local_pref: 250,
            },
            // Removing the received-route generation fence exposes this
            // superseded session's higher-preference route in the Loc-RIB.
            Op::AssertLocRibAbsent(stale),
            Op::AdvanceRetry,
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainAvailable,
        ],
    }
}

fn combined_saturation_regroup_replacement_schedule(seed: u64) -> Schedule {
    let first_octet = seed_octet(seed, 7);
    let second_octet = distinct_seed_octet(seed, 8, first_octet);
    let stale_octet = distinct_seed_octet_from(seed, 9, &[first_octet, second_octet]);
    let first = pfx(first_octet, 14);
    let second = pfx(second_octet, 15);
    let stale = pfx(stale_octet, 16);
    Schedule {
        name: "combined-saturation-regroup-session-replacement",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            // Replace RIGHT before injecting faults so generation 3 owns
            // both the full outbound channel and the dirty/regroup residue.
            Op::PeerUp {
                peer: RIGHT,
                generation: 3,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 110,
            },
            // The second announce misses the full generation-3 channel.
            // Regroup while that current session is dirty, then inject the
            // superseded generation's teardown and best-path candidate.
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyOne(first),
            },
            // Removing the policy-replacement membership recompute leaves
            // RIGHT in LEFT's group and makes this boundary fail.
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SeparateSharedGroupFrom(LEFT),
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 2,
            },
            Op::Announce {
                peer: RIGHT,
                generation: 2,
                prefix: stale,
                local_pref: 250,
            },
            // Clearing generation 3 on the stale PeerDown, or allowing this
            // predecessor route through the session fence, makes this fail.
            Op::AssertLocRibAbsent(stale),
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainOne(RIGHT),
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::Permit,
            },
            Op::DrainAvailable,
        ],
    }
}

fn schedules(seed: u64) -> [Schedule; 7] {
    [
        saturation_schedule(seed),
        dirty_policy_schedule(seed),
        stale_generation_rtc_schedule(seed),
        add_path_membership_schedule(seed),
        orf_membership_schedule(seed),
        replacement_during_resync_schedule(seed),
        combined_saturation_regroup_replacement_schedule(seed),
    ]
}

fn replay_for(
    seed: u64,
    scenario: &str,
    retained_indices: Option<&[usize]>,
) -> Result<ReplaySchedule, String> {
    let schedule = schedules(seed)
        .into_iter()
        .find(|schedule| schedule.name == scenario)
        .ok_or_else(|| {
            let names = schedules(seed)
                .iter()
                .map(|schedule| schedule.name)
                .collect::<Vec<_>>()
                .join(", ");
            format!("unknown {SCENARIO_ENV}={scenario:?}; expected one of: {names}")
        })?;
    let replay = ReplaySchedule::full(schedule);
    retained_indices.map_or(Ok(replay.clone()), |indices| replay.retaining(indices))
}

fn validate_force_failure_op(
    replay: &ReplaySchedule,
    force_failure_op: Option<usize>,
) -> Result<(), String> {
    if let Some(index) = force_failure_op
        && index >= replay.schedule.ops.len()
    {
        return Err(format!(
            "{FORCE_FAILURE_OP_ENV}={index} is out of range for scenario {} (0..{})",
            replay.schedule.name,
            replay.schedule.ops.len()
        ));
    }
    Ok(())
}

fn minimize_configured_failure(config: &ExtendedConfig) -> ! {
    let scenario = config
        .scenario
        .as_deref()
        .expect("minimization config validation requires a scenario");
    let original = replay_for(config.seed_start, scenario, config.op_indices.as_deref())
        .unwrap_or_else(|error| panic!("invalid extended fault-corpus replay: {error}"));
    validate_force_failure_op(&original, config.force_failure_op)
        .unwrap_or_else(|error| panic!("invalid extended fault-corpus replay: {error}"));
    if let Some(index) = config.force_failure_op
        && !original.retained_indices.contains(&index)
    {
        panic!(
            "{FORCE_FAILURE_OP_ENV}={index} is not retained by {OP_INDICES_ENV}={}",
            original.indices_value()
        );
    }
    assert!(
        original.satisfies_minimizer_dependencies(),
        "minimization input must retain session boundaries and assertion prerequisites: {}",
        original.replay_command()
    );
    let original_evaluation =
        evaluate_isolated_candidate(&original, config.max_ops, config.force_failure_op)
            .unwrap_or_else(|error| panic!("evaluate original fault-corpus failure: {error}"));
    let (target, original_detail) = minimization_target(original_evaluation)
        .unwrap_or_else(|error| panic!("{error}: {}", original.replay_command()));

    eprintln!(
        "update-group minimizer: target={:?} original_ops={} evaluation_cap={} candidate_timeout={}s",
        target.0,
        original.retained_indices.len(),
        config.minimize_evaluations,
        CANDIDATE_TIMEOUT.as_secs()
    );
    let reduction = minimize_failure(
        original.retained_indices.clone(),
        &target,
        config.minimize_evaluations,
        |indices| {
            let candidate = original
                .retaining(&indices)
                .expect("minimizer only removes valid original operation indices");
            if !candidate.satisfies_minimizer_dependencies() {
                eprintln!("update-group minimizer: rejected dependency-invalid ops={indices:?}");
                return Evaluation::Passed;
            }
            let evaluation =
                evaluate_isolated_candidate(&candidate, config.max_ops, config.force_failure_op)
                    .unwrap_or_else(|error| panic!("evaluate fault-corpus candidate: {error}"));
            if let Evaluation::Failed { fingerprint, .. } = &evaluation
                && fingerprint != &target
            {
                eprintln!(
                    "update-group minimizer: rejected different failure target={:?} candidate={:?} ops={indices:?}",
                    target.0, fingerprint.0
                );
            }
            if let Evaluation::UnclassifiedFailure { detail } = &evaluation {
                eprintln!(
                    "update-group minimizer: rejected unclassified candidate ops={indices:?}: {detail}"
                );
            }
            evaluation
        },
    );
    let best = original
        .retaining(&reduction.retained_indices)
        .expect("minimizer result contains original operation indices");
    eprintln!("UPDATE_GROUP_MINIMIZED_REPLAY={}", best.replay_command());
    eprintln!(
        "UPDATE_GROUP_MINIMIZER_RESULT retained_ops={} evaluations={}/{} complete_single_deletion_pass={}",
        reduction.retained_indices.len(),
        reduction.evaluations,
        config.minimize_evaluations,
        reduction.complete_single_deletion_pass
    );
    panic!(
        "fault-corpus minimization retained the target failure {:?}; original child output follows:\n{}",
        target.0, original_detail
    );
}

fn norm_announce(prefix: Ipv4Prefix, local_pref: u32) -> NormAnnounce {
    let route = ibgp_route(prefix, SOURCE, local_pref, vec![]);
    (
        route.prefix,
        route.path_id,
        route.next_hop,
        route.peer,
        (*route.attributes).clone(),
        None,
    )
}

fn norm_message(announce: Vec<NormAnnounce>, withdraw: Vec<(Prefix, u32)>) -> NormMsg {
    NormMsg {
        session_start: None,
        announce,
        withdraw,
        end_of_rib: vec![],
        vpn_announce: vec![],
        vpn_withdraw: vec![],
    }
}

fn session_start_message(generation: u64) -> NormMsg {
    NormMsg {
        session_start: Some(generation),
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        vpn_announce: vec![],
        vpn_withdraw: vec![],
    }
}

fn one_peer_stream(messages: Vec<NormMsg>) -> Streams {
    [(IpAddr::V4(LEFT), messages)].into_iter().collect()
}

#[test]
fn semantic_effects_reject_transient_announces_and_attribute_changes() {
    let first = pfx(41, 0);
    let extra = pfx(43, 0);
    let baseline = one_peer_stream(vec![norm_message(vec![norm_announce(first, 100)], vec![])]);

    let extra_transient = one_peer_stream(vec![
        norm_message(vec![norm_announce(first, 100)], vec![]),
        norm_message(vec![norm_announce(extra, 100)], vec![]),
        norm_message(vec![], vec![(Prefix::V4(extra), 0)]),
    ]);
    assert_ne!(
        semantic_effects(&baseline),
        semantic_effects(&extra_transient)
    );

    let wrong_attributes = one_peer_stream(vec![
        norm_message(vec![norm_announce(first, 100)], vec![]),
        norm_message(vec![norm_announce(first, 200)], vec![]),
        norm_message(vec![norm_announce(first, 100)], vec![]),
    ]);
    assert_ne!(
        semantic_effects(&baseline),
        semantic_effects(&wrong_attributes)
    );
}

#[test]
fn semantic_effects_allow_only_terminally_absent_unknown_withdraws() {
    let prefix = pfx(45, 0);
    let empty = one_peer_stream(vec![]);
    let safe_over_withdraw =
        one_peer_stream(vec![norm_message(vec![], vec![(Prefix::V4(prefix), 0)])]);
    assert_eq!(
        semantic_effects(&empty),
        semantic_effects(&safe_over_withdraw)
    );

    let terminal_route =
        one_peer_stream(vec![norm_message(vec![norm_announce(prefix, 100)], vec![])]);
    let withdraw_before_terminal_route = one_peer_stream(vec![
        norm_message(vec![], vec![(Prefix::V4(prefix), 0)]),
        norm_message(vec![norm_announce(prefix, 100)], vec![]),
    ]);
    assert_ne!(
        semantic_effects(&terminal_route),
        semantic_effects(&withdraw_before_terminal_route)
    );
}

#[test]
fn completion_gate_rejects_equal_but_incomplete_streams() {
    let empty: Streams = [(IpAddr::V4(LEFT), vec![]), (IpAddr::V4(RIGHT), vec![])]
        .into_iter()
        .collect();
    assert!(
        validate_terminal_stream(&empty).is_err(),
        "equal empty streams must not pass the differential oracle"
    );

    let truncated_message = norm_message(vec![norm_announce(pfx(42, 0), 100)], vec![]);
    let truncated: Streams = [
        (IpAddr::V4(LEFT), vec![truncated_message.clone()]),
        (IpAddr::V4(RIGHT), vec![truncated_message]),
    ]
    .into_iter()
    .collect();
    assert!(
        validate_terminal_stream(&truncated).is_err(),
        "equal nonempty streams truncated before convergence must not pass"
    );

    let sentinel_message = norm_message(vec![norm_announce(sentinel(), 250)], vec![]);
    let mut complete: Streams = [
        (IpAddr::V4(LEFT), vec![sentinel_message.clone()]),
        (IpAddr::V4(RIGHT), vec![sentinel_message]),
    ]
    .into_iter()
    .collect();
    assert!(validate_terminal_stream(&complete).is_ok());

    complete
        .get_mut(&IpAddr::V4(RIGHT))
        .unwrap()
        .push(session_start_message(9));
    assert!(
        validate_terminal_stream(&complete).is_err(),
        "a sentinel from a superseded connection cannot complete the current session"
    );
}

#[test]
fn extended_seed_sweep_varies_every_schedule_operation_fixture() {
    let baseline = schedules(DEFAULT_SEED_START);
    let mut varied = vec![false; baseline.len()];
    for offset in 1..DEFAULT_SEED_COUNT {
        let seed = DEFAULT_SEED_START
            + u64::try_from(offset).expect("extended seed count is capped at 64");
        let candidate = schedules(seed);
        for (index, (baseline, candidate)) in baseline.iter().zip(candidate.iter()).enumerate() {
            varied[index] |= baseline.ops != candidate.ops;
        }
    }

    // Reverting the mixer to raw little-endian seed bytes leaves four of
    // these actual operation fixtures unchanged across the default sweep.
    for (schedule, varied) in baseline.iter().zip(varied) {
        assert!(
            varied,
            "extended seeds did not vary operations for {}",
            schedule.name
        );
    }
}

#[tokio::test]
async fn deterministic_fault_corpus() {
    tokio::time::pause();
    for seed in PR_SEEDS {
        for schedule in schedules(seed) {
            run_schedule_reporting_failure(ReplaySchedule::full(schedule), DEFAULT_MAX_OPS, None)
                .await;
        }
    }
}

#[test]
fn extended_config_defaults_and_boundaries() {
    let longest = schedules(DEFAULT_SEED_START)
        .iter()
        .map(|schedule| schedule.ops.len())
        .max()
        .unwrap();
    assert_eq!(
        MIN_MAX_OPS, longest,
        "minimum cap must track longest schedule"
    );
    assert_eq!(
        parse_extended_config(|_| None).unwrap(),
        ExtendedConfig {
            seed_start: DEFAULT_SEED_START,
            seed_count: DEFAULT_SEED_COUNT,
            max_ops: DEFAULT_MAX_OPS,
            scenario: None,
            op_indices: None,
            minimize: false,
            minimize_evaluations: DEFAULT_MINIMIZE_EVALUATIONS,
            force_failure_op: None,
            minimizer_child: false,
        }
    );

    let get = |name: &str| match name {
        SEED_START_ENV => Some("0xffffffffffffffff".to_owned()),
        SEED_COUNT_ENV => Some("1".to_owned()),
        MAX_OPS_ENV => Some(MIN_MAX_OPS.to_string()),
        _ => None,
    };
    assert_eq!(
        parse_extended_config(get).unwrap(),
        ExtendedConfig {
            seed_start: u64::MAX,
            seed_count: 1,
            max_ops: MIN_MAX_OPS,
            scenario: None,
            op_indices: None,
            minimize: false,
            minimize_evaluations: DEFAULT_MINIMIZE_EVALUATIONS,
            force_failure_op: None,
            minimizer_child: false,
        }
    );

    for (name, value, expected) in [
        (
            SEED_START_ENV,
            "wat",
            "invalid RUSTBGPD_UPDATE_GROUP_SEED_START",
        ),
        (SEED_COUNT_ENV, "0", "must be in 1..=64"),
        (SEED_COUNT_ENV, "65", "must be in 1..=64"),
        (MAX_OPS_ENV, "17", "must be in 18..=64"),
        (MAX_OPS_ENV, "65", "must be in 18..=64"),
        (MINIMIZE_EVALUATIONS_ENV, "0", "must be in 1..=256"),
        (MINIMIZE_EVALUATIONS_ENV, "257", "must be in 1..=256"),
    ] {
        let error = parse_extended_config(|key| (key == name).then(|| value.to_owned()))
            .expect_err("invalid boundary must fail");
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    let overflow = parse_extended_config(|name| match name {
        SEED_START_ENV => Some(u64::MAX.to_string()),
        SEED_COUNT_ENV => Some("2".to_owned()),
        _ => None,
    })
    .expect_err("seed range overflow must fail");
    assert!(overflow.contains("overflows u64"));

    let empty_scenario = parse_extended_config(|name| match name {
        SCENARIO_ENV => Some(String::new()),
        SEED_COUNT_ENV => Some("1".to_owned()),
        _ => None,
    })
    .expect_err("an explicit empty scenario must not widen into the full sweep");
    assert!(empty_scenario.contains("must not be empty"));

    let invalid_child =
        parse_extended_config(|name| (name == MINIMIZER_CHILD_ENV).then(|| "1".to_owned()))
            .expect_err("a minimizer child must identify one exact candidate");
    assert!(invalid_child.contains("requires an exact scenario/operation replay"));
}

#[test]
fn exact_replay_keeps_seed_scenario_and_original_operation_indices() {
    let seed = 0x3570_0007;
    let replay = replay_for(seed, "saturation-drain-virtual-retry", Some(&[0, 5, 10]))
        .expect("known scenario and original indices must replay");

    assert_eq!(replay.schedule.seed, seed);
    assert_eq!(replay.schedule.name, "saturation-drain-virtual-retry");
    assert_eq!(replay.retained_indices, vec![0, 5, 10]);
    assert_eq!(
        replay.ops().map(|(index, _)| index).collect::<Vec<_>>(),
        vec![0, 5, 10]
    );
    let command = replay.replay_command();
    assert!(command.contains("RUSTBGPD_UPDATE_GROUP_SEED_START=0x35700007"));
    assert!(command.contains("RUSTBGPD_UPDATE_GROUP_SCENARIO=saturation-drain-virtual-retry"));
    assert!(command.contains("RUSTBGPD_UPDATE_GROUP_OP_INDICES=0,5,10"));
}

#[test]
fn empty_operation_replay_is_explicit_but_not_a_valid_minimizer_candidate() {
    assert_eq!(
        parse_op_indices(EMPTY_OPS_SENTINEL).unwrap(),
        Vec::<usize>::new()
    );
    let replay = replay_for(
        DEFAULT_SEED_START,
        "saturation-drain-virtual-retry",
        Some(&[]),
    )
    .unwrap();
    assert!(replay.retained_indices.is_empty());
    assert!(replay.replay().ends_with("ops=[]"));
    assert!(
        replay
            .replay_command()
            .contains("RUSTBGPD_UPDATE_GROUP_OP_INDICES=none")
    );
    assert!(!replay.satisfies_minimizer_dependencies());
}

#[test]
fn failure_classification_marker_is_stable_across_replay_details() {
    let first = failure_fingerprint(
        "exact stream mismatch: scenario=one seed=0x1 mode=ExactStream ops=[0:Quiesce]",
    );
    let second = failure_fingerprint(
        "exact stream mismatch: scenario=two seed=0x2 mode=ExactStream ops=[9:Quiesce]",
    );
    assert_eq!(first, second);
    assert_eq!(
        failure_marker(&format!("noise\n{FAILURE_FINGERPRINT_MARKER}{}\n", first.0)),
        Some(first)
    );

    let paths_one = failure_fingerprint(
        "assertion `left == right` failed: unexpected newly announced Add-Path identities for 10.0.0.0/24: {(1, 10.0.0.1), (2, 10.0.0.2)}",
    );
    let paths_two = failure_fingerprint(
        "assertion `left == right` failed: unexpected newly announced Add-Path identities for 10.0.0.0/24: {(2, 10.0.0.2), (1, 10.0.0.1)}",
    );
    assert_eq!(paths_one, paths_two);

    let join_one = failure_fingerprint(
        "called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(7), \"manager invariant failed\", ...)",
    );
    let join_two = failure_fingerprint(
        "called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(99), \"manager invariant failed\", ...)",
    );
    assert_eq!(join_one, join_two);
    let different_join_cause = failure_fingerprint(
        "called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(99), \"different invariant failed\", ...)",
    );
    assert_ne!(join_one, different_join_cause);
    let inner_id_one = failure_fingerprint(
        "called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(7), \"peer Id(41) failed\", ...)",
    );
    let inner_id_two = failure_fingerprint(
        "called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(99), \"peer Id(42) failed\", ...)",
    );
    assert_ne!(inner_id_one, inner_id_two);
}

#[test]
fn markerless_exit_101_is_unclassified_and_cannot_reduce() {
    let target = FailureFingerprint("target assertion".to_owned());
    let marked_output = format!("panic output\n{FAILURE_FINGERPRINT_MARKER}{}\n", target.0);
    let marked = classify_nonzero_child("exited with status 101", marked_output.clone());
    assert!(preserves_failure(&marked, &target));

    let markerless_output = marked_output.replace(FAILURE_FINGERPRINT_MARKER, "removed-marker=");
    let markerless = classify_nonzero_child("exited with status 101", markerless_output);
    assert!(matches!(
        &markerless,
        Evaluation::UnclassifiedFailure { .. }
    ));
    assert!(!preserves_failure(&markerless, &target));

    let unrelated = classify_nonzero_child(
        "exited with status 101",
        "different test-harness failure with the same exit code".to_owned(),
    );
    assert!(matches!(&unrelated, Evaluation::UnclassifiedFailure { .. }));
    let legacy_exit_code_fingerprint = FailureFingerprint("candidate-exit-101".to_owned());
    let reduction = minimize_failure(vec![0, 1], &legacy_exit_code_fingerprint, 4, |candidate| {
        if candidate == [1] {
            markerless.clone()
        } else {
            unrelated.clone()
        }
    });
    assert_eq!(reduction.retained_indices, vec![0, 1]);
}

#[test]
fn markerless_baseline_aborts_minimization() {
    let unclassified = classify_nonzero_child(
        "exited with status 101",
        "unrelated test-harness panic without a fingerprint marker".to_owned(),
    );
    let error = minimization_target(unclassified)
        .expect_err("an unclassified baseline must not supply a minimization target");
    assert!(error.contains("original child failure was unclassified"));
}

#[test]
fn isolated_candidate_runs_the_exact_ignored_test_and_classifies_its_failure() {
    let replay = replay_for(DEFAULT_SEED_START, "saturation-drain-virtual-retry", None).unwrap();
    let evaluation = evaluate_isolated_candidate(&replay, DEFAULT_MAX_OPS, Some(5)).unwrap();
    match evaluation {
        Evaluation::Failed {
            fingerprint,
            detail,
        } => {
            assert_eq!(
                fingerprint,
                FailureFingerprint("forced fault-corpus failure at original op 5".to_owned())
            );
            assert!(detail.contains("running 1 test"));
            assert!(detail.contains(FAILURE_FINGERPRINT_MARKER));
        }
        Evaluation::Passed => panic!("forced isolated candidate unexpectedly passed"),
        Evaluation::UnclassifiedFailure { detail } => {
            panic!("forced isolated candidate was not classified: {detail}")
        }
    }
}

#[test]
fn isolated_wait_timeout_kills_and_reaps_child() {
    let executable = env::current_exe().expect("locate current test executable");
    let child = Command::new(executable)
        .arg(TIMEOUT_FIXTURE_TEST_NAME)
        .args(["--ignored", "--exact"])
        .env(TIMEOUT_FIXTURE_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn timeout fixture");
    let mut child = ReapingChild::new(child);
    let started = Instant::now();
    let status = wait_for_child(&mut child, Duration::from_millis(50)).unwrap();
    assert!(status.is_none(), "timeout fixture unexpectedly exited");
    assert!(child.reaped, "timed-out child was not reaped");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "50ms child deadline was not wall-clock bounded"
    );
}

#[test]
#[ignore = "child-process fixture for the minimizer wall-clock timeout proof"]
fn minimizer_timeout_fixture() {
    if env::var(TIMEOUT_FIXTURE_ENV).as_deref() == Ok("1") {
        thread::sleep(Duration::from_mins(1));
    }
}

#[test]
fn minimizer_dependencies_reject_assertion_without_its_policy_transition() {
    let full = replay_for(DEFAULT_SEED_START, "dirty-policy-regroup-transitions", None).unwrap();
    assert!(full.satisfies_minimizer_dependencies());
    let assertion = full
        .schedule
        .ops
        .windows(2)
        .position(|pair| {
            matches!(
                pair,
                [
                    Op::ReplacePolicy {
                        policy: PolicySpec::PeerContext,
                        ..
                    },
                    Op::AssertMembership {
                        expectation: MembershipExpectation::PeerContextFallback,
                        ..
                    }
                ]
            )
        })
        .expect("dirty-policy schedule contains its peer-context proof")
        + 1;
    let retained = full
        .retained_indices
        .iter()
        .copied()
        .filter(|index| *index != assertion - 1)
        .collect::<Vec<_>>();
    let missing_transition = full.retaining(&retained).unwrap();
    assert!(!missing_transition.satisfies_minimizer_dependencies());
}

#[test]
fn replay_rejects_out_of_range_operation_controls() {
    let error = replay_for(
        DEFAULT_SEED_START,
        "saturation-drain-virtual-retry",
        Some(&[usize::MAX]),
    )
    .unwrap_err();
    assert!(error.contains("out of range"));

    let replay = replay_for(DEFAULT_SEED_START, "saturation-drain-virtual-retry", None).unwrap();
    let error = validate_force_failure_op(&replay, Some(usize::MAX)).unwrap_err();
    assert!(error.contains("out of range"));
}

#[test]
fn minimizer_obeys_evaluation_cap() {
    let reduction = minimize_failure(
        vec![0, 1, 2, 3],
        &FailureFingerprint("target".to_owned()),
        1,
        |_| Evaluation::Passed,
    );
    assert_eq!(reduction.retained_indices, vec![0, 1, 2, 3]);
    assert_eq!(reduction.evaluations, 1);
    assert!(!reduction.complete_single_deletion_pass);
}

#[test]
fn minimizer_rejects_a_different_failure_classification() {
    let target = FailureFingerprint("target".to_owned());
    let reduction = minimize_failure(vec![0, 1], &target, 8, |candidate| {
        if candidate == [1] {
            Evaluation::Failed {
                fingerprint: FailureFingerprint("different".to_owned()),
                detail: "different assertion".to_owned(),
            }
        } else {
            Evaluation::Passed
        }
    });
    assert_eq!(reduction.retained_indices, vec![0, 1]);
    assert!(reduction.complete_single_deletion_pass);
}

#[test]
fn minimizer_shrinks_and_completes_a_single_deletion_pass() {
    let target = FailureFingerprint("target".to_owned());
    let reduction = minimize_failure(vec![0, 1, 2, 3, 4, 5], &target, 32, |candidate| {
        if candidate.contains(&3) {
            Evaluation::Failed {
                fingerprint: target.clone(),
                detail: "same assertion".to_owned(),
            }
        } else {
            Evaluation::Passed
        }
    });
    assert_eq!(reduction.retained_indices, vec![3]);
    assert!(reduction.evaluations <= 32);
    assert!(reduction.complete_single_deletion_pass);
}

#[tokio::test]
#[ignore = "bounded extended corpus; run explicitly or via weekly workflow"]
async fn deterministic_fault_corpus_extended() {
    let config = parse_extended_config(|name| env::var(name).ok())
        .unwrap_or_else(|error| panic!("invalid extended fault-corpus controls: {error}"));
    if config.minimize {
        minimize_configured_failure(&config);
    }

    tokio::time::pause();
    if let Some(scenario) = config.scenario.as_deref() {
        let replay = replay_for(config.seed_start, scenario, config.op_indices.as_deref())
            .unwrap_or_else(|error| panic!("invalid extended fault-corpus replay: {error}"));
        validate_force_failure_op(&replay, config.force_failure_op)
            .unwrap_or_else(|error| panic!("invalid extended fault-corpus replay: {error}"));
        run_schedule_reporting_failure(replay, config.max_ops, config.force_failure_op).await;
        return;
    }

    for index in 0..config.seed_count {
        let seed = config.seed_start + u64::try_from(index).expect("seed count is capped at 64");
        for schedule in schedules(seed) {
            run_schedule_reporting_failure(
                ReplaySchedule::full(schedule),
                config.max_ops,
                config.force_failure_op,
            )
            .await;
        }
    }
}
