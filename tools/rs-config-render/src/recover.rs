//! Operator inspection and recovery of the durable activation and lifecycle
//! state.
//!
//! An exit 5 is characterised by three durable artifacts: the host fence, the
//! lifecycle journal, and the generation tree with its `current` link. The
//! activation receipt is advisory (it can be absent or stale after an exit 5).
//! `status` reads all of them, probes the daemon when asked, and changes
//! nothing; it is step 1 of the manual-recovery runbook. The `recover` verbs
//! are steps 2–5: each refuses outside manual-recovery state, plans first,
//! changes nothing without `--apply`, and leaves its record in the activation
//! receipt and the journal it clears.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::Exit;
use crate::ixp_manager_host::{self, Binding, Guard};
use crate::ixp_manager_lifecycle::{self as lifecycle, Callback, Journal, Phase};
use crate::{activation, activation::Health, activation::RuntimeDiff};

const ACTIVATION_RECEIPT: &str = "activation-receipt.json";
/// rbgp gets this long per probe before `status` reports it as invalid.
const PROBE: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct StatusOptions<'a> {
    pub state_dir: &'a Path,
    pub binding: &'a Binding,
    /// Exact rbgp executable; `None` skips the daemon probe.
    pub rbgp: Option<&'a Path>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The state directory cannot be read at all; nothing can be reported.
    Unreadable(&'static str),
    /// The options do not describe one handle's state, or the state is not
    /// one this verb may act on; nothing was changed.
    Refused(&'static str),
    /// A `recover --apply` step did not complete: the state is still manual
    /// recovery (fence and journal retained) and the message names the retry.
    ManualRecovery(&'static str),
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Unreadable(_) => Exit::InvalidInput,
            Self::Refused(_) => Exit::Refused,
            Self::ManualRecovery(_) => Exit::ManualRecovery,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(reason) | Self::Refused(reason) | Self::ManualRecovery(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for Error {}

/// The status report: one `key: value` line per field, in a fixed order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub fields: Vec<(&'static str, String)>,
}

impl Report {
    fn push(&mut self, key: &'static str, value: impl Into<String>) {
        self.fields.push((key, value.into()));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
    }
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (key, value) in &self.fields {
            writeln!(formatter, "{key}: {value}")?;
        }
        Ok(())
    }
}

enum Receipt {
    Absent,
    Unreadable,
    Present {
        status: String,
        candidate: String,
        previous: Option<String>,
    },
}

fn read_receipt(state: &Path) -> Receipt {
    let bytes = match fs::read(state.join(ACTIVATION_RECEIPT)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Receipt::Absent,
        Err(_) => return Receipt::Unreadable,
    };
    let receipt: Value = match serde_json::from_slice(&bytes) {
        Ok(receipt) => receipt,
        Err(_) => return Receipt::Unreadable,
    };
    match (
        receipt["status"].as_str(),
        receipt["candidate_sha256"]
            .as_str()
            .filter(|digest| activation::valid_digest(digest)),
    ) {
        (Some(status), Some(candidate)) => Receipt::Present {
            status: status.to_owned(),
            candidate: candidate.to_owned(),
            previous: receipt["previous_generation"].as_str().map(str::to_owned),
        },
        _ => Receipt::Unreadable,
    }
}

/// The generation whose render receipt a lifecycle journal names.
fn journal_generation(state: &Path, receipt_sha256: &str) -> Option<String> {
    let generations = state.join("generations");
    fs::read_dir(&generations).ok()?.find_map(|entry| {
        let name = entry.ok()?.file_name().into_string().ok()?;
        (activation::valid_digest(&name)
            && lifecycle::candidate_digest(&generations.join(&name)).as_deref()
                == Some(receipt_sha256))
        .then(|| format!("generations/{name}"))
    })
}

/// What the journal proves about the upstream router lock.
fn upstream_lock(journal: &Journal) -> &'static str {
    if journal.lock_released {
        return "released";
    }
    match journal.phase {
        Phase::LockRequestPending => "unknown",
        Phase::Locked
        | Phase::ActivationStarted
        | Phase::UpdatedPending
        | Phase::ReleasePending => "retained",
        // An activation outcome means the lock request succeeded; without one
        // the lock request itself was the ambiguous step.
        Phase::ManualRecovery if journal.activation_outcome.is_some() => "retained",
        Phase::ManualRecovery => "unknown",
    }
}

/// The generation's config, normalised the way the settle path compares it,
/// staged as a private comparison file (removed on drop).
fn comparison(
    state: &Path,
    target: &str,
    binding: &Binding,
) -> Result<activation::Comparison, activation::Error> {
    let verified = activation::verify_candidate(&state.join(target), binding)?;
    let bytes = activation::normalized_toml(&verified.config, state)?;
    activation::comparison_file(&bytes, state, "status")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeProbe {
    daemon: &'static str,
    comparison: RuntimeDiff,
}

impl RuntimeProbe {
    const fn report(self) -> &'static str {
        match self.comparison {
            RuntimeDiff::Equal => "yes",
            RuntimeDiff::Different => "no",
            RuntimeDiff::Unknown => "unknown",
        }
    }

    fn detail(self) -> String {
        match self.comparison {
            RuntimeDiff::Equal => format!("daemon {}, runtime equals current", self.daemon),
            RuntimeDiff::Different => {
                format!("daemon {}, runtime differs from current", self.daemon)
            }
            RuntimeDiff::Unknown => {
                format!("daemon {}, runtime comparison unknown", self.daemon)
            }
        }
    }
}

fn runtime_probe(
    rbgp: &Path,
    binding: &Binding,
    state: &Path,
    current: Option<&str>,
) -> RuntimeProbe {
    let health = activation::health_probe(rbgp, binding.rbgp_addr(), Instant::now() + PROBE);
    let daemon = match health {
        Health::Reachable(true) => "healthy",
        Health::Reachable(false) => "unhealthy",
        Health::Unreachable => "unreachable",
        Health::Invalid => "invalid",
    };
    let comparison = match (health, current) {
        (Health::Reachable(true), Some(current)) => match comparison(state, current, binding) {
            Ok(file) => activation::runtime_diff(
                rbgp,
                binding.rbgp_addr(),
                file.as_ref(),
                Instant::now() + PROBE,
            ),
            Err(_) => RuntimeDiff::Unknown,
        },
        _ => RuntimeDiff::Unknown,
    };
    RuntimeProbe { daemon, comparison }
}

/// Report the activation and lifecycle state of one handle without changing
/// it. Manual-recovery state is a successful report; only an unreadable
/// state directory is an error.
pub fn status(options: &StatusOptions<'_>) -> Result<Report, Error> {
    let binding = options.binding;
    let state = options.state_dir;
    if state != binding.activation_state_dir {
        return Err(Error::Refused("state directory must match host binding"));
    }
    if !state.is_absolute() || !fs::metadata(state).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(Error::Unreadable(
            "state directory is not a readable directory",
        ));
    }
    let mut report = Report::default();
    report.push(
        "fence",
        match ixp_manager_host::read_fence(&binding.host_state_dir) {
            Ok(None) => "absent",
            Ok(Some(owner)) if owner == *binding => "present",
            Ok(Some(_)) => "foreign",
            Err(_) => "unreadable",
        },
    );
    let journal = lifecycle::inspect_journal(state);
    report.push(
        "journal",
        match &journal {
            Ok(None) => "absent",
            Ok(Some(_)) => "present",
            Err(()) => "unreadable",
        },
    );
    let journal = journal.ok().flatten();
    let journal = journal.as_ref();
    report.push(
        "phase",
        journal.map_or("none", |journal| journal.phase.name()),
    );
    report.push(
        "callback",
        journal
            .and_then(|journal| journal.callback)
            .map_or("none", |callback| callback.name()),
    );
    report.push(
        "callback_attempts",
        journal
            .map_or(0, |journal| journal.callback_attempts)
            .to_string(),
    );
    report.push(
        "activation_outcome",
        journal
            .and_then(|journal| journal.activation_outcome.as_deref())
            .unwrap_or("none"),
    );
    report.push(
        "error_class",
        journal
            .and_then(|journal| journal.error_class.as_deref())
            .unwrap_or("none"),
    );
    report.push("lock", journal.map_or("none", upstream_lock));
    let current = activation::current_target(state, binding);
    report.push(
        "current",
        match &current {
            Ok(None) => "none".to_owned(),
            Ok(Some(target)) => target.clone(),
            Err(activation::Error::Refused(reason)) => format!("invalid ({reason})"),
            Err(_) => "invalid".to_owned(),
        },
    );
    let current = current.ok().flatten();
    let receipt = read_receipt(state);
    let receipt_matches = matches!(
        (&receipt, &current),
        (Receipt::Present { candidate, .. }, Some(target)) if *target == format!("generations/{candidate}")
    );
    // The candidate: proven by the journal when there is one; otherwise only
    // a receipt that describes the current attempt can name it.
    let candidate = match journal {
        Some(journal) => match &journal.candidate_sha256 {
            None => Some("none".to_owned()),
            Some(sha256) => journal_generation(state, sha256),
        },
        None if receipt_matches => current.clone(),
        None => None,
    };
    report.push("candidate", candidate.as_deref().unwrap_or("unknown"));
    report.push(
        "current_is_candidate",
        match (&candidate, &current) {
            (Some(candidate), _) if candidate == "none" => "no",
            (Some(candidate), Some(target)) => {
                if candidate == target {
                    "yes"
                } else {
                    "no"
                }
            }
            _ => "unknown",
        },
    );
    report.push(
        "advisory_receipt",
        match &receipt {
            Receipt::Absent => "absent",
            Receipt::Unreadable => "unreadable",
            Receipt::Present { .. } if receipt_matches => "matches-current",
            Receipt::Present { .. } => "stale",
        },
    );
    let (status, previous) = match &receipt {
        Receipt::Present {
            status, previous, ..
        } => (status.as_str(), previous.as_deref()),
        _ => ("none", None),
    };
    report.push("advisory_receipt_status", status);
    report.push(
        "advisory_receipt_previous_generation",
        previous.unwrap_or("none"),
    );
    let (daemon, equal) = options.rbgp.map_or(("not-probed", "unknown"), |rbgp| {
        let probe = runtime_probe(rbgp, binding, state, current.as_deref());
        (probe.daemon, probe.report())
    });
    report.push("daemon", daemon);
    report.push("runtime_equals_current", equal);
    Ok(report)
}

/// The IXP Manager connection a journal-holding recovery needs for its
/// callback; the same shape `ixp-manager-lifecycle resume` takes.
#[derive(Debug)]
pub struct Connection<'a> {
    pub ixp_origin: &'a str,
    pub api_key_file: &'a Path,
    pub timeout: Duration,
    pub allow_http_loopback: bool,
}

#[derive(Debug)]
pub struct Options<'a> {
    pub state_dir: &'a Path,
    pub binding: &'a Binding,
    /// Perform the plan; otherwise only print it.
    pub apply: bool,
    /// Required whenever a lifecycle journal owes the upstream lock.
    pub connection: Option<Connection<'a>>,
}

/// Which callback a `release-lock` delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The candidate stays live: `updated`.
    Kept,
    /// The candidate was rolled away from (or never activated):
    /// `release-update-lock`.
    RolledBack,
}

#[derive(Debug)]
pub enum Verb<'a> {
    /// Keep the candidate that is live: health-gated, `updated` callback,
    /// fence and journal cleared.
    KeepCurrent { rbgp: &'a Path, force: bool },
    /// Re-stage the previous generation through the activation path,
    /// `release-update-lock` callback, fence and journal cleared.
    Rollback {
        activation: RollbackActivation<'a>,
        /// The generation to re-stage; defaults to the activation receipt's
        /// `previous_generation` when that receipt describes the current attempt.
        to: Option<&'a str>,
    },
    /// One callback, standalone and retryable; the journal records delivery.
    ReleaseLock(Released),
    /// Fence and journal only; refuses while the upstream lock is still owed.
    Clear,
}

#[derive(Debug, Clone, Copy)]
pub struct RollbackActivation<'a> {
    pub rbgp: &'a Path,
    pub settle: Duration,
    pub activation_command: &'a Path,
    pub activation_args: &'a [OsString],
}

impl Verb<'_> {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::KeepCurrent { .. } => "keep-current",
            Self::Rollback { .. } => "rollback",
            Self::ReleaseLock(_) => "release-lock",
            Self::Clear => "clear",
        }
    }
}

/// What a verb did (`--apply`) or would do: one line per step, in order. On
/// an `--apply` failure the lines are exactly the steps that completed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub steps: Vec<String>,
}

/// A recovery failure plus the exact prefix of steps that completed.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub error: Error,
    pub completed: Outcome,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            error,
            completed: Outcome::default(),
        }
    }
}

enum Step {
    Probe(String),
    Receipt {
        status: &'static str,
        candidate: String,
        previous: Option<String>,
        runtime_equal: bool,
    },
    Republish {
        from: String,
        to: String,
    },
    Callback(Callback),
    MarkReleased,
    RemoveJournal,
    ClearFence,
}

impl Step {
    fn describe(&self, session: &Session<'_>) -> String {
        match self {
            Self::Probe(result) => format!("probe: {result}"),
            Self::Receipt {
                status,
                candidate,
                previous,
                ..
            } => format!(
                "write activation receipt: status {status}, candidate {candidate}, previous {}",
                previous.as_deref().unwrap_or("none")
            ),
            Self::Republish { from, to } => {
                let activation = session.activation.expect("rollback carries its activation");
                let mut command = activation.activation_command.display().to_string();
                for arg in activation.activation_args {
                    command.push(' ');
                    command.push_str(&arg.to_string_lossy());
                }
                format!(
                    "re-point current {from} -> {to}, run `{command}`, settle within {}s",
                    activation.settle.as_secs()
                )
            }
            Self::Callback(callback) => {
                let client = session.client.as_ref().expect("callbacks carry a client");
                let journal = session.journal.as_ref().expect("callbacks carry a journal");
                format!(
                    "deliver {} callback to {} for {} (attempt {})",
                    match callback {
                        Callback::Updated => "updated",
                        Callback::Release => "release-update-lock",
                    },
                    client.origin,
                    client.handle,
                    journal.callback_attempts + 1
                )
            }
            Self::MarkReleased => "mark the upstream lock released in the lifecycle journal".into(),
            Self::RemoveJournal => "remove lifecycle journal".into(),
            Self::ClearFence => "remove host fence".into(),
        }
    }
}

struct Session<'a> {
    options: &'a Options<'a>,
    guard: Guard,
    journal: Option<Journal>,
    client: Option<lifecycle::Client>,
    activation: Option<RollbackActivation<'a>>,
    checker_version: String,
}

fn host_refusal(error: ixp_manager_host::Error) -> Error {
    match error {
        ixp_manager_host::Error::Refused("no pending host fence exists") => {
            Error::Refused("no host fence for this binding; nothing to recover")
        }
        ixp_manager_host::Error::Refused(reason) => Error::Refused(reason),
        ixp_manager_host::Error::RecoveryRequired => {
            Error::Refused("host fence is unreadable; inspect it before recovering")
        }
    }
}

fn activation_refusal(error: activation::Error) -> Error {
    match error {
        activation::Error::Refused(reason) => Error::Refused(reason),
        activation::Error::RolledBack | activation::Error::RecoveryRequired => {
            Error::Refused("activation state is unusable")
        }
    }
}

fn lifecycle_refusal(error: lifecycle::Error) -> Error {
    match error {
        lifecycle::Error::Refused(reason) => Error::Refused(reason),
        _ => Error::Refused("lifecycle state is unusable"),
    }
}

/// Plan and, with `apply`, perform one recovery verb. Every verb refuses
/// (exit 2, nothing changed) unless this binding's fence stands and the
/// lifecycle journal, if any, is in manual recovery rather than resumable.
pub fn recover(options: &Options<'_>, verb: &Verb<'_>) -> Result<Outcome, Failure> {
    let binding = options.binding;
    let state = options.state_dir;
    if state != binding.activation_state_dir {
        return Err(Error::Refused("state directory must match host binding").into());
    }
    let guard = Guard::claim_existing(binding).map_err(host_refusal)?;
    let _activation_lock = activation::state_lock(state).map_err(activation_refusal)?;
    let _lifecycle_lock = lifecycle::state_lock(state).map_err(lifecycle_refusal)?;
    let journal = lifecycle::inspect_journal(state).map_err(|()| {
        Error::Refused("lifecycle journal is unreadable; inspect it before recovering")
    })?;
    if let Some(journal) = &journal {
        if journal.host != *binding {
            return Err(Error::Refused("lifecycle journal identity does not match").into());
        }
        if lifecycle::pending(journal).is_some() {
            return Err(Error::Refused(
                "lifecycle state is resumable, not manual recovery; run ixp-manager-lifecycle resume",
            )
            .into());
        }
    }
    // A callback needs the connection; validate it (origin, key file) before
    // planning so a dry run refuses exactly where --apply would.
    let client = match (&journal, &options.connection) {
        (Some(journal), Some(connection)) => {
            let client = lifecycle::Client::new(
                connection.ixp_origin,
                &binding.router_handle,
                connection.api_key_file,
                connection.timeout,
                connection.allow_http_loopback,
            )
            .map_err(lifecycle_refusal)?;
            if journal.origin != client.origin || journal.router_handle != client.handle {
                return Err(Error::Refused("lifecycle journal identity does not match").into());
            }
            Some(client)
        }
        (Some(_), None) if !matches!(verb, Verb::Clear) => {
            return Err(Error::Refused(
                "lifecycle journal owes the upstream lock; pass --ixp-origin and --api-key-file",
            )
            .into());
        }
        _ => None,
    };
    let current = activation::current_target(state, binding).map_err(activation_refusal)?;
    let receipt = read_receipt(state);
    let receipt_previous = match (&receipt, &current) {
        (
            Receipt::Present {
                candidate,
                previous,
                ..
            },
            Some(target),
        ) if *target == format!("generations/{candidate}") => previous.clone(),
        _ => None,
    };
    let mut session = Session {
        options,
        guard,
        journal,
        client,
        activation: None,
        checker_version: String::new(),
    };
    let journal = session.journal.as_ref();
    let lock_released = journal.is_some_and(|journal| journal.lock_released);
    // Lifecycle journals without an activation outcome never staged a
    // candidate: the lock request itself was the ambiguous step.
    let activated = journal.is_none_or(|journal| journal.activation_outcome.is_some());
    let mut plan = Vec::new();
    match verb {
        Verb::KeepCurrent { rbgp, force } => {
            if lock_released {
                return Err(
                    Error::Refused("upstream lock already released; run recover clear").into(),
                );
            }
            let Some(current) = current.as_deref() else {
                return Err(Error::Refused("no current generation to keep").into());
            };
            let probe = runtime_probe(rbgp, binding, state, Some(current));
            let equal = probe.comparison == RuntimeDiff::Equal;
            if !equal && !*force {
                return Err(Error::Refused(
                    "daemon is not settled on current; fix the daemon by hand or pass --force",
                )
                .into());
            }
            plan.push(Step::Probe(if equal {
                probe.detail()
            } else {
                format!("{} (overridden by --force)", probe.detail())
            }));
            session.checker_version = activation::verify_candidate(&state.join(current), binding)
                .map_err(activation_refusal)?
                .checker_version;
            plan.push(Step::Receipt {
                status: "kept",
                candidate: current
                    .strip_prefix("generations/")
                    .expect("current_target validated the prefix")
                    .to_owned(),
                previous: receipt_previous,
                runtime_equal: equal,
            });
            if journal.is_some() {
                plan.push(Step::Callback(if activated {
                    Callback::Updated
                } else {
                    Callback::Release
                }));
                plan.push(Step::RemoveJournal);
            }
            plan.push(Step::ClearFence);
        }
        Verb::Rollback { activation, to } => {
            if lock_released {
                return Err(
                    Error::Refused("upstream lock already released; run recover clear").into(),
                );
            }
            if !activated {
                return Err(Error::Refused(
                    "no candidate was activated (the lock request was ambiguous); run recover release-lock --rolled-back, then recover clear",
                )
                .into());
            }
            let Some(current) = current.as_deref() else {
                return Err(Error::Refused("no current generation to roll back from").into());
            };
            let target = match to {
                Some(to) => to.to_string(),
                None => receipt_previous.ok_or(Error::Refused(
                    "previous generation unknown (activation receipt absent or stale); pass --to generations/<digest>",
                ))?,
            };
            if target == current {
                return Err(Error::Refused(
                    "rollback target is the current generation; run recover keep-current",
                )
                .into());
            }
            if !target
                .strip_prefix("generations/")
                .is_some_and(activation::valid_digest)
                || activation::verify_candidate(&state.join(&target), binding).is_err()
            {
                return Err(Error::Refused("rollback target is not a published generation").into());
            }
            session.activation = Some(*activation);
            plan.push(Step::Republish {
                from: current.to_owned(),
                to: target,
            });
            if journal.is_some() {
                plan.push(Step::Callback(Callback::Release));
                plan.push(Step::RemoveJournal);
            }
            plan.push(Step::ClearFence);
        }
        Verb::ReleaseLock(released) => {
            if journal.is_none() {
                return Err(
                    Error::Refused("no lifecycle journal; no upstream lock is owed").into(),
                );
            }
            plan.push(Step::Callback(match released {
                Released::Kept => Callback::Updated,
                Released::RolledBack => Callback::Release,
            }));
            plan.push(Step::MarkReleased);
        }
        Verb::Clear => {
            if journal.is_some() && !lock_released {
                return Err(Error::Refused(
                    "upstream lock still owed; run recover keep-current, recover rollback, or recover release-lock first",
                )
                .into());
            }
            if journal.is_some() {
                plan.push(Step::RemoveJournal);
            }
            plan.push(Step::ClearFence);
        }
    }
    let mut outcome = Outcome::default();
    for step in &plan {
        let line = step.describe(&session);
        if options.apply
            && let Err(error) = session.perform(step)
        {
            return Err(Failure {
                error,
                completed: outcome,
            });
        }
        outcome.steps.push(line);
    }
    Ok(outcome)
}

impl Session<'_> {
    fn perform(&mut self, step: &Step) -> Result<(), Error> {
        let state = self.options.state_dir;
        let binding = self.options.binding;
        match step {
            Step::Probe(_) => Ok(()),
            Step::Receipt {
                candidate,
                previous,
                runtime_equal,
                ..
            } => activation::write_kept_receipt(
                state,
                candidate,
                previous.as_deref(),
                *runtime_equal,
                &self.checker_version,
                binding,
            )
            .map_err(|_| Error::ManualRecovery("activation receipt could not be written")),
            Step::Republish { from, to } => {
                let activation = self.activation.expect("rollback carries its activation");
                let candidate = from
                    .strip_prefix("generations/")
                    .expect("current_target validated the prefix");
                let settled = activation::republish(
                    state,
                    to,
                    candidate,
                    activation::Activation {
                        command: activation.activation_command,
                        args: activation.activation_args,
                        rbgp: activation.rbgp,
                        rbgp_addr: binding.rbgp_addr(),
                        settle: activation.settle,
                    },
                    binding,
                )
                .map_err(|error| match error {
                    activation::Error::Refused(reason) => Error::Refused(reason),
                    _ => Error::ManualRecovery("activation receipt could not be written"),
                })?;
                if settled {
                    Ok(())
                } else {
                    Err(Error::ManualRecovery(
                        "rollback did not settle: current is re-pointed but the daemon did not prove it; inspect with status",
                    ))
                }
            }
            Step::Callback(callback) => {
                let client = self.client.as_ref().expect("callbacks carry a client");
                let journal = self.journal.as_mut().expect("callbacks carry a journal");
                // Intent before the request, like the lifecycle itself.
                journal.callback = Some(*callback);
                journal.callback_attempts = journal.callback_attempts.saturating_add(1);
                lifecycle::write_journal(state, journal)
                    .map_err(|_| Error::ManualRecovery("lifecycle journal could not be written"))?;
                match client.callback(*callback) {
                    Ok(()) => {
                        journal.lock_released = true;
                        lifecycle::write_journal(state, journal).map_err(|_| {
                            Error::ManualRecovery("lifecycle journal could not be written")
                        })
                    }
                    Err(_) => Err(Error::ManualRecovery(match callback {
                        Callback::Updated => {
                            "updated callback was not delivered; upstream lock retained — retry with recover release-lock --kept"
                        }
                        Callback::Release => {
                            "release-update-lock callback was not delivered; upstream lock retained — retry with recover release-lock --rolled-back"
                        }
                    })),
                }
            }
            // Delivery already marked the journal; the step exists so the plan
            // names the durable effect.
            Step::MarkReleased => Ok(()),
            Step::RemoveJournal => lifecycle::remove_journal(state)
                .map_err(|_| Error::ManualRecovery("lifecycle journal could not be removed")),
            Step::ClearFence => self
                .guard
                .clear()
                .map_err(|_| Error::ManualRecovery("host fence could not be removed")),
        }
    }
}
