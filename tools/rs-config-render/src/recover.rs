//! Operator inspection of the durable activation and lifecycle state.
//!
//! An exit 5 is characterised by three durable artifacts: the host fence, the
//! lifecycle journal, and the generation tree with its `current` link. The
//! activation receipt is advisory (it can be absent or stale after an exit 5).
//! `status` reads all of them, probes the daemon when asked, and changes
//! nothing; it is step 1 of the manual-recovery runbook.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::Exit;
use crate::ixp_manager_host::{self, Binding};
use crate::ixp_manager_lifecycle::{self as lifecycle, Journal, Phase};
use crate::{activation, activation::Health};

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
    /// The options do not describe one handle's state.
    Refused(&'static str),
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Unreadable(_) => Exit::InvalidInput,
            Self::Refused(_) => Exit::Refused,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(reason) | Self::Refused(reason) => formatter.write_str(reason),
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
    let (daemon, equal) = match options.rbgp {
        None => ("not-probed", "unknown"),
        Some(rbgp) => {
            let addr = binding.rbgp_addr();
            let health = activation::health_probe(rbgp, addr, Instant::now() + PROBE);
            let daemon = match health {
                Health::Reachable(true) => "healthy",
                Health::Reachable(false) => "unhealthy",
                Health::Unreachable => "unreachable",
                Health::Invalid => "invalid",
            };
            let equal = match (health, &current) {
                (Health::Reachable(_), Some(target)) => match comparison(state, target, binding) {
                    Ok(file) => {
                        if activation::equal_runtime(
                            rbgp,
                            addr,
                            file.as_ref(),
                            Instant::now() + PROBE,
                        ) {
                            "yes"
                        } else {
                            "no"
                        }
                    }
                    Err(_) => "unknown",
                },
                _ => "unknown",
            };
            (daemon, equal)
        }
    };
    report.push("daemon", daemon);
    report.push("runtime_equals_current", equal);
    Ok(report)
}
