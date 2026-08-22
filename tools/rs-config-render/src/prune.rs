//! Opt-in retention for activation generations.
//!
//! Generations are content-addressed and immutable; the activation path never
//! removes one. `prune` is a separate operator-run command: it plans under the
//! activation state lock, defaults to a dry run, and refuses outright while a
//! host fence exists, so it can never remove the forensic state an exit 5
//! leaves behind.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::ixp_manager_host::{self, Binding};
use crate::{Exit, activation, ixp_manager_lifecycle};

const GENERATIONS: &str = "generations";
const RECEIPT: &str = "render-receipt.json";
const ACTIVATION_RECEIPT: &str = "activation-receipt.json";

#[derive(Debug)]
pub struct Options<'a> {
    pub state_dir: &'a Path,
    /// Most recent generations retained regardless of references.
    pub keep: usize,
    /// Remove the planned generations; otherwise report only.
    pub apply: bool,
    pub binding: &'a Binding,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused(&'static str),
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Refused(_) => Exit::Refused,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

/// One retained generation and every rule that retains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub digest: String,
    pub reasons: Vec<&'static str>,
}

/// The plan; newest generation first within each list.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub kept: Vec<Kept>,
    /// Removed by `--apply`; otherwise what `--apply` would remove.
    pub removed: Vec<String>,
    /// `--apply` removals that failed, with the I/O error text. Non-empty
    /// means the state directory needs attention and the run exits nonzero.
    pub failed: Vec<(String, String)>,
}

impl std::fmt::Display for Plan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for kept in &self.kept {
            writeln!(formatter, "keep {} {}", kept.digest, kept.reasons.join(","))?;
        }
        for digest in &self.removed {
            writeln!(formatter, "remove {digest}")?;
        }
        Ok(())
    }
}

fn generation_digest(target: &str) -> Option<&str> {
    target
        .strip_prefix("generations/")
        .filter(|digest| activation::valid_digest(digest))
}

fn receipt_sha256(generation: &Path) -> Option<String> {
    let bytes = fs::read(generation.join(RECEIPT)).ok()?;
    Some(
        Sha256::digest(bytes)
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                use std::fmt::Write as _;
                write!(output, "{byte:02x}").expect("String writes cannot fail");
                output
            }),
    )
}

/// Plan and, with `apply`, remove generations that no retention rule keeps.
///
/// Retained: the `current` target, the last activation receipt's candidate and
/// previous generation, the generation a pending lifecycle journal names, and
/// the `keep` most recently published generations.
pub fn prune(options: &Options<'_>) -> Result<Plan, Error> {
    if options.state_dir != options.binding.activation_state_dir {
        return Err(Error::Refused("state directory must match host binding"));
    }
    if !options.state_dir.is_absolute() || !activation::private(options.state_dir, true, 0o700) {
        return Err(Error::Refused(
            "state directory must be a pre-created absolute mode-0700 directory",
        ));
    }
    if ixp_manager_host::fence_present(&options.binding.host_state_dir) {
        return Err(Error::Refused(
            "host fence present; resolve it before pruning (retained state is forensic)",
        ));
    }
    let _lock = activation::state_lock(options.state_dir).map_err(|error| match error {
        activation::Error::Refused(reason) => Error::Refused(reason),
        activation::Error::RolledBack | activation::Error::RecoveryRequired => {
            Error::Refused("state lock failed")
        }
    })?;
    let generations_dir = options.state_dir.join(GENERATIONS);
    let mut generations: BTreeMap<String, SystemTime> = BTreeMap::new();
    match fs::read_dir(&generations_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|_| Error::Refused("generations are unreadable"))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let metadata = entry
                    .metadata()
                    .map_err(|_| Error::Refused("generations are unreadable"))?;
                // Staging leftovers (`.<digest>.<pid>.<nanos>`) are not generations.
                if activation::valid_digest(&name) && metadata.file_type().is_dir() {
                    // ponytail: publication order = directory mtime (set when the
                    // generation was staged, immediately before its rename into
                    // place); the receipt carries no timestamp to prefer.
                    generations.insert(name, metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Refused("generations are unreadable")),
    }
    let mut reasons: BTreeMap<&str, Vec<&'static str>> = BTreeMap::new();
    let mut retain = |digest: &str, reason: &'static str| {
        if let Some((key, _)) = generations.get_key_value(digest) {
            reasons.entry(key.as_str()).or_default().push(reason);
        }
    };
    match fs::read_link(options.state_dir.join("current")) {
        Ok(target) => {
            let digest = target
                .to_str()
                .and_then(generation_digest)
                .ok_or(Error::Refused(
                    "current must be a relative generation symlink",
                ))?;
            if !generations.contains_key(digest) {
                return Err(Error::Refused(
                    "current target is not a published generation",
                ));
            }
            retain(digest, "current");
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Refused("current generation is unreadable")),
    }
    match fs::read(options.state_dir.join(ACTIVATION_RECEIPT)) {
        Ok(bytes) => {
            let receipt: Value = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Refused("activation receipt is unreadable"))?;
            let candidate = receipt["candidate_sha256"]
                .as_str()
                .filter(|digest| activation::valid_digest(digest))
                .ok_or(Error::Refused("activation receipt is unreadable"))?;
            retain(candidate, "receipt");
            if let Some(previous) = receipt["previous_generation"].as_str() {
                let previous = generation_digest(previous)
                    .ok_or(Error::Refused("activation receipt is unreadable"))?;
                retain(previous, "predecessor");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Refused("activation receipt is unreadable")),
    }
    if let Some(journal_candidate) = ixp_manager_lifecycle::journal_candidate(options.state_dir)
        .map_err(|()| {
            Error::Refused("lifecycle journal is unreadable; resolve it before pruning")
        })?
    {
        let referenced: Vec<String> = generations
            .keys()
            .filter(|digest| {
                receipt_sha256(&generations_dir.join(digest)).as_deref()
                    == Some(journal_candidate.as_str())
            })
            .cloned()
            .collect();
        for digest in &referenced {
            retain(digest, "journal");
        }
    }
    let mut by_recency: Vec<(&String, &SystemTime)> = generations.iter().collect();
    by_recency.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
    for (digest, _) in by_recency.iter().take(options.keep) {
        retain(digest, "keep-N");
    }
    let mut plan = Plan::default();
    for (digest, _) in &by_recency {
        match reasons.get(digest.as_str()) {
            Some(found) => plan.kept.push(Kept {
                digest: (*digest).clone(),
                reasons: found.clone(),
            }),
            None => plan.removed.push((*digest).clone()),
        }
    }
    if options.apply {
        for digest in &plan.removed {
            if let Err(error) = fs::remove_dir_all(generations_dir.join(digest)) {
                plan.failed.push((digest.clone(), error.to_string()));
            }
        }
        if !plan.removed.is_empty()
            && fs::File::open(&generations_dir)
                .and_then(|directory| directory.sync_all())
                .is_err()
        {
            plan.failed
                .push((GENERATIONS.to_owned(), "directory sync failed".to_owned()));
        }
        plan.removed
            .retain(|digest| !plan.failed.iter().any(|(failed, _)| failed == digest));
    }
    Ok(plan)
}
