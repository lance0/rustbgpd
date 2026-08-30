//! Explicit, Linux-only, offline RFC 8212 config migrations.

#![deny(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use toml_edit::{DocumentMut, Item, TableLike, Value};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

use crate::config::{Config, ConfigEpoch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    PinLegacy,
    PrepareSecure,
    DowngradeV064,
}

impl Action {
    const fn name(self) -> &'static str {
        match self {
            Self::PinLegacy => "pin-legacy",
            Self::PrepareSecure => "prepare-secure",
            Self::DowngradeV064 => "downgrade-v0.64",
        }
    }
}

struct Request {
    action: Action,
    config_path: PathBuf,
    validator: Option<PathBuf>,
    dry_run: bool,
}

enum Outcome {
    Changed,
    Unchanged,
    WouldChange,
}

enum MigrationFailure {
    Operational(String),
    Internal(&'static str),
}

impl From<String> for MigrationFailure {
    fn from(message: String) -> Self {
        Self::Operational(message)
    }
}

struct Validator {
    spelled: PathBuf,
    resolved: PathBuf,
    fingerprint: Fingerprint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    digest: [u8; 32],
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let request = match parse(args) {
        Ok(request) => request,
        Err(message) => return fail(2, &message),
    };
    match migrate(&request) {
        Ok(outcome) => crate::stdout_exit(crate::write_stdout(|writer| {
            writeln!(
                writer,
                "migration action={} {}",
                request.action.name(),
                match outcome {
                    Outcome::Changed => "result=changed written=true",
                    Outcome::Unchanged => "result=unchanged written=false",
                    Outcome::WouldChange => "result=would-change written=false",
                }
            )
        })),
        Err(MigrationFailure::Operational(message)) => fail(1, &message),
        Err(MigrationFailure::Internal(message)) => fail(70, message),
    }
}

fn fail(code: u8, message: &str) -> ExitCode {
    eprintln!("error: config migration refused: {message}");
    ExitCode::from(code)
}

fn parse(args: &[String]) -> Result<Request, String> {
    let position = args
        .iter()
        .position(|arg| arg == "--migrate-config")
        .ok_or_else(|| "missing --migrate-config".to_string())?;
    if position != 1 {
        return Err("--migrate-config must be the first argument".to_string());
    }
    let action = match args.get(2).map(String::as_str) {
        Some("pin-legacy") => Action::PinLegacy,
        Some("prepare-secure") => Action::PrepareSecure,
        Some("downgrade-v0.64") => Action::DowngradeV064,
        Some(_) => return Err("unknown migration action".to_string()),
        None => return Err("missing migration action".to_string()),
    };
    let mut offline = false;
    let mut dry_run = false;
    let mut validator = None;
    let mut config_path = None;
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "--offline" if !offline => offline = true,
            "--dry-run" if !dry_run => dry_run = true,
            "--validator" if validator.is_none() => {
                index += 1;
                let path = args
                    .get(index)
                    .filter(|path| !path.starts_with('-'))
                    .ok_or_else(|| "--validator requires a path argument".to_string())?;
                validator = Some(PathBuf::from(path));
            }
            option if option.starts_with('-') => {
                return Err("unknown or duplicate migration option".to_string());
            }
            path if config_path.is_none() => config_path = Some(PathBuf::from(path)),
            _ => return Err("multiple config paths are not allowed".to_string()),
        }
        index += 1;
    }
    if !offline {
        return Err("--offline is required".to_string());
    }
    let config_path = config_path.ok_or_else(|| "CONFIG_PATH is required".to_string())?;
    match (action, &validator) {
        (Action::DowngradeV064, Some(_)) => {}
        (Action::DowngradeV064, None) => {
            return Err("downgrade-v0.64 requires --validator PATH".to_string());
        }
        (_, Some(_)) => {
            return Err("--validator is only valid with downgrade-v0.64".to_string());
        }
        (_, None) => {}
    }
    Ok(Request {
        action,
        config_path,
        validator,
        dry_run,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the atomic proof sequence stays visibly ordered around its sole rename"
)]
fn migrate(request: &Request) -> Result<Outcome, MigrationFailure> {
    let link_before = fingerprint_path(&request.config_path, false)?;
    let resolved = fs::canonicalize(&request.config_path)
        .map_err(|_| "cannot resolve CONFIG_PATH".to_string())?;
    let mut source = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&resolved)
        .map_err(|_| "cannot open CONFIG_PATH for an exclusive migration".to_string())?;
    source
        .lock()
        .map_err(|_| "cannot lock CONFIG_PATH exclusively".to_string())?;
    let source_before = fingerprint_file(&source)?;
    if source_before.mode & libc::S_IFMT != libc::S_IFREG {
        return Err("resolved CONFIG_PATH is not a regular file"
            .to_string()
            .into());
    }
    let mut bytes = Vec::new();
    source
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read CONFIG_PATH".to_string())?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "CONFIG_PATH is not valid UTF-8 TOML".to_string())?;
    let current = load_captured_config(text, &resolved, "migration source")
        .map_err(|diagnostic| format!("migration source validation failed:\n{diagnostic}"))?;
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|_| "CONFIG_PATH is not valid TOML".to_string())?;
    apply(request.action, &current, &mut document)?;
    let candidate = document.to_string();

    let unchanged = candidate.as_bytes() == bytes;
    if unchanged && request.action != Action::DowngradeV064 {
        verify_source(
            &request.config_path,
            &resolved,
            &source,
            &link_before,
            &source_before,
        )?;
        return Ok(Outcome::Unchanged);
    }
    let validator = request
        .validator
        .as_deref()
        .map(resolve_validator)
        .transpose()?;

    let mut stage = crate::confirm_journal::stage_atomic(&resolved, candidate.as_bytes())
        .map_err(|_| "cannot stage migrated config".to_string())?;
    let staged_config = validate_stage(&candidate, &resolved, validator.as_ref(), stage.path())?;
    verify_transform(request.action, &current, &staged_config)?;
    stage
        .preserve_metadata(
            source_before.uid,
            source_before.gid,
            source_before.mode & 0o7777,
        )
        .map_err(|_| "cannot preserve config ownership and mode".to_string())?;
    let staged_before = fingerprint_path(stage.path(), true)?;
    let stage_bytes =
        fs::read(stage.path()).map_err(|_| "cannot reread staged config".to_string())?;
    if stage_bytes != candidate.as_bytes() {
        return Err("staged config changed during validation".to_string().into());
    }
    if request.dry_run {
        verify_fence(
            &request.config_path,
            &resolved,
            &source,
            &link_before,
            &source_before,
            stage.path(),
            &staged_before,
        )?;
        stage.discard();
        return Ok(if unchanged {
            Outcome::Unchanged
        } else {
            Outcome::WouldChange
        });
    }
    if unchanged {
        verify_fence(
            &request.config_path,
            &resolved,
            &source,
            &link_before,
            &source_before,
            stage.path(),
            &staged_before,
        )?;
        stage.discard();
        return Ok(Outcome::Unchanged);
    }
    let stage_path = stage.path().to_path_buf();
    stage
        .commit_if(|| {
            verify_fence_io(
                &request.config_path,
                &resolved,
                &source,
                &link_before,
                &source_before,
                &stage_path,
                &staged_before,
            )
        })
        .map_err(|error| {
            if matches!(
                error,
                crate::confirm_journal::AtomicPublishError::PublicationAmbiguous(_)
            ) {
                "migration publication durability is ambiguous; inspect CONFIG_PATH before retrying"
                    .to_string()
            } else {
                "atomic config publication failed".to_string()
            }
        })?;
    Ok(Outcome::Changed)
}

fn apply(action: Action, current: &Config, document: &mut DocumentMut) -> Result<(), String> {
    match action {
        Action::PinLegacy => {
            let global = global_table(document)?;
            set_value(global, "ebgp_requires_policy", false);
            set_value(document.as_table_mut(), "config_epoch", 1_i64);
        }
        Action::PrepareSecure => {
            let global = global_table(document)?;
            set_value(global, "ebgp_requires_policy", true);
            set_value(document.as_table_mut(), "config_epoch", 2_i64);
        }
        Action::DowngradeV064 => {
            let effective = current.rfc8212_posture().policy_effective;
            let global = global_table(document)?;
            set_value(global, "ebgp_requires_policy", effective);
            document.remove("config_epoch");
        }
    }
    Ok(())
}

fn global_table(document: &mut DocumentMut) -> Result<&mut dyn TableLike, String> {
    document
        .get_mut("global")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| "CONFIG_PATH has no [global] table".to_string())
}

fn set_value(table: &mut dyn TableLike, key: &str, replacement: impl Into<Value>) {
    let mut replacement = replacement.into();
    if let Some(existing) = table.get_mut(key).and_then(Item::as_value_mut) {
        *replacement.decor_mut() = existing.decor().clone();
        *existing = replacement;
    } else {
        table.insert(key, Item::Value(replacement));
    }
}

fn validate_stage(
    candidate: &str,
    target: &Path,
    validator: Option<&Validator>,
    stage: &Path,
) -> Result<Config, String> {
    let config = load_captured_config(candidate, target, "migration candidate")
        .map_err(|_| "staged config failed current validation".to_string())?;
    if let Some(validator) = validator {
        verify_validator(validator)?;
        let version = run_validator(
            &validator.resolved,
            &["--version"],
            None,
            validator_timeout("version", Duration::from_secs(5)),
        )?;
        if !version.0 || version.1 != b"rustbgpd 0.64.0\n" {
            return Err("validator is not exactly rustbgpd 0.64.0".to_string());
        }
        verify_validator(validator)?;
        let checked = run_validator(
            &validator.resolved,
            &["--check"],
            Some(stage),
            validator_timeout("check", Duration::from_mins(5)),
        )?;
        if !checked.0 {
            return Err("v0.64 validator rejected the downgraded config".to_string());
        }
        verify_validator(validator)?;
    }
    Ok(config)
}

fn load_captured_config(content: &str, target: &Path, label: &str) -> Result<Config, String> {
    let original = std::env::current_dir().map_err(|_| "cannot capture working directory")?;
    let parent = target
        .parent()
        .ok_or("CONFIG_PATH has no parent directory")?;
    std::env::set_current_dir(parent).map_err(|_| "cannot enter CONFIG_PATH directory")?;
    let loaded = Config::load_toml_with_diagnostics(content, label);
    std::env::set_current_dir(original).map_err(|_| "cannot restore working directory")?;
    loaded
}

fn verify_transform(
    action: Action,
    current: &Config,
    staged: &Config,
) -> Result<(), MigrationFailure> {
    #[cfg(debug_assertions)]
    if std::env::var_os("RUSTBGPD_TEST_MIGRATION_INVARIANT_FAILURE").is_some() {
        return Err(MigrationFailure::Internal(
            "staged config violates the selected migration posture",
        ));
    }
    let posture = staged.rfc8212_posture();
    let valid = match action {
        Action::PinLegacy => {
            posture.config_epoch_raw == Some(ConfigEpoch::V1) && posture.policy_raw == Some(false)
        }
        Action::PrepareSecure => {
            posture.config_epoch_raw == Some(ConfigEpoch::V2) && posture.policy_raw == Some(true)
        }
        Action::DowngradeV064 => {
            posture.config_epoch_raw.is_none()
                && posture.policy_raw == Some(current.rfc8212_posture().policy_effective)
        }
    };
    if !valid {
        return Err(MigrationFailure::Internal(
            "staged config violates the selected migration posture",
        ));
    }
    Ok(())
}

fn validator_timeout(phase: &str, normal: Duration) -> Duration {
    #[cfg(not(debug_assertions))]
    let _ = phase;
    #[cfg(debug_assertions)]
    if std::env::var("RUSTBGPD_TEST_MIGRATION_TIMEOUT_PHASE").as_deref() == Ok(phase) {
        return Duration::from_millis(100);
    }
    normal
}

fn resolve_validator(path: &Path) -> Result<Validator, String> {
    let resolved =
        fs::canonicalize(path).map_err(|_| "cannot resolve validator PATH".to_string())?;
    let fingerprint = fingerprint_path(&resolved, true)?;
    if fingerprint.mode & libc::S_IFMT != libc::S_IFREG || fingerprint.mode & 0o111 == 0 {
        return Err("validator PATH is not a regular executable".to_string());
    }
    Ok(Validator {
        spelled: path.to_path_buf(),
        resolved,
        fingerprint,
    })
}

fn verify_validator(validator: &Validator) -> Result<(), String> {
    if fs::canonicalize(&validator.spelled).ok().as_ref() != Some(&validator.resolved)
        || fingerprint_path(&validator.resolved, true)? != validator.fingerprint
    {
        return Err("validator changed during migration".to_string());
    }
    Ok(())
}

fn run_validator(
    validator: &Path,
    args: &[&str],
    config: Option<&Path>,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), String> {
    let mut command = Command::new(validator);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(config) = config {
        command.arg(config);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "cannot execute the v0.64 validator".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cannot capture validator output".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "cannot capture validator output".to_string())?;
    let (drained_tx, drained_rx) = mpsc::sync_channel(2);
    let stdout_drained = drained_tx.clone();
    let stdout_thread = thread::spawn(move || {
        let mut retained = Vec::new();
        let mut reader = io::BufReader::new(stdout);
        let mut buffer = [0; 4096];
        loop {
            let count = reader.read(&mut buffer).unwrap_or(0);
            if count == 0 {
                break;
            }
            let keep = (128_usize.saturating_sub(retained.len())).min(count);
            retained.extend_from_slice(&buffer[..keep]);
        }
        let _ = stdout_drained.send(());
        retained
    });
    let stderr_thread = thread::spawn(move || {
        let result = io::copy(&mut io::BufReader::new(stderr), &mut io::sink());
        let _ = drained_tx.send(());
        result
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut status = None;
    let mut drained = 0;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| "v0.64 validator did not complete".to_string())?;
        }
        while drained_rx.try_recv().is_ok() {
            drained += 1;
        }
        if status.is_some() && drained == 2 {
            break;
        }
        if Instant::now() >= deadline {
            let pid = i32::try_from(child.id())
                .map_err(|_| "v0.64 validator did not complete".to_string())?;
            if killpg(Pid::from_raw(pid), Signal::SIGKILL).is_err() {
                let _ = child.kill();
            }
            timed_out = true;
            if status.is_none() {
                status = Some(
                    child
                        .wait()
                        .map_err(|_| "v0.64 validator did not complete".to_string())?,
                );
            }
            while drained < 2 {
                drained_rx
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "validator output drain did not complete".to_string())?;
                drained += 1;
            }
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let stdout = stdout_thread
        .join()
        .map_err(|_| "cannot collect validator output".to_string())?;
    stderr_thread
        .join()
        .map_err(|_| "cannot collect validator output".to_string())?
        .map_err(|_| "cannot collect validator output".to_string())?;
    if timed_out {
        return Err("v0.64 validator exceeded its execution deadline".to_string());
    }
    Ok((
        status
            .ok_or_else(|| "v0.64 validator did not complete".to_string())?
            .success(),
        stdout,
    ))
}

fn fingerprint_path(path: &Path, follow: bool) -> Result<Fingerprint, String> {
    let metadata = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
    .map_err(|_| "cannot fingerprint migration path".to_string())?;
    let digest = if metadata.is_file() {
        digest_path(path, &metadata)?
    } else {
        [0; 32]
    };
    Ok(fingerprint(&metadata, digest))
}

fn fingerprint_file(file: &File) -> Result<Fingerprint, String> {
    let metadata = file
        .metadata()
        .map_err(|_| "cannot fingerprint CONFIG_PATH".to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8 * 1024];
    let mut offset = 0_u64;
    loop {
        let count = file
            .read_at(&mut buffer, offset)
            .map_err(|_| "cannot fingerprint CONFIG_PATH".to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(fingerprint(&metadata, hasher.finalize().into()))
}

fn digest_path(path: &Path, expected: &fs::Metadata) -> Result<[u8; 32], String> {
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot fingerprint migration path".to_string())?;
    let opened = file
        .metadata()
        .map_err(|_| "cannot fingerprint migration path".to_string())?;
    if !opened.file_type().is_file()
        || (opened.dev(), opened.ino()) != (expected.dev(), expected.ino())
    {
        return Err("migration path changed during fingerprinting".to_string());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "cannot fingerprint migration path".to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| "cannot fingerprint migration path".to_string())?;
    if fingerprint(&after, [0; 32]) != fingerprint(expected, [0; 32]) {
        return Err("migration path changed during fingerprinting".to_string());
    }
    Ok(hasher.finalize().into())
}

fn fingerprint(metadata: &fs::Metadata, digest: [u8; 32]) -> Fingerprint {
    Fingerprint {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        digest,
    }
}

fn verify_fence(
    spelled: &Path,
    resolved: &Path,
    source: &File,
    link_before: &Fingerprint,
    source_before: &Fingerprint,
    stage: &Path,
    staged_before: &Fingerprint,
) -> Result<(), String> {
    if &fingerprint_path(spelled, false)? != link_before
        || fs::canonicalize(spelled).ok().as_deref() != Some(resolved)
        || &fingerprint_file(source)? != source_before
        || &fingerprint_path(resolved, true)? != source_before
        || &fingerprint_path(stage, true)? != staged_before
    {
        return Err("source, symlink, or staged config changed during migration".to_string());
    }
    Ok(())
}

fn verify_source(
    spelled: &Path,
    resolved: &Path,
    source: &File,
    link_before: &Fingerprint,
    source_before: &Fingerprint,
) -> Result<(), String> {
    if &fingerprint_path(spelled, false)? != link_before
        || fs::canonicalize(spelled).ok().as_deref() != Some(resolved)
        || &fingerprint_file(source)? != source_before
        || &fingerprint_path(resolved, true)? != source_before
    {
        return Err("source or symlink changed during migration".to_string());
    }
    Ok(())
}

fn verify_fence_io(
    spelled: &Path,
    resolved: &Path,
    source: &File,
    link_before: &Fingerprint,
    source_before: &Fingerprint,
    stage: &Path,
    staged_before: &Fingerprint,
) -> io::Result<()> {
    verify_fence(
        spelled,
        resolved,
        source,
        link_before,
        source_before,
        stage,
        staged_before,
    )
    .map_err(io::Error::other)
}
