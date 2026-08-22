//! Authenticated IXP Manager v7.4 lock, render, activation, and callback lifecycle.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::Exit;
use crate::ixp_manager_host::Binding;

#[derive(Debug)]
pub struct Options<'a> {
    pub ixp_origin: &'a str,
    pub router_handle: &'a str,
    pub api_key_file: &'a Path,
    pub candidate_dir: &'a Path,
    pub state_dir: &'a Path,
    pub checker: &'a Path,
    pub max_prefix_restart_seconds: u32,
    pub rbgp: &'a Path,
    pub rbgp_addr: &'a str,
    pub activation_command: &'a Path,
    pub activation_args: &'a [OsString],
    pub settle: Duration,
    pub timeout: Duration,
    pub initial: bool,
    pub allow_http_loopback: bool,
    pub binding: &'a Binding,
}

#[derive(Debug)]
pub struct ResumeOptions<'a> {
    pub ixp_origin: &'a str,
    pub router_handle: &'a str,
    pub api_key_file: &'a Path,
    pub state_dir: &'a Path,
    pub timeout: Duration,
    pub allow_http_loopback: bool,
    pub binding: &'a Binding,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Activated,
    Noop,
    Updated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused(&'static str),
    RolledBack,
    ManualRecovery,
    CallbackPending,
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Refused(_) => Exit::Refused,
            Self::RolledBack => Exit::RolledBack,
            Self::ManualRecovery => Exit::ManualRecovery,
            Self::CallbackPending => Exit::CallbackPending,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => formatter.write_str(reason),
            Self::RolledBack => formatter.write_str("activation did not start; lock released"),
            Self::ManualRecovery => {
                formatter.write_str("manual recovery required; upstream lock retained")
            }
            Self::CallbackPending => formatter.write_str("callback pending; run resume"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(not(unix))]
pub fn run(_: &Options<'_>) -> Result<Status, Error> {
    Err(Error::Refused(
        "IXP Manager lifecycle is supported only on Unix",
    ))
}

#[cfg(not(unix))]
pub fn resume(_: &ResumeOptions<'_>) -> Result<Status, Error> {
    Err(Error::Refused(
        "IXP Manager lifecycle is supported only on Unix",
    ))
}

#[cfg(unix)]
mod unix {
    use super::{Error, Options, ResumeOptions, Status};
    use crate::ixp_manager_host::{self, Binding, Guard};
    use crate::{activation, ixp_manager};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::net::IpAddr;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use ureq::Agent;
    use ureq::http::{HeaderMap, Uri};
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    use zeroize::Zeroizing;

    const KEY_HEADER: &str = "X-IXP-Manager-API-Key";
    const JOURNAL: &str = "ixp-manager-lifecycle.json";
    const JOURNAL_SCHEMA: &str = "rustbgpd.ixp-manager.lifecycle/v1";
    const LOCK: &str = "ixp-manager-lifecycle.lock";
    const MAX_KEY: u64 = 4 * 1024;
    const MAX_CONTROL: u64 = 64 * 1024;
    const MAX_CONFIG: u64 = 4 * 1024 * 1024;
    const MAX_JOURNAL: u64 = 64 * 1024;
    static TEMPORARY_NONCE: AtomicU64 = AtomicU64::new(0);

    type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum Phase {
        LockRequestPending,
        Locked,
        ActivationStarted,
        UpdatedPending,
        ReleasePending,
        ManualRecovery,
    }

    #[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum Callback {
        Updated,
        Release,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        schema: String,
        ixp_manager_version: String,
        origin: String,
        router_handle: String,
        host: Binding,
        phase: Phase,
        callback: Option<Callback>,
        callback_attempts: u32,
        candidate_sha256: Option<String>,
        activation_outcome: Option<String>,
        error_class: Option<String>,
    }

    struct Client {
        agent: Agent,
        origin: String,
        handle: String,
        key: Zeroizing<String>,
    }

    enum LockResult {
        Acquired,
        NotAcquired,
        Ambiguous(&'static str),
    }

    enum RequestError {
        Definite,
        Ambiguous(&'static str),
    }

    struct StateLock {
        _file: File,
    }

    fn private(path: &Path, directory: bool, mode: u32) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            let kind = metadata.file_type();
            let expected = if directory {
                kind.is_dir()
            } else {
                kind.is_file() && metadata.nlink() == 1
            };
            expected && metadata.permissions().mode() & 0o777 == mode
        })
    }

    fn same_private_file(path: &Path, file: &File, mode: u32) -> bool {
        let Ok(named) = fs::symlink_metadata(path) else {
            return false;
        };
        let Ok(opened) = file.metadata() else {
            return false;
        };
        named.file_type().is_file()
            && opened.file_type().is_file()
            && named.nlink() == 1
            && opened.nlink() == 1
            && named.permissions().mode() & 0o777 == mode
            && opened.permissions().mode() & 0o777 == mode
            && named.dev() == opened.dev()
            && named.ino() == opened.ino()
    }

    fn sync_dir(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::ManualRecovery)
    }

    fn state_lock(state: &Path) -> Result<StateLock> {
        if !state.is_absolute() || !private(state, true, 0o700) {
            return Err(Error::Refused(
                "state directory must be a pre-created absolute mode-0700 directory",
            ));
        }
        let path = state.join(LOCK);
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                file.sync_all().map_err(|_| Error::ManualRecovery)?;
                sync_dir(state)?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| Error::Refused("lifecycle lock is unavailable"))?;
                if !same_private_file(&path, &file, 0o600) {
                    return Err(Error::Refused("lifecycle lock is not private"));
                }
                file
            }
            Err(_) => return Err(Error::Refused("lifecycle lock is unavailable")),
        };
        file.try_lock()
            .map_err(|_| Error::Refused("another lifecycle command is active"))?;
        Ok(StateLock { _file: file })
    }

    fn validate_handle(handle: &str) -> Result<()> {
        if handle.is_empty()
            || handle.len() > 128
            || !handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(Error::Refused("router handle is invalid"));
        }
        Ok(())
    }

    fn normalized_origin(origin: &str, allow_http_loopback: bool) -> Result<String> {
        let uri: Uri = origin
            .parse()
            .map_err(|_| Error::Refused("IXP origin is invalid"))?;
        let scheme = uri
            .scheme_str()
            .ok_or(Error::Refused("IXP origin is invalid"))?;
        let authority = uri
            .authority()
            .ok_or(Error::Refused("IXP origin is invalid"))?;
        if authority.as_str().contains('@')
            || uri.query().is_some()
            || !matches!(uri.path(), "" | "/")
            || authority
                .host()
                .trim_end_matches('.')
                .eq_ignore_ascii_case("localhost")
        {
            return Err(Error::Refused("IXP origin must be a root origin"));
        }
        match scheme {
            "https" => {}
            "http"
                if allow_http_loopback
                    && authority
                        .host()
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback()) => {}
            "http" => {
                return Err(Error::Refused(
                    "HTTP requires an explicit numeric-loopback allowance",
                ));
            }
            _ => return Err(Error::Refused("IXP origin must use HTTPS")),
        }
        Ok(format!("{scheme}://{authority}"))
    }

    fn api_key(path: &Path) -> Result<Zeroizing<String>> {
        if !path.is_absolute() || !private(path, false, 0o600) {
            return Err(Error::Refused(
                "API key must be an absolute private mode-0600 regular file",
            ));
        }
        let file = File::open(path).map_err(|_| Error::Refused("API key is unreadable"))?;
        if !same_private_file(path, &file, 0o600) {
            return Err(Error::Refused(
                "API key must be an absolute private mode-0600 regular file",
            ));
        }
        let metadata = file
            .metadata()
            .map_err(|_| Error::Refused("API key is unreadable"))?;
        if metadata.len() == 0 || metadata.len() > MAX_KEY {
            return Err(Error::Refused("API key size is invalid"));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.take(MAX_KEY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Refused("API key is unreadable"))?;
        if bytes.len() as u64 > MAX_KEY {
            return Err(Error::Refused("API key size is invalid"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Refused("API key is invalid UTF-8"))?
            .trim_end_matches(['\r', '\n']);
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::Refused("API key is invalid"));
        }
        Ok(Zeroizing::new(text.to_owned()))
    }

    fn agent(timeout: Duration) -> Result<Agent> {
        if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&timeout) {
            return Err(Error::Refused("request timeout must be 1..=300 seconds"));
        }
        Ok(Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(32 * 1024)
            .timeout_global(Some(timeout))
            .tls_config(
                TlsConfig::builder()
                    .provider(TlsProvider::Rustls)
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .new_agent())
    }

    impl Client {
        fn new(
            origin: &str,
            handle: &str,
            key_file: &Path,
            timeout: Duration,
            allow_http_loopback: bool,
        ) -> Result<Self> {
            validate_handle(handle)?;
            Ok(Self {
                agent: agent(timeout)?,
                origin: normalized_origin(origin, allow_http_loopback)?,
                handle: handle.to_owned(),
                key: api_key(key_file)?,
            })
        }

        fn url(&self, action: &str) -> String {
            format!(
                "{}/admin/api/v4/router/{action}/{}",
                self.origin, self.handle
            )
        }

        fn control(&self, action: &str) -> std::result::Result<(), RequestError> {
            let mut response = self
                .agent
                .post(&self.url(action))
                .header(KEY_HEADER, self.key.as_str())
                .send_empty()
                .map_err(|_| RequestError::Ambiguous("transport"))?;
            let status = response.status();
            if !status.is_success() {
                return match status.as_u16() {
                    401 | 403 | 404 | 405 | 422 | 423 => Err(RequestError::Definite),
                    _ => Err(RequestError::Ambiguous("status")),
                };
            }
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_CONTROL + 1)
                .read_to_vec()
                .map_err(|_| RequestError::Ambiguous("control_body"))?;
            if body.len() as u64 > MAX_CONTROL || !valid_control_response(response.headers(), &body)
            {
                return Err(RequestError::Ambiguous("control_body"));
            }
            Ok(())
        }

        fn acquire(&self) -> LockResult {
            match self.control("get-update-lock") {
                Ok(()) => LockResult::Acquired,
                Err(RequestError::Definite) => LockResult::NotAcquired,
                Err(RequestError::Ambiguous(class)) => LockResult::Ambiguous(class),
            }
        }

        fn configuration(&self) -> std::result::Result<Zeroizing<Vec<u8>>, RequestError> {
            let mut response = self
                .agent
                .get(&self.url("gen-config"))
                .header(KEY_HEADER, self.key.as_str())
                .call()
                .map_err(|_| RequestError::Ambiguous("transport"))?;
            if !response.status().is_success() {
                return Err(RequestError::Definite);
            }
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/plain"))
            {
                return Err(RequestError::Definite);
            }
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_CONFIG + 1)
                .read_to_vec()
                .map_err(|_| RequestError::Ambiguous("config_body"))?;
            if body.len() as u64 > MAX_CONFIG {
                return Err(RequestError::Definite);
            }
            Ok(Zeroizing::new(body))
        }

        fn callback(&self, callback: Callback) -> std::result::Result<(), RequestError> {
            self.control(match callback {
                Callback::Updated => "updated",
                Callback::Release => "release-update-lock",
            })
        }
    }

    fn valid_control_response(headers: &HeaderMap, body: &[u8]) -> bool {
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        let Ok(Value::Object(object)) = serde_json::from_slice(body) else {
            return false;
        };
        let valid_pair = |text: &str, unix: &str| match (object.get(text), object.get(unix)) {
            (Some(Value::Null), Some(Value::Null)) => true,
            (Some(Value::String(text)), Some(Value::Number(unix))) => {
                !text.is_empty() && unix.as_i64().is_some()
            }
            _ => false,
        };
        content_type
            && object.len() == 4
            && valid_pair("last_update_started", "last_update_started_unix")
            && valid_pair("last_updated", "last_updated_unix")
    }

    fn journal_path(state: &Path) -> PathBuf {
        state.join(JOURNAL)
    }

    fn write_journal(state: &Path, journal: &Journal) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce = TEMPORARY_NONCE.fetch_add(1, Ordering::Relaxed);
        let temporary = state.join(format!(
            ".{JOURNAL}.{}.{}.{}.tmp",
            std::process::id(),
            timestamp,
            nonce
        ));
        let bytes = serde_json::to_vec_pretty(journal).expect("journal serializes");
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, journal_path(state))?;
            File::open(state)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::ManualRecovery);
        }
        Ok(())
    }

    fn read_journal(state: &Path) -> Result<Journal> {
        let path = journal_path(state);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Refused("no pending lifecycle callback exists"));
            }
            Err(_) => return Err(Error::ManualRecovery),
        }
        if !private(&path, false, 0o600) {
            return Err(Error::ManualRecovery);
        }
        let metadata = fs::metadata(&path).map_err(|_| Error::ManualRecovery)?;
        if metadata.len() == 0 || metadata.len() > MAX_JOURNAL {
            return Err(Error::ManualRecovery);
        }
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|file| file.take(MAX_JOURNAL + 1).read_to_end(&mut bytes))
            .map_err(|_| Error::ManualRecovery)?;
        let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| Error::ManualRecovery)?;
        if journal.schema != JOURNAL_SCHEMA || journal.ixp_manager_version != "7.4.0" {
            return Err(Error::ManualRecovery);
        }
        Ok(journal)
    }

    /// The `candidate_sha256` of a pending journal: `Ok(None)` when no journal
    /// exists or it predates the candidate, `Err(())` when one exists but cannot
    /// be parsed (callers treat that as forensic state and fail closed).
    pub(crate) fn journal_candidate(state: &Path) -> std::result::Result<Option<String>, ()> {
        let bytes = match fs::read(journal_path(state)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        serde_json::from_slice::<Journal>(&bytes)
            .map(|journal| journal.candidate_sha256)
            .map_err(|_| ())
    }

    fn remove_journal(state: &Path) -> Result<()> {
        fs::remove_file(journal_path(state)).map_err(|_| Error::ManualRecovery)?;
        sync_dir(state)
    }

    fn new_journal(origin: &str, handle: &str, binding: &Binding) -> Journal {
        Journal {
            schema: JOURNAL_SCHEMA.to_owned(),
            ixp_manager_version: "7.4.0".to_owned(),
            origin: origin.to_owned(),
            router_handle: handle.to_owned(),
            host: binding.clone(),
            phase: Phase::LockRequestPending,
            callback: None,
            callback_attempts: 0,
            candidate_sha256: None,
            activation_outcome: None,
            error_class: None,
        }
    }

    fn candidate_digest(path: &Path) -> Option<String> {
        let bytes = fs::read(path.join("render-receipt.json")).ok()?;
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

    fn callback_pending(
        state: &Path,
        client: &Client,
        journal: &mut Journal,
        callback: Callback,
        guard: &Guard,
    ) -> Result<()> {
        journal.phase = match callback {
            Callback::Updated => Phase::UpdatedPending,
            Callback::Release => Phase::ReleasePending,
        };
        journal.callback = Some(callback);
        write_journal(state, journal)?;
        journal.callback_attempts = journal.callback_attempts.saturating_add(1);
        write_journal(state, journal)?;
        match client.callback(callback) {
            Ok(()) => {
                remove_journal(state)?;
                guard.clear().map_err(host_error)
            }
            Err(_) => Err(Error::CallbackPending),
        }
    }

    fn host_error(error: ixp_manager_host::Error) -> Error {
        match error {
            ixp_manager_host::Error::Refused(reason) => Error::Refused(reason),
            ixp_manager_host::Error::RecoveryRequired => Error::ManualRecovery,
        }
    }

    pub fn run(options: &Options<'_>) -> Result<Status> {
        if options.router_handle != options.binding.router_handle
            || options.state_dir != options.binding.activation_state_dir
            || options.rbgp_addr != options.binding.rbgp_addr
        {
            return Err(Error::Refused(
                "lifecycle options do not match host binding",
            ));
        }
        let client = Client::new(
            options.ixp_origin,
            options.router_handle,
            options.api_key_file,
            options.timeout,
            options.allow_http_loopback,
        )?;
        let _lock = state_lock(options.state_dir)?;
        let guard = Guard::claim_new(options.binding).map_err(host_error)?;
        let path = journal_path(options.state_dir);
        match fs::symlink_metadata(&path) {
            Ok(_) if private(&path, false, 0o600) => {
                // Refusal must not leave the fence this run just wrote.
                guard.clear().map_err(host_error)?;
                return Err(Error::Refused("pending lifecycle state requires resume"));
            }
            Ok(_) => return Err(Error::ManualRecovery),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::ManualRecovery),
        }
        let mut journal = new_journal(&client.origin, &client.handle, options.binding);
        let finish = |journal: &mut Journal, callback| {
            callback_pending(options.state_dir, &client, journal, callback, &guard)
        };
        write_journal(options.state_dir, &journal)?;
        match client.acquire() {
            LockResult::Acquired => {
                journal.phase = Phase::Locked;
                write_journal(options.state_dir, &journal)?;
            }
            LockResult::NotAcquired => {
                remove_journal(options.state_dir)?;
                guard.clear().map_err(host_error)?;
                return Err(Error::Refused("IXP Manager update lock was not acquired"));
            }
            LockResult::Ambiguous(class) => {
                journal.phase = Phase::ManualRecovery;
                journal.error_class = Some(class.to_owned());
                write_journal(options.state_dir, &journal)?;
                return Err(Error::ManualRecovery);
            }
        }
        let input = match client.configuration() {
            Ok(input) => input,
            Err(_) => {
                journal.activation_outcome = Some("refused".to_owned());
                journal.error_class = Some("configuration_fetch".to_owned());
                finish(&mut journal, Callback::Release)?;
                return Err(Error::Refused("IXP Manager configuration fetch failed"));
            }
        };
        let render_binding = options.binding.render_binding();
        if ixp_manager::write_checked_candidate_bytes(
            &input,
            options.candidate_dir,
            options.max_prefix_restart_seconds,
            options.checker,
            &render_binding,
        )
        .is_err()
        {
            journal.activation_outcome = Some("refused".to_owned());
            journal.error_class = Some("candidate_render".to_owned());
            finish(&mut journal, Callback::Release)?;
            return Err(Error::Refused("IXP Manager candidate was refused"));
        }
        journal.candidate_sha256 = candidate_digest(options.candidate_dir);
        journal.phase = Phase::ActivationStarted;
        write_journal(options.state_dir, &journal)?;
        let activation_args = activation::Options {
            candidate: options.candidate_dir,
            state_dir: options.state_dir,
            checker: options.checker,
            rbgp: options.rbgp,
            rbgp_addr: options.rbgp_addr,
            settle: options.settle,
            initial: options.initial,
            activation_command: options.activation_command,
            activation_args: options.activation_args,
            binding: options.binding,
        };
        match activation::activate_guarded(&activation_args, &guard) {
            Ok(status) => {
                journal.activation_outcome = Some(
                    match status {
                        activation::Status::Activated => "activated",
                        activation::Status::Noop => "noop",
                    }
                    .to_owned(),
                );
                finish(&mut journal, Callback::Updated)?;
                Ok(match status {
                    activation::Status::Activated => Status::Activated,
                    activation::Status::Noop => Status::Noop,
                })
            }
            Err(activation::Error::Refused(_)) => {
                journal.activation_outcome = Some("refused".to_owned());
                finish(&mut journal, Callback::Release)?;
                Err(Error::Refused("candidate activation was refused"))
            }
            Err(activation::Error::RolledBack) => {
                journal.activation_outcome = Some("rolled_back".to_owned());
                finish(&mut journal, Callback::Release)?;
                Err(Error::RolledBack)
            }
            Err(activation::Error::RecoveryRequired) => {
                journal.phase = Phase::ManualRecovery;
                journal.activation_outcome = Some("recovery_required".to_owned());
                journal.error_class = Some("activation".to_owned());
                write_journal(options.state_dir, &journal)?;
                Err(Error::ManualRecovery)
            }
        }
    }

    pub fn resume(options: &ResumeOptions<'_>) -> Result<Status> {
        if options.router_handle != options.binding.router_handle
            || options.state_dir != options.binding.activation_state_dir
        {
            return Err(Error::Refused(
                "lifecycle options do not match host binding",
            ));
        }
        let guard = Guard::claim_existing(options.binding).map_err(host_error)?;
        let _lock = state_lock(options.state_dir)?;
        let client = Client::new(
            options.ixp_origin,
            options.router_handle,
            options.api_key_file,
            options.timeout,
            options.allow_http_loopback,
        )?;
        let mut journal = read_journal(options.state_dir)?;
        if journal.origin != client.origin
            || journal.router_handle != client.handle
            || journal.host != *options.binding
        {
            return Err(Error::Refused("lifecycle journal identity does not match"));
        }
        let finish = |journal: &mut Journal, callback| {
            callback_pending(options.state_dir, &client, journal, callback, &guard)
        };
        match journal.phase {
            Phase::UpdatedPending
                if journal.callback == Some(Callback::Updated)
                    && matches!(
                        journal.activation_outcome.as_deref(),
                        Some("activated" | "noop")
                    ) =>
            {
                finish(&mut journal, Callback::Updated)?;
                Ok(Status::Updated)
            }
            Phase::ReleasePending
                if journal.callback == Some(Callback::Release)
                    && matches!(
                        journal.activation_outcome.as_deref(),
                        Some("refused" | "rolled_back")
                    ) =>
            {
                let rolled_back = journal.activation_outcome.as_deref() == Some("rolled_back");
                finish(&mut journal, Callback::Release)?;
                if rolled_back {
                    Err(Error::RolledBack)
                } else {
                    Err(Error::Refused("lock released without activation"))
                }
            }
            Phase::Locked if journal.callback.is_none() && journal.activation_outcome.is_none() => {
                finish(&mut journal, Callback::Release)?;
                Err(Error::Refused("lock released before activation"))
            }
            Phase::LockRequestPending | Phase::ActivationStarted | Phase::ManualRecovery => {
                Err(Error::ManualRecovery)
            }
            Phase::UpdatedPending | Phase::ReleasePending | Phase::Locked => {
                Err(Error::ManualRecovery)
            }
        }
    }
}

#[cfg(unix)]
pub(crate) use unix::journal_candidate;
#[cfg(unix)]
pub use unix::{resume, run};
