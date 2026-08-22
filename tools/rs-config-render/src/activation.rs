use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::Exit;
use crate::ixp_manager_host::Binding;

#[derive(Debug)]
pub struct Options<'a> {
    pub candidate: &'a Path,
    pub state_dir: &'a Path,
    pub checker: &'a Path,
    pub rbgp: &'a Path,
    pub rbgp_addr: &'a str,
    pub settle: Duration,
    pub initial: bool,
    pub activation_command: &'a Path,
    pub activation_args: &'a [OsString],
    pub binding: &'a Binding,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Activated,
    Noop,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused(&'static str),
    RolledBack,
    RecoveryRequired,
}

impl Error {
    pub const fn exit_code(&self) -> Exit {
        match self {
            Self::Refused(_) => Exit::Refused,
            Self::RolledBack => Exit::RolledBack,
            Self::RecoveryRequired => Exit::ManualRecovery,
        }
    }
}

#[cfg(not(unix))]
pub fn activate(_: &Options<'_>) -> Result<Status, Error> {
    Err(Error::Refused("activation is supported only on Unix"))
}

#[cfg(unix)]
mod unix {
    use super::{Error, Options, Status};
    use crate::ixp_manager_host::{self, Binding, Guard, RenderBinding};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::fmt::Write as _;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Component, Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const RECEIPT: &str = "render-receipt.json";
    const ACTIVATION_RECEIPT: &str = "activation-receipt.json";
    const GENERATED: &str = "generated_files";
    const ROOT_KEYS: &[&str] = &[
        "input",
        "counts",
        "refusals",
        "host",
        GENERATED,
        "strict_check",
    ];
    const COUNT_KEYS: &[&str] = &["clients", "prefixes", "origins"];
    const SKINS: &str = "route_server_skin_files";
    const MULTI: &str = "multi_address_clients";
    const MAX_DIFF_TOML_BYTES: usize = 4_194_299;
    const REFUSAL_KEYS: &[&str] = &["status", "active_ui_filters", SKINS, MULTI];
    type AResult<T> = Result<T, Error>;

    pub(crate) struct Verified {
        pub(crate) digest: String,
        files: BTreeMap<String, String>,
        directories: Vec<String>,
        pub(crate) checker_version: String,
        pub(crate) config: Vec<u8>,
    }

    pub(crate) fn private(path: &Path, directory: bool, mode: u32) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            let kind = metadata.file_type();
            let exact_kind = kind.is_dir() == directory
                && (directory || (kind.is_file() && metadata.nlink() == 1));
            exact_kind && metadata.permissions().mode() & 0o777 == mode
        })
    }

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                write!(output, "{byte:02x}").expect("String writes cannot fail");
                output
            })
    }

    pub(crate) fn valid_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn exact_keys(value: &Value, expected: &[&str]) -> bool {
        let Some(object) = value.as_object() else {
            return false;
        };
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    }

    fn safe_relative(value: &str) -> bool {
        !value.is_empty()
            && Path::new(value)
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
    }

    fn walk(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
        dirs: &mut BTreeSet<String>,
    ) -> AResult<()> {
        for entry in
            fs::read_dir(directory).map_err(|_| Error::Refused("candidate tree is unreadable"))?
        {
            let entry = entry.map_err(|_| Error::Refused("candidate tree is unreadable"))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| Error::Refused("candidate tree escaped"))?;
            let name = relative
                .to_str()
                .ok_or(Error::Refused("candidate path is not UTF-8"))?
                .replace('\\', "/");
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| Error::Refused("candidate tree is unreadable"))?;
            if metadata.file_type().is_dir() && private(&path, true, 0o700) {
                dirs.insert(name);
                walk(root, &path, files, dirs)?;
            } else if metadata.file_type().is_file() && private(&path, false, 0o600) {
                files.insert(name);
            } else {
                return Err(Error::Refused(
                    "candidate entries must be private regular files or directories",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn verify_candidate(root: &Path, binding: &Binding) -> AResult<Verified> {
        if !private(root, true, 0o700) || !private(&root.join(RECEIPT), false, 0o600) {
            return Err(Error::Refused(
                "candidate and receipt must be private regular paths",
            ));
        }
        let receipt_bytes = fs::read(root.join(RECEIPT))
            .map_err(|_| Error::Refused("render receipt is unreadable"))?;
        if receipt_bytes.len() > 1024 * 1024 {
            return Err(Error::Refused("render receipt is oversized"));
        }
        let receipt: Value = serde_json::from_slice(&receipt_bytes)
            .map_err(|_| Error::Refused("render receipt is invalid"))?;
        if !exact_keys(&receipt, ROOT_KEYS)
            || !exact_keys(
                &receipt["input"],
                &["schema", "ixp_manager_version", "router_handle", "sha256"],
            )
            || !exact_keys(&receipt["counts"], COUNT_KEYS)
            || !exact_keys(&receipt["refusals"], REFUSAL_KEYS)
            || !exact_keys(&receipt["strict_check"], &["binary_version", "passed"])
            || !matches!(
                receipt["input"]["schema"].as_str(),
                Some(
                    "rustbgpd.ixp-manager.router-config/v1"
                        | "rustbgpd.ixp-manager.router-config/v2"
                )
            )
            || receipt["input"]["ixp_manager_version"] != "7.4.0"
            || receipt["input"]["router_handle"]
                .as_str()
                .is_none_or(str::is_empty)
            || !receipt["input"]["sha256"]
                .as_str()
                .is_some_and(valid_digest)
            || !COUNT_KEYS.iter().all(|key| {
                receipt["counts"][key]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            })
            || receipt["refusals"]["status"] != "passed"
            || !REFUSAL_KEYS[1..]
                .iter()
                .all(|key| receipt["refusals"][key] == 0)
            || receipt["strict_check"]["passed"] != true
            || !receipt["strict_check"]["binary_version"]
                .as_str()
                .is_some_and(|value| value.starts_with("rustbgpd "))
        {
            return Err(Error::Refused("render receipt contract does not match"));
        }
        let receipt_binding: RenderBinding = serde_json::from_value(receipt["host"].clone())
            .map_err(|_| Error::Refused("render receipt host binding is invalid"))?;
        if receipt_binding != binding.render_binding()
            || receipt["input"]["router_handle"] != binding.router_handle
        {
            return Err(Error::Refused("render receipt host binding does not match"));
        }
        let generated = receipt["generated_files"]
            .as_object()
            .ok_or(Error::Refused("render receipt file map is invalid"))?;
        let mut expected_dirs = BTreeSet::new();
        let mut hashes = BTreeMap::new();
        for (name, value) in generated {
            let hash = value
                .as_str()
                .filter(|value| valid_digest(value))
                .ok_or(Error::Refused("render receipt file hash is invalid"))?;
            if !safe_relative(name) || name == RECEIPT {
                return Err(Error::Refused("render receipt file path is unsafe"));
            }
            let mut parent = Path::new(name).parent();
            while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
                expected_dirs.insert(path.to_string_lossy().replace('\\', "/"));
                parent = path.parent();
            }
            hashes.insert(name.clone(), hash.to_owned());
        }
        if !hashes.contains_key("config.toml") || hashes.is_empty() {
            return Err(Error::Refused("render receipt omits config.toml"));
        }
        let mut actual_files = BTreeSet::new();
        let mut actual_dirs = BTreeSet::new();
        walk(root, root, &mut actual_files, &mut actual_dirs)?;
        let mut expected_files = hashes.keys().cloned().collect::<BTreeSet<_>>();
        expected_files.insert(RECEIPT.to_owned());
        if actual_files != expected_files || actual_dirs != expected_dirs {
            return Err(Error::Refused(
                "candidate tree differs from the render receipt",
            ));
        }
        let mut identity = Sha256::new();
        let mut config = Vec::new();
        for (name, expected) in &hashes {
            let bytes = fs::read(root.join(name))
                .map_err(|_| Error::Refused("candidate file is unreadable"))?;
            if digest(&bytes) != *expected {
                return Err(Error::Refused("candidate file hash mismatch"));
            }
            identity.update(name.as_bytes());
            identity.update([0]);
            identity.update(expected.as_bytes());
            identity.update([0]);
            if name == "config.toml" {
                config = bytes;
            }
        }
        let config_text = std::str::from_utf8(&config)
            .map_err(|_| Error::Refused("candidate config is not UTF-8"))?;
        let parsed: toml::Value = toml::from_str(config_text)
            .map_err(|_| Error::Refused("candidate config is invalid TOML"))?;
        let global = parsed.get("global").and_then(toml::Value::as_table);
        let runtime = global
            .and_then(|global| global.get("runtime_state_dir"))
            .and_then(toml::Value::as_str);
        let uds = global
            .and_then(|global| global.get("telemetry"))
            .and_then(toml::Value::as_table)
            .and_then(|telemetry| telemetry.get("grpc_uds"))
            .and_then(toml::Value::as_table)
            .and_then(|uds| uds.get("path"))
            .and_then(toml::Value::as_str);
        if runtime != binding.runtime_state_dir.to_str()
            || uds != binding.runtime_state_dir.join("grpc.sock").to_str()
        {
            return Err(Error::Refused(
                "candidate runtime binding does not match receipt",
            ));
        }
        let mut directories = actual_dirs.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
        Ok(Verified {
            digest: digest(&identity.finalize()),
            files: hashes,
            directories,
            checker_version: receipt["strict_check"]["binary_version"]
                .as_str()
                .expect("validated above")
                .to_owned(),
            config,
        })
    }

    fn create_private_dir(path: &Path) -> AResult<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| Error::Refused("cannot create private state directory"))?;
        private(path, true, 0o700)
            .then_some(())
            .ok_or(Error::Refused("state directories must be mode 0700"))
    }

    pub(crate) fn state_lock(state: &Path) -> AResult<File> {
        let path = state.join("activation.lock");
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|_| Error::Refused("state lock is unsafe"))?,
            Err(_) => return Err(Error::Refused("cannot create state lock")),
        };
        let opened = file
            .metadata()
            .map_err(|_| Error::Refused("state lock is unsafe"))?;
        let named =
            fs::symlink_metadata(&path).map_err(|_| Error::Refused("state lock is unsafe"))?;
        if !named.file_type().is_file()
            || named.permissions().mode() & 0o777 != 0o600
            || opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.nlink() != 1
        {
            return Err(Error::Refused("state lock is unsafe"));
        }
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(fs::TryLockError::WouldBlock) => {
                Err(Error::Refused("another activation holds the state lock"))
            }
            Err(fs::TryLockError::Error(_)) => Err(Error::Refused("state lock failed")),
        }
    }

    fn sync_dir(path: &Path) -> AResult<()> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::RecoveryRequired)
    }

    struct Staging(Option<PathBuf>);

    impl Drop for Staging {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = fs::remove_dir_all(path);
            }
        }
    }

    pub(crate) struct Comparison(PathBuf);

    impl AsRef<Path> for Comparison {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Comparison {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    /// Publish the verified candidate as an immutable generation; the flag is
    /// true when this call created it (false when equal content already existed).
    fn copy_generation(
        candidate: &Path,
        state: &Path,
        verified: &Verified,
        binding: &Binding,
    ) -> AResult<(PathBuf, bool)> {
        let generations = state.join("generations");
        create_private_dir(&generations)?;
        let final_path = generations.join(&verified.digest);
        if final_path.exists() {
            let existing = verify_candidate(&final_path, binding)?;
            if existing.digest != verified.digest {
                return Err(Error::Refused("immutable generation content mismatch"));
            }
            sync_dir(&generations)?;
            return Ok((final_path, false));
        }
        let temporary = generations.join(unique_name(&format!(".{}", verified.digest)));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&temporary)
            .map_err(|_| Error::Refused("cannot stage generation"))?;
        let mut staging = Staging(Some(temporary.clone()));
        for name in verified
            .files
            .keys()
            .map(String::as_str)
            .chain(std::iter::once(RECEIPT))
        {
            let destination = temporary.join(name);
            if let Some(parent) = destination.parent() {
                create_private_dir(parent)?;
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination)
                .map_err(|_| Error::Refused("cannot stage generation"))?;
            output
                .write_all(
                    &fs::read(candidate.join(name))
                        .map_err(|_| Error::Refused("candidate file is unreadable"))?,
                )
                .map_err(|_| Error::Refused("cannot stage generation"))?;
            output
                .sync_all()
                .map_err(|_| Error::Refused("cannot sync generation"))?;
        }
        for directory in &verified.directories {
            sync_dir(&temporary.join(directory))
                .map_err(|_| Error::Refused("cannot sync generation"))?;
        }
        sync_dir(&temporary).map_err(|_| Error::Refused("cannot sync generation"))?;
        let staged = verify_candidate(&temporary, binding)?;
        if staged.digest != verified.digest {
            return Err(Error::Refused("staged generation changed during copy"));
        }
        fs::rename(&temporary, &final_path)
            .map_err(|_| Error::Refused("cannot publish generation"))?;
        staging.0.take();
        sync_dir(&generations)?;
        Ok((final_path, true))
    }

    pub(crate) fn current_target(state: &Path, binding: &Binding) -> AResult<Option<String>> {
        let current = state.join("current");
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Refused("current generation is unreadable")),
        };
        if !metadata.file_type().is_symlink() {
            return Err(Error::Refused(
                "current must be a relative generation symlink",
            ));
        }
        let target = fs::read_link(current)
            .map_err(|_| Error::Refused("current generation is unreadable"))?;
        let text = target
            .to_str()
            .ok_or(Error::Refused("current generation target is invalid"))?;
        let parts = target.components().collect::<Vec<_>>();
        if parts.len() != 2
            || parts[0] != Component::Normal("generations".as_ref())
            || !matches!(parts[1], Component::Normal(_))
        {
            return Err(Error::Refused(
                "current must be a relative generation symlink",
            ));
        }
        let hash = text
            .strip_prefix("generations/")
            .ok_or(Error::Refused("current generation target is invalid"))?;
        if !valid_digest(hash) || verify_candidate(&state.join(&target), binding)?.digest != hash {
            return Err(Error::Refused(
                "current generation is not immutable content",
            ));
        }
        Ok(Some(text.to_owned()))
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Publication {
        Durable,
        RenamedUnsynced,
        UnchangedError,
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        format!("{prefix}.{}.{nanos}", std::process::id())
    }

    fn publish_current(state: &Path, target: &str) -> Publication {
        let temporary = state.join(unique_name(".current"));
        if symlink(target, &temporary).is_err() {
            return Publication::UnchangedError;
        }
        if fs::rename(&temporary, state.join("current")).is_err() {
            let _ = fs::remove_file(temporary);
            return Publication::UnchangedError;
        }
        if sync_dir(state).is_ok() {
            Publication::Durable
        } else {
            Publication::RenamedUnsynced
        }
    }

    pub(crate) fn normalized_toml(config: &[u8], state: &Path) -> AResult<Vec<u8>> {
        let current = fs::canonicalize(state)
            .map_err(|_| Error::Refused("state path is invalid"))?
            .join("current");
        current
            .to_str()
            .ok_or(Error::Refused("state path is not UTF-8"))?;
        let input = std::str::from_utf8(config)
            .map_err(|_| Error::Refused("generation config is invalid"))?;
        let mut document: toml::Value =
            toml::from_str(input).map_err(|_| Error::Refused("generation config is invalid"))?;
        if let Some(policy) = document
            .get_mut("policy")
            .and_then(toml::Value::as_table_mut)
        {
            for key in ["rpol_files", "rpol_roots"] {
                if let Some(paths) = policy.get_mut(key).and_then(toml::Value::as_array_mut) {
                    for path in paths {
                        let relative = path.as_str().filter(|value| safe_relative(value)).ok_or(
                            Error::Refused("policy paths must stay inside the generation"),
                        )?;
                        *path = toml::Value::String(
                            current
                                .join(relative)
                                .to_str()
                                .ok_or(Error::Refused("state path is not UTF-8"))?
                                .to_owned(),
                        );
                    }
                }
            }
        }
        let bytes = toml::to_string(&document)
            .map_err(|_| Error::Refused("cannot normalize runtime comparison"))?
            .into_bytes();
        if bytes.len() > MAX_DIFF_TOML_BYTES {
            return Err(Error::Refused(
                "normalized config exceeds rbgp diff request limit",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn comparison_file(bytes: &[u8], state: &Path, label: &str) -> AResult<Comparison> {
        let path = state.join(unique_name(&format!(".compare-{label}")));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::Refused("cannot stage runtime comparison"))?;
        let comparison = Comparison(path);
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Refused("cannot stage runtime comparison"))?;
        Ok(comparison)
    }

    fn wait_output(mut child: Child, deadline: Instant) -> Option<Output> {
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return child.wait_with_output().ok(),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Health {
        Reachable(bool),
        Unreachable,
        Invalid,
    }

    pub(crate) fn health_probe(rbgp: &Path, rbgp_addr: &str, deadline: Instant) -> Health {
        let Ok(child) = Command::new(rbgp)
            .args(["--json", "--addr", rbgp_addr, "health"])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        else {
            return Health::Invalid;
        };
        let Some(output) = wait_output(child, deadline) else {
            return Health::Invalid;
        };
        if output.status.success() {
            return serde_json::from_slice::<Value>(&output.stdout)
                .ok()
                .and_then(|value| value.get("healthy")?.as_bool())
                .map_or(Health::Invalid, Health::Reachable);
        }
        let error = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(1)
            && (error.contains("cannot reach rustbgpd at ")
                || error.contains("daemon is not running or unreachable"))
        {
            Health::Unreachable
        } else {
            Health::Invalid
        }
    }

    pub(crate) fn equal_runtime(
        rbgp: &Path,
        rbgp_addr: &str,
        comparison: &Path,
        deadline: Instant,
    ) -> bool {
        let Ok(child) = Command::new(rbgp)
            .args(["--addr", rbgp_addr, "config", "diff"])
            .arg(comparison)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        wait_output(child, deadline).is_some_and(|output| output.status.code() == Some(0))
    }

    fn settle(rbgp: &Path, rbgp_addr: &str, comparison: &Path, deadline: Instant) -> bool {
        loop {
            if health_probe(rbgp, rbgp_addr, deadline) == Health::Reachable(true)
                && equal_runtime(rbgp, rbgp_addr, comparison, deadline)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    #[derive(Clone, Copy, Default)]
    struct Attempt {
        ran: bool,
        health_checked: bool,
        settled: bool,
    }

    /// The activation command, then the settlement test; everything a
    /// re-activation needs besides the generation itself.
    #[derive(Clone, Copy)]
    pub(crate) struct Activation<'a> {
        pub(crate) command: &'a Path,
        pub(crate) args: &'a [OsString],
        pub(crate) rbgp: &'a Path,
        pub(crate) rbgp_addr: &'a str,
        pub(crate) settle: Duration,
    }

    impl<'a> From<&Options<'a>> for Activation<'a> {
        fn from(options: &Options<'a>) -> Self {
            Self {
                command: options.activation_command,
                args: options.activation_args,
                rbgp: options.rbgp,
                rbgp_addr: options.rbgp_addr,
                settle: options.settle,
            }
        }
    }

    fn activate_and_settle(activation: Activation<'_>, comparison: &Path) -> Attempt {
        let deadline = Instant::now() + activation.settle;
        let Ok(child) = Command::new(activation.command)
            .args(activation.args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return Attempt::default();
        };
        if !wait_output(child, deadline).is_some_and(|output| output.status.success()) {
            return Attempt {
                ran: true,
                ..Attempt::default()
            };
        }
        Attempt {
            ran: true,
            health_checked: true,
            settled: settle(activation.rbgp, activation.rbgp_addr, comparison, deadline),
        }
    }

    #[derive(Clone, Copy, Default)]
    struct Phases {
        initial: bool,
        candidate_publication: Option<Publication>,
        rollback_publication: Option<Publication>,
        candidate: Attempt,
        rollback: Attempt,
        runtime_equal: bool,
    }

    fn write_receipt(
        state: &Path,
        status: &str,
        candidate: &str,
        previous: Option<&str>,
        phases: Phases,
        checker_version: &str,
        binding: &Binding,
    ) -> AResult<()> {
        let receipt = json!({
            "schema": "rustbgpd.ixp-manager.activation/v1",
            "status": status,
            "candidate_sha256": candidate,
            "previous_generation": previous,
            "initial": phases.initial,
            "activation_runs": u8::from(phases.candidate.ran) + u8::from(phases.rollback.ran),
            "strict_check": {"passed": true, "binary_version": checker_version},
            "host": binding,
            "phases": {
                "candidate_link": {"published": phases.candidate_publication.is_some(), "durable": phases.candidate_publication == Some(Publication::Durable)},
                "candidate_activation_ran": phases.candidate.ran,
                "initial_unreachable_checked": phases.initial,
                "rollback_link": {"published": phases.rollback_publication.is_some(), "durable": phases.rollback_publication == Some(Publication::Durable)},
                "rollback_activation_ran": phases.rollback.ran,
                "health_checked": !phases.initial || phases.candidate.health_checked || phases.rollback.health_checked,
                "runtime_equal": phases.runtime_equal
            }
        });
        let temporary = state.join(unique_name(&format!(".{ACTIVATION_RECEIPT}")));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Error::RecoveryRequired)?;
        let mut bytes = serde_json::to_vec_pretty(&receipt).expect("receipt serializes");
        bytes.push(b'\n');
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::RecoveryRequired)?;
        fs::rename(&temporary, state.join(ACTIVATION_RECEIPT))
            .map_err(|_| Error::RecoveryRequired)?;
        sync_dir(state)
    }

    fn disjoint(candidate: &Path, state: &Path) -> bool {
        let Ok(candidate) = fs::canonicalize(candidate) else {
            return false;
        };
        let Ok(state) = fs::canonicalize(state) else {
            return false;
        };
        !candidate.starts_with(&state) && !state.starts_with(candidate)
    }

    fn activate_inner(options: &Options<'_>) -> AResult<Status> {
        if options.settle < Duration::from_secs(1)
            || options.settle > Duration::from_secs(120)
            || options.rbgp_addr != options.binding.rbgp_addr
            || options.state_dir != options.binding.activation_state_dir
        {
            return Err(Error::Refused(
                "activation state and rbgp address must match host binding",
            ));
        }
        if !options.state_dir.is_absolute() || !private(options.state_dir, true, 0o700) {
            return Err(Error::Refused(
                "state directory must be a pre-created absolute mode-0700 directory",
            ));
        }
        let candidate = verify_candidate(options.candidate, options.binding)?;
        if !disjoint(options.candidate, options.state_dir) {
            return Err(Error::Refused(
                "candidate and state directory must not overlap",
            ));
        }
        let _lock = state_lock(options.state_dir)?;
        let checker_deadline = Instant::now() + options.settle;
        let version_child = Command::new(options.checker)
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Error::Refused("strict checker could not run"))?;
        let version_output = wait_output(version_child, checker_deadline)
            .ok_or(Error::Refused("strict checker timed out"))?;
        let mut version_bytes = version_output.stdout;
        version_bytes.extend(version_output.stderr);
        let version_text = std::str::from_utf8(&version_bytes)
            .map_err(|_| Error::Refused("strict checker version is invalid"))?;
        let mut version_words = version_text
            .lines()
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace();
        let (Some(name), Some(number)) = (version_words.next(), version_words.next()) else {
            return Err(Error::Refused("strict checker version is invalid"));
        };
        if !version_output.status.success()
            || name != "rustbgpd"
            || !number
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte))
        {
            return Err(Error::Refused("strict checker version is invalid"));
        }
        let checker_version = format!("rustbgpd {number}");
        if checker_version != candidate.checker_version {
            return Err(Error::Refused("strict checker version changed"));
        }
        let previous = current_target(options.state_dir, options.binding)?;
        if options.initial == previous.is_some() {
            return Err(Error::Refused(
                "--initial requires exactly an empty current state",
            ));
        }
        if options.initial
            && health_probe(
                options.rbgp,
                options.rbgp_addr,
                Instant::now() + options.settle,
            ) != Health::Unreachable
        {
            return Err(Error::Refused("--initial requires no reachable daemon"));
        }
        let candidate_runtime = normalized_toml(&candidate.config, options.state_dir)?;
        let prior_runtime = previous
            .as_deref()
            .map(|target| {
                verify_candidate(&options.state_dir.join(target), options.binding)
                    .and_then(|verified| normalized_toml(&verified.config, options.state_dir))
            })
            .transpose()?;
        let mut phases = Phases {
            initial: options.initial,
            ..Phases::default()
        };
        let (generation, created) = copy_generation(
            options.candidate,
            options.state_dir,
            &candidate,
            options.binding,
        )?;
        // A refusal from here until `current` is published must leave no trace:
        // a generation this run created and never linked is removed again.
        let mut unpublished = Staging(created.then(|| generation.clone()));
        let check_child = Command::new(options.checker)
            .args(["--check", "--strict"])
            .arg(generation.join("config.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Refused("strict checker could not run"))?;
        let checked = wait_output(check_child, Instant::now() + options.settle)
            .ok_or(Error::Refused("strict checker timed out"))?;
        if !checked.status.success() {
            return Err(Error::Refused("strict candidate check failed"));
        }
        let candidate_target = format!("generations/{}", candidate.digest);
        let candidate_comparison =
            comparison_file(&candidate_runtime, options.state_dir, "candidate")?;
        let finish = |status: &str, phases: Phases| {
            write_receipt(
                options.state_dir,
                status,
                &candidate.digest,
                previous.as_deref(),
                phases,
                &checker_version,
                options.binding,
            )
        };
        if let Some(previous_target) = previous.as_deref() {
            let prior_comparison = comparison_file(
                prior_runtime
                    .as_deref()
                    .expect("present with previous target"),
                options.state_dir,
                "prior",
            )?;
            let known_good_deadline = Instant::now() + options.settle;
            if health_probe(options.rbgp, options.rbgp_addr, known_good_deadline)
                != Health::Reachable(true)
                || !equal_runtime(
                    options.rbgp,
                    options.rbgp_addr,
                    prior_comparison.as_ref(),
                    known_good_deadline,
                )
            {
                return Err(Error::Refused("current runtime is not known-good"));
            }
            if previous_target == candidate_target {
                phases.runtime_equal = true;
                drop(prior_comparison);
                drop(candidate_comparison);
                finish("noop", phases)?;
                return Ok(Status::Noop);
            }
            let publication = publish_current(options.state_dir, &candidate_target);
            if publication == Publication::UnchangedError {
                return Err(Error::Refused(
                    "atomic current publication failed before rename",
                ));
            }
            unpublished.0.take();
            phases.candidate_publication = Some(publication);
            if publication == Publication::Durable {
                phases.candidate =
                    activate_and_settle(options.into(), candidate_comparison.as_ref());
                if phases.candidate.settled {
                    phases.runtime_equal = true;
                    drop(prior_comparison);
                    drop(candidate_comparison);
                    finish("activated", phases)?;
                    return Ok(Status::Activated);
                }
                if !phases.candidate.ran {
                    let rollback = publish_current(options.state_dir, previous_target);
                    if rollback != Publication::UnchangedError {
                        phases.rollback_publication = Some(rollback);
                    }
                    let deadline = Instant::now() + options.settle;
                    if rollback == Publication::Durable
                        && health_probe(options.rbgp, options.rbgp_addr, deadline)
                            == Health::Reachable(true)
                        && equal_runtime(
                            options.rbgp,
                            options.rbgp_addr,
                            prior_comparison.as_ref(),
                            deadline,
                        )
                    {
                        phases.runtime_equal = true;
                        drop(prior_comparison);
                        drop(candidate_comparison);
                        finish("rolled_back", phases)?;
                        return Err(Error::RolledBack);
                    }
                }
            }
            drop(prior_comparison);
            drop(candidate_comparison);
            finish("recovery_required", phases)?;
            return Err(Error::RecoveryRequired);
        }
        let publication = publish_current(options.state_dir, &candidate_target);
        if publication == Publication::UnchangedError {
            return Err(Error::Refused(
                "atomic current publication failed before rename",
            ));
        }
        unpublished.0.take();
        phases.candidate_publication = Some(publication);
        if publication == Publication::Durable {
            phases.candidate = activate_and_settle(options.into(), candidate_comparison.as_ref());
            phases.runtime_equal = phases.candidate.settled;
            if phases.candidate.settled {
                drop(candidate_comparison);
                finish("activated", phases)?;
                return Ok(Status::Activated);
            }
        }
        drop(candidate_comparison);
        finish("recovery_required", phases)?;
        Err(Error::RecoveryRequired)
    }

    /// The receipt a `recover keep-current` leaves: the exit-5 candidate stays
    /// live (`kept`), with the probe result as `runtime_equal`.
    pub(crate) fn write_kept_receipt(
        state: &Path,
        candidate: &str,
        previous: Option<&str>,
        runtime_equal: bool,
        checker_version: &str,
        binding: &Binding,
    ) -> AResult<()> {
        let attempt = Attempt {
            ran: true,
            health_checked: true,
            settled: runtime_equal,
        };
        write_receipt(
            state,
            "kept",
            candidate,
            previous,
            Phases {
                candidate_publication: Some(Publication::Durable),
                candidate: attempt,
                runtime_equal,
                ..Phases::default()
            },
            checker_version,
            binding,
        )
    }

    /// Re-point `current` at the already published generation `target` and run
    /// the activation command through the same publish-activate-settle path a
    /// first activation uses, then write the activation receipt for
    /// `candidate` (the generation being rolled away from): `rolled_back` when
    /// the daemon settled on `target`, `recovery_required` otherwise. The
    /// caller holds the activation state lock. Returns whether it settled.
    pub(crate) fn republish(
        state: &Path,
        target: &str,
        candidate: &str,
        activation: Activation<'_>,
        binding: &Binding,
    ) -> AResult<bool> {
        let verified = verify_candidate(&state.join(target), binding)?;
        let comparison =
            comparison_file(&normalized_toml(&verified.config, state)?, state, "recover")?;
        let mut phases = Phases {
            candidate_publication: Some(Publication::Durable),
            candidate: Attempt {
                ran: true,
                ..Attempt::default()
            },
            ..Phases::default()
        };
        let publication = publish_current(state, target);
        if publication == Publication::UnchangedError {
            return Err(Error::Refused(
                "atomic current publication failed before rename",
            ));
        }
        phases.rollback_publication = Some(publication);
        if publication == Publication::Durable {
            phases.rollback = activate_and_settle(activation, comparison.as_ref());
            phases.runtime_equal = phases.rollback.settled;
        }
        drop(comparison);
        let status = if phases.runtime_equal {
            "rolled_back"
        } else {
            "recovery_required"
        };
        write_receipt(
            state,
            status,
            candidate,
            Some(target),
            phases,
            &verified.checker_version,
            binding,
        )?;
        Ok(phases.runtime_equal)
    }

    fn host_error(error: ixp_manager_host::Error) -> Error {
        match error {
            ixp_manager_host::Error::Refused(reason) => Error::Refused(reason),
            ixp_manager_host::Error::RecoveryRequired => Error::RecoveryRequired,
        }
    }

    pub(crate) fn activate_guarded(options: &Options<'_>, guard: &Guard) -> AResult<Status> {
        if !guard.owns(options.binding) {
            return Err(Error::Refused("host guard does not own activation binding"));
        }
        activate_inner(options)
    }

    pub fn activate(options: &Options<'_>) -> AResult<Status> {
        let guard = Guard::claim_new(options.binding).map_err(host_error)?;
        let result = activate_guarded(options, &guard);
        if result == Err(Error::RecoveryRequired) {
            return result;
        }
        guard.clear().map_err(host_error)?;
        result
    }
}

#[cfg(unix)]
pub use unix::activate;
#[cfg(unix)]
pub(crate) use unix::{
    Activation, Comparison, Health, activate_guarded, comparison_file, current_target,
    equal_runtime, health_probe, normalized_toml, private, republish, state_lock, valid_digest,
    verify_candidate, write_kept_receipt,
};
