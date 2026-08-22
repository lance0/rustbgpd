//! `status` (and the `recover` verbs) against the durable state a real
//! lifecycle leaves behind: a bootstrapped handle, a loopback stand-in for the
//! IXP Manager v7.4 router API, and fake `rustbgpd`/`rbgp`/activation
//! executables whose outcomes the test controls through mode files.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rs_config_render::activation;
use rs_config_render::ixp_manager;
use rs_config_render::ixp_manager_host::{Binding, Guard};
use rs_config_render::ixp_manager_lifecycle::{self as lifecycle, Error as LifecycleError};

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v2-supported.json");
const API_KEY: &str = "recover-api-key-must-not-leak";
const HANDLE: &str = "b2-rs1-lan1-ipv4";
// Serialize the binary: a foreign child can inherit another test's flock descriptor.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    mode(path, 0o700);
}

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    mode(path, 0o700);
}

#[derive(Clone)]
struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: br#"{"last_update_started":"2026-08-20T00:00:00+00:00","last_update_started_unix":1787184000,"last_updated":null,"last_updated_unix":null}"#.to_vec(),
        }
    }

    fn config(body: &[u8]) -> Self {
        Self {
            status: 200,
            content_type: "text/plain; charset=UTF-8",
            body: body.to_vec(),
        }
    }
}

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    join: thread::JoinHandle<()>,
}

fn read_request(mut stream: &TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "HTTP request ended before its headers");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() <= 32 * 1024, "test request headers too large");
    }
    String::from_utf8(bytes).unwrap()
}

impl Server {
    fn start(responses: Vec<Response>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                captured.lock().unwrap().push(read_request(&stream));
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let reason = match response.status {
                    200 => "OK",
                    423 => "Locked",
                    500 => "Server Error",
                    _ => "Error",
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.content_type,
                    response.body.len()
                );
                let _ = stream.write_all(&response.body);
            }
        });
        Self {
            origin,
            requests,
            join,
        }
    }

    fn finish(self) -> Vec<String> {
        self.join.join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

fn assert_request(request: &str, method: &str, action: &str) {
    assert!(
        request.starts_with(&format!(
            "{method} /admin/api/v4/router/{action}/{HANDLE} HTTP/1.1\r\n"
        )),
        "unexpected request: {request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("\r\nx-ixp-manager-api-key: {API_KEY}\r\n"))
    );
}

struct Rig {
    _temp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    runtime: PathBuf,
    host: PathBuf,
    candidate: PathBuf,
    key: PathBuf,
    checker: PathBuf,
    rbgp: PathBuf,
    activation: PathBuf,
    binding: Binding,
}

impl Rig {
    /// A bootstrapped handle: one activated generation, `current` on it, the
    /// fake daemon "running" it, no fence, no journal.
    fn new() -> Self {
        let current = std::env::current_dir().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("recover-")
            .tempdir_in(current)
            .unwrap();
        let root = temp.path().to_path_buf();
        let runtime = root.join(HANDLE);
        let state = runtime.join("activation");
        let candidate = root.join("candidate");
        let host = root.join("host-state");
        private_dir(&runtime);
        private_dir(&state);
        private_dir(&candidate);
        private_dir(&host);
        let key = root.join("api-key");
        fs::write(&key, format!("{API_KEY}\n")).unwrap();
        mode(&key, 0o600);
        fs::write(root.join("health-mode"), "ok").unwrap();
        fs::write(root.join("activation-mode"), "ok").unwrap();
        let checker = root.join("rustbgpd");
        executable(
            &checker,
            "#!/bin/sh\n[ \"$1\" = --version ] && { echo 'rustbgpd 0.65.0'; exit 0; }\nexit 0\n",
        );
        // The fake daemon "runs" whatever generation the activation command
        // last loaded (`runtime`); `config diff` is equal iff that is what
        // `current` points at now. `health-mode` is ok | unhealthy | down.
        let rbgp = root.join("rbgp");
        executable(
            &rbgp,
            &format!(
                r#"#!/bin/sh
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
printf '%s\n' "$*" >> "$root/rbgp.log"
case "$*" in
  *" health")
    health_mode=$(cat "$root/health-mode")
    if [ "$health_mode" = down ] || [ ! -f "$root/runtime" ]; then
      printf 'Error: cannot reach rustbgpd at test (connection refused)\n' >&2
      exit 1
    fi
    [ "$health_mode" = unhealthy ] && healthy=false || healthy=true
    printf '{{"healthy":%s}}\n' "$healthy"
    exit 0
    ;;
esac
[ "$(cat "$root/runtime" 2>/dev/null)" = "$(readlink "$root/{HANDLE}/activation/current")" ] && exit 0
exit 2
"#
            ),
        );
        // `activation-mode`: ok (load and succeed) | load-then-fail (the
        // daemon loads the new current but the command exits nonzero) | fail
        // (nothing loaded, nonzero exit).
        let activation = root.join("activate");
        executable(
            &activation,
            &format!(
                r#"#!/bin/sh
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
target=$(readlink "$root/{HANDLE}/activation/current") || exit 7
printf '%s\n' "$target" >> "$root/activation.log"
case "$(cat "$root/activation-mode")" in
  ok) printf '%s\n' "$target" > "$root/runtime"; exit 0 ;;
  load-then-fail) printf '%s\n' "$target" > "$root/runtime"; exit 9 ;;
  *) exit 9 ;;
esac
"#
            ),
        );
        let binding = Binding::new(
            HANDLE,
            &runtime,
            &state,
            &host,
            &format!("unix://{}", runtime.join("grpc.sock").display()),
        )
        .unwrap();
        let rig = Self {
            _temp: temp,
            root,
            state,
            runtime,
            host,
            candidate,
            key,
            checker,
            rbgp,
            activation,
            binding,
        };
        rig.bootstrap();
        rig
    }

    fn bootstrap(&self) {
        let candidate = self.root.join("bootstrap");
        private_dir(&candidate);
        ixp_manager::write_checked_candidate_bytes(
            FIXTURE,
            &candidate,
            300,
            &self.checker,
            &self.binding.render_binding(),
        )
        .unwrap();
        assert_eq!(
            activation::activate(&activation::Options {
                candidate: &candidate,
                state_dir: &self.state,
                checker: &self.checker,
                rbgp: &self.rbgp,
                rbgp_addr: self.binding.rbgp_addr(),
                settle: Duration::from_secs(2),
                initial: true,
                activation_command: &self.activation,
                activation_args: &[],
                binding: &self.binding,
            }),
            Ok(activation::Status::Activated)
        );
    }

    fn set(&self, name: &str, value: &str) {
        fs::write(self.root.join(name), value).unwrap();
    }

    fn current(&self) -> String {
        fs::read_link(self.state.join("current"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn journal(&self) -> PathBuf {
        self.state.join("ixp-manager-lifecycle.json")
    }

    fn fence(&self) -> PathBuf {
        self.host.join("ixp-manager-host-fence.json")
    }

    fn receipt(&self) -> PathBuf {
        self.state.join("activation-receipt.json")
    }

    fn options<'a>(&'a self, origin: &'a str) -> lifecycle::Options<'a> {
        lifecycle::Options {
            ixp_origin: origin,
            router_handle: HANDLE,
            api_key_file: &self.key,
            candidate_dir: &self.candidate,
            state_dir: &self.state,
            checker: &self.checker,
            // 301 differs from the bootstrap's 300, so the candidate is a new
            // generation rather than a no-op.
            max_prefix_restart_seconds: 301,
            rbgp: &self.rbgp,
            rbgp_addr: self.binding.rbgp_addr(),
            activation_command: &self.activation,
            activation_args: &[],
            settle: Duration::from_secs(2),
            timeout: Duration::from_secs(2),
            initial: false,
            allow_http_loopback: true,
            binding: &self.binding,
        }
    }

    /// Drive one lifecycle run into exit 5 with the activation command in
    /// `activation_mode`; the upstream lock is retained and no callback sent.
    /// The stand-in keeps serving `afterwards` to whatever recovery follows.
    fn induce_exit_5(&self, activation_mode: &str, afterwards: Vec<Response>) -> Server {
        self.set("activation-mode", activation_mode);
        let mut responses = vec![Response::json(200), Response::config(FIXTURE)];
        responses.extend(afterwards);
        let server = Server::start(responses);
        assert_eq!(
            lifecycle::run(&self.options(&server.origin)),
            Err(LifecycleError::ManualRecovery)
        );
        assert_eq!(
            server.requests.lock().unwrap().len(),
            2,
            "exit 5 must not callback"
        );
        self.set("activation-mode", "ok");
        assert!(self.fence().exists());
        assert!(self.journal().exists());
        server
    }

    /// One `recover` verb through the binary. A dry run is asserted to change
    /// nothing; the returned lines are the `recover <verb>: ` step lines
    /// without the prefix, followed by the summary line.
    fn recover_cli(
        &self,
        verb: &[&str],
        apply: bool,
        origin: Option<&str>,
    ) -> (i32, Vec<String>, String) {
        let before = snapshot(&self.root);
        let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
        self.recover_args(&mut command, verb, apply, origin);
        let output = command.output().unwrap();
        if !apply {
            assert_eq!(snapshot(&self.root), before, "dry run changed state");
        }
        self.recover_output(verb, output)
    }

    /// `recover … --apply` through the binary under RLIMIT_FSIZE 0: every
    /// file write past zero bytes fails with EFBIG (SIGXFSZ ignored).
    fn recover_cli_unwritable(
        &self,
        verb: &[&str],
        origin: Option<&str>,
    ) -> (i32, Vec<String>, String) {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
            .arg(env!("CARGO_BIN_EXE_rs-config-render"));
        self.recover_args(&mut command, verb, true, origin);
        self.recover_output(verb, command.output().unwrap())
    }

    fn recover_args(
        &self,
        command: &mut Command,
        verb: &[&str],
        apply: bool,
        origin: Option<&str>,
    ) {
        command.arg("recover").args(verb);
        self.binding_args(command);
        if apply {
            command.arg("--apply");
        }
        if let Some(origin) = origin {
            command
                .args(["--ixp-origin", origin, "--api-key-file"])
                .arg(&self.key)
                .args(["--request-timeout-seconds", "2", "--allow-http-loopback"]);
        }
    }

    fn recover_output(
        &self,
        verb: &[&str],
        output: std::process::Output,
    ) -> (i32, Vec<String>, String) {
        let prefix = format!("recover {}: ", verb[0]);
        let lines = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                line.strip_prefix(&prefix)
                    .unwrap_or_else(|| panic!("unprefixed line: {line}"))
                    .to_owned()
            })
            .collect();
        (
            output.status.code().unwrap(),
            lines,
            String::from_utf8(output.stderr).unwrap(),
        )
    }

    /// A second checked candidate (max_prefix 12 differs from the bootstrap).
    fn second_candidate(&self) -> PathBuf {
        let candidate = self.root.join("second");
        private_dir(&candidate);
        let mut input: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        input["clients"][0]["max_prefix"] = 12.into();
        ixp_manager::write_checked_candidate_bytes(
            &serde_json::to_vec(&input).unwrap(),
            &candidate,
            300,
            &self.checker,
            &self.binding.render_binding(),
        )
        .unwrap();
        candidate
    }

    /// `activate` through the binary, optionally under RLIMIT_FSIZE 0.
    fn activate_cli(&self, candidate: &Path, unwritable: bool) -> std::process::Output {
        let mut command = if unwritable {
            let mut shell = Command::new("/bin/sh");
            shell
                .args(["-c", "trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
                .arg(env!("CARGO_BIN_EXE_rs-config-render"));
            shell
        } else {
            Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        };
        command.args(["activate", "--candidate"]).arg(candidate);
        self.binding_args(&mut command);
        command
            .arg("--check-with")
            .arg(&self.checker)
            .arg("--rbgp")
            .arg(&self.rbgp)
            .args(["--settle-seconds", "2", "--activation-command"])
            .arg(&self.activation)
            .output()
            .unwrap()
    }

    fn runtime(&self) -> String {
        fs::read_to_string(self.root.join("runtime"))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn journal_value(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.journal()).unwrap()).unwrap()
    }

    fn receipt_value(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.receipt()).unwrap()).unwrap()
    }

    /// One failed `updated` callback after a successful activation: exit 6.
    fn induce_exit_6(&self) {
        let server = Server::start(vec![
            Response::json(200),
            Response::config(FIXTURE),
            Response::json(500),
        ]);
        assert_eq!(
            lifecycle::run(&self.options(&server.origin)),
            Err(LifecycleError::CallbackPending)
        );
        assert_request(&server.finish()[2], "POST", "updated");
    }

    fn binding_args(&self, command: &mut Command) {
        command
            .args(["--router-handle", HANDLE])
            .arg("--runtime-state-dir")
            .arg(&self.runtime)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--host-state-dir")
            .arg(&self.host)
            .arg("--rbgp-addr")
            .arg(self.binding.rbgp_addr());
    }

    /// `status` through the binary, asserting it changed nothing: the state,
    /// runtime, and host-state trees are byte-for-byte identical afterwards.
    fn status_cli(&self, probe: bool) -> (i32, BTreeMap<String, String>, String) {
        let before = snapshot(&self.root);
        let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
        command.arg("status");
        self.binding_args(&mut command);
        if probe {
            command.arg("--rbgp").arg(&self.rbgp);
        }
        let output = command.output().unwrap();
        assert_eq!(snapshot(&self.root), before, "status changed state");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let fields = stdout
            .lines()
            .map(|line| {
                let (key, value) = line
                    .split_once(": ")
                    .unwrap_or_else(|| panic!("not `key: value`: {line}"));
                (key.to_owned(), value.to_owned())
            })
            .collect();
        (
            output.status.code().unwrap(),
            fields,
            String::from_utf8(output.stderr).unwrap(),
        )
    }
}

/// Every path under `root` with its type, mode, and content (or link target),
/// excluding the fake executables' own logs.
fn snapshot(root: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<String, (u32, Vec<u8>)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if relative.ends_with(".log") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).unwrap();
            let mode = metadata.permissions().mode();
            let content = if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .into_os_string()
                    .into_encoded_bytes()
            } else if metadata.is_dir() {
                walk(root, &path, out);
                Vec::new()
            } else {
                fs::read(&path).unwrap()
            };
            out.insert(relative, (mode, content));
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

const STATUS_KEYS: [&str; 16] = [
    "fence",
    "journal",
    "phase",
    "callback",
    "callback_attempts",
    "activation_outcome",
    "error_class",
    "lock",
    "current",
    "candidate",
    "current_is_candidate",
    "advisory_receipt",
    "advisory_receipt_status",
    "advisory_receipt_previous_generation",
    "daemon",
    "runtime_equals_current",
];

fn assert_fields(fields: &BTreeMap<String, String>, expected: &[(&str, &str)]) {
    for (key, value) in expected {
        assert_eq!(
            fields.get(*key).map(String::as_str),
            Some(*value),
            "{key} in {fields:#?}"
        );
    }
}

#[test]
fn status_on_a_healthy_handle_reports_no_state_and_a_settled_daemon() {
    let _guard = test_guard();
    let rig = Rig::new();
    let current = rig.current();
    let (code, fields, stderr) = rig.status_cli(true);
    assert_eq!(code, 0, "{stderr}");
    let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
    let mut expected: Vec<&str> = STATUS_KEYS.to_vec();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(keys, expected, "status keys drifted");
    assert_fields(
        &fields,
        &[
            ("fence", "absent"),
            ("journal", "absent"),
            ("phase", "none"),
            ("callback", "none"),
            ("callback_attempts", "0"),
            ("activation_outcome", "none"),
            ("error_class", "none"),
            ("lock", "none"),
            ("current", &current),
            ("candidate", &current),
            ("current_is_candidate", "yes"),
            ("advisory_receipt", "matches-current"),
            ("advisory_receipt_status", "activated"),
            ("advisory_receipt_previous_generation", "none"),
            ("daemon", "healthy"),
            ("runtime_equals_current", "yes"),
        ],
    );
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("daemon", "not-probed"),
            ("runtime_equals_current", "unknown"),
        ],
    );
}

#[test]
fn status_reports_a_pending_callback_as_resumable_lifecycle_state() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    rig.induce_exit_6();
    let current = rig.current();
    assert_ne!(current, previous);
    let (code, fields, _) = rig.status_cli(true);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("fence", "present"),
            ("journal", "present"),
            ("phase", "updated_pending"),
            ("callback", "updated"),
            ("callback_attempts", "1"),
            ("activation_outcome", "activated"),
            ("error_class", "none"),
            ("lock", "retained"),
            ("current", &current),
            ("candidate", &current),
            ("current_is_candidate", "yes"),
            ("advisory_receipt", "matches-current"),
            ("advisory_receipt_status", "activated"),
            ("advisory_receipt_previous_generation", &previous),
            ("daemon", "healthy"),
            ("runtime_equals_current", "yes"),
        ],
    );
}

#[test]
fn status_reports_manual_recovery_with_the_candidate_live() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    rig.induce_exit_5("load-then-fail", vec![]);
    let current = rig.current();
    assert_ne!(current, previous);
    let (code, fields, _) = rig.status_cli(true);
    assert_eq!(code, 0, "manual recovery is a report, not an error");
    assert_fields(
        &fields,
        &[
            ("fence", "present"),
            ("journal", "present"),
            ("phase", "manual_recovery"),
            ("callback", "none"),
            ("callback_attempts", "0"),
            ("activation_outcome", "recovery_required"),
            ("error_class", "activation"),
            ("lock", "retained"),
            ("current", &current),
            ("candidate", &current),
            ("current_is_candidate", "yes"),
            ("advisory_receipt", "matches-current"),
            ("advisory_receipt_status", "recovery_required"),
            ("advisory_receipt_previous_generation", &previous),
            ("daemon", "healthy"),
            ("runtime_equals_current", "yes"),
        ],
    );
}

#[test]
fn status_reports_manual_recovery_with_the_candidate_not_live() {
    let _guard = test_guard();
    let rig = Rig::new();
    rig.induce_exit_5("fail", vec![]);
    let (code, fields, _) = rig.status_cli(true);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("phase", "manual_recovery"),
            ("lock", "retained"),
            ("current_is_candidate", "yes"),
            ("daemon", "healthy"),
            ("runtime_equals_current", "no"),
        ],
    );
    rig.set("health-mode", "unhealthy");
    let (_, fields, _) = rig.status_cli(true);
    assert_fields(
        &fields,
        &[("daemon", "unhealthy"), ("runtime_equals_current", "no")],
    );
    rig.set("health-mode", "down");
    let (_, fields, _) = rig.status_cli(true);
    assert_fields(
        &fields,
        &[
            ("daemon", "unreachable"),
            ("runtime_equals_current", "unknown"),
        ],
    );
}

#[test]
fn status_marks_an_absent_or_stale_receipt_and_still_names_the_candidate() {
    let _guard = test_guard();
    let rig = Rig::new();
    let bootstrap_receipt = fs::read(rig.receipt()).unwrap();
    rig.induce_exit_5("fail", vec![]);
    let current = rig.current();
    fs::remove_file(rig.receipt()).unwrap();
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("advisory_receipt", "absent"),
            ("advisory_receipt_status", "none"),
            ("advisory_receipt_previous_generation", "none"),
            ("candidate", &current),
            ("current_is_candidate", "yes"),
        ],
    );
    // The previous run's receipt survived an unlanded final write.
    fs::write(rig.receipt(), &bootstrap_receipt).unwrap();
    mode(&rig.receipt(), 0o600);
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("advisory_receipt", "stale"),
            ("advisory_receipt_status", "activated"),
            ("candidate", &current),
            ("current_is_candidate", "yes"),
        ],
    );
    fs::write(rig.receipt(), b"{not json").unwrap();
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(&fields, &[("advisory_receipt", "unreadable")]);
}

#[test]
fn status_reports_an_ambiguous_lock_request_as_no_candidate_and_unknown_lock() {
    let _guard = test_guard();
    let rig = Rig::new();
    let current = rig.current();
    let server = Server::start(vec![Response::json(500)]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(LifecycleError::ManualRecovery)
    );
    server.finish();
    let (code, fields, _) = rig.status_cli(true);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("fence", "present"),
            ("phase", "manual_recovery"),
            ("activation_outcome", "none"),
            ("error_class", "status"),
            ("lock", "unknown"),
            ("current", &current),
            ("candidate", "none"),
            ("current_is_candidate", "no"),
            ("advisory_receipt", "matches-current"),
            ("daemon", "healthy"),
            ("runtime_equals_current", "yes"),
        ],
    );
}

#[test]
fn status_distinguishes_foreign_and_unreadable_fences_and_journals() {
    let _guard = test_guard();
    let rig = Rig::new();
    let foreign_runtime = rig.root.join("foreign-ipv4");
    private_dir(&foreign_runtime);
    let foreign_state = foreign_runtime.join("activation");
    private_dir(&foreign_state);
    let foreign = Binding::new(
        "foreign-ipv4",
        &foreign_runtime,
        &foreign_state,
        &rig.host,
        &format!("unix://{}/grpc.sock", foreign_runtime.display()),
    )
    .unwrap();
    let held = Guard::claim_new(&foreign).unwrap();
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(&fields, &[("fence", "foreign"), ("journal", "absent")]);
    held.clear().unwrap();
    drop(held);
    fs::write(rig.fence(), b"{}").unwrap();
    mode(&rig.fence(), 0o644);
    fs::write(rig.journal(), b"{}").unwrap();
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("fence", "unreadable"),
            ("journal", "unreadable"),
            ("phase", "none"),
            ("lock", "none"),
        ],
    );
}

#[test]
fn status_exits_1_for_an_unreadable_state_directory_and_2_for_a_bad_binding() {
    let _guard = test_guard();
    let rig = Rig::new();
    fs::remove_dir_all(&rig.state).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
    command.arg("status");
    rig.binding_args(&mut command);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "rs-config-render: status: state directory is not a readable directory\n"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["status", "--router-handle", HANDLE])
        .arg("--runtime-state-dir")
        .arg(&rig.runtime)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--host-state-dir")
        .arg(&rig.host)
        .args(["--rbgp-addr", "unix:///wrong/grpc.sock"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

fn keep_args(rig: &Rig) -> Vec<String> {
    vec![
        "keep-current".into(),
        "--rbgp".into(),
        rig.rbgp.display().to_string(),
    ]
}

fn rollback_args(rig: &Rig) -> Vec<String> {
    vec![
        "rollback".into(),
        "--rbgp".into(),
        rig.rbgp.display().to_string(),
        "--settle-seconds".into(),
        "2".into(),
        "--activation-command".into(),
        rig.activation.display().to_string(),
    ]
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn every_recover_verb_refuses_outside_manual_recovery() {
    let _guard = test_guard();
    let rig = Rig::new();
    let keep = keep_args(&rig);
    let rollback = rollback_args(&rig);
    let verbs: [&[&str]; 4] = [
        &strs(&keep),
        &strs(&rollback),
        &["release-lock", "--kept"],
        &["clear"],
    ];
    // Healthy handle: no fence, nothing to recover.
    for verb in verbs {
        for apply in [false, true] {
            let (code, lines, stderr) = rig.recover_cli(verb, apply, None);
            assert_eq!(code, 2, "{verb:?}: {stderr}");
            assert!(lines.is_empty());
            assert_eq!(
                stderr,
                format!(
                    "rs-config-render: recover {}: no host fence for this binding; nothing to recover\n",
                    verb[0]
                )
            );
        }
    }
    // Exit 6: the fence stands but the journal is resumable, not manual recovery.
    let rig = Rig::new();
    rig.induce_exit_6();
    for verb in verbs {
        let (code, _, stderr) = rig.recover_cli(verb, true, Some("http://127.0.0.1:9"));
        assert_eq!(code, 2, "{verb:?}: {stderr}");
        assert!(
            stderr.contains("lifecycle state is resumable, not manual recovery"),
            "{stderr}"
        );
    }
    assert!(rig.journal().exists());
    assert!(rig.fence().exists());
}

#[test]
fn dry_runs_change_nothing_and_apply_performs_exactly_the_printed_steps() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    let server = rig.induce_exit_5("load-then-fail", vec![Response::json(200)]);
    let candidate = rig.current();
    let keep = keep_args(&rig);
    // Without the connection a journal-holding recovery refuses before planning.
    let (code, _, stderr) = rig.recover_cli(&strs(&keep), false, None);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("pass --ixp-origin and --api-key-file"),
        "{stderr}"
    );
    let (code, dry, stderr) = rig.recover_cli(&strs(&keep), false, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        dry,
        vec![
            "probe: daemon healthy, runtime equals current".to_owned(),
            format!(
                "write activation receipt: status kept, candidate {}, previous {previous}",
                candidate.strip_prefix("generations/").unwrap()
            ),
            format!(
                "deliver updated callback to {} for {HANDLE} (attempt 1)",
                server.origin
            ),
            "remove lifecycle journal".to_owned(),
            "remove host fence".to_owned(),
            "dry run — 5 step(s) planned; pass --apply to perform them".to_owned(),
        ]
    );
    assert!(rig.journal().exists() && rig.fence().exists());
    let (code, applied, stderr) = rig.recover_cli(&strs(&keep), true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        applied[..5],
        dry[..5],
        "--apply must do what the dry run printed"
    );
    assert_eq!(applied[5], "applied 5 step(s)");
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[2], "POST", "updated");
    assert!(!rig.journal().exists());
    assert!(!rig.fence().exists());
    assert_eq!(rig.current(), candidate);
    let receipt = rig.receipt_value();
    assert_eq!(receipt["status"], "kept");
    assert_eq!(
        format!(
            "generations/{}",
            receipt["candidate_sha256"].as_str().unwrap()
        ),
        candidate
    );
    assert_eq!(receipt["previous_generation"], previous);
    assert_eq!(receipt["phases"]["runtime_equal"], true);
    // The handle is usable again: status is clean and a new lifecycle runs.
    let (_, fields, _) = rig.status_cli(true);
    assert_fields(
        &fields,
        &[
            ("fence", "absent"),
            ("journal", "absent"),
            ("advisory_receipt", "matches-current"),
            ("advisory_receipt_status", "kept"),
            ("runtime_equals_current", "yes"),
        ],
    );
    fs::remove_dir_all(&rig.candidate).unwrap();
    private_dir(&rig.candidate);
    let again = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(200),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&again.origin)),
        Ok(lifecycle::Status::Noop)
    );
    again.finish();
}

#[test]
fn keep_current_is_health_gated_unless_forced() {
    let _guard = test_guard();
    let rig = Rig::new();
    let server = rig.induce_exit_5("fail", vec![Response::json(200)]);
    let keep = keep_args(&rig);
    // The daemon still runs the previous generation: not settled on current.
    let (code, lines, stderr) = rig.recover_cli(&strs(&keep), true, Some(&server.origin));
    assert_eq!(code, 2);
    assert!(lines.is_empty());
    assert!(
        stderr.contains("daemon is not settled on current"),
        "{stderr}"
    );
    assert!(rig.journal().exists() && rig.fence().exists());
    rig.set("health-mode", "down");
    let (code, _, stderr) = rig.recover_cli(&strs(&keep), true, Some(&server.origin));
    assert_eq!(code, 2, "{stderr}");
    rig.set("health-mode", "ok");
    let mut forced = keep.clone();
    forced.push("--force".into());
    let (code, lines, stderr) = rig.recover_cli(&strs(&forced), true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        lines[0],
        "probe: daemon healthy, runtime differs from current (overridden by --force)"
    );
    assert_request(&server.finish()[2], "POST", "updated");
    assert!(!rig.journal().exists() && !rig.fence().exists());
    assert_eq!(rig.receipt_value()["phases"]["runtime_equal"], false);
}

#[test]
fn rollback_re_stages_the_previous_generation_through_the_activation_path() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    let server = rig.induce_exit_5("fail", vec![Response::json(200)]);
    let candidate = rig.current();
    assert_eq!(
        rig.runtime(),
        previous,
        "the failed activation loaded nothing"
    );
    let rollback = rollback_args(&rig);
    let (code, dry, stderr) = rig.recover_cli(&strs(&rollback), false, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        dry[0],
        format!(
            "re-point current {candidate} -> {previous}, run `{}`, settle within 2s",
            rig.activation.display()
        )
    );
    assert_eq!(
        dry[1],
        format!(
            "deliver release-update-lock callback to {} for {HANDLE} (attempt 1)",
            server.origin
        )
    );
    assert_eq!(
        dry[2..],
        [
            "remove lifecycle journal",
            "remove host fence",
            "dry run — 4 step(s) planned; pass --apply to perform them"
        ]
    );
    let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
    let (code, applied, stderr) = rig.recover_cli(&strs(&rollback), true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(applied[..4], dry[..4]);
    assert_eq!(rig.current(), previous);
    assert_eq!(
        rig.runtime(),
        previous,
        "the activation command ran and the daemon loaded it"
    );
    assert_eq!(
        fs::read_to_string(rig.root.join("activation.log")).unwrap(),
        format!("{activations}{previous}\n"),
        "exactly one activation command run"
    );
    assert_request(&server.finish()[2], "POST", "release-update-lock");
    assert!(!rig.journal().exists() && !rig.fence().exists());
    let receipt = rig.receipt_value();
    assert_eq!(receipt["status"], "rolled_back");
    assert_eq!(
        format!(
            "generations/{}",
            receipt["candidate_sha256"].as_str().unwrap()
        ),
        candidate
    );
    assert_eq!(receipt["previous_generation"], previous);
    assert_eq!(receipt["phases"]["rollback_activation_ran"], true);
    assert_eq!(receipt["phases"]["runtime_equal"], true);
    let (_, fields, _) = rig.status_cli(true);
    assert_fields(
        &fields,
        &[
            ("fence", "absent"),
            ("current", &previous),
            ("daemon", "healthy"),
            ("runtime_equals_current", "yes"),
        ],
    );
}

#[test]
fn rollback_needs_a_known_target_and_refuses_when_nothing_was_activated() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    let server = rig.induce_exit_5("fail", vec![Response::json(200)]);
    let candidate = rig.current();
    let rollback = rollback_args(&rig);
    // A stale receipt cannot name the previous generation: --to is required.
    fs::remove_file(rig.receipt()).unwrap();
    let (code, _, stderr) = rig.recover_cli(&strs(&rollback), true, Some(&server.origin));
    assert_eq!(code, 2);
    assert!(
        stderr.contains("pass --to generations/<digest>"),
        "{stderr}"
    );
    let mut explicit = rollback.clone();
    explicit.extend(["--to".to_owned(), candidate.clone()]);
    let (code, _, stderr) = rig.recover_cli(&strs(&explicit), true, Some(&server.origin));
    assert_eq!(code, 2);
    assert!(
        stderr.contains("rollback target is the current generation"),
        "{stderr}"
    );
    let mut bogus = rollback.clone();
    bogus.extend(["--to".to_owned(), format!("generations/{}", "0".repeat(64))]);
    let (code, _, stderr) = rig.recover_cli(&strs(&bogus), true, Some(&server.origin));
    assert_eq!(code, 2);
    assert!(stderr.contains("not a published generation"), "{stderr}");
    explicit.pop();
    explicit.push(previous.clone());
    let (code, _, stderr) = rig.recover_cli(&strs(&explicit), true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(rig.current(), previous);
    server.finish();

    // An ambiguous lock request staged nothing: rollback refuses, keep-current
    // releases rather than claiming an update.
    let rig = Rig::new();
    let server = Server::start(vec![Response::json(500), Response::json(200)]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(LifecycleError::ManualRecovery)
    );
    let rollback = rollback_args(&rig);
    let (code, _, stderr) = rig.recover_cli(&strs(&rollback), true, Some(&server.origin));
    assert_eq!(code, 2);
    assert!(stderr.contains("no candidate was activated"), "{stderr}");
    let keep = keep_args(&rig);
    let (code, lines, stderr) = rig.recover_cli(&strs(&keep), true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert!(
        lines[2].starts_with("deliver release-update-lock callback"),
        "{lines:?}"
    );
    assert_request(&server.finish()[1], "POST", "release-update-lock");
    assert!(!rig.journal().exists() && !rig.fence().exists());
}

#[test]
fn release_lock_is_retryable_and_clear_waits_for_it() {
    let _guard = test_guard();
    let rig = Rig::new();
    let server = rig.induce_exit_5(
        "load-then-fail",
        vec![Response::json(500), Response::json(200)],
    );
    // clear refuses while the journal still owes the lock.
    let (code, _, stderr) = rig.recover_cli(&["clear"], true, None);
    assert_eq!(code, 2);
    assert!(stderr.contains("upstream lock still owed"), "{stderr}");
    // release-lock needs the connection and a direction.
    let (code, _, stderr) = rig.recover_cli(&["release-lock", "--kept"], true, None);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("pass --ixp-origin and --api-key-file"),
        "{stderr}"
    );
    let (code, dry, _) = rig.recover_cli(&["release-lock", "--kept"], false, Some(&server.origin));
    assert_eq!(code, 0);
    assert_eq!(
        dry,
        vec![
            format!(
                "deliver updated callback to {} for {HANDLE} (attempt 1)",
                server.origin
            ),
            "mark the upstream lock released in the lifecycle journal".to_owned(),
            "dry run — 2 step(s) planned; pass --apply to perform them".to_owned(),
        ]
    );
    // First delivery fails (injected 500): exit 5, intent journaled, retry named.
    let (code, lines, stderr) =
        rig.recover_cli(&["release-lock", "--kept"], true, Some(&server.origin));
    assert_eq!(code, 5, "{stderr}");
    assert!(lines.is_empty(), "{lines:?}");
    assert!(
        stderr.contains("updated callback was not delivered; upstream lock retained — retry with recover release-lock --kept"),
        "{stderr}"
    );
    let journal = rig.journal_value();
    assert_eq!(journal["callback"], "updated");
    assert_eq!(journal["callback_attempts"], 1);
    assert_eq!(journal["lock_released"], false);
    assert_eq!(journal["phase"], "manual_recovery");
    let (code, _, stderr) = rig.recover_cli(&["clear"], true, None);
    assert_eq!(code, 2, "{stderr}");
    // Retry succeeds; the journal records delivery and stays for clear.
    let (code, lines, stderr) =
        rig.recover_cli(&["release-lock", "--kept"], true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        lines[0],
        format!(
            "deliver updated callback to {} for {HANDLE} (attempt 2)",
            server.origin
        )
    );
    let origin = server.origin.clone();
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert_request(&requests[2], "POST", "updated");
    assert_request(&requests[3], "POST", "updated");
    let journal = rig.journal_value();
    assert_eq!(journal["callback_attempts"], 2);
    assert_eq!(journal["lock_released"], true);
    assert!(rig.fence().exists());
    let (_, fields, _) = rig.status_cli(false);
    assert_fields(
        &fields,
        &[("lock", "released"), ("phase", "manual_recovery")],
    );
    // keep-current and rollback now defer to clear.
    let keep = keep_args(&rig);
    let (code, _, stderr) = rig.recover_cli(&strs(&keep), true, Some(&origin));
    assert_eq!(code, 2);
    assert!(
        stderr.contains("upstream lock already released; run recover clear"),
        "{stderr}"
    );
    let (code, dry, _) = rig.recover_cli(&["clear"], false, None);
    assert_eq!(code, 0);
    assert_eq!(
        dry,
        [
            "remove lifecycle journal",
            "remove host fence",
            "dry run — 2 step(s) planned; pass --apply to perform them"
        ]
    );
    let (code, applied, stderr) = rig.recover_cli(&["clear"], true, None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(applied[..2], dry[..2]);
    assert!(!rig.journal().exists() && !rig.fence().exists());
}

#[test]
fn a_plain_activate_exit_5_recovers_without_a_journal_or_connection() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    // A second candidate through the bare activation path, failing after the
    // command started: exit 5 with a fence and no journal.
    let candidate = rig.second_candidate();
    rig.set("activation-mode", "fail");
    assert_eq!(
        activation::activate(&activation::Options {
            candidate: &candidate,
            state_dir: &rig.state,
            checker: &rig.checker,
            rbgp: &rig.rbgp,
            rbgp_addr: rig.binding.rbgp_addr(),
            settle: Duration::from_secs(2),
            initial: false,
            activation_command: &rig.activation,
            activation_args: &[],
            binding: &rig.binding,
        }),
        Err(activation::Error::RecoveryRequired)
    );
    rig.set("activation-mode", "ok");
    assert!(rig.fence().exists() && !rig.journal().exists());
    let (_, fields, _) = rig.status_cli(true);
    assert_fields(
        &fields,
        &[
            ("fence", "present"),
            ("journal", "absent"),
            ("lock", "none"),
            ("current_is_candidate", "yes"),
            ("runtime_equals_current", "no"),
        ],
    );
    // release-lock has nothing to release; clear is allowed (no lock owed)
    // but the runbook's choice is rollback here.
    let (code, _, stderr) = rig.recover_cli(&["release-lock", "--rolled-back"], true, None);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("no lifecycle journal; no upstream lock is owed"),
        "{stderr}"
    );
    let (code, dry, _) = rig.recover_cli(&["clear"], false, None);
    assert_eq!(code, 0);
    assert_eq!(dry[0], "remove host fence");
    let rollback = rollback_args(&rig);
    let (code, lines, stderr) = rig.recover_cli(&strs(&rollback), true, None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[1], "remove host fence");
    assert_eq!(rig.current(), previous);
    assert_eq!(rig.runtime(), previous);
    assert!(!rig.fence().exists());
}

#[test]
fn a_rollback_that_does_not_settle_exits_5_with_current_on_the_target() {
    let _guard = test_guard();
    let rig = Rig::new();
    let previous = rig.current();
    // The daemon loaded the candidate before the command failed.
    let server = rig.induce_exit_5("load-then-fail", vec![Response::json(200)]);
    let candidate = rig.current();
    assert_eq!(rig.runtime(), candidate);
    // Rollback re-points current and runs the command, which loads nothing.
    rig.set("activation-mode", "fail");
    let rollback = rollback_args(&rig);
    let (code, lines, stderr) = rig.recover_cli(&strs(&rollback), true, Some(&server.origin));
    rig.set("activation-mode", "ok");
    assert_eq!(code, 5, "{stderr}");
    assert!(lines.is_empty(), "no step completed: {lines:?}");
    assert!(
        stderr.contains(
            "rollback did not settle: current is re-pointed but the daemon did not prove it; inspect with status"
        ),
        "{stderr}"
    );
    assert_eq!(rig.current(), previous, "current is on the rollback target");
    assert_eq!(
        rig.runtime(),
        candidate,
        "the daemon still runs the candidate"
    );
    // The receipt records the unsettled rollback of the candidate …
    let receipt = rig.receipt_value();
    assert_eq!(receipt["status"], "recovery_required");
    assert_eq!(
        format!(
            "generations/{}",
            receipt["candidate_sha256"].as_str().unwrap()
        ),
        candidate
    );
    assert_eq!(receipt["previous_generation"], previous);
    assert_eq!(receipt["phases"]["rollback_link"]["published"], true);
    assert_eq!(receipt["phases"]["rollback_activation_ran"], true);
    assert_eq!(receipt["phases"]["runtime_equal"], false);
    // … fence and journal stay, no callback was attempted …
    assert!(rig.fence().exists() && rig.journal().exists());
    let journal = rig.journal_value();
    assert_eq!(journal["phase"], "manual_recovery");
    assert_eq!(journal["callback"], serde_json::Value::Null);
    assert_eq!(journal["callback_attempts"], 0);
    assert_eq!(journal["lock_released"], false);
    assert_eq!(server.requests.lock().unwrap().len(), 2);
    // … and status reports exactly that state.
    let (code, fields, _) = rig.status_cli(true);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("fence", "present"),
            ("journal", "present"),
            ("phase", "manual_recovery"),
            ("callback", "none"),
            ("lock", "retained"),
            ("current", &previous),
            ("candidate", &candidate),
            ("current_is_candidate", "no"),
            ("advisory_receipt", "stale"),
            ("advisory_receipt_status", "recovery_required"),
            ("advisory_receipt_previous_generation", &previous),
            ("daemon", "healthy"),
            ("runtime_equals_current", "no"),
        ],
    );
    // The lock is still owed and release-lock + clear settle the state.
    let (code, _, stderr) = rig.recover_cli(
        &["release-lock", "--rolled-back"],
        true,
        Some(&server.origin),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_request(&server.finish()[2], "POST", "release-update-lock");
    let (code, _, stderr) = rig.recover_cli(&["clear"], true, None);
    assert_eq!(code, 0, "{stderr}");
    assert!(!rig.journal().exists() && !rig.fence().exists());
    assert_eq!(rig.current(), previous);
}

#[test]
fn a_journal_write_failure_before_the_callback_exits_5_and_sends_nothing() {
    let _guard = test_guard();
    let rig = Rig::new();
    let server = rig.induce_exit_5("load-then-fail", vec![Response::json(200)]);
    let before = rig.journal_value();
    // The intent write that precedes the request cannot land.
    let (code, lines, stderr) =
        rig.recover_cli_unwritable(&["release-lock", "--kept"], Some(&server.origin));
    assert_eq!(code, 5, "{stderr}");
    assert!(lines.is_empty(), "{lines:?}");
    assert!(
        stderr.contains("lifecycle journal could not be written"),
        "{stderr}"
    );
    assert_eq!(rig.journal_value(), before, "journal unchanged");
    assert_eq!(
        server.requests.lock().unwrap().len(),
        2,
        "no callback without a journaled intent"
    );
    assert!(rig.fence().exists());
    assert!(
        fs::read_dir(&rig.state).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ixp-manager-lifecycle.json.")
        }),
        "journal staging file left behind"
    );
    let (_, fields, _) = rig.status_cli(false);
    assert_fields(
        &fields,
        &[
            ("phase", "manual_recovery"),
            ("callback", "none"),
            ("callback_attempts", "0"),
            ("lock", "retained"),
        ],
    );
    // The same verb, writable again, journals the intent and delivers.
    let (code, lines, stderr) =
        rig.recover_cli(&["release-lock", "--kept"], true, Some(&server.origin));
    assert_eq!(code, 0, "{stderr}");
    assert!(lines[0].ends_with("(attempt 1)"), "{lines:?}");
    assert_request(&server.finish()[2], "POST", "updated");
    let journal = rig.journal_value();
    assert_eq!(journal["callback_attempts"], 1);
    assert_eq!(journal["lock_released"], true);
}

#[test]
fn a_fence_write_failure_exits_5_and_leaves_a_fence_only_a_hand_can_clear() {
    let _guard = test_guard();
    let rig = Rig::new();
    let current = rig.current();
    let candidate = rig.second_candidate();
    // The fence is created but its bytes cannot land: exit 5 before anything
    // else happened.
    let output = rig.activate_cli(&candidate, true);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert_eq!(rig.current(), current);
    assert_eq!(
        fs::read_dir(rig.state.join("generations")).unwrap().count(),
        1,
        "nothing was staged"
    );
    assert!(!rig.journal().exists());
    assert_eq!(fs::metadata(rig.fence()).unwrap().len(), 0);
    let (code, fields, _) = rig.status_cli(false);
    assert_eq!(code, 0);
    assert_fields(
        &fields,
        &[
            ("fence", "unreadable"),
            ("journal", "absent"),
            ("current", &current),
            ("advisory_receipt", "matches-current"),
        ],
    );
    // Every recover verb refuses to act on a fence it cannot read …
    let keep = keep_args(&rig);
    let rollback = rollback_args(&rig);
    let verbs: [&[&str]; 4] = [
        &strs(&keep),
        &strs(&rollback),
        &["release-lock", "--rolled-back"],
        &["clear"],
    ];
    for verb in verbs {
        let (code, lines, stderr) = rig.recover_cli(verb, true, None);
        assert_eq!(code, 2, "{verb:?}: {stderr}");
        assert!(lines.is_empty());
        assert!(
            stderr.contains("host fence is unreadable; inspect it before recovering"),
            "{stderr}"
        );
    }
    // … and every later activation is fenced out (exit 5, nothing changed) …
    let output = rig.activate_cli(&candidate, false);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert_eq!(rig.current(), current);
    assert_eq!(fs::metadata(rig.fence()).unwrap().len(), 0);
    // … until the fence is removed by hand.
    fs::remove_file(rig.fence()).unwrap();
    let output = rig.activate_cli(&candidate, false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_ne!(rig.current(), current);
    assert!(!rig.fence().exists());
}
