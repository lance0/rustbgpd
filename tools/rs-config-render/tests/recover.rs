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
    fn induce_exit_5(&self, activation_mode: &str) {
        self.set("activation-mode", activation_mode);
        let server = Server::start(vec![Response::json(200), Response::config(FIXTURE)]);
        assert_eq!(
            lifecycle::run(&self.options(&server.origin)),
            Err(LifecycleError::ManualRecovery)
        );
        assert_eq!(server.finish().len(), 2, "exit 5 must not callback");
        self.set("activation-mode", "ok");
        assert!(self.fence().exists());
        assert!(self.journal().exists());
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
    rig.induce_exit_5("load-then-fail");
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
    rig.induce_exit_5("fail");
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
    rig.induce_exit_5("fail");
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
