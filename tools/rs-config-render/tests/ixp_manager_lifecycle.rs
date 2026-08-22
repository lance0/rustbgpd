#![cfg(unix)]

use std::fs::{self, File};
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
use rs_config_render::ixp_manager_host::{Binding, Guard, RenderBinding};
use rs_config_render::ixp_manager_lifecycle::{self as lifecycle, Error, Status};

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v2-supported.json");
const V1_FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const API_KEY: &str = "lifecycle-api-key-must-not-leak";
// Serialize the binary: a foreign child can inherit another test's flock descriptor.
static LIFECYCLE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lifecycle_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = LIFECYCLE_TEST_LOCK.lock();
    guard.unwrap_or_else(|error| error.into_inner())
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
    location: Option<String>,
    expected_state: Option<(PathBuf, &'static str)>,
    delay: Option<Duration>,
    chmod_before_reply: Option<(PathBuf, u32)>,
}

impl Response {
    fn json(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: br#"{"last_update_started":"2026-08-20T00:00:00+00:00","last_update_started_unix":1787184000,"last_updated":null,"last_updated_unix":null}"#.to_vec(),
            location: None,
            expected_state: None,
            delay: None,
            chmod_before_reply: None,
        }
    }

    fn config(body: &[u8]) -> Self {
        Self {
            status: 200,
            content_type: "text/plain; charset=UTF-8",
            body: body.to_vec(),
            location: None,
            expected_state: None,
            delay: None,
            chmod_before_reply: None,
        }
    }

    fn after_state_contains(mut self, path: PathBuf, expected: &'static str) -> Self {
        self.expected_state = Some((path, expected));
        self
    }

    fn after_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    fn after_chmod(mut self, path: PathBuf, permissions: u32) -> Self {
        self.chmod_before_reply = Some((path, permissions));
        self
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
            let mut writers = Vec::new();
            for response in responses {
                let (stream, _) = listener.accept().unwrap();
                let request = read_request(&stream);
                captured.lock().unwrap().push(request);
                if let Some((path, expected)) = &response.expected_state {
                    let state = fs::read_to_string(path).unwrap();
                    assert!(
                        state.contains(expected),
                        "request arrived before durable state {expected}: {state}"
                    );
                }
                if let Some((path, permissions)) = &response.chmod_before_reply {
                    mode(path, *permissions);
                }
                writers.push(thread::spawn(move || {
                    let mut stream = stream;
                    if let Some(delay) = response.delay {
                        thread::sleep(delay);
                    }
                    stream
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let reason = match response.status {
                        200 => "OK",
                        302 => "Found",
                        423 => "Locked",
                        500 => "Server Error",
                        _ => "Error",
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.status,
                        response.content_type,
                        response.body.len()
                    );
                    if let Some(location) = response.location {
                        let _ = write!(stream, "Location: {location}\r\n");
                    }
                    let _ = write!(stream, "\r\n");
                    let _ = stream.write_all(&response.body);
                }));
            }
            for writer in writers {
                writer.join().unwrap();
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
    fn new() -> Self {
        let current = std::env::current_dir().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("ixp-lifecycle-")
            .tempdir_in(current)
            .unwrap();
        let root = temp.path().to_path_buf();
        let runtime = root.join("b2-rs1-lan1-ipv4");
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
        let checker = root.join("rustbgpd");
        executable(
            &checker,
            "#!/bin/sh\n[ \"$1\" = --version ] && { echo 'rustbgpd 0.65.0'; exit 0; }\nexit 0\n",
        );
        let rbgp = root.join("rbgp");
        executable(
            &rbgp,
            &format!(
                "#!/bin/sh\ncase \"$*\" in\n  *' health')\n    if [ -L {state}/current ]; then echo '{{\"healthy\":true}}'; exit 0; fi\n    echo 'Error: cannot reach rustbgpd at test (connection refused)' >&2; exit 1;;\nesac\nexit 0\n",
                state = state.display()
            ),
        );
        let activation = root.join("activate");
        executable(&activation, "#!/bin/sh\nexit 0\n");
        let binding = Binding::new(
            "b2-rs1-lan1-ipv4",
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
        let binding = self.binding();
        let render_binding = binding.render_binding();
        ixp_manager::write_checked_candidate_bytes(
            FIXTURE,
            &candidate,
            300,
            &self.checker,
            &render_binding,
        )
        .unwrap();
        assert_eq!(
            activation::activate(&activation::Options {
                candidate: &candidate,
                state_dir: &self.state,
                checker: &self.checker,
                rbgp: &self.rbgp,
                rbgp_addr: binding.rbgp_addr(),
                settle: Duration::from_secs(2),
                initial: true,
                activation_command: &self.activation,
                activation_args: &[],
                binding,
            }),
            Ok(activation::Status::Activated)
        );
    }

    fn binding(&self) -> &Binding {
        &self.binding
    }

    fn options<'a>(&'a self, origin: &'a str) -> lifecycle::Options<'a> {
        lifecycle::Options {
            ixp_origin: origin,
            router_handle: "b2-rs1-lan1-ipv4",
            api_key_file: &self.key,
            candidate_dir: &self.candidate,
            state_dir: &self.state,
            checker: &self.checker,
            max_prefix_restart_seconds: 300,
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

    fn resume_options<'a>(&'a self, origin: &'a str) -> lifecycle::ResumeOptions<'a> {
        lifecycle::ResumeOptions {
            ixp_origin: origin,
            router_handle: "b2-rs1-lan1-ipv4",
            api_key_file: &self.key,
            state_dir: &self.state,
            timeout: Duration::from_secs(2),
            allow_http_loopback: true,
            binding: &self.binding,
        }
    }
}

fn run_cli(rig: &Rig, origin: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
    command
        .args([
            "ixp-manager-lifecycle",
            "run",
            "--ixp-origin",
            origin,
            "--router-handle",
            "b2-rs1-lan1-ipv4",
            "--api-key-file",
        ])
        .arg(&rig.key)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--runtime-state-dir")
        .arg(&rig.runtime)
        .arg("--host-state-dir")
        .arg(&rig.host)
        .arg("--rbgp-addr")
        .arg(rig.binding.rbgp_addr())
        .arg("--candidate-dir")
        .arg(&rig.candidate)
        .arg("--check-with")
        .arg(&rig.checker)
        .args(["--max-prefix-restart-seconds", "300", "--rbgp"])
        .arg(&rig.rbgp)
        .args(["--settle-seconds", "2", "--activation-command"])
        .arg(&rig.activation)
        .args(["--request-timeout-seconds", "30", "--allow-http-loopback"]);
    command
}

fn assert_request(request: &str, method: &str, action: &str) {
    let lower = request.to_ascii_lowercase();
    assert!(
        request.starts_with(&format!(
            "{method} /admin/api/v4/router/{action}/b2-rs1-lan1-ipv4 HTTP/1.1\r\n"
        )),
        "unexpected request: {request}"
    );
    assert!(lower.contains(&format!(
        "\r\nx-ixp-manager-api-key: {}\r\n",
        API_KEY.to_ascii_lowercase()
    )));
}

fn assert_no_key(path: &Path) {
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            assert_no_key(&entry.unwrap().path());
        }
    } else if path.is_file() {
        assert!(
            !fs::read(path)
                .unwrap()
                .windows(API_KEY.len())
                .any(|window| window == API_KEY.as_bytes()),
            "API key leaked to {}",
            path.display()
        );
    }
}

#[test]
fn noop_lifecycle_uses_exact_authenticated_order_and_acknowledges() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(200),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Ok(Status::Noop)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "POST", "get-update-lock");
    assert_request(&requests[1], "GET", "gen-config");
    assert_request(&requests[2], "POST", "updated");
    assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());
    assert_no_key(&rig.state);
    assert_no_key(&rig.candidate);
}

#[test]
fn definite_lock_and_render_failures_have_bounded_release_semantics() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let unavailable = Server::start(vec![Response::json(423)]);
    assert!(matches!(
        lifecycle::run(&rig.options(&unavailable.origin)),
        Err(Error::Refused(_))
    ));
    let requests = unavailable.finish();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST", "get-update-lock");
    assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());

    let rejected = Server::start(vec![
        Response::json(200),
        Response::config(br#"{}"#),
        Response::json(200).after_state_contains(
            rig.state.join("ixp-manager-lifecycle.json"),
            "release_pending",
        ),
    ]);
    assert!(matches!(
        lifecycle::run(&rig.options(&rejected.origin)),
        Err(Error::Refused(_))
    ));
    let requests = rejected.finish();
    assert_request(&requests[0], "POST", "get-update-lock");
    assert_request(&requests[1], "GET", "gen-config");
    assert_request(&requests[2], "POST", "release-update-lock");
    assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());

    let rig = Rig::new();
    let v1 = Server::start(vec![
        Response::json(200),
        Response::config(V1_FIXTURE),
        Response::json(200),
    ]);
    assert!(matches!(
        lifecycle::run(&rig.options(&v1.origin)),
        Err(Error::Refused(_))
    ));
    let requests = v1.finish();
    assert_request(&requests[0], "POST", "get-update-lock");
    assert_request(&requests[1], "GET", "gen-config");
    assert_request(&requests[2], "POST", "release-update-lock");
    assert!(!rig.candidate.join("render-receipt.json").exists());
}

#[test]
fn failed_callback_is_durable_and_resume_never_refetches_or_activates() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(500).after_state_contains(
            rig.state.join("ixp-manager-lifecycle.json"),
            "updated_pending",
        ),
        Response::json(200),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(Error::CallbackPending)
    );
    let journal = fs::read_to_string(rig.state.join("ixp-manager-lifecycle.json")).unwrap();
    assert!(journal.contains("updated_pending"));
    assert!(rig.host.join("ixp-manager-host-fence.json").exists());
    assert!(!journal.contains(API_KEY));
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&server.origin)),
        Ok(Status::Updated)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert_request(&requests[2], "POST", "updated");
    assert_request(&requests[3], "POST", "updated");
    assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());
}

#[test]
fn started_activation_uncertainty_retains_remote_lock_for_manual_recovery() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    executable(&rig.activation, "#!/bin/sh\nexit 9\n");
    let server = Server::start(vec![Response::json(200), Response::config(FIXTURE)]);
    let mut options = rig.options(&server.origin);
    options.max_prefix_restart_seconds = 301;
    assert_eq!(lifecycle::run(&options), Err(Error::ManualRecovery));
    let origin = server.origin.clone();
    let requests = server.finish();
    assert_eq!(requests.len(), 2, "manual recovery must not callback");
    let journal = fs::read_to_string(rig.state.join("ixp-manager-lifecycle.json")).unwrap();
    assert!(journal.contains("manual_recovery"));
    assert!(journal.contains("recovery_required"));
    assert!(rig.host.join("ixp-manager-host-fence.json").exists());
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    let path = rig.state.join("ixp-manager-lifecycle.json");
    let mut started: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    started["phase"] = "activation_started".into();
    fs::write(&path, serde_json::to_vec(&started).unwrap()).unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    fs::remove_file(&path).unwrap();
    let missing = rig.state.join("missing-journal-target");
    std::os::unix::fs::symlink(&missing, &path).unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    assert_eq!(
        lifecycle::run(&rig.options(&origin)),
        Err(Error::ManualRecovery)
    );
    assert_eq!(fs::read_link(&path).unwrap(), missing);
}

#[test]
fn redirects_and_unsafe_origins_or_key_files_are_refused_without_key_forwarding() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    sink.set_nonblocking(true).unwrap();
    let redirected = Server::start(vec![Response {
        status: 302,
        content_type: "application/json",
        body: b"{}".to_vec(),
        location: Some(format!("http://{}/stolen", sink.local_addr().unwrap())),
        expected_state: None,
        delay: None,
        chmod_before_reply: None,
    }]);
    assert_eq!(
        lifecycle::run(&rig.options(&redirected.origin)),
        Err(Error::ManualRecovery)
    );
    let requests = redirected.finish();
    assert_eq!(requests.len(), 1);
    assert!(matches!(
        sink.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    fs::remove_file(rig.state.join("ixp-manager-lifecycle.json")).unwrap();

    for origin in [
        "http://example.com",
        "http://localhost:80",
        "https://LOCALHOST.",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query=1",
    ] {
        assert!(matches!(
            lifecycle::run(&rig.options(origin)),
            Err(Error::Refused(_))
        ));
    }
    mode(&rig.key, 0o644);
    assert!(matches!(
        lifecycle::run(&rig.options("https://127.0.0.1")),
        Err(Error::Refused(_))
    ));
    mode(&rig.key, 0o600);
    fs::write(&rig.key, "non-ascii-é").unwrap();
    assert!(matches!(
        lifecycle::run(&rig.options("https://127.0.0.1")),
        Err(Error::Refused(_))
    ));
    let target = rig.root.join("real-key");
    fs::write(&target, API_KEY).unwrap();
    mode(&target, 0o600);
    fs::remove_file(&rig.key).unwrap();
    std::os::unix::fs::symlink(target, &rig.key).unwrap();
    assert!(matches!(
        lifecycle::run(&rig.options("https://127.0.0.1")),
        Err(Error::Refused(_))
    ));
}

#[test]
fn control_and_configuration_body_caps_fail_closed() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let slow = Server::start(vec![
        Response::json(200).after_delay(Duration::from_millis(1_500)),
    ]);
    let mut options = rig.options(&slow.origin);
    options.timeout = Duration::from_secs(1);
    assert_eq!(lifecycle::run(&options), Err(Error::ManualRecovery));
    slow.finish();

    let rig = Rig::new();
    let control = Server::start(vec![Response {
        status: 200,
        content_type: "application/json",
        body: vec![b'x'; 64 * 1024 + 1],
        location: None,
        expected_state: None,
        delay: None,
        chmod_before_reply: None,
    }]);
    assert_eq!(
        lifecycle::run(&rig.options(&control.origin)),
        Err(Error::ManualRecovery)
    );
    control.finish();

    let rig = Rig::new();
    let malformed = Server::start(vec![Response {
        status: 200,
        content_type: "application/json",
        body: b"{}".to_vec(),
        location: None,
        expected_state: None,
        delay: None,
        chmod_before_reply: None,
    }]);
    assert_eq!(
        lifecycle::run(&rig.options(&malformed.origin)),
        Err(Error::ManualRecovery)
    );
    malformed.finish();

    let rig = Rig::new();
    let mut oversized = FIXTURE.to_vec();
    oversized.resize(4 * 1024 * 1024 + 1, b' ');
    let config = Server::start(vec![
        Response::json(200),
        Response::config(&oversized),
        Response::json(200),
    ]);
    assert!(matches!(
        lifecycle::run(&rig.options(&config.origin)),
        Err(Error::Refused(_))
    ));
    let requests = config.finish();
    assert_request(&requests[2], "POST", "release-update-lock");
}

#[test]
fn in_memory_renderer_is_byte_identical_to_private_file_entry_point() {
    let _lifecycle_guard = lifecycle_test_guard();
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.json");
    fs::write(&input, FIXTURE).unwrap();
    mode(&input, 0o600);
    let from_file = temp.path().join("from-file");
    let from_memory = temp.path().join("from-memory");
    private_dir(&from_file);
    private_dir(&from_memory);
    let checker = temp.path().join("rustbgpd");
    executable(
        &checker,
        "#!/bin/sh\n[ \"$1\" = --version ] && echo 'rustbgpd 0.65.0'\nexit 0\n",
    );
    let binding =
        RenderBinding::new("b2-rs1-lan1-ipv4", &temp.path().join("b2-rs1-lan1-ipv4")).unwrap();
    assert_eq!(
        ixp_manager::write_checked_candidate(
            &input,
            &from_file,
            300,
            &checker,
            &binding,
            ixp_manager::SchemaVersion::V2,
        ),
        ixp_manager::write_checked_candidate_bytes(FIXTURE, &from_memory, 300, &checker, &binding,)
    );
    for relative in [
        "birdwatcher-protocol-aliases.conf",
        "config.toml",
        "policy/ixp-hygiene.rpol",
        "policy/client-1.rpol",
        "policy/client-4.rpol",
        "render-receipt.json",
    ] {
        assert_eq!(
            fs::read(from_file.join(relative)).unwrap(),
            fs::read(from_memory.join(relative)).unwrap(),
            "{relative} changed between entry points"
        );
    }
}

#[test]
fn host_lock_is_exclusive_before_any_network_request() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let _held = Guard::claim_new(rig.binding()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args([
            "ixp-manager-lifecycle",
            "resume",
            "--ixp-origin",
            "http://127.0.0.1:9",
            "--router-handle",
            "b2-rs1-lan1-ipv4",
            "--api-key-file",
        ])
        .arg(&rig.key)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--runtime-state-dir")
        .arg(&rig.runtime)
        .arg("--host-state-dir")
        .arg(&rig.host)
        .arg("--rbgp-addr")
        .arg(rig.binding.rbgp_addr())
        .args(["--request-timeout-seconds", "1", "--allow-http-loopback"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("another host command is active")
    );
}

#[test]
fn guard_clear_is_bound_to_the_claimed_host() {
    let _lifecycle_guard = lifecycle_test_guard();
    let first = Rig::new();
    let second = Rig::new();
    let first_guard = Guard::claim_new(first.binding()).unwrap();
    let second_guard = Guard::claim_new(second.binding()).unwrap();
    first_guard.clear().unwrap();
    assert!(!first.host.join("ixp-manager-host-fence.json").exists());
    assert!(second.host.join("ixp-manager-host-fence.json").exists());
    second_guard.clear().unwrap();
}

#[test]
fn per_handle_state_lock_refuses_before_publishing_host_fence() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let lock = rig.state.join("ixp-manager-lifecycle.lock");
    fs::write(&lock, []).unwrap();
    mode(&lock, 0o600);
    let held = File::options().read(true).write(true).open(lock).unwrap();
    held.try_lock().unwrap();
    assert_eq!(
        lifecycle::run(&rig.options("http://127.0.0.1:9")),
        Err(Error::Refused("another lifecycle command is active"))
    );
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());
}

#[test]
fn topology_mismatches_are_refused_before_network_effects() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let forged: Binding = serde_json::from_value(serde_json::json!({
        "router_handle": "foreign",
        "runtime_state_dir": rig.runtime,
        "activation_state_dir": rig.state,
        "host_state_dir": rig.host,
        "rbgp_addr": rig.binding.rbgp_addr()
    }))
    .unwrap();
    assert!(matches!(
        Guard::claim_new(&forged),
        Err(rs_config_render::ixp_manager_host::Error::Refused(_))
    ));
    let wrong_runtime = rig.root.join("wrong-basename");
    assert!(
        Binding::new(
            "b2-rs1-lan1-ipv4",
            &wrong_runtime,
            &wrong_runtime.join("activation"),
            &rig.host,
            &format!("unix://{}/grpc.sock", wrong_runtime.display()),
        )
        .is_err()
    );
    assert!(
        Binding::new(
            "b2-rs1-lan1-ipv4",
            &rig.runtime,
            &rig.root.join("other-state"),
            &rig.host,
            rig.binding.rbgp_addr(),
        )
        .is_err()
    );
    assert!(
        Binding::new(
            "b2-rs1-lan1-ipv4",
            &rig.runtime,
            &rig.state,
            &rig.host,
            "unix:///wrong/grpc.sock",
        )
        .is_err()
    );

    let wrong_state = rig.root.join("other-state");
    private_dir(&wrong_state);
    let mut options = rig.options("http://127.0.0.1:9");
    options.state_dir = &wrong_state;
    assert!(matches!(lifecycle::run(&options), Err(Error::Refused(_))));
    let mut options = rig.options("http://127.0.0.1:9");
    options.rbgp_addr = "unix:///wrong/grpc.sock";
    assert!(matches!(lifecycle::run(&options), Err(Error::Refused(_))));
}

#[test]
fn killed_run_retains_owner_fence_and_foreign_resume_cannot_bypass_it() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200).after_delay(Duration::from_secs(30)),
    ]);
    let mut child = run_cli(&rig, &server.origin)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while server.requests.lock().unwrap().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "lock request was not observed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(rig.host.join("ixp-manager-host-fence.json").exists());
    assert!(rig.state.join("ixp-manager-lifecycle.json").exists());

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
    let foreign_resume = lifecycle::ResumeOptions {
        ixp_origin: &server.origin,
        router_handle: "foreign-ipv4",
        api_key_file: &rig.key,
        state_dir: &foreign_state,
        timeout: Duration::from_secs(1),
        allow_http_loopback: true,
        binding: &foreign,
    };
    assert_eq!(
        lifecycle::resume(&foreign_resume),
        Err(Error::Refused("foreign host fence"))
    );
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(Error::ManualRecovery)
    );
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&server.origin)),
        Err(Error::ManualRecovery)
    );
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[test]
fn callback_cleanup_failure_retains_fence_until_matching_resume() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(200).after_chmod(rig.state.clone(), 0o500),
        Response::json(200),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(Error::ManualRecovery)
    );
    assert!(rig.state.join("ixp-manager-lifecycle.json").exists());
    assert!(rig.host.join("ixp-manager-host-fence.json").exists());
    mode(&rig.state, 0o700);
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&server.origin)),
        Ok(Status::Updated)
    );
    server.finish();
    assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());
}

#[test]
fn additive_cli_help_pins_run_and_callback_only_resume() {
    let _lifecycle_guard = lifecycle_test_guard();
    let binary = env!("CARGO_BIN_EXE_rs-config-render");
    let root = Command::new(binary)
        .args(["ixp-manager-lifecycle", "--help"])
        .output()
        .unwrap();
    assert!(root.status.success());
    let root = String::from_utf8(root.stdout).unwrap();
    assert!(root.contains("run") && root.contains("resume"));
    let resume = Command::new(binary)
        .args(["ixp-manager-lifecycle", "resume", "--help"])
        .output()
        .unwrap();
    assert!(resume.status.success());
    let resume = String::from_utf8(resume.stdout).unwrap();
    for flag in [
        "--ixp-origin",
        "--router-handle",
        "--api-key-file",
        "--state-dir",
        "--runtime-state-dir",
        "--host-state-dir",
        "--rbgp-addr",
        "--request-timeout-seconds",
    ] {
        assert!(resume.contains(flag), "missing {flag}: {resume}");
    }
    for forbidden in ["--candidate-dir", "--rbgp <", "--activation-command"] {
        assert!(!resume.contains(forbidden), "resume exposed {forbidden}");
    }
}

#[test]
fn poisoned_proxy_is_ignored_and_cli_reports_the_exact_terminal_status() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(200),
    ]);
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    sink.set_nonblocking(true).unwrap();
    let proxy = format!("http://{}", sink.local_addr().unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args([
            "ixp-manager-lifecycle",
            "run",
            "--ixp-origin",
            &server.origin,
            "--router-handle",
            "b2-rs1-lan1-ipv4",
            "--api-key-file",
        ])
        .arg(&rig.key)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--runtime-state-dir")
        .arg(&rig.runtime)
        .arg("--host-state-dir")
        .arg(&rig.host)
        .arg("--candidate-dir")
        .arg(&rig.candidate)
        .arg("--check-with")
        .arg(&rig.checker)
        .args(["--max-prefix-restart-seconds", "300", "--rbgp"])
        .arg(&rig.rbgp)
        .args([
            "--rbgp-addr",
            rig.binding.rbgp_addr(),
            "--settle-seconds",
            "2",
            "--request-timeout-seconds",
            "2",
            "--activation-command",
        ])
        .arg(&rig.activation)
        .arg("--allow-http-loopback")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"IXP Manager lifecycle noop\n");
    assert!(!String::from_utf8(output.stderr).unwrap().contains(API_KEY));
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(matches!(
        sink.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn only_the_pinned_definite_lock_statuses_clear_the_intent() {
    let _lifecycle_guard = lifecycle_test_guard();
    for status in [401, 403, 404, 405, 422, 423] {
        let rig = Rig::new();
        let server = Server::start(vec![Response::json(status)]);
        assert!(matches!(
            lifecycle::run(&rig.options(&server.origin)),
            Err(Error::Refused(_))
        ));
        server.finish();
        assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    }
    for status in [302, 400, 429, 500] {
        let rig = Rig::new();
        let server = Server::start(vec![Response::json(status)]);
        assert_eq!(
            lifecycle::run(&rig.options(&server.origin)),
            Err(Error::ManualRecovery)
        );
        server.finish();
        assert!(rig.state.join("ixp-manager-lifecycle.json").exists());
        assert!(rig.host.join("ixp-manager-host-fence.json").exists());
    }
}

#[test]
fn corrupt_or_contradictory_durable_state_never_sends_a_callback() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let server = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(500),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&server.origin)),
        Err(Error::CallbackPending)
    );
    let origin = server.origin.clone();
    server.finish();
    let journal_path = rig.state.join("ixp-manager-lifecycle.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["callback"] = "release".into();
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    journal["callback"] = "updated".into();
    journal["activation_outcome"] = "refused".into();
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    journal["phase"] = "release_pending".into();
    journal["callback"] = "release".into();
    journal["activation_outcome"] = "activated".into();
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
    fs::write(&journal_path, b"{}\n").unwrap();
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&origin)),
        Err(Error::ManualRecovery)
    );
}

#[test]
fn release_resume_preserves_the_original_refusal_or_rollback_exit() {
    let _lifecycle_guard = lifecycle_test_guard();
    let rig = Rig::new();
    let refused = Server::start(vec![
        Response::json(200),
        Response::config(b"{}"),
        Response::json(500),
        Response::json(200),
    ]);
    assert_eq!(
        lifecycle::run(&rig.options(&refused.origin)),
        Err(Error::CallbackPending)
    );
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&refused.origin)),
        Err(Error::Refused("lock released without activation"))
    );
    let requests = refused.finish();
    assert_request(&requests[2], "POST", "release-update-lock");
    assert_request(&requests[3], "POST", "release-update-lock");

    let rig = Rig::new();
    let rolled_back = Server::start(vec![
        Response::json(200),
        Response::config(FIXTURE),
        Response::json(500),
        Response::json(200),
    ]);
    let mut options = rig.options(&rolled_back.origin);
    options.max_prefix_restart_seconds = 301;
    let missing = rig.root.join("missing-activation-command");
    options.activation_command = &missing;
    assert_eq!(lifecycle::run(&options), Err(Error::CallbackPending));
    assert_eq!(
        lifecycle::resume(&rig.resume_options(&rolled_back.origin)),
        Err(Error::RolledBack)
    );
    let requests = rolled_back.finish();
    assert_request(&requests[2], "POST", "release-update-lock");
    assert_request(&requests[3], "POST", "release-update-lock");
}

#[test]
fn every_lifecycle_test_acquires_the_process_guard_first() {
    let _lifecycle_guard = lifecycle_test_guard();
    let lines: Vec<_> = include_str!("ixp_manager_lifecycle.rs").lines().collect();
    let tests = lines
        .windows(3)
        .filter(|window| window[0] == "#[test]")
        .map(|window| {
            assert_eq!(
                window[2], "    let _lifecycle_guard = lifecycle_test_guard();",
                "{} must acquire the process guard before fixtures or children",
                window[1]
            );
            window[1]
                .strip_prefix("fn ")
                .and_then(|line| line.strip_suffix("() {"))
                .expect("lifecycle tests must keep simple named functions")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tests.join(","),
        "noop_lifecycle_uses_exact_authenticated_order_and_acknowledges,definite_lock_and_render_failures_have_bounded_release_semantics,failed_callback_is_durable_and_resume_never_refetches_or_activates,started_activation_uncertainty_retains_remote_lock_for_manual_recovery,redirects_and_unsafe_origins_or_key_files_are_refused_without_key_forwarding,control_and_configuration_body_caps_fail_closed,in_memory_renderer_is_byte_identical_to_private_file_entry_point,host_lock_is_exclusive_before_any_network_request,guard_clear_is_bound_to_the_claimed_host,per_handle_state_lock_refuses_before_publishing_host_fence,topology_mismatches_are_refused_before_network_effects,killed_run_retains_owner_fence_and_foreign_resume_cannot_bypass_it,callback_cleanup_failure_retains_fence_until_matching_resume,additive_cli_help_pins_run_and_callback_only_resume,poisoned_proxy_is_ignored_and_cli_reports_the_exact_terminal_status,only_the_pinned_definite_lock_statuses_clear_the_intent,corrupt_or_contradictory_durable_state_never_sends_a_callback,release_resume_preserves_the_original_refusal_or_rollback_exit,every_lifecycle_test_acquires_the_process_guard_first"
    );
}
