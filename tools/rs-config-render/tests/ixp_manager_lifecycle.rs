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
use rs_config_render::ixp_manager_lifecycle::{self as lifecycle, Error, Status};

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const API_KEY: &str = "lifecycle-api-key-must-not-leak";

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
    candidate: PathBuf,
    key: PathBuf,
    checker: PathBuf,
    rbgp: PathBuf,
    activation: PathBuf,
}

impl Rig {
    fn new() -> Self {
        let current = std::env::current_dir().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("ixp-lifecycle-")
            .tempdir_in(current)
            .unwrap();
        let root = temp.path().to_path_buf();
        let state = root.join("state");
        let candidate = root.join("candidate");
        private_dir(&state);
        private_dir(&candidate);
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
        let rig = Self {
            _temp: temp,
            root,
            state,
            candidate,
            key,
            checker,
            rbgp,
            activation,
        };
        rig.bootstrap();
        rig
    }

    fn bootstrap(&self) {
        let candidate = self.root.join("bootstrap");
        private_dir(&candidate);
        ixp_manager::write_checked_candidate_bytes(FIXTURE, &candidate, 300, &self.checker)
            .unwrap();
        assert_eq!(
            activation::activate(&activation::Options {
                candidate: &candidate,
                state_dir: &self.state,
                checker: &self.checker,
                rbgp: &self.rbgp,
                rbgp_addr: "test",
                settle: Duration::from_secs(2),
                initial: true,
                activation_command: &self.activation,
                activation_args: &[],
            }),
            Ok(activation::Status::Activated)
        );
    }

    fn options<'a>(&'a self, origin: &'a str) -> lifecycle::Options<'a> {
        lifecycle::Options {
            ixp_origin: origin,
            router_handle: "rs1-ipv4",
            api_key_file: &self.key,
            candidate_dir: &self.candidate,
            state_dir: &self.state,
            checker: &self.checker,
            max_prefix_restart_seconds: 300,
            rbgp: &self.rbgp,
            rbgp_addr: "test",
            activation_command: &self.activation,
            activation_args: &[],
            settle: Duration::from_secs(2),
            timeout: Duration::from_secs(2),
            initial: false,
            allow_http_loopback: true,
        }
    }

    fn resume_options<'a>(&'a self, origin: &'a str) -> lifecycle::ResumeOptions<'a> {
        lifecycle::ResumeOptions {
            ixp_origin: origin,
            router_handle: "rs1-ipv4",
            api_key_file: &self.key,
            state_dir: &self.state,
            timeout: Duration::from_secs(2),
            allow_http_loopback: true,
        }
    }
}

fn assert_request(request: &str, method: &str, action: &str) {
    let lower = request.to_ascii_lowercase();
    assert!(
        request.starts_with(&format!(
            "{method} /admin/api/v4/router/{action}/rs1-ipv4 HTTP/1.1\r\n"
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
    assert_no_key(&rig.state);
    assert_no_key(&rig.candidate);
}

#[test]
fn definite_lock_and_render_failures_have_bounded_release_semantics() {
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
}

#[test]
fn failed_callback_is_durable_and_resume_never_refetches_or_activates() {
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
}

#[test]
fn started_activation_uncertainty_retains_remote_lock_for_manual_recovery() {
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
    assert_eq!(
        ixp_manager::write_checked_candidate(&input, &from_file, 300, &checker),
        ixp_manager::write_checked_candidate_bytes(FIXTURE, &from_memory, 300, &checker)
    );
    for relative in [
        "config.toml",
        "policy/ixp-hygiene.rpol",
        "policy/client-3.rpol",
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
fn lifecycle_state_lock_is_exclusive_before_any_network_request() {
    let rig = Rig::new();
    let lock = rig.state.join("ixp-manager-lifecycle.lock");
    fs::write(&lock, []).unwrap();
    mode(&lock, 0o600);
    let held = File::options().read(true).write(true).open(lock).unwrap();
    held.try_lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args([
            "ixp-manager-lifecycle",
            "resume",
            "--ixp-origin",
            "http://127.0.0.1:9",
            "--router-handle",
            "rs1-ipv4",
            "--api-key-file",
        ])
        .arg(&rig.key)
        .arg("--state-dir")
        .arg(&rig.state)
        .args(["--request-timeout-seconds", "1", "--allow-http-loopback"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("another lifecycle command is active")
    );
}

#[test]
fn additive_cli_help_pins_run_and_callback_only_resume() {
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
        "--request-timeout-seconds",
    ] {
        assert!(resume.contains(flag), "missing {flag}: {resume}");
    }
    for forbidden in ["--candidate-dir", "--rbgp", "--activation-command"] {
        assert!(!resume.contains(forbidden), "resume exposed {forbidden}");
    }
}

#[test]
fn poisoned_proxy_is_ignored_and_cli_reports_the_exact_terminal_status() {
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
            "rs1-ipv4",
            "--api-key-file",
        ])
        .arg(&rig.key)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--candidate-dir")
        .arg(&rig.candidate)
        .arg("--check-with")
        .arg(&rig.checker)
        .args(["--max-prefix-restart-seconds", "300", "--rbgp"])
        .arg(&rig.rbgp)
        .args([
            "--rbgp-addr",
            "test",
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
    let rig = Rig::new();
    for status in [401, 403, 404, 405, 422, 423] {
        let server = Server::start(vec![Response::json(status)]);
        assert!(matches!(
            lifecycle::run(&rig.options(&server.origin)),
            Err(Error::Refused(_))
        ));
        server.finish();
        assert!(!rig.state.join("ixp-manager-lifecycle.json").exists());
    }
    for status in [302, 400, 429, 500] {
        let server = Server::start(vec![Response::json(status)]);
        assert_eq!(
            lifecycle::run(&rig.options(&server.origin)),
            Err(Error::ManualRecovery)
        );
        server.finish();
        assert!(rig.state.join("ixp-manager-lifecycle.json").exists());
        fs::remove_file(rig.state.join("ixp-manager-lifecycle.json")).unwrap();
    }
}

#[test]
fn corrupt_or_contradictory_durable_state_never_sends_a_callback() {
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
