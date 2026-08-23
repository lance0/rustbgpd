//! Real-daemon matrix for deterministic settlement-budget fail-stop coverage.

mod support;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustbgpd_api::proto::{
    PeerGroupDefinition, SetPeerGroupRequest, peer_group_service_client::PeerGroupServiceClient,
};
use tonic::{Code, Request, Status, transport::Endpoint};

use support::{RetainOnPanic, rbgp_binary};

const CONTROL_ENV: &str = "RUSTBGPD_TEST_SETTLEMENT_CONTROL_DIR";
const CONTROL_VERSION: &str = "settlement-control-v1";
const SETTINGS: &str = "settings.v1";
const ARM: &str = "arm.v1";
const CLAIMED: &str = "claimed.v1";
const RECEIPT: &str = "receipt.v1";
const RELEASE: &str = "release.v1";
const BUDGET: Duration = Duration::from_secs(2);
// Budget in force for every settlement registered before a row arms its
// checkpoint. Strictly larger than every harness command timeout, so the
// watchdog can never fail-stop an un-held setup mutation on a starved box:
// a stalled setup hits the harness's own bound (with the directory
// retained) instead of killing the daemon mid-RPC.
const SETUP_BUDGET: Duration = Duration::from_secs(30);
const GRACE: Duration = Duration::from_millis(500);
const EXIT_JITTER: Duration = Duration::from_secs(2);
const MATRIX_LIMIT: Duration = Duration::from_secs(120);
const TOKEN: &str = "settlement-matrix-token";
#[derive(Clone, Copy, Debug)]
enum MatrixRow {
    Apply,
    AutoRevert,
    PeerGroup,
    Policy,
}

impl MatrixRow {
    const ALL: [Self; 4] = [Self::Apply, Self::AutoRevert, Self::PeerGroup, Self::Policy];

    const fn tag(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::AutoRevert => "auto-revert",
            Self::PeerGroup => "peer-group",
            Self::Policy => "policy",
        }
    }
    const fn checkpoint(self) -> &'static str {
        match self {
            Self::Apply => "transaction_after_begin_mutation",
            Self::AutoRevert => "replace_before_publish",
            Self::PeerGroup => "catalog_actor_command_accepted",
            Self::Policy => "staged_commit_before_publish",
        }
    }
    const fn kind(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::AutoRevert => "auto_revert",
            Self::PeerGroup => "peer_group_set",
            Self::Policy => "policy_set",
        }
    }
    const fn phase(self) -> &'static str {
        match self {
            Self::Apply | Self::PeerGroup => "mutating",
            Self::AutoRevert | Self::Policy => "settling_rollback",
        }
    }
    const fn attachment(self) -> &'static str {
        match self {
            Self::Apply | Self::AutoRevert => "detached",
            Self::PeerGroup | Self::Policy => "attached",
        }
    }
}

struct Process {
    child: Child,
}

impl Process {
    fn spawn(command: &mut Command) -> Self {
        command.process_group(0);
        Self {
            child: command.spawn().expect("spawn process"),
        }
    }
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn signal(&self, signal: Signal) {
        let group = i32::try_from(self.child.id()).expect("process group fits i32");
        kill(Pid::from_raw(-group), signal)
            .unwrap_or_else(|error| panic!("signal live process group {group}: {error}"));
    }
    fn signal_cleanup(&self, signal: Signal) {
        let group = i32::try_from(self.child.id()).expect("process group fits i32");
        let _ = kill(Pid::from_raw(-group), signal);
    }
    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("query process")
    }
    fn wait_status(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait() {
                self.assert_group_gone();
                return status;
            }
            if Instant::now() >= deadline {
                self.signal_cleanup(Signal::SIGKILL);
                let status = self.child.wait().expect("reap timed-out process");
                self.assert_group_gone();
                panic!("process timed out and was killed with {status}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn terminate_and_reap(&mut self) {
        if self.try_wait().is_some() {
            return;
        }
        self.signal_cleanup(Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.try_wait().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if self.try_wait().is_none() {
            self.signal_cleanup(Signal::SIGKILL);
            let _ = self.child.wait();
        }
    }
    fn wait_output(mut self, timeout: Duration) -> Output {
        let stdout = read_pipe(self.child.stdout.take().expect("piped stdout"));
        let stderr = read_pipe(self.child.stderr.take().expect("piped stderr"));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.try_wait() {
                break status;
            }
            if Instant::now() >= deadline {
                self.signal_cleanup(Signal::SIGKILL);
                let _ = self.child.wait();
                self.assert_group_gone();
                let _ = stdout.join().expect("join stdout reader");
                let _ = stderr.join().expect("join stderr reader");
                panic!("command did not finish within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        self.assert_group_gone();
        Output {
            status,
            stdout: stdout.join().expect("join stdout reader"),
            stderr: stderr.join().expect("join stderr reader"),
        }
    }
    fn assert_group_gone(&self) {
        let group = i32::try_from(self.child.id()).expect("process group fits i32");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match kill(Pid::from_raw(-group), None) {
                Err(Errno::ESRCH) => return,
                Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                other => panic!("process group {group} survived reap: {other:?}"),
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

fn read_pipe(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).expect("read process pipe");
        bytes
    })
}

struct Daemon {
    process: Process,
    log: PathBuf,
}

impl Daemon {
    fn spawn(config: &Path, log: PathBuf, control: Option<&Path>) -> Self {
        let stderr = File::create(&log).expect("create daemon log");
        let stdout = stderr.try_clone().expect("clone daemon log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
        command
            .arg(config)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .env_remove(CONTROL_ENV);
        if let Some(control) = control {
            command.env(CONTROL_ENV, control);
        }
        Self {
            process: Process::spawn(&mut command),
            log,
        }
    }

    fn pid(&self) -> u32 {
        self.process.pid()
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.process.try_wait() {
            panic!("rustbgpd exited early with {status}\n{}", self.log());
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn sigterm(&self) {
        self.process.signal(Signal::SIGTERM);
    }

    fn wait_exit70(&mut self, fenced_at: Instant) {
        let remaining = (GRACE + EXIT_JITTER)
            .checked_sub(fenced_at.elapsed())
            .expect("fail-stop exceeded grace plus jitter before wait");
        let status = self.process.wait_status(remaining);
        assert_eq!(status.code(), Some(70), "daemon log:\n{}", self.log());
        assert!(
            fenced_at.elapsed() <= GRACE + EXIT_JITTER,
            "exit 70 exceeded grace plus jitter"
        );
        self.process.assert_group_gone();
        let events = self
            .log()
            .lines()
            .filter(|line| line.contains("runtime config settlement fail-stop armed"))
            .count();
        assert_eq!(events, 1, "daemon log:\n{}", self.log());
    }
}

struct Control {
    dir: PathBuf,
    nonce: String,
}

impl Control {
    fn new(root: &Path, ordinal: usize) -> Self {
        let dir = root.join("settlement-control");
        std::fs::create_dir(&dir).expect("create settlement control directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = Self {
            dir,
            nonce: format!("{ordinal:032x}"),
        };
        control.write_settings(SETUP_BUDGET);
        control
    }

    fn write_settings(&self, budget: Duration) {
        atomic_write(
            &self.dir,
            SETTINGS,
            format!(
                "version={CONTROL_VERSION}\nbudget_ms={}\ngrace_ms={}\n",
                budget.as_millis(),
                GRACE.as_millis()
            )
            .as_bytes(),
        );
    }

    fn command(&self, checkpoint: &str) -> String {
        format!(
            "version={CONTROL_VERSION}\nnonce={}\ncheckpoint={checkpoint}\naction=hold\n",
            self.nonce
        )
    }

    fn arm(&self, checkpoint: &str) {
        for forbidden in [ARM, CLAIMED, RECEIPT, RELEASE] {
            assert!(!self.dir.join(forbidden).exists());
        }
        // The daemon re-reads the budget at every settlement registration,
        // so tightening here scopes the 2 s budget to exactly the armed
        // settlement; everything registered earlier ran under SETUP_BUDGET.
        self.write_settings(BUDGET);
        atomic_write(&self.dir, ARM, self.command(checkpoint).as_bytes());
    }

    fn wait_for_receipt(&self, checkpoint: &str, pid: u32, daemon: &mut Daemon) {
        let expected_command = self.command(checkpoint);
        let expected_receipt = format!("{expected_command}pid={pid}\n");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(receipt) = std::fs::read_to_string(self.dir.join(RECEIPT)) {
                assert_eq!(receipt, expected_receipt);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "missing control receipt\n{}",
                daemon.log()
            );
            daemon.assert_running();
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read_to_string(self.dir.join(CLAIMED)).unwrap(),
            expected_command
        );
        assert!(!self.dir.join(ARM).exists());
        assert!(!self.dir.join(RELEASE).exists());
        for name in [SETTINGS, CLAIMED, RECEIPT] {
            let mode = std::fs::metadata(self.dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} mode");
        }
    }

    fn assert_one_claim_without_release(&self) {
        assert!(!self.dir.join(ARM).exists());
        assert!(self.dir.join(CLAIMED).is_file());
        assert!(self.dir.join(RECEIPT).is_file());
        assert!(!self.dir.join(RELEASE).exists());
        let temporary = std::fs::read_dir(&self.dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(temporary, 0, "atomic control temp survived");
    }
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) {
    let temporary = directory.join(format!(".{name}.parent.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&temporary, directory.join(name)).unwrap();
    File::open(directory).unwrap().sync_all().unwrap();
}

struct Lab {
    root: RetainOnPanic,
    config: PathBuf,
    grpc: String,
    grpc_tcp: SocketAddr,
    metrics: SocketAddr,
    control: Control,
    base: String,
}

impl Lab {
    fn new(row: MatrixRow, cycle: usize, ordinal: usize) -> Self {
        let root = tempfile::Builder::new()
            .prefix(&format!("settlement-{}-{cycle}-", row.tag()))
            .tempdir()
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metrics = unused_loopback_addr();
        let grpc_tcp = unused_loopback_addr();
        let token = root.path().join("grpc-token");
        atomic_write(root.path(), "grpc-token", format!("{TOKEN}\n").as_bytes());
        let base = config_text(&runtime, metrics, grpc_tcp, &token);
        let config = root.path().join("rustbgpd.toml");
        std::fs::write(&config, &base).unwrap();
        let control = Control::new(root.path(), ordinal);
        Self {
            grpc: format!("unix://{}", runtime.join("grpc.sock").display()),
            grpc_tcp,
            root: RetainOnPanic::new(root),
            config,
            metrics,
            control,
            base,
        }
    }

    fn spawn(&self, name: &str, controlled: bool) -> Daemon {
        Daemon::spawn(
            &self.config,
            self.root.path().join(format!("{name}.log")),
            controlled.then_some(self.control.dir.as_path()),
        )
    }

    fn command(&self, args: &[&str]) -> Process {
        let mut command = rbgp_command(&self.grpc, args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        Process::spawn(&mut command)
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).wait_output(Duration::from_secs(15))
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let output = self.run(args);
        assert!(
            output.status.success() || output.status.code() == Some(2),
            "rbgp {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("rbgp JSON")
    }

    fn candidate(&self, name: &str) -> PathBuf {
        let path = self.root.path().join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "{}\n[peer_groups.{name}]\nfamilies = [\"ipv4_unicast\"]\nroute_server_client = true\n",
                self.base
            ),
        )
        .unwrap();
        path
    }

    fn plan(&self, candidate: &Path) -> (String, String) {
        let plan = self.json(&["--json", "config", "plan", candidate.to_str().unwrap()]);
        assert_eq!(plan["status"], "committable", "plan: {plan}");
        (
            plan["runtime_snapshot_token"].as_str().unwrap().to_string(),
            plan["plan_token"].as_str().unwrap().to_string(),
        )
    }

    fn assert_disk(&self, needle: &str, present: bool) {
        let bytes = std::fs::read(&self.config).unwrap();
        let _: toml::Value = toml::from_slice(&bytes).expect("operator config parses");
        assert_eq!(String::from_utf8(bytes).unwrap().contains(needle), present);
    }

    fn stage_path(&self) -> PathBuf {
        let mut path = self.config.clone().into_os_string();
        path.push(".tmp");
        PathBuf::from(path)
    }

    fn restart_and_assert_absent(&self, name: &str, command: &[&str]) {
        let mut daemon = self.spawn("restart", false);
        wait_ready_and_idle(self.metrics, &mut daemon);
        let output = self.run(command);
        assert!(
            !output.status.success(),
            "{name} unexpectedly survived restart"
        );
        daemon.assert_running();
    }
}

fn rbgp_command(grpc: &str, args: &[&str]) -> Command {
    let mut command = Command::new(rbgp_binary());
    command.arg("--addr").arg(grpc).args(args);
    command
}

fn unused_loopback_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config_text(runtime: &Path, metrics: SocketAddr, grpc_tcp: SocketAddr, token: &Path) -> String {
    format!(
        r#"[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/settlement-matrix" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
runtime_state_dir = "{}"

[global.telemetry]
log_format = "json"
prometheus_addr = "{metrics}"

[global.telemetry.grpc_uds]
path = "{}/grpc.sock"
principal = "rustbgpd://operator/settlement-matrix"

[global.telemetry.grpc_tcp]
address = "{grpc_tcp}"
token_file = "{}"
principal = "rustbgpd://operator/settlement-matrix"
"#,
        runtime.display(),
        runtime.display(),
        token.display()
    )
}

fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(100)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn metrics(addr: SocketAddr) -> Option<String> {
    http_get(addr, "/metrics")?
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
}

fn ready(addr: SocketAddr) -> Option<u16> {
    http_get(addr, "/readyz")?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn wait_ready_and_idle(addr: SocketAddr, daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ready(addr) == Some(200)
            && metrics(addr).is_some_and(|text| {
                !text
                    .lines()
                    .any(|line| line.starts_with("bgp_runtime_config_settlement_active{"))
            })
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon not ready and idle\n{}",
            daemon.log()
        );
        daemon.assert_running();
        thread::sleep(Duration::from_millis(20));
    }
}

fn metric_value(text: &str, name: &str, row: MatrixRow, reason: &str) -> Option<f64> {
    let prefix = format!("{name}{{");
    let lines = text
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return None;
    }
    let line = lines[0];
    for label in [
        format!("kind=\"{}\"", row.kind()),
        format!("phase=\"{}\"", row.phase()),
        format!("response_attached=\"{}\"", row.attachment()),
        format!("fence_reason=\"{reason}\""),
    ] {
        if !line.contains(&label) {
            return None;
        }
    }
    line.rsplit_once(' ')?.1.parse().ok()
}

fn exact_metrics(text: &str, row: MatrixRow, reason: &str, fenced: bool) -> bool {
    let minimum_elapsed = if fenced { BUDGET.as_secs_f64() } else { 0.0 };
    metric_value(text, "bgp_runtime_config_settlement_active", row, reason) == Some(1.0)
        && metric_value(
            text,
            "bgp_runtime_config_settlement_budget_seconds",
            row,
            reason,
        ) == Some(2.0)
        && metric_value(
            text,
            "bgp_runtime_config_settlement_fail_stops_total",
            row,
            reason,
        ) == Some(f64::from(u8::from(fenced)))
        && metric_value(
            text,
            "bgp_runtime_config_settlement_elapsed_seconds",
            row,
            reason,
        )
        .is_some_and(|elapsed| elapsed >= minimum_elapsed)
}

fn wait_metrics(
    addr: SocketAddr,
    row: MatrixRow,
    reason: &str,
    fenced: bool,
    daemon: &mut Daemon,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(text) = metrics(addr)
            && exact_metrics(&text, row, reason, fenced)
        {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "missing {reason} metric tuple\n{}",
            daemon.log()
        );
        daemon.assert_running();
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_fenced(lab: &Lab, row: MatrixRow, daemon: &mut Daemon) -> Instant {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if ready(lab.metrics) == Some(503)
            && metrics(lab.metrics)
                .is_some_and(|text| exact_metrics(&text, row, "budget_expired", true))
        {
            return Instant::now();
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not fence\n{}",
            daemon.log()
        );
        daemon.assert_running();
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_read_success(lab: &Lab, args: &[&str], daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if lab.run(args).status.success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "actor effect not observable\n{}",
            daemon.log()
        );
        daemon.assert_running();
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_failed(output: &Output, context: &str) {
    assert!(
        !output.status.success(),
        "{context} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct QueuedMutation {
    result: mpsc::Receiver<Result<(), Status>>,
    task: thread::JoinHandle<()>,
}

impl QueuedMutation {
    fn spawn(lab: &Lab) -> Self {
        let (send, result) = mpsc::channel();
        let address = lab.grpc_tcp;
        let task = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(async move {
                let channel = Endpoint::from_shared(format!("http://{address}"))
                    .unwrap()
                    .connect_timeout(Duration::from_secs(1))
                    .connect()
                    .await
                    .unwrap();
                let mut client = PeerGroupServiceClient::new(channel);
                let mut request = Request::new(SetPeerGroupRequest {
                    name: "queued-second-owner".into(),
                    definition: Some(PeerGroupDefinition {
                        families: vec!["ipv4_unicast".into()],
                        ..Default::default()
                    }),
                });
                request
                    .metadata_mut()
                    .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
                request.set_timeout(Duration::from_secs(4));
                client.set_peer_group(request).await.map(|_| ())
            });
            send.send(result).unwrap();
        });
        Self { result, task }
    }

    fn assert_waiting(&self) {
        assert!(matches!(
            self.result.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn wait(self) -> Status {
        let status = self
            .result
            .recv_timeout(Duration::from_millis(350))
            .expect("queued owner must be rejected during grace")
            .expect_err("queued owner unexpectedly succeeded");
        self.task.join().expect("join queued owner");
        status
    }
}

enum RowResult {
    Apply(QueuedMutation),
    Requests(Vec<Process>),
    None,
}

fn exercise_apply(lab: &Lab, daemon: &mut Daemon) -> RowResult {
    let candidate = lab.candidate("apply-candidate");
    let (snapshot, plan) = lab.plan(&candidate);
    lab.control.arm(MatrixRow::Apply.checkpoint());
    let mut first = lab.command(&[
        "--json",
        "config",
        "apply",
        candidate.to_str().unwrap(),
        "--expected-runtime-snapshot-token",
        &snapshot,
        "--plan-token",
        &plan,
    ]);
    lab.control
        .wait_for_receipt(MatrixRow::Apply.checkpoint(), daemon.pid(), daemon);
    assert!(
        first.try_wait().is_none(),
        "held Apply exited before cancellation"
    );
    first.signal(Signal::SIGTERM);
    let status = first.wait_status(Duration::from_secs(1));
    assert!(!status.success());
    wait_metrics(lab.metrics, MatrixRow::Apply, "none", false, daemon);

    let queued = QueuedMutation::spawn(lab);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let text = metrics(lab.metrics).unwrap();
        let elapsed = metric_value(
            &text,
            "bgp_runtime_config_settlement_elapsed_seconds",
            MatrixRow::Apply,
            "none",
        )
        .unwrap_or_default();
        if elapsed >= 0.25 {
            queued.assert_waiting();
            break;
        }
        assert!(Instant::now() < deadline, "could not prove queued overlap");
        daemon.assert_running();
    }
    lab.assert_disk("apply-candidate", false);
    lab.assert_disk("queued-second-owner", false);
    assert!(!lab.stage_path().exists());
    RowResult::Apply(queued)
}

fn apply_confirmed(lab: &Lab, candidate: &Path) {
    let (snapshot, plan) = lab.plan(candidate);
    let output = lab.run(&[
        "--json",
        "config",
        "apply",
        candidate.to_str().unwrap(),
        "--expected-runtime-snapshot-token",
        &snapshot,
        "--plan-token",
        &plan,
        "--confirm-id",
        "matrix-auto-revert",
        "--confirm-timeout",
        "4",
    ]);
    assert!(
        output.status.success(),
        "confirmed apply failed: {output:?}"
    );
}

fn exercise_auto_revert(lab: &Lab, daemon: &mut Daemon) -> RowResult {
    let candidate = lab.candidate("auto-candidate");
    apply_confirmed(lab, &candidate);
    wait_metrics_idle(lab.metrics, daemon);
    let locator = PathBuf::from(format!(
        "{}.commit-confirm-locator.json",
        lab.config.display()
    ));
    assert!(locator.is_file());
    lab.assert_disk("auto-candidate", true);
    lab.control.arm(MatrixRow::AutoRevert.checkpoint());
    lab.control
        .wait_for_receipt(MatrixRow::AutoRevert.checkpoint(), daemon.pid(), daemon);
    wait_metrics(lab.metrics, MatrixRow::AutoRevert, "none", false, daemon);
    assert!(locator.is_file(), "hold must retain rollback authority");
    lab.assert_disk("auto-candidate", true);
    assert!(!lab.stage_path().exists());
    RowResult::None
}

fn wait_metrics_idle(addr: SocketAddr, daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if metrics(addr).is_some_and(|text| {
            !text
                .lines()
                .any(|line| line.starts_with("bgp_runtime_config_settlement_active{"))
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "settlement owner did not become idle"
        );
        daemon.assert_running();
        thread::sleep(Duration::from_millis(10));
    }
}

fn exercise_peer_group(lab: &Lab, daemon: &mut Daemon) -> RowResult {
    let definition = lab.root.path().join("peer-group.json");
    std::fs::write(
        &definition,
        r#"{"families":["ipv4_unicast"],"route_server_client":true}"#,
    )
    .unwrap();
    lab.control.arm(MatrixRow::PeerGroup.checkpoint());
    let request = lab.command(&[
        "peer-group",
        "set",
        "matrix-peer-group",
        "--from-file",
        definition.to_str().unwrap(),
    ]);
    lab.control
        .wait_for_receipt(MatrixRow::PeerGroup.checkpoint(), daemon.pid(), daemon);
    wait_metrics(lab.metrics, MatrixRow::PeerGroup, "none", false, daemon);
    wait_read_success(
        lab,
        &["--json", "peer-group", "get", "matrix-peer-group"],
        daemon,
    );
    lab.assert_disk("matrix-peer-group", false);
    let staged = std::fs::read_to_string(lab.stage_path()).expect("peer-group stage");
    assert!(staged.contains("matrix-peer-group"));
    RowResult::Requests(vec![request])
}

fn exercise_policy(lab: &Lab, daemon: &mut Daemon) -> RowResult {
    let definition = lab.root.path().join("policy.json");
    std::fs::write(
        &definition,
        r#"{"default_action":"permit","statements":[]}"#,
    )
    .unwrap();
    lab.control.arm(MatrixRow::Policy.checkpoint());
    let request = lab.command(&[
        "policy",
        "set",
        "matrix-policy",
        "--from-file",
        definition.to_str().unwrap(),
    ]);
    lab.control
        .wait_for_receipt(MatrixRow::Policy.checkpoint(), daemon.pid(), daemon);
    wait_metrics(lab.metrics, MatrixRow::Policy, "none", false, daemon);
    wait_read_success(lab, &["--json", "policy", "get", "matrix-policy"], daemon);
    lab.assert_disk("matrix-policy", false);
    let staged = std::fs::read_to_string(lab.stage_path()).expect("policy stage");
    assert!(staged.contains("matrix-policy"));
    RowResult::Requests(vec![request])
}

fn finish_row(lab: &Lab, row: MatrixRow, daemon: &mut Daemon, result: RowResult) {
    let fenced_at = wait_fenced(lab, row, daemon);
    lab.control.assert_one_claim_without_release();
    daemon.assert_running();
    let requests = match result {
        RowResult::Apply(queued) => {
            let status = queued.wait();
            assert_eq!(status.code(), Code::Unavailable);
            assert_eq!(status.message(), "runtime config coordinator is closed");
            daemon.assert_running();
            lab.assert_disk("apply-candidate", false);
            lab.assert_disk("queued-second-owner", false);
            Vec::new()
        }
        RowResult::Requests(requests) => requests,
        RowResult::None => Vec::new(),
    };
    daemon.sigterm();
    daemon.wait_exit70(fenced_at);
    for request in requests {
        assert_failed(
            &request.wait_output(Duration::from_secs(2)),
            "held mutation",
        );
    }

    match row {
        MatrixRow::Apply => {
            lab.assert_disk("apply-candidate", false);
            lab.assert_disk("queued-second-owner", false);
            assert!(!lab.stage_path().exists());
            let mut restarted = lab.spawn("restart", false);
            wait_ready_and_idle(lab.metrics, &mut restarted);
            for name in ["apply-candidate", "queued-second-owner"] {
                assert!(
                    !lab.run(&["--json", "peer-group", "get", name])
                        .status
                        .success()
                );
            }
            restarted.assert_running();
        }
        MatrixRow::AutoRevert => {
            lab.assert_disk("auto-candidate", true);
            let locator = PathBuf::from(format!(
                "{}.commit-confirm-locator.json",
                lab.config.display()
            ));
            assert!(locator.is_file(), "exit must retain rollback authority");
            let mut restarted = lab.spawn("restart", false);
            wait_ready_and_idle(lab.metrics, &mut restarted);
            lab.assert_disk("auto-candidate", false);
            assert!(
                std::fs::read_to_string(lab.root.path().join("rustbgpd.toml.unconfirmed"))
                    .unwrap()
                    .contains("auto-candidate")
            );
            assert!(
                !lab.run(&["--json", "peer-group", "get", "auto-candidate"])
                    .status
                    .success()
            );
            assert!(!locator.exists());
            restarted.assert_running();
        }
        MatrixRow::PeerGroup => {
            lab.assert_disk("matrix-peer-group", false);
            assert!(lab.stage_path().exists());
            lab.restart_and_assert_absent(
                "peer group",
                &["--json", "peer-group", "get", "matrix-peer-group"],
            );
        }
        MatrixRow::Policy => {
            lab.assert_disk("matrix-policy", false);
            assert!(lab.stage_path().exists());
            lab.restart_and_assert_absent("policy", &["--json", "policy", "get", "matrix-policy"]);
        }
    }
}

#[test]
fn runtime_config_settlement_matrix_four_rows_three_cycles() {
    let _ = rbgp_binary();
    let matrix_started = Instant::now();
    let mut ordinal = 1;
    for row in MatrixRow::ALL {
        for cycle in 0..3 {
            let lab = Lab::new(row, cycle, ordinal);
            ordinal += 1;
            let mut daemon = lab.spawn("controlled", true);
            wait_ready_and_idle(lab.metrics, &mut daemon);
            assert!(lab.control.dir.join(SETTINGS).is_file());

            let requests = match row {
                MatrixRow::Apply => exercise_apply(&lab, &mut daemon),
                MatrixRow::AutoRevert => exercise_auto_revert(&lab, &mut daemon),
                MatrixRow::PeerGroup => exercise_peer_group(&lab, &mut daemon),
                MatrixRow::Policy => exercise_policy(&lab, &mut daemon),
            };
            finish_row(&lab, row, &mut daemon, requests);
        }
    }
    assert!(
        matrix_started.elapsed() < MATRIX_LIMIT,
        "twelve-cycle settlement matrix exceeded {MATRIX_LIMIT:?}"
    );
}

#[test]
fn settlement_real_process_evidence_inventory_is_composed() {
    let matrix = include_str!("runtime_config_settlement_matrix.rs");
    let persistence = include_str!("runtime_config_persistence_failstop.rs");
    let confirm = include_str!("commit_confirm_binary.rs");
    let settlement = include_str!("../crates/api/src/runtime_config_settlement.rs");
    let exit = include_str!("../crates/api/tests/runtime_config_settlement_exit.rs");
    let fib = include_str!("../src/fib_table_control.rs");
    let m58 = include_str!("interop/scripts/test-m58-fib-table-crud-frr.sh");
    let has = |source: &str, needles: &[&str]| {
        for needle in needles {
            assert!(source.contains(needle), "composed proof lost {needle}");
        }
    };
    has(
        matrix,
        &[
            "MatrixRow::Apply",
            "MatrixRow::AutoRevert",
            "MatrixRow::PeerGroup",
            "MatrixRow::Policy",
            "for cycle in 0..3",
            "daemon.sigterm();",
            "daemon.wait_exit70(fenced_at)",
        ],
    );
    has(
        persistence,
        &[
            "pre_rename_failure_fences_and_restart_loads_prior_config",
            "post_rename_failure_fences_and_restart_loads_complete_candidate",
            "sighup_reconcile_ack_loss_fences_and_exits_once",
            "sighup_bridge_persister_ack_loss_fences_and_exits_once",
        ],
    );
    assert_eq!(persistence.matches("for _ in 0..3").count(), 2);
    has(
        confirm,
        &[
            "sigkill_in_confirm_window_boots_previous_config_and_saves_candidate_aside",
            "confirm_then_sigkill_retains_new_config_and_leaves_no_journal",
        ],
    );
    has(
        settlement,
        &[
            "shared_executor_outlives_rpc_cancellation_and_settles_cleanly",
            "shared_executor_ambiguity_fences_queued_and_future_owners",
        ],
    );
    has(exit, &["executor_loss_uses_production_exit_status"]);
    has(fib, &["fib_set_delete_settlement_inventory_is_closed"]);
    has(
        m58,
        &["SetFibTable adds", "Restart rustbgpd", "DeleteFibTable"],
    );
}
