//! Real-daemon matrix for deterministic settlement-budget fail-stop coverage.

mod support;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
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
use rustbgpd_api::runtime_config_settlement::AMBIGUITY_FENCE_GRACE;
use tonic::{Code, Request, Status, transport::Endpoint};

use support::{RetainOnPanic, bound_bgp_addr, bound_grpc_addr, bound_metrics_addr, rbgp_binary};

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
// Readiness, metrics, and queued-refusal observations run during grace;
// give the real-process observer the same window as a production supervisor.
const GRACE: Duration = AMBIGUITY_FENCE_GRACE;
const EXIT_JITTER: Duration = Duration::from_secs(2);
const MATRIX_LIMIT: Duration = Duration::from_secs(180);
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
            // Auto-revert re-applies the captured prior config through the
            // transaction executor, which now durably stages the candidate
            // and publishes it with a commit rather than a single-phase
            // replace. Its persister checkpoint is therefore the staged
            // commit, the same phase every other transaction family reaches.
            Self::AutoRevert => "staged_commit_before_publish",
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
    metrics: SocketAddr,
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
        let mut process = Process::spawn(&mut command);
        let deadline = Instant::now() + Duration::from_secs(15);
        let metrics = loop {
            let logs = std::fs::read_to_string(&log).unwrap_or_default();
            if let Some(addr) = bound_metrics_addr(&logs) {
                break addr;
            }
            if let Some(status) = process.try_wait() {
                panic!("rustbgpd exited early with {status}\n{logs}");
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not report its bound metrics endpoint\n{logs}"
            );
            thread::sleep(Duration::from_millis(20));
        };
        Self {
            process,
            log,
            metrics,
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

    /// Whether a JSON log line's message starts with `message` (the key-log
    /// prefix; some messages carry a detail suffix) and contains `needle`.
    fn log_has(&self, message: &str, needle: &str) -> bool {
        self.log().lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|entry| {
                entry["fields"]["message"]
                    .as_str()
                    .is_some_and(|logged| logged.starts_with(message))
            }) && line.contains(needle)
        })
    }

    /// Wait for a log line with `message` containing `needle`, returning the
    /// instant it was first observed.
    fn wait_log(&mut self, message: &str, needle: &str) -> Instant {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.log_has(message, needle) {
                return Instant::now();
            }
            assert!(
                Instant::now() < deadline,
                "missing log line {message:?} with {needle:?}\n{}",
                self.log()
            );
            self.assert_running();
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_exit(&mut self, code: i32, timeout: Duration) {
        let status = self.process.wait_status(timeout);
        assert_eq!(status.code(), Some(code), "daemon log:\n{}", self.log());
        self.process.assert_group_gone();
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
    /// Budget the armed settlement registers under.
    budget: Duration,
}

impl Control {
    fn new(root: &Path, ordinal: usize) -> Self {
        let dir = root.join("settlement-control");
        std::fs::create_dir(&dir).expect("create settlement control directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let control = Self {
            dir,
            nonce: format!("{ordinal:032x}"),
            budget: BUDGET,
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
        self.write_settings(self.budget);
        atomic_write(&self.dir, ARM, self.command(checkpoint).as_bytes());
    }

    /// Let the held owner continue from its checkpoint.
    fn release(&self, checkpoint: &str) {
        assert!(self.dir.join(RECEIPT).is_file(), "release before claim");
        atomic_write(&self.dir, RELEASE, self.command(checkpoint).as_bytes());
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
        // The daemon owns every ephemeral listener from its initial bind.
        let grpc_tcp = "127.0.0.1:0".parse().unwrap();
        let token = root.path().join("grpc-token");
        atomic_write(root.path(), "grpc-token", format!("{TOKEN}\n").as_bytes());
        let base = config_text(&runtime, grpc_tcp, &token);
        let config = root.path().join("rustbgpd.toml");
        std::fs::write(&config, &base).unwrap();
        let control = Control::new(root.path(), ordinal);
        Self {
            grpc: format!("unix://{}", runtime.join("grpc.sock").display()),
            root: RetainOnPanic::new(root),
            config,
            control,
            base,
        }
    }

    /// Register the armed settlement under `budget` instead of the 2 s default.
    fn with_hold_budget(mut self, budget: Duration) -> Self {
        self.control.budget = budget;
        self
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
        wait_ready_and_idle(daemon.metrics, &mut daemon);
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

fn config_text(runtime: &Path, grpc_tcp: SocketAddr, token: &Path) -> String {
    format!(
        r#"[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/settlement-matrix" = "operator"

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
# Keep ephemeral BGP binds away from the API and metrics loopback address.
listen_addresses = ["127.0.0.2"]
runtime_state_dir = "{}"

[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:0"

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
        if let Some(grpc_addr) = bound_grpc_addr(&daemon.log())
            && ready(addr) == Some(200)
            && metrics(addr).is_some_and(|text| {
                !text
                    .lines()
                    .any(|line| line.starts_with("bgp_runtime_config_settlement_active{"))
            })
        {
            assert_ne!(
                grpc_addr, addr,
                "gRPC and metrics must own distinct endpoints"
            );
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

fn exact_metrics(text: &str, row: MatrixRow, reason: &str, fenced: bool, budget: Duration) -> bool {
    // Only budget expiry proves the owner outlived its budget; every other
    // fence lands at whatever elapsed the owner had reached.
    let minimum_elapsed = if fenced && reason == "budget_expired" {
        budget.as_secs_f64()
    } else {
        0.0
    };
    metric_value(text, "bgp_runtime_config_settlement_active", row, reason) == Some(1.0)
        && metric_value(
            text,
            "bgp_runtime_config_settlement_budget_seconds",
            row,
            reason,
        ) == Some(budget.as_secs_f64())
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
    lab: &Lab,
    row: MatrixRow,
    reason: &str,
    fenced: bool,
    daemon: &mut Daemon,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(text) = metrics(daemon.metrics)
            && exact_metrics(&text, row, reason, fenced, lab.control.budget)
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
        if ready(daemon.metrics) == Some(503)
            && metrics(daemon.metrics).is_some_and(|text| {
                exact_metrics(&text, row, "budget_expired", true, lab.control.budget)
            })
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
    fn spawn(address: SocketAddr) -> Self {
        let (send, result) = mpsc::channel();
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
    wait_metrics(lab, MatrixRow::Apply, "none", false, daemon);

    let log = daemon.log();
    let address = bound_grpc_addr(&log)
        .unwrap_or_else(|| panic!("daemon did not report its gRPC endpoint\n{log}"));
    let queued = QueuedMutation::spawn(address);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let text = metrics(daemon.metrics).unwrap();
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
    wait_metrics_idle(daemon.metrics, daemon);
    let locator = PathBuf::from(format!(
        "{}.commit-confirm-locator.json",
        lab.config.display()
    ));
    assert!(locator.is_file());
    lab.assert_disk("auto-candidate", true);
    lab.control.arm(MatrixRow::AutoRevert.checkpoint());
    lab.control
        .wait_for_receipt(MatrixRow::AutoRevert.checkpoint(), daemon.pid(), daemon);
    wait_metrics(lab, MatrixRow::AutoRevert, "none", false, daemon);
    assert!(locator.is_file(), "hold must retain rollback authority");
    lab.assert_disk("auto-candidate", true);
    // Auto-revert now durably stages the reverted config before the held
    // commit publishes it, so the stage file is present and already carries
    // the reverted (pre-auto-candidate) config while the operator file on
    // disk still holds the auto-candidate this commit has not yet replaced.
    let staged = std::fs::read_to_string(lab.stage_path()).expect("auto-revert stage");
    assert!(
        !staged.contains("auto-candidate"),
        "the staged revert must drop the auto-candidate"
    );
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
    wait_metrics(lab, MatrixRow::PeerGroup, "none", false, daemon);
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
    wait_metrics(lab, MatrixRow::Policy, "none", false, daemon);
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
            wait_ready_and_idle(restarted.metrics, &mut restarted);
            for name in ["apply-candidate", "queued-second-owner"] {
                assert!(
                    !lab.run(&["--json", "peer-group", "get", name])
                        .status
                        .success()
                );
            }
            restarted.assert_running();
        }
        MatrixRow::AutoRevert => assert_auto_revert_recovery(lab),
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

/// After a fail-stop with the auto-revert held mid-commit, the exited process
/// left its rollback authority on disk and the next start runs the revert.
fn assert_auto_revert_recovery(lab: &Lab) {
    lab.assert_disk("auto-candidate", true);
    let locator = PathBuf::from(format!(
        "{}.commit-confirm-locator.json",
        lab.config.display()
    ));
    assert!(locator.is_file(), "exit must retain rollback authority");
    let mut restarted = lab.spawn("restart", false);
    wait_ready_and_idle(restarted.metrics, &mut restarted);
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

#[test]
fn grpc_endpoint_requires_bound_nonzero_tcp_listener_evidence() {
    for log in [
        "",
        "not JSON",
        r#"{"fields":{"message":"starting gRPC TCP listener"}}"#,
        r#"{"fields":{"message":"starting gRPC TCP listener","bound_addr":42}}"#,
        r#"{"fields":{"message":"starting gRPC TCP listener","bound_addr":"invalid"}}"#,
        r#"{"fields":{"message":"starting gRPC TCP listener","bound_addr":"127.0.0.1:0"}}"#,
        r#"{"fields":{"message":"configured gRPC TCP listener","bound_addr":"127.0.0.1:12345"}}"#,
    ] {
        assert_eq!(bound_grpc_addr(log), None, "unexpected endpoint from {log}");
    }
    let log = concat!(
        "startup banner\n",
        r#"{"fields":{"message":"starting gRPC UDS listener","bound_addr":"127.0.0.1:54321"}}"#,
        "\n",
        r#"{"fields":{"message":"starting gRPC TCP listener","requested_addr":"127.0.0.1:0","bound_addr":"127.0.0.1:12345"}}"#,
        "\n",
    );
    assert_eq!(
        bound_grpc_addr(log),
        Some("127.0.0.1:12345".parse().unwrap())
    );
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
            wait_ready_and_idle(daemon.metrics, &mut daemon);
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

// Budget for the shutdown-escalation rows: the held owner must still be
// unfenced when the further signal lands, so no observation below may reach
// the watchdog deadline. Well above every harness wait in these rows.
const ESCALATION_HOLD_BUDGET: Duration = SETUP_BUDGET;
const SIGNAL_LINE: &str = "termination signal received during coordinated shutdown";
// The two distinct continuations of SIGNAL_LINE: the signal fenced the owner
// itself, versus the signal arrived after something else already had. Neither
// string is a substring of the other, so each excludes the other.
const SIGNAL_FENCED_NOW: &str =
    "the owned runtime-config settlement is fenced and the daemon will fail-stop";
const SIGNAL_ALREADY_FENCED: &str =
    "the owned runtime-config settlement is already fenced and the daemon will fail-stop";
const FAIL_STOP_LINE: &str = "runtime config settlement fail-stop armed";
const SETTLED_LINE: &str = "runtime config settlement settled";
const OPERATOR_FORCED: &str = "\"fence_reason\":\"operator_forced\"";
const CLEAN_EXIT_LIMIT: Duration = Duration::from_secs(30);

/// Begin coordinated shutdown with a registered, unfenced owner and prove
/// the daemon is waiting on it: shutdown has begun (readiness is red), the
/// owner is still active with no fence reason, and nothing has escalated.
fn shutdown_waits_on_held_owner(lab: &Lab, row: MatrixRow, daemon: &mut Daemon, via: Stop) {
    match via {
        Stop::Signal => daemon.sigterm(),
        Stop::Rpc => {
            let output = lab.run(&["shutdown", "--reason", "escalation-row"]);
            assert!(output.status.success(), "shutdown RPC failed: {output:?}");
        }
    }
    daemon.wait_log("initiating coordinated shutdown", "");
    assert_eq!(ready(daemon.metrics), Some(503), "{}", daemon.log());
    wait_metrics(lab, row, "none", false, daemon);
    assert!(!daemon.log_has(SIGNAL_LINE, ""), "{}", daemon.log());
    assert!(!daemon.log_has(FAIL_STOP_LINE, ""), "{}", daemon.log());
    daemon.assert_running();
}

/// A further termination signal with a held owner: the owner is fenced as
/// `operator_forced` at once and the process exits 70 within the grace.
fn escalate_and_wait_exit70(lab: &Lab, row: MatrixRow, daemon: &mut Daemon) -> Instant {
    let signalled = Instant::now();
    daemon.sigterm();
    daemon.wait_log(SIGNAL_LINE, OPERATOR_FORCED);
    daemon.wait_log(SIGNAL_LINE, SIGNAL_FENCED_NOW);
    assert!(
        !daemon.log_has(SIGNAL_LINE, SIGNAL_ALREADY_FENCED),
        "a signal that fenced the owner must not report it as already fenced\n{}",
        daemon.log()
    );
    daemon.wait_log(FAIL_STOP_LINE, OPERATOR_FORCED);
    wait_metrics(lab, row, "operator_forced", true, daemon);
    assert_eq!(ready(daemon.metrics), Some(503));
    signalled
}

#[derive(Clone, Copy)]
enum Stop {
    Signal,
    Rpc,
}

/// Rows (a), (b) and (f): the first stop waits on the held owner; a further
/// signal fail-stops it with the recovery evidence intact; the next start
/// runs the persisted revert. `Stop::Rpc` proves a signal after an
/// RPC-initiated shutdown is the same escalation.
fn escalation_row_held_auto_revert(ordinal: usize, via: Stop) {
    let lab = Lab::new(MatrixRow::AutoRevert, 0, ordinal).with_hold_budget(ESCALATION_HOLD_BUDGET);
    let mut daemon = lab.spawn("controlled", true);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    assert!(matches!(
        exercise_auto_revert(&lab, &mut daemon),
        RowResult::None
    ));
    shutdown_waits_on_held_owner(&lab, MatrixRow::AutoRevert, &mut daemon, via);
    let signalled = escalate_and_wait_exit70(&lab, MatrixRow::AutoRevert, &mut daemon);
    daemon.wait_exit70(signalled);
    lab.control.assert_one_claim_without_release();
    assert!(!daemon.log_has(SETTLED_LINE, "\"kind\":\"auto_revert\""));
    assert_auto_revert_recovery(&lab);
}

/// Row (c), owner first: the held owner settles after the first signal and
/// before any further one, so the drain completes and the exit is clean.
fn escalation_row_owner_settles_first(ordinal: usize) {
    let lab = Lab::new(MatrixRow::PeerGroup, 0, ordinal).with_hold_budget(ESCALATION_HOLD_BUDGET);
    let mut daemon = lab.spawn("controlled", true);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    let RowResult::Requests(requests) = exercise_peer_group(&lab, &mut daemon) else {
        panic!("peer-group row returns its request");
    };
    shutdown_waits_on_held_owner(&lab, MatrixRow::PeerGroup, &mut daemon, Stop::Signal);
    lab.control.release(MatrixRow::PeerGroup.checkpoint());
    // Once the owner settles the daemon finishes shutdown in milliseconds, so
    // there is no window in which a further signal could be delivered after
    // settlement and before exit. This row therefore sends no second signal
    // and claims only what it can prove: an owner that settles during
    // shutdown is not fenced and the daemon exits 0. The fence-versus-
    // settlement race itself is proven deterministically by the API crate's
    // one-winner test, and the signal-first ordering by the row below.
    // Asserting after exit for the same reason: polling the log while the
    // daemon is dying would race its exit, and every line it wrote is in the
    // file once it is gone.
    daemon.wait_exit(0, CLEAN_EXIT_LIMIT);
    assert!(
        daemon.log_has(SETTLED_LINE, "\"kind\":\"peer_group_set\""),
        "the released owner never settled\n{}",
        daemon.log()
    );
    assert!(!daemon.log_has(FAIL_STOP_LINE, ""), "{}", daemon.log());
    assert!(
        !daemon.log_has(SIGNAL_LINE, OPERATOR_FORCED),
        "{}",
        daemon.log()
    );
    for request in requests {
        let output = request.wait_output(Duration::from_secs(2));
        assert!(
            output.status.success(),
            "settled mutation failed\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    lab.assert_disk("matrix-peer-group", true);
    let mut restarted = lab.spawn("restart", false);
    wait_ready_and_idle(restarted.metrics, &mut restarted);
    assert!(
        lab.run(&["--json", "peer-group", "get", "matrix-peer-group"])
            .status
            .success()
    );
    restarted.assert_running();
}

/// Row (c), signal first: the fence is observed before the held owner is
/// released, so its later settlement attempt loses and the exit is still 70.
fn escalation_row_signal_lands_first(ordinal: usize) {
    let lab = Lab::new(MatrixRow::PeerGroup, 0, ordinal).with_hold_budget(ESCALATION_HOLD_BUDGET);
    let mut daemon = lab.spawn("controlled", true);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    let RowResult::Requests(requests) = exercise_peer_group(&lab, &mut daemon) else {
        panic!("peer-group row returns its request");
    };
    shutdown_waits_on_held_owner(&lab, MatrixRow::PeerGroup, &mut daemon, Stop::Signal);
    let signalled = escalate_and_wait_exit70(&lab, MatrixRow::PeerGroup, &mut daemon);
    lab.control.release(MatrixRow::PeerGroup.checkpoint());
    daemon.wait_exit70(signalled);
    assert!(
        !daemon.log_has(SETTLED_LINE, "\"kind\":\"peer_group_set\""),
        "a fenced owner settled\n{}",
        daemon.log()
    );
    for request in requests {
        assert_failed(
            &request.wait_output(Duration::from_secs(2)),
            "fenced mutation",
        );
    }
    let mut restarted = lab.spawn("restart", false);
    wait_ready_and_idle(restarted.metrics, &mut restarted);
    restarted.assert_running();
}

/// Row (e): with no owner, a further signal keeps its existing meaning.
///
/// A no-owner shutdown completes in milliseconds, and nothing in this lab can
/// hold one open: the unwatched coordinator holder the bounded drain exists
/// for is `ListFibTables`, which returns at once with no FIB reconciler
/// configured, and the deadline-free stages (EVPN IMET sweep, peer-manager
/// drain, BMP enqueue, RIB event stage) are all unconfigured here. A signal
/// sent after observing `initiating coordinated shutdown` therefore usually
/// arrives once the process is already gone, which is why this row must not
/// rest on negative assertions.
///
/// Both signals are instead delivered while the process is stopped. SIGTERM
/// and SIGINT are distinct signals, so both stay pending and both are
/// delivered on SIGCONT: the main loop consumes whichever its `select!` polls
/// first and begins coordinated shutdown, and the other is still unconsumed
/// in its own signal stream, so the shutdown listener takes the
/// further-signal path immediately. No sleep, and the row fails if that path
/// never runs.
fn escalation_row_no_owner(ordinal: usize) {
    let lab = Lab::new(MatrixRow::PeerGroup, 0, ordinal);
    let mut daemon = lab.spawn("plain", false);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    daemon.process.signal(Signal::SIGSTOP);
    daemon.process.signal(Signal::SIGTERM);
    daemon.process.signal(Signal::SIGINT);
    daemon.process.signal(Signal::SIGCONT);
    daemon.wait_exit(0, CLEAN_EXIT_LIMIT);
    assert!(
        daemon.log_has(SIGNAL_LINE, ""),
        "the further signal never reached the shutdown listener\n{}",
        daemon.log()
    );
    assert!(
        !daemon.log_has(SIGNAL_LINE, OPERATOR_FORCED),
        "the no-owner signal must not fence anything\n{}",
        daemon.log()
    );
    assert!(!daemon.log_has(FAIL_STOP_LINE, ""), "{}", daemon.log());
}

/// A further signal that finds the owner already fenced by its own budget
/// rather than by the signal: the daemon reports the fail-stop that is
/// already in flight, with the real reason, instead of a skipped wait.
///
/// This cannot be a third signal inside another row's grace window.
/// `stop_waiting_on_signal` awaits one signal, logs, cancels its token and
/// ends, so a later signal has no receiver awaiting it and is never logged.
/// The owner must therefore be fenced by something other than the signal
/// before the first further signal arrives, and the only such cause the lab
/// can drive is budget expiry. The default two-second hold budget expires
/// while coordinated shutdown waits on the owner, which leaves the
/// five-second recovery-fence grace to deliver the further signal into.
fn escalation_row_already_fenced(ordinal: usize) {
    let lab = Lab::new(MatrixRow::PeerGroup, 0, ordinal);
    let mut daemon = lab.spawn("controlled", true);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    let RowResult::Requests(requests) = exercise_peer_group(&lab, &mut daemon) else {
        panic!("peer-group row returns its request");
    };
    daemon.sigterm();
    daemon.wait_log("initiating coordinated shutdown", "");
    // The owner's own budget fences it while the drain waits; the signal did not.
    let fenced_at = wait_fenced(&lab, MatrixRow::PeerGroup, &mut daemon);
    daemon.wait_log(FAIL_STOP_LINE, "\"fence_reason\":\"budget_expired\"");
    assert!(
        !daemon.log_has(SIGNAL_LINE, ""),
        "nothing has taken the further-signal path yet\n{}",
        daemon.log()
    );

    // The further signal lands inside the grace, with the owner already
    // fenced. The row's existing outcome must be unchanged: one fence, one
    // fail-stop line, still exit 70 within the grace. Assert the log after
    // that exit rather than polling for it: the daemon exits at the grace
    // boundary whatever the signal did, so polling would race the exit, and
    // every line it wrote is in the file once it is gone.
    daemon.sigterm();
    daemon.wait_exit70(fenced_at);
    assert!(
        daemon.log_has(SIGNAL_LINE, SIGNAL_ALREADY_FENCED),
        "the further signal did not report the fail-stop already in flight\n{}",
        daemon.log()
    );
    assert!(
        daemon.log_has(SIGNAL_LINE, "\"fence_reason\":\"budget_expired\""),
        "the already-fenced report must carry the real fence reason\n{}",
        daemon.log()
    );
    for absent in [SIGNAL_FENCED_NOW, OPERATOR_FORCED] {
        assert!(
            !daemon.log_has(SIGNAL_LINE, absent),
            "the signal must not claim it fenced an already-fenced owner\n{}",
            daemon.log()
        );
    }
    assert!(
        !daemon.log_has(FAIL_STOP_LINE, OPERATOR_FORCED),
        "the owner must not be fenced a second time\n{}",
        daemon.log()
    );
    for request in requests {
        assert_failed(
            &request.wait_output(Duration::from_secs(2)),
            "fenced mutation",
        );
    }
}

#[test]
fn shutdown_signal_escalation_rows() {
    let _ = rbgp_binary();
    escalation_row_held_auto_revert(101, Stop::Signal);
    escalation_row_held_auto_revert(102, Stop::Rpc);
    escalation_row_owner_settles_first(103);
    escalation_row_signal_lands_first(104);
    escalation_row_no_owner(105);
    escalation_row_already_fenced(106);
}

// Budget for the stalled-stage row: long enough that its 10% pre-effect
// margin (300 ms) is observable, short enough that the unfixed failure mode,
// fencing at the budget, lands inside the row's own waits.
const STAGE_HOLD_BUDGET: Duration = Duration::from_secs(3);
const STAGE_CHECKPOINT: &str = "stage_before_ack";
const STAGE_TIMED_OUT: &str =
    "config persistence did not stage the candidate in time; nothing was applied";

/// A persister that never acknowledges a stage leaves a mutation that
/// provably changed nothing. The owner must refuse it as UNAVAILABLE at its
/// pre-effect deadline, before the budget, so the daemon stays up and ready
/// instead of fencing `budget_expired` and exiting 70.
#[test]
fn stalled_stage_acknowledgement_settles_clean_before_the_budget() {
    let _ = rbgp_binary();
    let lab = Lab::new(MatrixRow::PeerGroup, 0, 201).with_hold_budget(STAGE_HOLD_BUDGET);
    let mut daemon = lab.spawn("controlled", true);
    wait_ready_and_idle(daemon.metrics, &mut daemon);
    let definition = lab.root.path().join("peer-group.json");
    std::fs::write(
        &definition,
        r#"{"families":["ipv4_unicast"],"route_server_client":true}"#,
    )
    .unwrap();
    let set = |name: &str| {
        lab.command(&[
            "peer-group",
            "set",
            name,
            "--from-file",
            definition.to_str().unwrap(),
        ])
    };

    lab.control.arm(STAGE_CHECKPOINT);
    let armed = Instant::now();
    let request = set("matrix-peer-group");
    lab.control
        .wait_for_receipt(STAGE_CHECKPOINT, daemon.pid(), &mut daemon);
    let output = request.wait_output(Duration::from_secs(15));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let exited = daemon.process.try_wait();
    assert!(
        !output.status.success() && stderr.contains(STAGE_TIMED_OUT),
        "stalled stage must be refused cleanly\nstderr:\n{stderr}\ndaemon exit: \
         {exited:?}\ndaemon log:\n{}",
        daemon.log()
    );
    daemon.assert_running();
    assert_eq!(ready(daemon.metrics), Some(200), "{}", daemon.log());
    wait_metrics_idle(daemon.metrics, &mut daemon);

    // The persister answers late; the dropped commit makes the bridge
    // discard the stage rather than publish it.
    lab.control.write_settings(SETUP_BUDGET);
    lab.control.release(STAGE_CHECKPOINT);

    // A clean settlement arms no fatal clock: outlive the budget plus grace.
    while armed.elapsed() < STAGE_HOLD_BUDGET + GRACE + EXIT_JITTER {
        daemon.assert_running();
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!daemon.log_has(FAIL_STOP_LINE, ""), "{}", daemon.log());
    assert_eq!(ready(daemon.metrics), Some(200), "{}", daemon.log());

    // The config plane is free, and only the later mutation reaches disk.
    let after = set("after-stall").wait_output(Duration::from_secs(15));
    assert!(
        after.status.success(),
        "mutation after the stall failed\nstderr:\n{}",
        String::from_utf8_lossy(&after.stderr)
    );
    lab.assert_disk("after-stall", true);
    lab.assert_disk("matrix-peer-group", false);
    assert!(
        !lab.run(&["--json", "peer-group", "get", "matrix-peer-group"])
            .status
            .success()
    );
    daemon.sigterm();
    daemon.wait_exit(0, CLEAN_EXIT_LIMIT);
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

#[test]
fn metrics_endpoint_requires_bound_nonzero_loopback_listener_evidence() {
    for log in [
        "",
        "not JSON",
        r#"{"fields":{"message":"metrics server listening"}}"#,
        r#"{"fields":{"message":"metrics server listening","addr":42}}"#,
        r#"{"fields":{"message":"metrics server listening","addr":"invalid"}}"#,
        r#"{"fields":{"message":"metrics server listening","addr":"127.0.0.1:0"}}"#,
        r#"{"fields":{"message":"metrics server listening","addr":"192.0.2.1:12345"}}"#,
        r#"{"fields":{"message":"BGP listener bound","addr":"127.0.0.1:12345"}}"#,
    ] {
        assert_eq!(
            bound_metrics_addr(log),
            None,
            "unexpected endpoint from {log}"
        );
    }
    let log = concat!(
        "startup banner\n",
        r#"{"fields":{"message":"BGP listener bound","addr":"127.0.0.1:54321"}}"#,
        "\n",
        r#"{"fields":{"message":"metrics server listening","addr":"127.0.0.1:12345"}}"#,
        "\n",
    );
    assert_eq!(
        bound_metrics_addr(log),
        Some("127.0.0.1:12345".parse().unwrap())
    );
}

#[test]
fn bgp_endpoint_requires_bound_nonzero_loopback_listener_evidence() {
    for log in [
        "",
        "not JSON",
        r#"{"fields":{"message":"BGP listener bound"}}"#,
        r#"{"fields":{"message":"BGP listener bound","addr":42}}"#,
        r#"{"fields":{"message":"BGP listener bound","addr":"invalid"}}"#,
        r#"{"fields":{"message":"BGP listener bound","addr":"127.0.0.1:0"}}"#,
        // A legacy dual-family daemon that lost its IPv4 bind warns and
        // reports only the IPv6 wildcard, which an IPv4 stub cannot dial.
        concat!(
            r#"{"fields":{"message":"failed to bind the BGP listener for this address family; inbound BGP sessions of this family will not be accepted","addr":"0.0.0.0:12345"}}"#,
            "\n",
            r#"{"fields":{"message":"BGP listener bound","addr":"[::]:12345"}}"#,
        ),
        r#"{"fields":{"message":"metrics server listening","addr":"127.0.0.1:12345"}}"#,
    ] {
        assert_eq!(bound_bgp_addr(log), None, "unexpected endpoint from {log}");
    }
    let log = concat!(
        "startup banner\n",
        r#"{"fields":{"message":"metrics server listening","addr":"127.0.0.1:54321"}}"#,
        "\n",
        r#"{"fields":{"message":"BGP listener bound","addr":"127.0.0.1:12345","requested_addr":"127.0.0.1:0"}}"#,
        "\n",
    );
    assert_eq!(
        bound_bgp_addr(log),
        Some("127.0.0.1:12345".parse().unwrap())
    );
}
