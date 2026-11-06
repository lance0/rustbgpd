//! External sources named by a candidate sent through `rbgp config plan`
//! (`StreamPlanConfigTransaction`) against a live daemon.
//!
//! An observer may name only files under the running config's policy
//! directories, and an operator may name any file. Neither gets the file's
//! text back in an error. A FIFO or a device is refused without blocking
//! the daemon, which keeps answering other requests.

#[path = "support/mod.rs"]
mod support;

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "observer-bearer-TOKEN-5c1d";

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run `rbgp` with `args`, killing it after `limit`. `None` means it did not
/// finish in time.
fn rbgp_within(args: &[&str], limit: Duration) -> Option<Output> {
    let mut child = Command::new(support::rbgp_binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rbgp");
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if child.try_wait().expect("poll rbgp").is_some() {
            return Some(child.wait_with_output().expect("rbgp output"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The running config with its `rpol_files` replaced by `rpol`.
fn candidate(running: &Path, dir: &Path, name: &str, rpol: &Path) -> PathBuf {
    let config = std::fs::read_to_string(running).unwrap();
    let start = config.find("rpol_files = [").unwrap();
    let end = start + config[start..].find(']').unwrap() + 1;
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "{}rpol_files = [{:?}]{}",
            &config[..start],
            rpol.display().to_string(),
            &config[end..]
        ),
    )
    .unwrap();
    path
}

#[test]
fn streamed_plan_candidate_sources_are_confined_bounded_and_never_echoed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    let policy = root.join("policy");
    let staged = root.join("staged");
    for dir in [&state, &policy, &staged] {
        std::fs::create_dir(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        policy.join("edge.rpol"),
        "policy edge-in {\n    term rest { accept }\n}\n",
    )
    .unwrap();
    let token = state.join("observer.token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let fifo = policy.join("pipe.rpol");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let config = root.join("rustbgpd.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{state}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "127.0.0.1:0"
token_file = "{token}"
principal = "observer"

[global.telemetry.grpc_uds]
path = "{state}/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
observer = "observer"
operator = "operator"

[policy]
rpol_files = ["{policy}/edge.rpol"]
"#,
            state = state.display(),
            token = token.display(),
            policy = policy.display(),
        ),
    )
    .unwrap();

    // The address-space limit keeps an unbounded read from taking the host
    // with it when this test runs against a tree without the bound.
    let log = root.join("rustbgpd.log");
    let mut daemon = Daemon {
        child: Command::new("sh")
            .arg("-c")
            .arg("ulimit -v 16000000 && exec \"$0\" \"$1\"")
            .arg(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config)
            .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        log,
    };
    let sock = state.join("grpc.sock");
    support::wait_until_grpc_socket_accepts(&sock, &mut daemon.child);
    let deadline = Instant::now() + Duration::from_secs(30);
    let grpc = loop {
        if let Some(addr) = support::bound_grpc_addr(&daemon.log()) {
            break format!("http://{addr}");
        }
        assert!(
            Instant::now() < deadline,
            "no gRPC TCP listener\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let token_arg = token.display().to_string();
    let observer = ["-s", grpc.as_str(), "--token-file", token_arg.as_str()];
    let operator_sock = format!("unix://{}", sock.display());
    let operator = ["-s", operator_sock.as_str()];
    let plan = |caller: &[&str], candidate: &Path| {
        let mut args = caller.to_vec();
        let candidate = candidate.display().to_string();
        args.extend(["config", "plan", candidate.as_str()]);
        let output = rbgp_within(&args, Duration::from_secs(15));
        // Release a reader blocked in open(2) so a failing run exits.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo);
        output.map(|output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    };
    let responsive = |caller: &[&str]| {
        let mut args = caller.to_vec();
        args.push("neighbor");
        rbgp_within(&args, Duration::from_secs(10)).is_some_and(|output| output.status.success())
    };

    // Every case runs and reports, so one run shows each outcome.
    let mut failures = Vec::new();
    let mut expect = |case: &str, out: Option<String>, wanted: &str| match out {
        None => failures.push(format!("{case}: no answer within 15 s")),
        Some(out) if out.contains(TOKEN) => {
            failures.push(format!("{case}: the error carries file content: {out}"));
        }
        Some(out) if !out.contains(wanted) => {
            failures.push(format!("{case}: expected {wanted:?}: {out}"));
        }
        Some(_) => {}
    };
    let outside = "outside the accepted config's policy directories";

    // Disclosure: the observer names the listener's own token file. An
    // operator may name it, and still gets no file text back.
    let disclosure = candidate(&config, &staged, "disclosure.toml", &token);
    expect("observer disclosure", plan(&observer, &disclosure), outside);
    expect(
        "operator disclosure",
        plan(&operator, &disclosure),
        "observer.token:1:1: ",
    );

    // A FIFO inside the policy directory, from either caller.
    let piped = candidate(&config, &staged, "fifo.toml", &fifo);
    expect(
        "observer FIFO",
        plan(&observer, &piped),
        "not a regular file",
    );
    expect(
        "operator FIFO",
        plan(&operator, &piped),
        "not a regular file",
    );

    // A device: outside the policy directories for the observer, and
    // refused without an unbounded read for the operator.
    let zero = candidate(&config, &staged, "zero.toml", Path::new("/dev/zero"));
    expect("observer /dev/zero", plan(&observer, &zero), outside);
    expect(
        "operator /dev/zero",
        plan(&operator, &zero),
        "not a regular file",
    );

    if !responsive(&operator) || !responsive(&observer) {
        failures.push("the daemon stopped answering `rbgp neighbor`".to_string());
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
