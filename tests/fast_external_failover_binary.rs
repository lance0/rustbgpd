//! Privileged netns proof of fast external failover.
//!
//! Two real daemons, A (AS 65001) and B (AS 65002), each in its own network
//! namespace, joined by four veth pairs:
//!
//! | link | A side          | B side          | sessions on it                            |
//! |------|-----------------|-----------------|-------------------------------------------|
//! | eth1 | 10.0.1.1/30, fe80::1 | 10.0.1.2/30, fe80::2 | numbered eBGP and a static link-local neighbor |
//! | eth2 | 10.0.2.1/30     | 10.0.2.2/30     | numbered eBGP, `fast_external_failover = false` on A |
//! | eth3 | 10.0.3.1/30     | 10.0.3.2/30     | numbered eBGP, never touched              |
//! | eth4 | 10.0.4.1/30     | 10.0.4.2/30     | numbered eBGP, A's address is removed     |
//!
//! Every session runs a 90 s hold timer with Graceful Restart negotiated. The
//! test asserts, on A:
//!
//! - pulling eth1 (B's end down, so A sees carrier loss) takes both eth1
//!   sessions down in well under the hold time, with no GR-retained routes;
//! - the opt-out session on eth2, pulled at the same moment, stays Established;
//! - the eth3 session is unaffected throughout;
//! - the eth1 sessions recover when the link returns and after A's own admin
//!   down/up; the numbered one also after the veth pair is deleted and
//!   recreated;
//! - removing A's eth4 address takes that session down at once;
//! - control: an ordinary transport loss (B killed) still retains routes under
//!   GR, so the purge above is the failover's doing.
//!
//! Gates on `EVPN_LINUX_NETNS=1`; run via
//! `bash crates/evpn-linux/tests/docker/run-netns-tests.sh fast_external_failover`.

#![cfg(target_os = "linux")]

#[path = "support/cargo.rs"]
mod cargo;

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HOLD_TIME_SECS: u64 = 90;
/// "Well before the hold timer": a teardown slower than this fails.
const FAILOVER_BOUND: Duration = Duration::from_secs(5);
const RECOVERY_BOUND: Duration = Duration::from_secs(90);
const PREFIX: &str = "198.51.100.0/24";

fn netns_enabled() -> bool {
    let enabled = std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1");
    if !enabled {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the fast external failover test");
    }
    enabled
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// (Re)install the deterministic link-local address on `eth1`. Admin down
/// flushes IPv6 addresses, and `/proc/sys` is read-only in the harness
/// container, so `keep_addr_on_down` is not an option.
fn link_local(ns: &str, host: u8) {
    ip(&[
        "-n",
        ns,
        "addr",
        "replace",
        &format!("fe80::{host}/64"),
        "dev",
        "eth1",
        "nodad",
    ]);
}

struct Namespaces {
    a: String,
    b: String,
}

impl Namespaces {
    fn create() -> Self {
        let id = std::process::id();
        let this = Self {
            a: format!("ffo-a-{id}"),
            b: format!("ffo-b-{id}"),
        };
        for ns in [&this.a, &this.b] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
            ip(&["netns", "add", ns]);
            ip(&["-n", ns, "link", "set", "lo", "up"]);
        }
        this
    }

    /// Create veth pair `ethN` between A and B and address both ends.
    fn link(&self, n: u8) {
        let (a_tmp, b_tmp) = (
            format!("ffoa{n}-{}", std::process::id() % 10_000),
            format!("ffob{n}-{}", std::process::id() % 10_000),
        );
        ip(&[
            "link", "add", &a_tmp, "type", "veth", "peer", "name", &b_tmp,
        ]);
        let name = format!("eth{n}");
        for (tmp, ns, host) in [(&a_tmp, &self.a, 1), (&b_tmp, &self.b, 2)] {
            ip(&["link", "set", tmp, "netns", ns, "name", &name]);
            // Deterministic link-local addresses (no EUI-64 generation).
            ip(&["-n", ns, "link", "set", &name, "addrgenmode", "none"]);
            ip(&[
                "-n",
                ns,
                "addr",
                "add",
                &format!("10.0.{n}.{host}/30"),
                "dev",
                &name,
            ]);
            if n == 1 {
                link_local(ns, host);
            }
            ip(&["-n", ns, "link", "set", &name, "up"]);
        }
    }
}

impl Drop for Namespaces {
    fn drop(&mut self) {
        for ns in [&self.a, &self.b] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
        }
    }
}

struct Daemon {
    child: Child,
    log: PathBuf,
    grpc: String,
}

impl Daemon {
    fn start(ns: &str, dir: &Path, asn: u32, router_id: &str, neighbors: &str) -> Self {
        let runtime = dir.join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = dir.join("rustbgpd.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/ffo-test" = "operator"

[global]
asn = {asn}
router_id = "{router_id}"
listen_port = 179
runtime_state_dir = "{runtime}"

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime}/grpc.sock"
principal = "rustbgpd://operator/ffo-test"
{neighbors}"#,
                runtime = runtime.display()
            ),
        )
        .unwrap();
        let log = dir.join("rustbgpd.log");
        let child = Command::new("ip")
            .args(["netns", "exec", ns])
            .arg(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config)
            .stdout(Stdio::from(File::create(&log).unwrap()))
            .stderr(Stdio::from(
                File::options().append(true).open(&log).unwrap(),
            ))
            .spawn()
            .expect("spawn rustbgpd");
        Self {
            child,
            log,
            grpc: format!("unix://{}/grpc.sock", runtime.display()),
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn rbgp(&self, args: &[&str]) -> std::process::Output {
        let mut cmd = if let Ok(path) = std::env::var("CARGO_BIN_EXE_rbgp") {
            Command::new(path)
        } else {
            let mut cmd = cargo::command();
            cmd.args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"]);
            cmd
        };
        cmd.arg("--addr")
            .arg(&self.grpc)
            .args(args)
            .output()
            .expect("spawn rbgp")
    }

    /// All neighbor rows.
    fn neighbors(&mut self) -> Option<Vec<serde_json::Value>> {
        if let Ok(Some(status)) = self.child.try_wait() {
            panic!("rustbgpd exited: {status}\nlog:\n{}", self.log());
        }
        let out = self.rbgp(&["--json", "neighbor"]);
        if !out.status.success() {
            return None;
        }
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .ok()?
            .as_array()
            .cloned()
    }

    /// One neighbor row; a link-local neighbor is named `fe80::2%eth1`.
    fn neighbor(&mut self, address: &str) -> Option<serde_json::Value> {
        let (address, interface) = address.split_once('%').unwrap_or((address, ""));
        self.neighbors()?.into_iter().find(|row| {
            row["address"].as_str() == Some(address)
                && row["interface"].as_str().unwrap_or_default() == interface
        })
    }

    fn established(&mut self, address: &str) -> bool {
        self.neighbor(address)
            .is_some_and(|row| row["state"].as_str() == Some("Established"))
    }

    /// Poll until `pred` holds; return the elapsed time.
    fn wait(
        &mut self,
        what: &str,
        bound: Duration,
        mut pred: impl FnMut(&mut Self) -> bool,
    ) -> Duration {
        let start = Instant::now();
        while start.elapsed() < bound {
            if pred(self) {
                return start.elapsed();
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "timed out after {bound:?} waiting for {what}; neighbors: {:#?}\nlog:\n{}",
            self.neighbors(),
            self.log()
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn neighbor_block(remote_asn: u32, address: &str, extra: &str) -> String {
    format!(
        "\n[[neighbors]]\naddress = \"{address}\"\nremote_asn = {remote_asn}\nhold_time = {HOLD_TIME_SECS}\n{extra}\n"
    )
}

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

const ETH1_V4: &str = "10.0.1.2";
const ETH1_LL: &str = "fe80::2%eth1";
const OPTED_OUT: &str = "10.0.2.2";
const UNTOUCHED: &str = "10.0.3.2";
const ADDRESS_REMOVED: &str = "10.0.4.2";

fn assert_failed_over(a: &mut Daemon, address: &str, reason: &str) {
    let row = a.neighbor(address).expect("neighbor row");
    let last_error = row["last_error"].as_str().unwrap_or_default();
    assert!(
        last_error.contains("fast external failover") && last_error.contains(reason),
        "{address}: expected a fast external failover ({reason}) cause, got {last_error:?}"
    );
    assert_eq!(
        // The JSON omits an empty retention list.
        row["gr_retention"].as_array().map_or(0, Vec::len),
        0,
        "{address}: no route may be retained under GR after failover: {row:#}"
    );
    assert_eq!(
        row["prefixes_received"].as_u64(),
        Some(0),
        "{address}: routes from the dead link must be gone: {row:#}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario: each phase depends on the previous topology"
)]
fn fast_external_failover_end_to_end() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    for n in 1..=4 {
        ns.link(n);
    }
    let dir_a = private_tempdir();
    let dir_b = private_tempdir();

    let a_neighbors = [
        neighbor_block(65002, "10.0.1.2", ""),
        neighbor_block(
            65002,
            "fe80::2",
            "interface = \"eth1\"\nfamilies = [\"ipv6_unicast\"]",
        ),
        neighbor_block(65002, "10.0.2.2", "fast_external_failover = false"),
        neighbor_block(65002, "10.0.3.2", ""),
        neighbor_block(65002, "10.0.4.2", ""),
    ]
    .concat();
    let b_neighbors = [
        neighbor_block(65001, "10.0.1.1", ""),
        neighbor_block(
            65001,
            "fe80::1",
            "interface = \"eth1\"\nfamilies = [\"ipv6_unicast\"]",
        ),
        neighbor_block(65001, "10.0.2.1", ""),
        neighbor_block(65001, "10.0.3.1", ""),
        neighbor_block(65001, "10.0.4.1", ""),
    ]
    .concat();
    let mut a = Daemon::start(&ns.a, dir_a.path(), 65001, "192.0.2.1", &a_neighbors);
    let b = Daemon::start(&ns.b, dir_b.path(), 65002, "192.0.2.2", &b_neighbors);

    let all = [ETH1_V4, ETH1_LL, OPTED_OUT, UNTOUCHED, ADDRESS_REMOVED];
    a.wait("every session Established", RECOVERY_BOUND, |a| {
        all.iter().all(|peer| a.established(peer))
    });
    let added = b.rbgp(&["rib", "add", PREFIX, "--nexthop", "10.0.1.2"]);
    assert!(
        added.status.success(),
        "rib add: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let v4 = [ETH1_V4, OPTED_OUT, UNTOUCHED, ADDRESS_REMOVED];
    a.wait("the route from every IPv4 session", RECOVERY_BOUND, |a| {
        v4.iter().all(|peer| {
            a.neighbor(peer)
                .is_some_and(|row| row["prefixes_received"].as_u64() == Some(1))
        })
    });

    // Phase 1: pull eth1 and eth2 by downing B's ends; A sees carrier loss.
    ip(&["-n", &ns.b, "link", "set", "eth1", "down"]);
    ip(&["-n", &ns.b, "link", "set", "eth2", "down"]);
    let elapsed = a.wait(
        "eth1 sessions down after carrier loss",
        FAILOVER_BOUND,
        |a| !a.established(ETH1_V4) && !a.established(ETH1_LL),
    );
    eprintln!("carrier-loss failover took {elapsed:?} (hold time {HOLD_TIME_SECS}s)");
    assert_failed_over(&mut a, ETH1_V4, "carrier lost");
    assert!(
        a.established(OPTED_OUT),
        "the opted-out session must wait for its hold timer"
    );
    assert!(
        a.established(UNTOUCHED),
        "a session on another link is untouched"
    );
    assert!(a.established(ADDRESS_REMOVED));

    ip(&["-n", &ns.b, "link", "set", "eth1", "up"]);
    link_local(&ns.b, 2);
    ip(&["-n", &ns.b, "link", "set", "eth2", "up"]);
    a.wait(
        "eth1 sessions recover after the link returns",
        RECOVERY_BOUND,
        |a| a.established(ETH1_V4) && a.established(ETH1_LL),
    );

    // Phase 2: A's own admin down.
    ip(&["-n", &ns.a, "link", "set", "eth1", "down"]);
    a.wait("eth1 sessions down after admin down", FAILOVER_BOUND, |a| {
        !a.established(ETH1_V4) && !a.established(ETH1_LL)
    });
    assert_failed_over(&mut a, ETH1_V4, "administratively down");
    ip(&["-n", &ns.a, "link", "set", "eth1", "up"]);
    link_local(&ns.a, 1);
    a.wait(
        "eth1 sessions recover after admin up",
        RECOVERY_BOUND,
        |a| a.established(ETH1_V4) && a.established(ETH1_LL),
    );

    // Phase 3: delete the veth pair, then recreate it.
    ip(&["-n", &ns.a, "link", "del", "eth1"]);
    a.wait(
        "eth1 sessions down after interface removal",
        FAILOVER_BOUND,
        |a| !a.established(ETH1_V4) && !a.established(ETH1_LL),
    );
    assert_failed_over(&mut a, ETH1_V4, "");
    ns.link(1);
    // Only the numbered session can come back: a static link-local neighbor
    // resolves its interface index once, at configuration time, so it keeps
    // dialing the deleted interface's index. That is independent of failover.
    a.wait(
        "the numbered eth1 session recovers on the recreated interface",
        RECOVERY_BOUND,
        |a| a.established(ETH1_V4),
    );
    assert!(a.established(UNTOUCHED));

    // Phase 4: remove A's eth4 source address; the link itself stays up.
    ip(&["-n", &ns.a, "addr", "del", "10.0.4.1/30", "dev", "eth4"]);
    a.wait(
        "eth4 session down after address removal",
        FAILOVER_BOUND,
        |a| !a.established(ADDRESS_REMOVED),
    );
    assert_failed_over(&mut a, ADDRESS_REMOVED, "local address removed");
    assert!(a.established(UNTOUCHED));

    // Control: an ordinary transport loss keeps the GR helper behavior.
    drop(b);
    a.wait("GR retention on an ordinary loss", RECOVERY_BOUND, |a| {
        a.neighbor(UNTOUCHED).is_some_and(|row| {
            row["state"].as_str() != Some("Established")
                && row["gr_retention"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
        })
    });
}
