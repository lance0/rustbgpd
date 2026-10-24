//! Privileged netns proof of ADR-0142 interface-only neighbors.
//!
//! Two real daemons, A (AS 65001) and B (AS 65002), each in its own network
//! namespace, joined by one veth pair named `veth` on both sides. Neither
//! configuration names an address: each has one `interface = "veth"`
//! neighbor with `remote_asn = "external"`. Link-local addresses are fixed
//! (`fe80::a1` on A, `fe80::b1` on B) so the test can change one. The test
//! asserts, on both daemons:
//!
//! - each learns the other's address from Router Advertisements and the
//!   session reaches Established;
//! - confirmed carrier loss removes the session at once, and it comes back
//!   when the link returns;
//! - after B's address changes to `fe80::b2`, A follows it: the session
//!   comes back Established on the new endpoint and the old one is gone.
//!
//! Gates on `EVPN_LINUX_NETNS=1`; run via
//! `bash crates/evpn-linux/tests/docker/run-netns-tests.sh interface_only_neighbors`.

#![cfg(target_os = "linux")]

#[path = "support/cargo.rs"]
mod cargo;

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Short timers keep the address-change phase bounded: the old address
/// stays a candidate for one Router Lifetime (3 × 4 s) and the session
/// fails within one hold time.
const RA_INTERVAL_SECS: u16 = 4;
const HOLD_TIME_SECS: u16 = 9;
const FAILOVER_BOUND: Duration = Duration::from_secs(5);
const RECOVERY_BOUND: Duration = Duration::from_secs(90);

fn netns_enabled() -> bool {
    let enabled = std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1");
    if !enabled {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the interface-only neighbor test");
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

fn link_local(ns: &str, address: &str) {
    link_local_on(ns, "veth", address);
}

fn link_local_on(ns: &str, dev: &str, address: &str) {
    ip(&[
        "-n",
        ns,
        "addr",
        "replace",
        &format!("{address}/64"),
        "dev",
        dev,
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
            a: format!("ion-a-{id}"),
            b: format!("ion-b-{id}"),
        };
        for ns in [&this.a, &this.b] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
            ip(&["netns", "add", ns]);
            ip(&["-n", ns, "link", "set", "lo", "up"]);
        }
        this.add_link("veth", "fe80::a1", "fe80::b1");
        this
    }

    /// A veth pair named `name` in both namespaces, with fixed link-local
    /// addresses.
    fn add_link(&self, name: &str, a_address: &str, b_address: &str) {
        let id = std::process::id() % 10_000;
        let (a_tmp, b_tmp) = (format!("iona{name}{id}"), format!("ionb{name}{id}"));
        ip(&[
            "link", "add", &a_tmp, "type", "veth", "peer", "name", &b_tmp,
        ]);
        for (tmp, ns, address) in [(&a_tmp, &self.a, a_address), (&b_tmp, &self.b, b_address)] {
            ip(&["link", "set", tmp, "netns", ns, "name", name]);
            ip(&["-n", ns, "link", "set", name, "addrgenmode", "none"]);
            link_local_on(ns, name, address);
            ip(&["-n", ns, "link", "set", name, "up"]);
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
    config: PathBuf,
    log: PathBuf,
    grpc: String,
}

impl Daemon {
    fn start(ns: &str, dir: &Path, asn: u32, router_id: &str) -> Self {
        Self::start_with(ns, dir, asn, router_id, "")
    }

    /// [`Self::start`] with `extra` TOML on the `veth` neighbor.
    fn start_with(ns: &str, dir: &Path, asn: u32, router_id: &str, extra: &str) -> Self {
        Self::start_neighbor(
            ns,
            dir,
            asn,
            router_id,
            &format!("interface = \"veth\"\nremote_asn = \"external\"\n{extra}"),
        )
    }

    /// A daemon whose one `veth` neighbor is `neighbor` (TOML keys).
    fn start_neighbor(ns: &str, dir: &Path, asn: u32, router_id: &str, neighbor: &str) -> Self {
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
"rustbgpd://operator/ion-test" = "operator"

[global]
asn = {asn}
router_id = "{router_id}"
listen_port = 179
runtime_state_dir = "{runtime}"

[global.unnumbered]
ra_interval_secs = {RA_INTERVAL_SECS}

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "{runtime}/grpc.sock"
principal = "rustbgpd://operator/ion-test"

[[neighbors]]
families = ["ipv6_unicast"]
hold_time = {HOLD_TIME_SECS}
{neighbor}
"#,
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
            config,
            log,
            grpc: format!("unix://{}/grpc.sock", runtime.display()),
        }
    }

    /// Append `toml` to the last (`veth`) neighbor's stanza and SIGHUP the
    /// daemon, waiting until the reload completes.
    fn reload_appending(&mut self, toml: &str) {
        let mut config = std::fs::read_to_string(&self.config).unwrap();
        config.push_str(toml);
        std::fs::write(&self.config, config).unwrap();
        let reloads = |log: &str| log.matches("config reload complete").count();
        let before = reloads(&self.log());
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            nix::sys::signal::Signal::SIGHUP,
        )
        .unwrap();
        self.wait("the reload to complete", FAILOVER_BOUND, |d| {
            reloads(&d.log()) > before
        });
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

    /// Neighbor rows on `veth`; `None` when the query or its parse failed,
    /// which is never the same as a successful empty list.
    fn veth_rows(&mut self) -> Option<Vec<serde_json::Value>> {
        self.rows_on("veth")
    }

    /// [`Self::veth_rows`] for `interface`.
    fn rows_on(&mut self, interface: &str) -> Option<Vec<serde_json::Value>> {
        if let Ok(Some(status)) = self.child.try_wait() {
            panic!("rustbgpd exited: {status}\nlog:\n{}", self.log());
        }
        let out = self.rbgp(&["--json", "neighbor"]);
        if !out.status.success() {
            return None;
        }
        let rows = serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .ok()?
            .as_array()?
            .clone();
        Some(
            rows.into_iter()
                .filter(|row| row["interface"].as_str() == Some(interface))
                .collect(),
        )
    }

    /// Exactly one `veth` neighbor, Established with the learned `address`
    /// (an interface-only row's own `address` is empty). An unavailable
    /// control plane is retried by the caller's poll.
    fn established_with(&mut self, address: &str) -> bool {
        self.established_on("veth", address)
    }

    /// [`Self::established_with`] for `interface`.
    fn established_on(&mut self, interface: &str, address: &str) -> bool {
        self.rows_on(interface).is_some_and(|rows| {
            rows.len() == 1
                && rows[0]["address"].as_str() == Some("")
                && rows[0]["learned_peer_address"].as_str() == Some(address)
                && rows[0]["state"].as_str() == Some("Established")
        })
    }

    /// The `veth` neighbor's learned address and state, when listed.
    fn veth_binding(&mut self) -> Option<(String, String)> {
        let rows = self.veth_rows()?;
        let row = rows.first()?;
        Some((
            row["learned_peer_address"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            row["state"].as_str().unwrap_or("").to_string(),
        ))
    }

    /// A successful query whose `veth` neighbor is listed unbound, with no
    /// learned address and its link down.
    fn veth_neighbor_unbound(&mut self) -> bool {
        self.veth_rows().is_some_and(|rows| {
            rows.len() == 1
                && rows[0].get("learned_peer_address").is_none()
                && rows[0]["discovery_state"].as_str() == Some("link_down")
        })
    }

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
            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "timed out after {bound:?} waiting for {what}; rows: {:#?}\nlog:\n{}",
            self.veth_rows(),
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

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

#[test]
fn interface_only_neighbors_discover_each_other_and_follow_an_address_change() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    let (dir_a, dir_b) = (private_tempdir(), private_tempdir());
    let mut a = Daemon::start(&ns.a, dir_a.path(), 65001, "192.0.2.1");
    let mut b = Daemon::start(&ns.b, dir_b.path(), 65002, "192.0.2.2");

    let elapsed = a.wait(
        "A Established with B via RA discovery",
        RECOVERY_BOUND,
        |a| a.established_with("fe80::b1"),
    );
    eprintln!("discovery to Established took {elapsed:?}");
    b.wait("B Established with A", RECOVERY_BOUND, |b| {
        b.established_with("fe80::a1")
    });

    // Confirmed carrier loss ends the session at once (A sees B's end go
    // down), and it comes back with the link.
    ip(&["-n", &ns.b, "link", "set", "veth", "down"]);
    let elapsed = a.wait("A's session gone after carrier loss", FAILOVER_BOUND, |a| {
        a.veth_neighbor_unbound()
    });
    eprintln!("carrier-loss teardown took {elapsed:?} (hold time {HOLD_TIME_SECS}s)");
    ip(&["-n", &ns.b, "link", "set", "veth", "up"]);
    // Admin down flushed B's address (keep_addr_on_down is not writable here).
    link_local(&ns.b, "fe80::b1");
    a.wait(
        "A Established again after the link returns",
        RECOVERY_BOUND,
        |a| a.established_with("fe80::b1"),
    );
    b.wait("B Established again", RECOVERY_BOUND, |b| {
        b.established_with("fe80::a1")
    });

    // B's address changes. A keeps the healthy session until it fails, then
    // binds the new address under the same neighbor.
    link_local(&ns.b, "fe80::b2");
    ip(&["-n", &ns.b, "addr", "del", "fe80::b1/64", "dev", "veth"]);
    let elapsed = a.wait("A Established with B's new address", RECOVERY_BOUND, |a| {
        a.established_with("fe80::b2")
    });
    eprintln!("address change recovery took {elapsed:?}");
    b.wait("B Established from its new address", RECOVERY_BOUND, |b| {
        b.established_with("fe80::a1")
    });
    // The failed session retained nothing (Hold Timer expiry closes with a
    // NOTIFICATION), so when discovery is briefly unbound before the new
    // address's RA arrives, the old peer is released first and the new
    // address binds afresh; otherwise it is replaced as an address change.
    let log = a.log();
    assert!(
        log.contains("peer_address_changed") || log.contains("binding_expired"),
        "the old endpoint's retirement is logged"
    );
}

#[path = "support/host_ipv6_netns.rs"]
mod host_ipv6_netns;

/// GTSM (`ttl_security`) on interface-only neighbors: with B's link route
/// hop limit lowered to 254, A binds B's learned address but never establishes,
/// because the listener and A's own active open refuse segments below 255.
/// Once B also runs GTSM, its session socket sends 255 and both establish.
#[test]
fn interface_only_gtsm_refuses_hop_limit_254_and_accepts_255() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    // B's link route carries Hop Limit 254, so a session socket that does
    // not set its own (no GTSM) sends 254; GTSM's explicit 255 overrides it.
    ip(&[
        "-n",
        &ns.b,
        "-6",
        "route",
        "replace",
        "fe80::/64",
        "dev",
        "veth",
        "hoplimit",
        "254",
    ]);
    let (dir_a, dir_b) = (private_tempdir(), private_tempdir());
    let gtsm = "ttl_security = true";
    let mut a = Daemon::start_with(&ns.a, dir_a.path(), 65001, "192.0.2.1", gtsm);
    let b = Daemon::start(&ns.b, dir_b.path(), 65002, "192.0.2.2");

    a.wait("A bound to B's learned address", RECOVERY_BOUND, |a| {
        a.veth_binding()
            .is_some_and(|(learned, _)| learned == "fe80::b1")
    });
    // Discovery and both directions' handshakes have had several attempts
    // (connect retry and RA interval are a few seconds here).
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        // Mutation-red: without the learned selector or the inbound
        // IP_MINTTL, B's hop-limit-254 session reaches Established.
        assert!(
            !a.established_with("fe80::b1"),
            "A established with a hop-limit-254 peer\nlog:\n{}",
            a.log()
        );
        thread::sleep(Duration::from_millis(500));
    }
    drop(b);

    let dir_b = private_tempdir();
    let mut b = Daemon::start_with(&ns.b, dir_b.path(), 65002, "192.0.2.2", gtsm);
    a.wait("A Established once B runs GTSM", RECOVERY_BOUND, |a| {
        a.established_with("fe80::b1")
    });
    b.wait("B Established with A", RECOVERY_BOUND, |b| {
        b.established_with("fe80::a1")
    });
}

/// The same RA-silent GTSM peer when a reload turns on A's GTSM: until
/// then A's listener answers at the default Hop Limit and B drops every
/// SYN-ACK, so nothing is learned; the reload raises it to 255 before any
/// binding exists, and A then learns B from its next connection.
#[test]
fn an_ra_silent_gtsm_peer_is_learned_after_a_reload_enables_gtsm() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    let (dir_a, dir_b) = (private_tempdir(), private_tempdir());
    let mut a = Daemon::start(&ns.a, dir_a.path(), 65001, "192.0.2.1");
    let _b = Daemon::start_neighbor(
        &ns.b,
        dir_b.path(),
        65002,
        "192.0.2.2",
        "address = \"fe80::a1\"\ninterface = \"veth\"\nremote_asn = 65001\nttl_security = true",
    );
    a.wait("A's neighbor listed", RECOVERY_BOUND, |a| {
        a.veth_rows().is_some_and(|rows| rows.len() == 1)
    });
    // B dials repeatedly in this window; none of its handshakes completes.
    thread::sleep(Duration::from_secs(15));
    assert!(
        !a.log()
            .contains("peer address learned from an inbound connection"),
        "nothing learned while A answers at the default Hop Limit"
    );

    // Mutation-red: without the live raise, A keeps the default Hop Limit
    // and B's handshakes keep failing.
    a.reload_appending("ttl_security = true\n");
    a.wait(
        "A Established with the RA-silent GTSM peer after the reload",
        RECOVERY_BOUND,
        |a| a.established_with("fe80::b1"),
    );
    assert!(
        a.log()
            .contains("peer address learned from an inbound connection"),
        "learned from B's inbound connection, not an RA"
    );
}

/// An RA-silent GTSM peer that dials in: B has a static link-local neighbor
/// toward A with `ttl_security` and no interface-only neighbor, so it sends no
/// RAs and A can learn it only from B's inbound connection. B's socket drops
/// any SYN-ACK below Hop Limit 255, so A's listener must send 255 before any
/// binding exists; A then learns B, installs its selector and establishes.
#[test]
fn an_ra_silent_gtsm_peer_is_learned_from_its_inbound_connection() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    let (dir_a, dir_b) = (private_tempdir(), private_tempdir());
    let mut a = Daemon::start_with(
        &ns.a,
        dir_a.path(),
        65001,
        "192.0.2.1",
        "ttl_security = true",
    );
    let _b = Daemon::start_neighbor(
        &ns.b,
        dir_b.path(),
        65002,
        "192.0.2.2",
        "address = \"fe80::a1\"\ninterface = \"veth\"\nremote_asn = 65001\nttl_security = true",
    );
    // Mutation-red: without the listener's startup Hop Limit, B never
    // completes a handshake and A never learns it.
    a.wait(
        "A Established with the RA-silent GTSM peer",
        RECOVERY_BOUND,
        |a| a.established_with("fe80::b1"),
    );
    assert!(
        a.log()
            .contains("peer address learned from an inbound connection"),
        "learned from B's inbound connection, not an RA"
    );
}

/// Two parallel links to a peer that uses one link-local address on both
/// (`fe80::b1` on `veth` and `veth2`, as a router reusing its MAC on every
/// port does), with GTSM on A's `veth` neighbor only. The learned-endpoint
/// selector matches address and arrival interface, so A admits both
/// bindings of the shared address: while B sends Hop Limit 254 and runs no
/// GTSM, `veth2` establishes and `veth` never does; once B runs GTSM on
/// `veth`, both sessions to `fe80::b1` are Established.
#[test]
fn interface_only_neighbors_with_differing_gtsm_share_a_learned_address() {
    if !netns_enabled() {
        return;
    }
    let ns = Namespaces::create();
    ns.add_link("veth2", "fe80::a2", "fe80::b1");
    for dev in ["veth", "veth2"] {
        ip(&[
            "-n",
            &ns.b,
            "-6",
            "route",
            "replace",
            "fe80::/64",
            "dev",
            dev,
            "hoplimit",
            "254",
        ]);
    }
    let neighbors = |veth: &str| {
        format!(
            "interface = \"veth\"\nremote_asn = \"external\"\n{veth}\n\n\
             [[neighbors]]\nfamilies = [\"ipv6_unicast\"]\nhold_time = {HOLD_TIME_SECS}\n\
             interface = \"veth2\"\nremote_asn = \"external\"\n"
        )
    };
    let gtsm = "ttl_security = true";
    let (dir_a, dir_b) = (private_tempdir(), private_tempdir());
    let mut a = Daemon::start_neighbor(&ns.a, dir_a.path(), 65001, "192.0.2.1", &neighbors(gtsm));
    let b = Daemon::start_neighbor(&ns.b, dir_b.path(), 65002, "192.0.2.2", &neighbors(""));

    // Mutation-red: with the address-keyed refusal, the second link to
    // learn fe80::b1 is refused with `shared_address_feature`.
    a.wait(
        "A Established with fe80::b1 on veth2",
        RECOVERY_BOUND,
        |a| a.established_on("veth2", "fe80::b1"),
    );
    a.wait("A bound to fe80::b1 on veth", RECOVERY_BOUND, |a| {
        a.veth_binding()
            .is_some_and(|(learned, _)| learned == "fe80::b1")
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        assert!(
            !a.established_with("fe80::b1"),
            "A's GTSM link established with a hop-limit-254 peer\nlog:\n{}",
            a.log()
        );
        thread::sleep(Duration::from_millis(500));
    }
    assert!(
        a.established_on("veth2", "fe80::b1"),
        "the link without GTSM stays Established\nlog:\n{}",
        a.log()
    );
    drop(b);

    let dir_b = private_tempdir();
    let mut b = Daemon::start_neighbor(&ns.b, dir_b.path(), 65002, "192.0.2.2", &neighbors(gtsm));
    a.wait("A Established on both links", RECOVERY_BOUND, |a| {
        a.established_with("fe80::b1") && a.established_on("veth2", "fe80::b1")
    });
    b.wait("B Established on both links", RECOVERY_BOUND, |b| {
        b.established_with("fe80::a1") && b.established_on("veth2", "fe80::a2")
    });
}
