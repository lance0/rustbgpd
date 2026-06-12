//! Privileged netns round-trip for the single-active AC-gate kernel
//! primitive.
//!
//! Exercises `LinuxDataplane::apply(&DataplaneOp::SetAcPortState
//! { ifindex, blocked })` against a real kernel: a veth pair enslaved
//! to a bridge, blocked (`IFLA_BRPORT_STATE = BR_STATE_DISABLED`)
//! then restored (`BR_STATE_FORWARDING`), with `bridge -d link show`
//! asserting both transitions. Two invariants are load-bearing:
//!
//! 1. **State applies** — `state disabled` after block, `state
//!    forwarding` after restore.
//! 2. **Flood flags survive** — the gate message carries ONLY
//!    `IFLA_BRPORT_STATE`, so the Gate 8b
//!    `flood / mcast_flood / bcast_flood` triplet must still read
//!    `on` after both transitions (the kernel's `br_setport` applies
//!    only attributes present in the message; this pins it).
//!
//! Gates on `EVPN_LINUX_NETNS=1` and requires `CAP_NET_ADMIN` +
//! `CAP_SYS_ADMIN` (netns create). Run locally:
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_ac_gate
//! ```
//!
//! Or inside the Docker harness:
//!
//! ```bash
//! bash crates/evpn-linux/tests/docker/run-netns-tests.sh
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;

use rustbgpd_evpn_linux::{Dataplane, DataplaneOp, LinuxDataplane};

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
}

fn run(cmd: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(cmd).args(args).output().expect("spawn");
    if !out.status.success() {
        panic!(
            "{cmd} {args:?} failed: status={} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

fn try_run(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// RAII netns guard — mirrors `tests/netns_bum_filter.rs`.
struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str) -> Self {
        let name = format!("rustbgpd-test-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }

    fn ns_exec(&self, cmd: &str, args: &[&str]) -> std::process::Output {
        let mut full = vec!["netns", "exec", self.name.as_str(), cmd];
        full.extend(args);
        run("ip", &full)
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

#[tokio::test]
async fn linux_dataplane_set_ac_port_state_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to round-trip SetAcPortState via real netlink");
        return;
    }

    // Inner passes re-exec inside the netns and apply one transition
    // each; the outer pass builds the topology and asserts kernel
    // state between transitions.
    if let Ok(phase @ ("block" | "unblock")) = std::env::var("RUSTBGPD_AC_GATE_INNER").as_deref() {
        let mut dp = LinuxDataplane::connect()
            .await
            .expect("netlink connect inside netns");
        let ifindex_str =
            std::fs::read_to_string("/sys/class/net/ce-br/ifindex").expect("read ce-br ifindex");
        let ifindex: u32 = ifindex_str.trim().parse().expect("parse ifindex");
        assert!(ifindex > 0, "got ifindex 0");
        dp.apply(&DataplaneOp::SetAcPortState {
            ifindex,
            blocked: phase == "block",
        })
        .await
        .expect("SetAcPortState");
        return;
    }

    let ns = NetnsFixture::create("ac-gate");
    ns.ns_exec("ip", &["link", "add", "br100", "type", "bridge"]);
    ns.ns_exec(
        "ip",
        &[
            "link", "add", "ce-br", "type", "veth", "peer", "name", "ce-tap",
        ],
    );
    ns.ns_exec("ip", &["link", "set", "ce-br", "master", "br100"]);
    ns.ns_exec("ip", &["link", "set", "br100", "up"]);
    ns.ns_exec("ip", &["link", "set", "ce-br", "up"]);
    ns.ns_exec("ip", &["link", "set", "ce-tap", "up"]);

    let exe = std::env::current_exe().expect("self-exe");
    let inner = |phase: &str| {
        let status = Command::new("ip")
            .args(["netns", "exec", &ns.name])
            .arg(&exe)
            .args([
                "--exact",
                "--nocapture",
                "linux_dataplane_set_ac_port_state_round_trip",
            ])
            .env("RUSTBGPD_AC_GATE_INNER", phase)
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner {phase} invocation failed");
    };
    let port_dump = || {
        let out = ns.ns_exec("bridge", &["-d", "link", "show", "dev", "ce-br"]);
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    // The flood-flag triplet must read `on` (the kernel default)
    // before and after both gate transitions — the gate message
    // carries only IFLA_BRPORT_STATE, so any `flood off` in the dump
    // would mean the message clobbered a sibling attribute. Note
    // `"flood on"` alone is a substring of `mcast_flood on`, so the
    // honest assertion is the absence of any `off` flood flag.
    let assert_flood_untouched = |dump: &str, phase: &str| {
        for label in ["flood off", "mcast_flood off", "bcast_flood off"] {
            assert!(
                !dump.contains(label),
                "{phase} must not clobber the flood-flag triplet (found `{label}`):\n{dump}"
            );
        }
        assert!(
            dump.contains("mcast_flood on") && dump.contains("bcast_flood on"),
            "{phase}: expected the flood flags still on:\n{dump}"
        );
    };

    // Phase 1: block. State flips to disabled; flood flags untouched.
    inner("block");
    let dump = port_dump();
    assert!(
        dump.contains("state disabled"),
        "expected `state disabled` after block:\n{dump}"
    );
    assert_flood_untouched(&dump, "block");

    // Phase 2: unblock. State restores to forwarding.
    inner("unblock");
    let dump = port_dump();
    assert!(
        dump.contains("state forwarding"),
        "expected `state forwarding` after restore:\n{dump}"
    );
    assert_flood_untouched(&dump, "restore");
}
