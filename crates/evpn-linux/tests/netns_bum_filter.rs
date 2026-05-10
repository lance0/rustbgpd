//! Privileged netns spike for the Gate 8b BUM-suppression primitive.
//!
//! Two flavors:
//!
//! 1. `bum_filter_spike_validates_kernel_primitive` — runs the
//!    shell-driven topology + traffic generator at
//!    `tests/scripts/netns-bum-filter-spike.sh`. Validates that
//!    the per-port `bridge link set ... flood off mcast_flood off
//!    bcast_flood off` triplet is the right kernel primitive: DF
//!    allows / Non-DF blocks BUM, known unicast survives, restore
//!    is symmetric, FDB programming is unaffected.
//!
//! 2. `linux_dataplane_set_bum_port_flags_round_trip` — exercises
//!    the same primitive through the Rust path: `LinuxDataplane::
//!    apply(&DataplaneOp::SetBumPortFlags { ifindex, flags })`
//!    issues an `RTM_NEWLINK` carrying the
//!    `IFLA_BRPORT_*_FLOOD` triplet, then `bridge -j -d link
//!    show` confirms the flags applied. This is the load-bearing
//!    integration test for the rtnetlink wiring — without it
//!    we'd be trusting the netlink-packet-route attribute layout
//!    blindly.
//!
//! Both gate on `EVPN_LINUX_NETNS=1` and require `CAP_NET_ADMIN`
//! plus kernel >= 4.18 (per-port `bcast_flood`).
//!
//! Run locally:
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_bum_filter
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;

use rustbgpd_evpn_linux::{BumPortFlags, Dataplane, DataplaneOp, LinuxDataplane};

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

#[test]
fn bum_filter_spike_validates_kernel_primitive() {
    if !netns_gate() {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to run privileged BUM-filter spike (requires \
             CAP_NET_ADMIN + kernel >= 4.18)"
        );
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let script = format!("{manifest}/tests/scripts/netns-bum-filter-spike.sh");

    let status = Command::new("bash")
        .arg(&script)
        .status()
        .expect("failed to spawn netns-bum-filter-spike.sh");

    assert!(
        status.success(),
        "BUM-filter spike script failed (exit {status}); see script output above"
    );
}

#[tokio::test]
async fn linux_dataplane_set_bum_port_flags_round_trip() {
    if !netns_gate() {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to round-trip SetBumPortFlags via real netlink"
        );
        return;
    }

    let ns = format!("rb-bum-rt-{}", std::process::id());
    try_run("ip", &["netns", "delete", &ns]);
    run("ip", &["netns", "add", &ns]);
    let ns_exec = |cmd: &str, args: &[&str]| {
        let mut full = vec!["netns", "exec", &ns, cmd];
        full.extend(args);
        run("ip", &full);
    };
    ns_exec("ip", &["link", "set", "lo", "up"]);
    ns_exec("ip", &["link", "add", "br100", "type", "bridge"]);
    ns_exec(
        "ip",
        &[
            "link", "add", "ce-br", "type", "veth", "peer", "name", "ce-tap",
        ],
    );
    ns_exec("ip", &["link", "set", "ce-br", "master", "br100"]);
    ns_exec("ip", &["link", "set", "br100", "up"]);
    ns_exec("ip", &["link", "set", "ce-br", "up"]);
    ns_exec("ip", &["link", "set", "ce-tap", "up"]);

    // Re-exec inside the netns; the inner pass connects rtnetlink
    // and exercises the LinuxDataplane apply path. The outer pass
    // collects the kernel state via `bridge -d link show ce-br`
    // and asserts the flags landed.
    let inner_marker = std::env::var("RUSTBGPD_BUM_INNER").is_ok();
    if !inner_marker {
        let exe = std::env::current_exe().expect("self-exe");
        let status = Command::new("ip")
            .args(["netns", "exec", &ns])
            .arg(&exe)
            .args([
                "--exact",
                "--nocapture",
                "linux_dataplane_set_bum_port_flags_round_trip",
            ])
            .env("RUSTBGPD_BUM_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");

        // Outer pass: read ce-br's flag state and assert all three
        // flooding flags landed in the suppress configuration the
        // inner pass requested last.
        let mut full = vec!["netns", "exec", &ns];
        full.extend(["bridge", "-d", "link", "show", "dev", "ce-br"]);
        let out = run("ip", &full);
        let dump = String::from_utf8_lossy(&out.stdout);
        for label in ["flood off", "mcast_flood off", "bcast_flood off"] {
            assert!(
                dump.contains(label),
                "expected `{label}` in `bridge -d link show ce-br` output:\n{dump}"
            );
        }

        try_run("ip", &["netns", "delete", &ns]);
        return;
    }

    // Inner pass: connect rtnetlink in the netns and apply the op.
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    // Resolve ce-br's ifindex via /sys.
    let ifindex_str =
        std::fs::read_to_string("/sys/class/net/ce-br/ifindex").expect("read ce-br ifindex");
    let ifindex: u32 = ifindex_str.trim().parse().expect("parse ifindex");
    assert!(ifindex > 0, "got ifindex 0");

    // Apply suppress (Non-DF) — matches the spike's primary case.
    dp.apply(&DataplaneOp::SetBumPortFlags {
        ifindex,
        flags: BumPortFlags::suppress_all(),
    })
    .await
    .expect("SetBumPortFlags suppress_all");
}
