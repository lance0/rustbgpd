//! Privileged netns proof for the ADR-0085 Decision 4 link carrier
//! monitor.
//!
//! Re-exec pattern (mirrors `netns_bum_filter.rs`): the outer pass
//! creates a throwaway netns and re-runs this test binary inside it;
//! the inner pass builds a veth pair, spawns
//! [`spawn_link_carrier_monitor`], and drives real carrier
//! transitions with `ip link set ... down/up` on the **peer** end —
//! which flips `IFF_LOWER_UP` on the watched end without touching
//! its admin state, exactly the cable-pull shape the monitor exists
//! to observe. Asserts:
//!
//! - first-probe state (admin-down veth = no carrier; a watched name
//!   with no kernel link is present and `false`, fail-closed);
//! - the watch transitions up/down/up on peer flaps (edge-triggered,
//!   not poll-bound: timeouts are well under the 10 s backstop);
//! - `replace_watched_links` re-evaluates immediately from kernel
//!   state;
//! - link deletion projects down.
//!
//! Gates on `EVPN_LINUX_NETNS=1` and requires `CAP_NET_ADMIN` +
//! `CAP_SYS_ADMIN` (for `ip netns add`), same as the sibling netns
//! tests — skipped (early return) otherwise. Run locally via the
//! Docker harness:
//!
//! ```bash
//! bash crates/evpn-linux/tests/docker/run-netns-tests.sh link_carrier
//! ```

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use rustbgpd_evpn_linux::{LinkCarrierMap, spawn_link_carrier_monitor};
use tokio::sync::watch;

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

/// RAII netns guard — see `netns_bum_filter.rs::NetnsFixture`.
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
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// Await a watch transition matching `pred`, bounded well under the
/// monitor's 10 s poll backstop so a pass proves the *event* path.
async fn wait_for(
    rx: &mut watch::Receiver<LinkCarrierMap>,
    what: &str,
    pred: impl FnMut(&LinkCarrierMap) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(5), rx.wait_for(pred))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for: {what}"))
        .unwrap_or_else(|_| panic!("carrier monitor exited waiting for: {what}"));
}

#[tokio::test]
async fn link_carrier_monitor_tracks_veth_carrier_transitions() {
    if !netns_gate() {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to run the privileged link-carrier netns test \
             (requires CAP_NET_ADMIN + CAP_SYS_ADMIN)"
        );
        return;
    }

    // Outer pass: create the netns and re-exec this test inside it,
    // so every `ip link` mutation below is namespace-local.
    if std::env::var("RUSTBGPD_LINKCAR_INNER").is_err() {
        let ns = NetnsFixture::create("linkcar");
        let exe = std::env::current_exe().expect("self-exe");
        let status = Command::new("ip")
            .args(["netns", "exec", &ns.name])
            .arg(&exe)
            .args([
                "--exact",
                "--nocapture",
                "link_carrier_monitor_tracks_veth_carrier_transitions",
            ])
            .env("RUSTBGPD_LINKCAR_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");
        return;
        // NetnsFixture::drop deletes the netns on both success and
        // panic paths.
    }

    // Inner pass — inside the netns.
    run(
        "ip",
        &["link", "add", "es0", "type", "veth", "peer", "name", "es0p"],
    );

    let handle = spawn_link_carrier_monitor(names(&["es0", "ghost0"]))
        .await
        .expect("netlink connect inside netns");
    let mut rx = handle.subscribe();

    // First-probe state, published before any event processing:
    // es0 exists but is admin-down (fresh veth) → no carrier;
    // ghost0 has no kernel link → present and down (fail-closed).
    {
        let initial = rx.borrow().clone();
        assert_eq!(
            initial.get("es0"),
            Some(&false),
            "fresh veth must start down"
        );
        assert_eq!(
            initial.get("ghost0"),
            Some(&false),
            "watched name with no kernel link must be present and down"
        );
        assert_eq!(
            initial.len(),
            2,
            "projection must contain exactly the watched names"
        );
    }

    // Both ends up → IFF_LOWER_UP on es0.
    run("ip", &["link", "set", "es0", "up"]);
    run("ip", &["link", "set", "es0p", "up"]);
    wait_for(&mut rx, "es0 carrier up", |m| m.get("es0") == Some(&true)).await;

    // Peer admin-down clears es0's carrier without touching es0's
    // admin state — the cable-pull shape.
    run("ip", &["link", "set", "es0p", "down"]);
    wait_for(&mut rx, "es0 carrier loss on peer down", |m| {
        m.get("es0") == Some(&false)
    })
    .await;

    // Carrier returns.
    run("ip", &["link", "set", "es0p", "up"]);
    wait_for(&mut rx, "es0 carrier recovery", |m| {
        m.get("es0") == Some(&true)
    })
    .await;

    // Replace the watched set at runtime: drop ghost0, add the peer.
    // Re-evaluation is immediate from kernel state — es0p is already
    // carrier-up, no transition needed to learn that.
    assert!(
        handle.replace_watched_links(names(&["es0", "es0p"])).await,
        "monitor must still be running"
    );
    wait_for(&mut rx, "watched-set replace re-evaluation", |m| {
        m.len() == 2 && !m.contains_key("ghost0") && m.get("es0p") == Some(&true)
    })
    .await;

    // Deleting the pair projects both names down (fail-closed), via
    // the RTM_DELLINK edge.
    run("ip", &["link", "del", "es0"]);
    wait_for(&mut rx, "deleted links project down", |m| {
        m.get("es0") == Some(&false) && m.get("es0p") == Some(&false)
    })
    .await;
}
