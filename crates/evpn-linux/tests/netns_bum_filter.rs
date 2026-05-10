//! Privileged netns spike for the Gate 8b BUM-suppression primitive.
//!
//! Verifies that the per-port `bridge link set ... flood off
//! mcast_flood off bcast_flood off` triplet is the right kernel
//! primitive to suppress CE-facing BUM on Non-DF without breaking
//! known-unicast forwarding or remote-FDB programming.
//!
//! Heavy lifting lives in
//! `tests/scripts/netns-bum-filter-spike.sh` — this wrapper just
//! gates on `EVPN_LINUX_NETNS=1` and shells out, so the spike can
//! land ahead of the rtnetlink wiring without bringing in any new
//! Rust dependencies (libpnet / nix raw sockets / etc.).
//!
//! ## Why gated
//!
//! The script needs `CAP_NET_ADMIN` to create a netns and bridge,
//! plus a kernel >= 4.18 for the per-port `bcast_flood` flag. PR-CI
//! runners don't have either guaranteed, so the test is gated on
//! `EVPN_LINUX_NETNS=1`. The gate matches the existing
//! `netns_dataplane.rs` pattern.
//!
//! Run locally:
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_bum_filter
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
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
