//! Privileged netns integration test for the ADR-0059 slice 2
//! [`NexthopSocket`] primitive.
//!
//! Slice 2 has no diff/apply caller yet — the only way to verify
//! that the bytes [`super::nexthop_raw::encode`] produces actually
//! program the kernel correctly is to round-trip them against a
//! real `NETLINK_ROUTE` socket inside a CAP_NET_ADMIN-bearing
//! namespace and read the result back via `ip nexthop show`.
//!
//! Three load-bearing assertions:
//!
//! 1. `add_fdb_member` lands a per-VTEP nexthop with the right
//!    gateway and the `fdb` flag.
//! 2. `add_fdb_group` lands a group naming the two members in
//!    order, also with `fdb`.
//! 3. `del` removes the named nexthop and a re-`del` of the same
//!    id returns Ok (ENOENT-as-idempotent semantics).
//!
//! Plus the slice 3.5 PR 3 IPv6 add round-trip and two negative
//! paths:
//!
//! 4. `add_fdb_member` with `IpAddr::V6` — installs successfully and
//!    `ip nexthop show` round-trips `via <v6> fdb`.
//! 5. `add_fdb_group` with no members → `NexthopValidationError::EmptyGroup`.
//! 6. `add_fdb_group` with duplicate member ids →
//!    `NexthopValidationError::DuplicateMemberId`.
//!
//! ## Why gated
//!
//! Creating a netns + emitting `RTM_NEWNEXTHOP` both require
//! `CAP_NET_ADMIN`. PR-CI runners don't have it, so this test is
//! gated by the `EVPN_LINUX_NETNS=1` environment variable. The
//! current process must already hold the capability — the test
//! does not attempt privilege escalation.
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_nexthop_raw
//! ```

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;

use rustbgpd_evpn_linux::{
    NexthopError, NexthopGroupMember, NexthopSocket, NexthopValidationError,
};

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

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str) -> Self {
        let name = format!("rustbgpd-nh-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        Self { name }
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

fn run_inner(ns: &NetnsFixture, test_name: &str) {
    let exe = std::env::current_exe().expect("self-exe");
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "1")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

fn is_inner() -> bool {
    std::env::var("RUSTBGPD_NETNS_INNER").is_ok()
}

/// Round-trip: install per-VTEP nexthop, verify via `ip nexthop show`,
/// del, verify empty.
#[tokio::test]
async fn round_trip_add_fdb_member_then_del() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 + sudo to run");
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("member");
        run_inner(&ns, "round_trip_add_fdb_member_then_del");
        // After inner exits, the netns is gone (Drop). Nothing else
        // to assert from the outer side.
        return;
    }

    // ── inner: in the netns ──
    let mut sock = NexthopSocket::connect().expect("NexthopSocket::connect inside netns");

    let gateway: IpAddr = "10.99.99.99".parse().unwrap();
    sock.add_fdb_member(42, gateway)
        .await
        .expect("add_fdb_member");

    // Verify via shell out to ip nexthop show.
    let out = Command::new("ip")
        .args(["nexthop", "show", "id", "42"])
        .output()
        .expect("ip nexthop show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("via 10.99.99.99") && stdout.contains("fdb"),
        "expected 'via 10.99.99.99 ... fdb' in: {stdout}"
    );

    // Del + verify empty.
    sock.del(42).await.expect("del id 42");
    let out = Command::new("ip")
        .args(["nexthop", "show", "id", "42"])
        .output()
        .expect("ip nexthop show after del");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "expected empty after del, got: {stdout}"
    );

    // Second del should be idempotent (ENOENT → Ok).
    sock.del(42).await.expect("re-del idempotent");
}

/// Round-trip: install two per-VTEP members + one group; verify the
/// group references both members; tear down in order.
#[tokio::test]
async fn round_trip_add_fdb_group_then_del() {
    if !netns_gate() {
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("group");
        run_inner(&ns, "round_trip_add_fdb_group_then_del");
        return;
    }

    let mut sock = NexthopSocket::connect().expect("connect");

    let gw_a: IpAddr = "10.0.0.2".parse().unwrap();
    let gw_b: IpAddr = "10.0.0.3".parse().unwrap();
    sock.add_fdb_member(12, gw_a).await.expect("member 12");
    sock.add_fdb_member(13, gw_b).await.expect("member 13");

    let members = vec![
        NexthopGroupMember::new(12).unwrap(),
        NexthopGroupMember::new(13).unwrap(),
    ];
    sock.add_fdb_group(200, &members).await.expect("group 200");

    let out = Command::new("ip")
        .args(["nexthop", "show", "id", "200"])
        .output()
        .expect("show group");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("group 12/13") && stdout.contains("fdb"),
        "expected 'group 12/13 ... fdb' in: {stdout}"
    );

    // Tear down in order (ADR-0059 §5 invariant 2: FDB row first,
    // group second, members third — slice 2 has no FDB row yet so
    // group then members.)
    sock.del(200).await.expect("del group");
    sock.del(13).await.expect("del member 13");
    sock.del(12).await.expect("del member 12");

    let out = Command::new("ip")
        .args(["nexthop", "show"])
        .output()
        .expect("show all");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "expected empty after full teardown, got: {stdout}"
    );
}

/// IPv6 gateway accepted end-to-end (ADR-0059 slice 3.5 PR 3): the
/// encoder picks `AF_INET6`, the kernel installs the row, and the
/// subsequent dump round-trips a `Member { gateway: V6 }` back.
#[tokio::test]
async fn add_fdb_member_v6_installs_and_round_trips() {
    if !netns_gate() {
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("v6install");
        run_inner(&ns, "add_fdb_member_v6_installs_and_round_trips");
        return;
    }

    let mut sock = NexthopSocket::connect().expect("connect");
    let id: u32 = 99;
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    sock.add_fdb_member(id, v6)
        .await
        .expect("v6 add should succeed (PR 3 enabled IPv6 alias members)");

    // Verify via the iproute2 CLI that the row landed with the
    // expected `via <v6> fdb` form.
    let out = Command::new("ip")
        .args(["nexthop", "show", "id", &id.to_string()])
        .output()
        .expect("ip nexthop show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2001:db8::1") && stdout.contains("fdb"),
        "expected v6 fdb nexthop, got: {stdout}"
    );

    // Cleanup so subsequent tests aren't disturbed.
    sock.del(id).await.expect("v6 del should succeed");
}

/// Empty group → validation error before any netlink send.
#[tokio::test]
async fn add_fdb_group_empty_returns_validation_error() {
    if !netns_gate() {
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("empty");
        run_inner(&ns, "add_fdb_group_empty_returns_validation_error");
        return;
    }

    let mut sock = NexthopSocket::connect().expect("connect");
    let err = sock.add_fdb_group(100, &[]).await.unwrap_err();
    assert!(
        matches!(
            err,
            NexthopError::Validation(NexthopValidationError::EmptyGroup)
        ),
        "expected EmptyGroup, got {err:?}"
    );
}

/// Duplicate member ids → validation error.
#[tokio::test]
async fn add_fdb_group_duplicate_returns_validation_error() {
    if !netns_gate() {
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("dup");
        run_inner(&ns, "add_fdb_group_duplicate_returns_validation_error");
        return;
    }

    let mut sock = NexthopSocket::connect().expect("connect");
    let members = vec![
        NexthopGroupMember::new(5).unwrap(),
        NexthopGroupMember::new(5).unwrap(),
    ];
    let err = sock.add_fdb_group(100, &members).await.unwrap_err();
    assert!(
        matches!(
            err,
            NexthopError::Validation(NexthopValidationError::DuplicateMemberId(5))
        ),
        "expected DuplicateMemberId(5), got {err:?}"
    );
}
