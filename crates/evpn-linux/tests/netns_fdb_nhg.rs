//! Privileged netns integration test for ADR-0059 slice 3b's
//! [`NexthopOps`] impl on [`LinuxDataplane`] — FDB nexthop groups +
//! bridge FDB rows with `NDA_NH_ID` against a real kernel.
//!
//! Coordinator orchestration (allocator, refcount, adoption,
//! cleanup) is unit-tested in `nh_id_alloc.rs` / `group_state.rs` /
//! `diff.rs`. This file validates the *netlink path* end-to-end:
//! the bytes our encoder produces, sent via `NexthopSocket`, hit the
//! kernel and surface in `ip nexthop show` / `bridge fdb show` as
//! expected — and the CVE-2025-39851 guard refuses installs when the
//! L2VXLAN has learning enabled.
//!
//! Format strings researched in the slice 3b prep (research §4–5):
//!
//! - `bridge fdb show` prints `nhid %u` (no colon).
//! - `ip nexthop show` for a member: `id %u via %s fdb`.
//! - `ip nexthop show` for a group: `id %u group %u/%u fdb`.
//!
//! ## Why gated
//!
//! Creating a netns + bridge + VXLAN + FDB-NHG requires
//! `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` (the latter for `ip netns
//! add` / `mount --make-shared`). The Docker harness at
//! `crates/evpn-linux/tests/docker/run-netns-tests.sh` carries the
//! correct cap set + AppArmor unconfined profile. Manual invocation:
//!
//! ```bash
//! crates/evpn-linux/tests/docker/run-netns-tests.sh fdb_nhg
//! ```

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;

use rustbgpd_evpn::{EvpnInstanceId, MacAddress};
use rustbgpd_evpn_linux::LinuxDataplane;
use rustbgpd_evpn_linux::dataplane::{KernelNexthopKind, NexthopOps};

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
        let name = format!("rustbgpd-fdbnhg-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        Self { name }
    }

    #[allow(dead_code)] // helper kept for future test additions
    fn exec(&self, cmd: &str, args: &[&str]) -> String {
        let mut full = vec!["netns", "exec", self.name.as_str(), cmd];
        full.extend(args);
        let out = run("ip", &full);
        String::from_utf8_lossy(&out.stdout).into_owned()
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

/// Build a bridge + VXLAN port with `nolearning` in the current netns.
/// Returns the VNI for downstream test setup.
fn build_l2_topology() -> EvpnInstanceId {
    run("ip", &["addr", "add", "127.0.0.10/32", "dev", "lo"]);
    run("ip", &["link", "set", "lo", "up"]);
    run("ip", &["link", "add", "name", "br100", "type", "bridge"]);
    run("ip", &["link", "set", "br100", "up"]);
    run(
        "ip",
        &[
            "link",
            "add",
            "name",
            "vxlan100",
            "type",
            "vxlan",
            "id",
            "100",
            "local",
            "127.0.0.10",
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    run("ip", &["link", "set", "vxlan100", "master", "br100"]);
    run("ip", &["link", "set", "vxlan100", "up"]);
    EvpnInstanceId::new(100).expect("VNI 100")
}

/// Get the bridge FDB show output for the VXLAN port.
fn bridge_fdb_show() -> String {
    let out = run("bridge", &["fdb", "show", "dev", "vxlan100"]);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Get the nexthop show output.
fn ip_nexthop_show() -> String {
    let out = run("ip", &["nexthop", "show"]);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Round-trip: install per-VTEP member + group + FDB row pointing at
/// nhid; verify kernel state; remove all; verify empty.
#[tokio::test]
async fn round_trip_install_and_remove_fdb_nhg() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 + Docker harness to run");
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("roundtrip");
        run_inner(&ns, "round_trip_install_and_remove_fdb_nhg");
        return;
    }

    // ── inner ──
    let vni = build_l2_topology();
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("LinuxDataplane::connect");

    // Prime the link cache by issuing a probe so the CVE guard in
    // fdb_nhg can read learning_disabled.
    let mut table = rustbgpd_evpn::EvpnInstanceTable::new();
    let mut rd_bytes = [0u8; 8];
    rd_bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    rd_bytes[4..8].copy_from_slice(&vni.as_u32().to_be_bytes());
    table
        .insert(
            rustbgpd_evpn::EvpnInstance::new(
                vni,
                rustbgpd_evpn::RouteDistinguisher::new(rd_bytes),
                vec![rustbgpd_evpn::RouteTarget::TwoOctetAs {
                    asn: 65001,
                    value: vni.as_u32(),
                }],
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                Some("br100".into()),
                false,
            )
            .expect("EvpnInstance"),
        )
        .expect("insert");
    let probes = rustbgpd_evpn_linux::dataplane::Dataplane::probe(&mut dp, &table).await;
    assert!(
        matches!(
            probes.get(vni),
            Some(rustbgpd_evpn_linux::snapshot::InstanceProbe::Ready)
        ),
        "probe should be Ready with nolearning on the VXLAN",
    );

    // Install a per-VTEP member nexthop.
    let member_id: u32 = 0x3000_0001;
    let gateway: IpAddr = "10.0.0.2".parse().unwrap();
    dp.add_nexthop_member(member_id, gateway)
        .await
        .expect("add_nexthop_member");

    let nh = ip_nexthop_show();
    assert!(
        nh.contains("via 10.0.0.2") && nh.contains("fdb"),
        "expected 'via 10.0.0.2 ... fdb' in: {nh}",
    );

    // Install the group naming the single member.
    let group_id: u32 = 0x4000_0001;
    dp.add_nexthop_group(group_id, &[member_id])
        .await
        .expect("add_nexthop_group");

    let nh = ip_nexthop_show();
    assert!(
        nh.contains("group 0x30000001") || nh.contains("group 805306369"),
        "expected group payload referencing member 0x3000_0001 (= 805306369) in: {nh}",
    );

    // Install an FDB row pointing at the group.
    let test_mac = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
    dp.install_fdb_nhg_row(vni, test_mac, group_id)
        .await
        .expect("install_fdb_nhg_row");

    let fdb = bridge_fdb_show();
    let expected_nhid = group_id.to_string();
    // Per research §4: format is `nhid %u`, space-separated.
    assert!(
        fdb.contains(&format!("nhid {expected_nhid}")),
        "expected 'nhid {expected_nhid}' in: {fdb}",
    );

    // dump_owned_nexthops should see both entries (filtered by tag bits).
    let dumped = dp.dump_owned_nexthops().await.expect("dump_owned_nexthops");
    let ids: Vec<u32> = dumped.iter().map(|n| n.id).collect();
    assert!(ids.contains(&member_id), "dump missing member id: {ids:?}");
    assert!(ids.contains(&group_id), "dump missing group id: {ids:?}");
    // Spot-check kinds.
    let member_entry = dumped.iter().find(|n| n.id == member_id).unwrap();
    assert!(matches!(
        member_entry.kind,
        KernelNexthopKind::Member { .. }
    ));
    let group_entry = dumped.iter().find(|n| n.id == group_id).unwrap();
    assert!(matches!(group_entry.kind, KernelNexthopKind::Group { .. }));

    // Remove the FDB row, then group, then member (ADR §5 invariant 2 order).
    dp.remove_fdb_nhg_row(vni, test_mac)
        .await
        .expect("remove_fdb_nhg_row");
    dp.del_nexthop(group_id).await.expect("del group");
    dp.del_nexthop(member_id).await.expect("del member");

    // Verify everything's gone.
    let fdb_after = bridge_fdb_show();
    assert!(
        !fdb_after.contains(&format!("nhid {expected_nhid}")),
        "FDB row should be gone: {fdb_after}",
    );
    // `ip nexthop show` is a sanity-only display; the authoritative
    // emptiness check filters by tag bits via the kernel dump itself.
    // (`ip` prints IDs in decimal, so a hex substring match would be
    // unreliable even if the entries were still present.)
    let dumped_after = dp
        .dump_owned_nexthops()
        .await
        .expect("dump_owned_nexthops after teardown");
    assert!(
        dumped_after.is_empty(),
        "expected no tagged nexthops after teardown, got: {dumped_after:?}",
    );

    // Idempotent del — re-issuing del returns Ok (slice 3a's
    // classify_remove_apply_error fix).
    dp.remove_fdb_nhg_row(vni, test_mac)
        .await
        .expect("re-remove_fdb_nhg_row idempotent");
    dp.del_nexthop(group_id).await.expect("re-del group");
    dp.del_nexthop(member_id).await.expect("re-del member");
}

/// CVE-2025-39851 guard negative path: enable learning on the VXLAN,
/// attempt `install_fdb_nhg_row`, expect `InvalidArgument` error
/// (classified `Permanent` by the actor's failure classifier). The
/// guard runs purely from the link cache; no netlink call should
/// reach the kernel.
#[tokio::test]
async fn cve_guard_blocks_install_when_learning_enabled() {
    if !netns_gate() {
        return;
    }

    if !is_inner() {
        let ns = NetnsFixture::create("cveguard");
        run_inner(&ns, "cve_guard_blocks_install_when_learning_enabled");
        return;
    }

    // Build topology with `learning on` (omit `nolearning` from the
    // vxlan add to keep learning enabled by default).
    run("ip", &["addr", "add", "127.0.0.10/32", "dev", "lo"]);
    run("ip", &["link", "set", "lo", "up"]);
    run("ip", &["link", "add", "name", "br100", "type", "bridge"]);
    run("ip", &["link", "set", "br100", "up"]);
    run(
        "ip",
        &[
            "link",
            "add",
            "name",
            "vxlan100",
            "type",
            "vxlan",
            "id",
            "100",
            "local",
            "127.0.0.10",
            "dstport",
            "4789",
        ],
    );
    run("ip", &["link", "set", "vxlan100", "master", "br100"]);
    run("ip", &["link", "set", "vxlan100", "up"]);

    let vni = EvpnInstanceId::new(100).expect("VNI 100");

    let mut dp = LinuxDataplane::connect()
        .await
        .expect("LinuxDataplane::connect");

    // Prime the link cache via probe. The probe itself will surface
    // the instance as NotReady (the existing learning_disabled check
    // is the upstream guard); the apply-layer CVE check is what we
    // want to exercise here, so we call install_fdb_nhg_row directly
    // bypassing compute_diff's NotReady scoping.
    let mut table = rustbgpd_evpn::EvpnInstanceTable::new();
    let mut rd_bytes = [0u8; 8];
    rd_bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    rd_bytes[4..8].copy_from_slice(&vni.as_u32().to_be_bytes());
    table
        .insert(
            rustbgpd_evpn::EvpnInstance::new(
                vni,
                rustbgpd_evpn::RouteDistinguisher::new(rd_bytes),
                vec![rustbgpd_evpn::RouteTarget::TwoOctetAs {
                    asn: 65001,
                    value: vni.as_u32(),
                }],
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                Some("br100".into()),
                false,
            )
            .expect("EvpnInstance"),
        )
        .expect("insert");
    let _ = rustbgpd_evpn_linux::dataplane::Dataplane::probe(&mut dp, &table).await;

    // Now attempt the install; expect InvalidArgument referencing
    // CVE-2025-39851 in the message.
    let test_mac = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02]);
    let result = dp.install_fdb_nhg_row(vni, test_mac, 0x4000_0001).await;
    match result {
        Err(rustbgpd_evpn_linux::error::DataplaneError::InvalidArgument(msg)) => {
            assert!(
                msg.contains("CVE-2025-39851"),
                "expected CVE error msg, got: {msg}",
            );
        }
        other => panic!("expected InvalidArgument(CVE...); got {other:?}"),
    }

    // Belt-and-suspenders: no FDB row should have been programmed.
    let fdb = bridge_fdb_show();
    assert!(
        !fdb.contains("nhid"),
        "no FDB row should reference an nhid: {fdb}",
    );
}
