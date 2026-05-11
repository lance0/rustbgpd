//! Privileged netns integration test for the Gate 9 slice 6c L3
//! install path.
//!
//! Exercises [`crate::LinuxDataplane`]'s `AddRemoteIpRoute`,
//! `AddL3Neighbor`, `AddL3VxlanFdb`, and their matching remove
//! ops against a real Linux kernel inside an isolated network
//! namespace. The unit tests in `l3_diff.rs` cover the pure-
//! function diff math (refcount, shape change, value drift,
//! Router-MAC conflict, partial-success cleanup); this file
//! validates that the netlink wire shape the dataplane crate
//! emits actually programs the kernel rows operators see via
//! `ip route show vrf`, `ip neigh show dev`, and
//! `bridge fdb show dev`.
//!
//! Three load-bearing assertions per test:
//!
//! 1. The IP route lands in the IP-VRF's table with
//!    `RTPROT_BGP`, `RTNH_F_ONLINK`, and the L3 VXLAN as `dev` —
//!    without `onlink` the kernel rejects routes whose
//!    next-hop isn't directly reachable via the output device,
//!    without `proto bgp` slice 6a's local-route observer would
//!    re-originate our installs.
//! 2. The L3 neighbor row carries the desired router MAC as
//!    `lladdr` with `NUD_PERMANENT` / `extern_learn` — the
//!    kernel uses `lladdr` for the inner Ethernet header during
//!    symmetric-IRB encap.
//! 3. The L3VXLAN FDB row carries the desired next-hop as `dst`
//!    with `self extern_learn` — the VXLAN driver consults this
//!    when it sees the inner DMAC.
//!
//! Plus a foreign-preservation check: an operator-pre-installed
//! `proto static` route in the same VRF table survives our
//! install + withdraw cycle (ADR-0054 §5).
//!
//! ## Why gated
//!
//! Creating a netns + VRF / L3VXLAN devices requires
//! `CAP_NET_ADMIN`. PR-CI runners don't have it, so this test is
//! gated by the `EVPN_LINUX_NETNS=1` environment variable. The
//! current process must already hold the capability — the test
//! does not attempt privilege escalation.
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_l3_install
//! ```

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use rustbgpd_evpn::{Ipv4Prefix, MacAddress};
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

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str) -> Self {
        let name = format!("rustbgpd-l3-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }

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

/// Build the standard L3 IRB topology in the netns:
///
/// - VRF master device `vrf-test` bound to table `<TABLE_ID>`
/// - L3 VXLAN device `l3vxlan-test` with VNI `<L3VNI>`, local IP
///   `<LOCAL_IP>`, MAC `<router_mac>`, enslaved to the VRF
/// - Both devices `up`
///
/// Returns the L3VXLAN ifindex so the test can drive
/// `LinuxDataplane::apply` with the right key.
fn setup_topology(
    ns: &NetnsFixture,
    table_id: u32,
    l3vni: u32,
    local_ip: &str,
    router_mac: MacAddress,
) -> u32 {
    let mac_str = format_mac(router_mac);

    // Local source address for VXLAN encap.
    ns.exec(
        "ip",
        &["addr", "add", &format!("{local_ip}/32"), "dev", "lo"],
    );

    // VRF master device.
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "vrf-test",
            "type",
            "vrf",
            "table",
            &table_id.to_string(),
        ],
    );
    ns.exec("ip", &["link", "set", "vrf-test", "up"]);

    // L3 VXLAN with the operator-configured router MAC.
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            "l3vxlan-test",
            "address",
            &mac_str,
            "type",
            "vxlan",
            "id",
            &l3vni.to_string(),
            "local",
            local_ip,
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", "l3vxlan-test", "master", "vrf-test"]);
    ns.exec("ip", &["link", "set", "l3vxlan-test", "up"]);

    // Read the L3VXLAN ifindex back.
    let out = ns.exec("ip", &["-o", "link", "show", "dev", "l3vxlan-test"]);
    let first = out.split(':').next().expect("ip -o link output");
    first.trim().parse::<u32>().expect("ifindex parse")
}

fn format_mac(m: MacAddress) -> String {
    let o = m.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

fn v4_prefix(octets: [u8; 4], len: u8) -> rustbgpd_evpn::EvpnIpPrefixValue {
    rustbgpd_evpn::EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len))
}

const TABLE_ID: u32 = 200;
const L3VNI: u32 = 100;
const LOCAL_VTEP: &str = "10.0.0.1";

/// Spawn the inner test invocation inside the netns. The outer
/// process sets up the topology and any pre-loaded foreign state;
/// the inner process opens the dataplane (which inherits the netns
/// context from `ip netns exec`) and drives the netlink ops.
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

/// One full cycle: install route + neighbor + FDB via the dataplane,
/// verify each lands with the expected attributes via shell, withdraw
/// the cycle in reverse order, verify each is gone.
#[tokio::test]
async fn linux_dataplane_installs_and_withdraws_l3_triple() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged L3 install test");
        return;
    }
    let router_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xaa]);
    let prefix = v4_prefix([198, 51, 100, 0], 24);
    let next_hop: IpAddr = "10.0.0.2".parse().unwrap();

    if !is_inner() {
        let ns = NetnsFixture::create("install");
        setup_topology(&ns, TABLE_ID, L3VNI, LOCAL_VTEP, router_mac);
        run_inner(&ns, "linux_dataplane_installs_and_withdraws_l3_triple");
        return;
    }

    // ── inner: dataplane operates inside the netns ──
    let l3vxlan_ifindex = read_l3vxlan_ifindex();
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    // Phase B / C: install neighbor → FDB → route (matches the diff's
    // emission order so the netlink wire shape is consistent with
    // production).
    dp.apply(&DataplaneOp::AddL3Neighbor {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        next_hop,
        router_mac,
    })
    .await
    .expect("AddL3Neighbor");
    dp.apply(&DataplaneOp::AddL3VxlanFdb {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        router_mac,
        next_hop,
    })
    .await
    .expect("AddL3VxlanFdb");
    dp.apply(&DataplaneOp::AddRemoteIpRoute {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        prefix,
        table_id: TABLE_ID,
        l3vxlan_ifindex,
        next_hop,
        router_mac,
    })
    .await
    .expect("AddRemoteIpRoute");

    // ── kernel state assertions ──
    //
    // Route: `ip route show table <id>` lists every row in the VRF
    // table. Match by fields (per the review's parser-safety note),
    // not full-line equality.
    let route_dump = shell_capture("ip", &["route", "show", "table", &TABLE_ID.to_string()]);
    assert_owned_route_present(&route_dump, "198.51.100.0/24", "10.0.0.2", "l3vxlan-test");

    // Neighbor: `ip neigh show dev l3vxlan-test` must contain
    // `<next_hop> lladdr <router_mac> ... PERMANENT` with
    // extern_learn (or PERMANENT alone if the kernel collapses
    // NUD_PERMANENT + NTF_EXT_LEARNED into one displayed state).
    let neigh_dump = shell_capture("ip", &["neigh", "show", "dev", "l3vxlan-test"]);
    assert_neighbor_present(&neigh_dump, "10.0.0.2", &format_mac(router_mac));

    // FDB: `bridge fdb show dev l3vxlan-test` must contain
    // `<router_mac> dst <next_hop> self`. The "self" tag (NTF_SELF)
    // is load-bearing — without it the row wouldn't be picked up by
    // the VXLAN driver.
    let fdb_dump = shell_capture("bridge", &["fdb", "show", "dev", "l3vxlan-test"]);
    assert_fdb_present(&fdb_dump, &format_mac(router_mac), "10.0.0.2");

    // ── withdraw cycle: route → neighbor → FDB ──
    dp.apply(&DataplaneOp::RemoveRemoteIpRoute {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        prefix,
        table_id: TABLE_ID,
        l3vxlan_ifindex,
        next_hop,
    })
    .await
    .expect("RemoveRemoteIpRoute");
    dp.apply(&DataplaneOp::RemoveL3Neighbor {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        next_hop,
    })
    .await
    .expect("RemoveL3Neighbor");
    dp.apply(&DataplaneOp::RemoveL3VxlanFdb {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        router_mac,
    })
    .await
    .expect("RemoveL3VxlanFdb");

    let route_after = shell_capture("ip", &["route", "show", "table", &TABLE_ID.to_string()]);
    assert_route_absent(&route_after, "198.51.100.0/24");
    let neigh_after = shell_capture("ip", &["neigh", "show", "dev", "l3vxlan-test"]);
    assert_neighbor_absent(&neigh_after, "10.0.0.2");
    let fdb_after = shell_capture("bridge", &["fdb", "show", "dev", "l3vxlan-test"]);
    assert_fdb_absent(&fdb_after, &format_mac(router_mac));
}

/// Foreign preservation (ADR-0054 §5): an operator-pre-installed
/// route in the same VRF table survives a full install + withdraw
/// cycle on a different prefix.
#[tokio::test]
async fn linux_dataplane_foreign_route_survives_l3_cycle() {
    if !netns_gate() {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to run privileged L3 foreign-preservation test"
        );
        return;
    }
    let router_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xbb]);
    let prefix = v4_prefix([198, 51, 100, 0], 24);
    let next_hop: IpAddr = "10.0.0.2".parse().unwrap();
    let foreign_prefix = "203.0.113.0/24";
    let foreign_gw = "10.0.0.99";

    if !is_inner() {
        let ns = NetnsFixture::create("foreign");
        setup_topology(&ns, TABLE_ID, L3VNI, LOCAL_VTEP, router_mac);
        // Operator-pre-installed route in the same VRF table, with
        // `proto static` so slice 6a's classifier would also leave it
        // alone. We use the same L3 VXLAN as `dev` so the dst-side
        // shape matches our install but the prefix differs.
        ns.exec(
            "ip",
            &[
                "route",
                "add",
                foreign_prefix,
                "via",
                foreign_gw,
                "dev",
                "l3vxlan-test",
                "table",
                &TABLE_ID.to_string(),
                "proto",
                "static",
                "onlink",
            ],
        );
        run_inner(&ns, "linux_dataplane_foreign_route_survives_l3_cycle");

        // After the inner test completes, verify the foreign route
        // still exists from the outer netns context.
        let after = ns.exec("ip", &["route", "show", "table", &TABLE_ID.to_string()]);
        assert_route_present(&after, foreign_prefix, foreign_gw, "l3vxlan-test");
        return;
    }

    // ── inner: apply full install + withdraw cycle ──
    let l3vxlan_ifindex = read_l3vxlan_ifindex();
    let mut dp = LinuxDataplane::connect().await.expect("netlink connect");

    dp.apply(&DataplaneOp::AddL3Neighbor {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        next_hop,
        router_mac,
    })
    .await
    .expect("AddL3Neighbor");
    dp.apply(&DataplaneOp::AddL3VxlanFdb {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        router_mac,
        next_hop,
    })
    .await
    .expect("AddL3VxlanFdb");
    dp.apply(&DataplaneOp::AddRemoteIpRoute {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        prefix,
        table_id: TABLE_ID,
        l3vxlan_ifindex,
        next_hop,
        router_mac,
    })
    .await
    .expect("AddRemoteIpRoute");

    // Both routes should be in the table — the owned one with the
    // full BGP/onlink shape, the foreign one preserved verbatim.
    let with_both = shell_capture("ip", &["route", "show", "table", &TABLE_ID.to_string()]);
    assert_owned_route_present(&with_both, "198.51.100.0/24", "10.0.0.2", "l3vxlan-test");
    assert_route_present(&with_both, foreign_prefix, foreign_gw, "l3vxlan-test");

    // Withdraw our cycle.
    dp.apply(&DataplaneOp::RemoveRemoteIpRoute {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        prefix,
        table_id: TABLE_ID,
        l3vxlan_ifindex,
        next_hop,
    })
    .await
    .expect("RemoveRemoteIpRoute");
    dp.apply(&DataplaneOp::RemoveL3Neighbor {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        next_hop,
    })
    .await
    .expect("RemoveL3Neighbor");
    dp.apply(&DataplaneOp::RemoveL3VxlanFdb {
        vrf_id: rustbgpd_evpn::IpVrfId::new(L3VNI).unwrap(),
        l3vxlan_ifindex,
        router_mac,
    })
    .await
    .expect("RemoveL3VxlanFdb");

    // Our prefix gone; foreign survives.
    let after_withdraw = shell_capture("ip", &["route", "show", "table", &TABLE_ID.to_string()]);
    assert_route_absent(&after_withdraw, "198.51.100.0/24");
    assert_route_present(&after_withdraw, foreign_prefix, foreign_gw, "l3vxlan-test");
}

/// Sub-second slice 6a withdraw: an `ip route add` / `ip route del`
/// in a custom IP-VRF table must wake the reconcile actor via the
/// `RTNLGRP_IPV4_ROUTE` subscription, not wait for the 60 s periodic
/// dump. We can't drive the full reconcile actor here, but we can
/// validate the kernel-event channel by polling [`Dataplane::next_event`]
/// directly — if the subscription is wired correctly, the channel
/// resolves within a few hundred milliseconds; if the regression
/// returns the wire goes back to `pending()` and the test times out.
#[tokio::test]
async fn linux_dataplane_route_event_wakes_within_1s() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged route-event wake test");
        return;
    }
    let router_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xcc]);

    if !is_inner() {
        let ns = NetnsFixture::create("wake");
        setup_topology(&ns, TABLE_ID, L3VNI, LOCAL_VTEP, router_mac);
        run_inner(&ns, "linux_dataplane_route_event_wakes_within_1s");
        return;
    }

    // ── inner: dataplane operates inside the netns ──
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    // Give the kernel a beat to finalize the multicast subscription
    // before we trigger the event. Practical observation: subscriptions
    // applied via setsockopt during connect are active almost
    // immediately, but a tiny sleep eliminates flakiness around the
    // very first event after socket creation.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Fire an `ip route add` in the custom VRF table. `proto static`
    // is one of the protocols `classify_route` keeps; `onlink` is
    // required for the kernel to accept the route given that 10.0.0.99
    // is not reachable via a connected route on l3vxlan-test.
    run(
        "ip",
        &[
            "route",
            "add",
            "203.0.113.0/24",
            "via",
            "10.0.0.99",
            "dev",
            "l3vxlan-test",
            "table",
            &TABLE_ID.to_string(),
            "proto",
            "static",
            "onlink",
        ],
    );

    let evt = tokio::time::timeout(std::time::Duration::from_secs(2), dp.next_event())
        .await
        .expect("RTNLGRP_IPV4_ROUTE add must wake next_event within 2s");
    assert!(
        evt.is_some(),
        "next_event returned None on RTM_NEWROUTE — kernel-event channel closed unexpectedly"
    );

    // Drain any stray follow-up events the kernel may have batched
    // (e.g., a duplicate broadcast). Cap the drain so we don't busy-
    // loop indefinitely.
    for _ in 0..4 {
        if tokio::time::timeout(std::time::Duration::from_millis(50), dp.next_event())
            .await
            .is_err()
        {
            break;
        }
    }

    // Symmetric: `ip route del` must also wake.
    run(
        "ip",
        &[
            "route",
            "del",
            "203.0.113.0/24",
            "table",
            &TABLE_ID.to_string(),
        ],
    );

    let evt = tokio::time::timeout(std::time::Duration::from_secs(2), dp.next_event())
        .await
        .expect("RTNLGRP_IPV4_ROUTE del must wake next_event within 2s");
    assert!(
        evt.is_some(),
        "next_event returned None on RTM_DELROUTE — kernel-event channel closed unexpectedly"
    );
}

// ── shell helpers ────────────────────────────────────────────────

fn shell_capture(cmd: &str, args: &[&str]) -> String {
    let out = run(cmd, args);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_l3vxlan_ifindex() -> u32 {
    let out = shell_capture("ip", &["-o", "link", "show", "dev", "l3vxlan-test"]);
    let first = out.split(':').next().expect("ip -o link");
    first.trim().parse::<u32>().expect("ifindex parse")
}

/// Match a route by destination + gateway + dev + operational
/// flags. iproute2's `ip route show` output formats each row as
/// one line of fields; we tolerate field-order variations by
/// matching fragments rather than full-line equality (per the
/// review's parser-safety guide).
///
/// Use [`assert_owned_route_present`] for routes we installed
/// (asserts the full `apply_add_ip_route` shape including
/// `proto bgp` + `onlink`), and this helper for foreign routes
/// where we only care that the destination/next-hop survived.
fn assert_route_present(dump: &str, prefix: &str, gateway: &str, dev: &str) {
    let matched = dump.lines().any(|line| {
        line.contains(prefix)
            && line.contains(&format!("via {gateway}"))
            && line.contains(&format!("dev {dev}"))
    });
    assert!(
        matched,
        "route `{prefix} via {gateway} dev {dev}` missing from dump:\n{dump}",
    );
}

/// Match a route that `apply_add_ip_route` should have installed:
/// destination + gateway + dev plus every operational flag the
/// L3 install path is documented to set on the same line —
/// `proto bgp` (RTPROT_BGP, so slice 6a's local-route observer
/// never re-originates) and `onlink` (RTNH_F_ONLINK, required
/// for the L3VXLAN-direct topology where the next-hop is not
/// reachable via a connected route on the output device).
/// Tightens review finding #4: matches the operational shape
/// the slice 6c module docs claim.
fn assert_owned_route_present(dump: &str, prefix: &str, gateway: &str, dev: &str) {
    let matched = dump.lines().any(|line| {
        line.contains(prefix)
            && line.contains(&format!("via {gateway}"))
            && line.contains(&format!("dev {dev}"))
            && line.contains("proto bgp")
            && line.contains("onlink")
    });
    assert!(
        matched,
        "owned route `{prefix} via {gateway} dev {dev} proto bgp ... onlink` \
         missing from dump:\n{dump}",
    );
}

fn assert_route_absent(dump: &str, prefix: &str) {
    assert!(
        !dump.lines().any(|line| line.starts_with(prefix)),
        "route `{prefix}` should have been withdrawn:\n{dump}",
    );
}

fn assert_neighbor_present(dump: &str, addr: &str, lladdr: &str) {
    let matched = dump.lines().any(|line| {
        let lower = line.to_lowercase();
        let lladdr_l = lladdr.to_lowercase();
        line.contains(addr) && lower.contains(&lladdr_l)
    });
    assert!(
        matched,
        "neighbor `{addr} lladdr {lladdr}` missing from dump:\n{dump}",
    );
}

fn assert_neighbor_absent(dump: &str, addr: &str) {
    assert!(
        !dump
            .lines()
            .any(|line| line.contains(addr) && !line.contains("FAILED")),
        "neighbor for `{addr}` should have been removed:\n{dump}",
    );
}

fn assert_fdb_present(dump: &str, mac: &str, dst: &str) {
    let matched = dump.lines().any(|line| {
        let lower = line.to_lowercase();
        let mac_l = mac.to_lowercase();
        lower.contains(&mac_l) && line.contains(&format!("dst {dst}")) && line.contains("self")
    });
    assert!(
        matched,
        "FDB row `{mac} dst {dst} self` missing from dump:\n{dump}",
    );
}

fn assert_fdb_absent(dump: &str, mac: &str) {
    assert!(
        !dump
            .lines()
            .any(|line| line.to_lowercase().contains(&mac.to_lowercase())),
        "FDB row for `{mac}` should have been removed:\n{dump}",
    );
}
