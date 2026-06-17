//! Privileged netns proof for SVD / collect-metadata VXLAN programming.
//!
//! Proves the LAN-64 programming contract against a real kernel:
//!
//! - `external` / collect-metadata VXLAN links are visible to the link
//!   inventory without a fixed VNI.
//! - A VLAN tunnel mapping (`bridge vlan ... tunnel_info id`) makes the
//!   configured L2VNI Ready.
//! - Runtime FDB programming emits `NDA_SRC_VNI` on the shared SVD ifindex.
//! - Deletes are VNI-scoped: the same MAC in another VNI survives.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;

use rustbgpd_evpn::{
    BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RouteDistinguisher,
    RouteTarget,
};
use rustbgpd_evpn_linux::{Dataplane, DataplaneOp, InstanceProbe, LinuxDataplane};

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
        let name = format!("rustbgpd-test-{test_name}-{}", std::process::id());
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }

    fn exec(&self, cmd: &str, args: &[&str]) -> String {
        let mut full = vec!["netns", "exec", &self.name, cmd];
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

fn vni(raw: u32) -> EvpnInstanceId {
    EvpnInstanceId::new(raw).unwrap()
}

fn mac(b: u8) -> MacAddress {
    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, b])
}

fn rd_for(vni: EvpnInstanceId) -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&vni.as_u32().to_be_bytes());
    RouteDistinguisher::new(bytes)
}

fn table_with_svd_instances() -> EvpnInstanceTable {
    let mut table = EvpnInstanceTable::new();
    for (raw_vni, vlan) in [(100, 10), (200, 20)] {
        let vni = vni(raw_vni);
        table
            .insert(
                EvpnInstance::new(
                    vni,
                    rd_for(vni),
                    vec![RouteTarget::TwoOctetAs {
                        asn: 65001,
                        value: vni.as_u32(),
                    }],
                    "10.255.0.10".parse::<IpAddr>().unwrap(),
                    Some("brvlan".to_string()),
                    false,
                )
                .expect("EvpnInstance")
                .with_bridge_vlan(Some(BridgeVlan::new(vlan).unwrap())),
            )
            .expect("insert");
    }
    table
}

fn setup_svd_topology(ns: &NetnsFixture) {
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            "brvlan",
            "type",
            "bridge",
            "vlan_filtering",
            "1",
            "vlan_default_pvid",
            "0",
        ],
    );
    ns.exec("ip", &["link", "set", "brvlan", "up"]);
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            "vxlan0",
            "type",
            "vxlan",
            "external",
            "vnifilter",
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", "vxlan0", "master", "brvlan"]);
    ns.exec("ip", &["link", "set", "vxlan0", "up"]);
    ns.exec(
        "bridge",
        &["link", "set", "dev", "vxlan0", "vlan_tunnel", "on"],
    );
    for (vlan, vni) in [("10", "100"), ("20", "200")] {
        ns.exec(
            "bridge",
            &["vlan", "add", "vid", vlan, "dev", "brvlan", "self"],
        );
        ns.exec("bridge", &["vlan", "add", "vid", vlan, "dev", "vxlan0"]);
        ns.exec(
            "bridge",
            &[
                "vlan",
                "add",
                "vid",
                vlan,
                "dev",
                "vxlan0",
                "tunnel_info",
                "id",
                vni,
            ],
        );
    }
}

#[tokio::test]
async fn svd_topology_is_ready_and_programs_vni_scoped_fdb_rows() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("svd-fdb-vni") {
        svd_topology_is_ready_and_programs_vni_scoped_fdb_rows_inner().await;
        return;
    }

    let ns = NetnsFixture::create("svd-fdb-vni");
    setup_svd_topology(&ns);

    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "svd_topology_is_ready_and_programs_vni_scoped_fdb_rows";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "svd-fdb-vni")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn svd_topology_is_ready_and_programs_vni_scoped_fdb_rows_inner() {
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let table = table_with_svd_instances();
    let probes = dp.probe(&table).await;
    for raw_vni in [100, 200] {
        match probes.get(vni(raw_vni)) {
            Some(InstanceProbe::Ready) => {}
            Some(other) => panic!("SVD VNI {raw_vni} must be Ready: {other:?}"),
            None => panic!("probe returned no result for VNI {raw_vni}"),
        }
    }

    let test_mac = mac(0x42);
    dp.apply(&DataplaneOp::AddRemoteFdb {
        vni: vni(100),
        mac: test_mac,
        vlan: Some(10),
        dst: "127.0.0.20".parse().unwrap(),
    })
    .await
    .expect("program VNI 100 SVD FDB row");
    dp.apply(&DataplaneOp::AddRemoteFdb {
        vni: vni(200),
        mac: test_mac,
        vlan: Some(20),
        dst: "127.0.0.21".parse().unwrap(),
    })
    .await
    .expect("program VNI 200 SVD FDB row for same MAC");

    let fdb_dump = run("bridge", &["-d", "fdb", "show", "dev", "vxlan0"]);
    let fdb_dump = String::from_utf8_lossy(&fdb_dump.stdout);
    assert!(
        fdb_dump.contains("src_vni 100") || fdb_dump.contains("vni 100"),
        "SVD FDB dump did not expose VNI 100 attribution:\n{fdb_dump}"
    );
    assert!(
        fdb_dump.contains("src_vni 200") || fdb_dump.contains("vni 200"),
        "SVD FDB dump did not expose VNI 200 attribution:\n{fdb_dump}"
    );

    let snapshot = dp.dump_snapshot().await.expect("dump snapshot");
    let entry = snapshot
        .find_fdb_in_vlan(vni(100), test_mac, Some(10))
        .unwrap_or_else(|| panic!("src_vni FDB row missing from parsed snapshot: {snapshot:?}"));
    assert_eq!(entry.vlan, Some(10));
    assert!(entry.flags.extern_learn);
    assert!(
        snapshot
            .find_fdb_in_vlan(vni(200), test_mac, Some(20))
            .is_some(),
        "VNI 200 row missing from parsed snapshot: {snapshot:?}"
    );

    dp.apply(&DataplaneOp::RemoveRemoteFdb {
        vni: vni(100),
        mac: test_mac,
        vlan: Some(10),
    })
    .await
    .expect("remove VNI 100 SVD FDB row");

    let snapshot = dp
        .dump_snapshot()
        .await
        .expect("dump snapshot after remove");
    assert!(
        snapshot
            .find_fdb_in_vlan(vni(100), test_mac, Some(10))
            .is_none(),
        "VNI 100 row survived scoped remove: {snapshot:?}"
    );
    assert!(
        snapshot
            .find_fdb_in_vlan(vni(200), test_mac, Some(20))
            .is_some(),
        "VNI 200 same-MAC row was removed by VNI 100 withdraw: {snapshot:?}"
    );
}
