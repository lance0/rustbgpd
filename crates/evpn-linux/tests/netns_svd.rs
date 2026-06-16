//! Privileged netns proof for SVD / collect-metadata VXLAN substrate.
//!
//! This intentionally does **not** enable SVD readiness. It proves the
//! LAN-64 prerequisites against a real kernel:
//!
//! - `external` / collect-metadata VXLAN links are visible to the link
//!   inventory without a fixed VNI.
//! - A VLAN tunnel mapping (`bridge vlan ... tunnel_info id`) produces a
//!   precise SVD NotReady reason instead of disappearing as "no VXLAN".
//! - An FDB row on the SVD ifindex carrying `src_vni` is parsed into the
//!   snapshot under the explicit VNI, not under an ifindex-derived VNI.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;

use rustbgpd_evpn::{
    BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RouteDistinguisher,
    RouteTarget,
};
use rustbgpd_evpn_linux::{Dataplane, InstanceProbe, LinuxDataplane};

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

fn mac_str(m: MacAddress) -> String {
    let o = m.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

fn rd_for(vni: EvpnInstanceId) -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&vni.as_u32().to_be_bytes());
    RouteDistinguisher::new(bytes)
}

fn table_with_svd_instance() -> EvpnInstanceTable {
    let vni = vni(100);
    let mut table = EvpnInstanceTable::new();
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
            .with_bridge_vlan(Some(BridgeVlan::new(10).unwrap())),
        )
        .expect("insert");
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
    ns.exec(
        "bridge",
        &["vlan", "add", "vid", "10", "dev", "brvlan", "self"],
    );
    ns.exec("bridge", &["vlan", "add", "vid", "10", "dev", "vxlan0"]);
    ns.exec(
        "bridge",
        &[
            "vlan",
            "add",
            "vid",
            "10",
            "dev",
            "vxlan0",
            "tunnel_info",
            "id",
            "100",
        ],
    );
}

#[tokio::test]
async fn svd_topology_is_detected_and_explicit_src_vni_fdb_rows_parse() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("svd-fdb-vni") {
        svd_topology_is_detected_and_explicit_src_vni_fdb_rows_parse_inner().await;
        return;
    }

    let ns = NetnsFixture::create("svd-fdb-vni");
    setup_svd_topology(&ns);

    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "svd_topology_is_detected_and_explicit_src_vni_fdb_rows_parse";
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

async fn svd_topology_is_detected_and_explicit_src_vni_fdb_rows_parse_inner() {
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let table = table_with_svd_instance();
    let probes = dp.probe(&table).await;
    match probes.get(vni(100)) {
        Some(InstanceProbe::NotReady { reason }) => {
            assert!(
                reason.contains("collect-metadata VXLAN")
                    && reason.contains("explicit FDB VNI programming"),
                "unexpected SVD NotReady reason: {reason}"
            );
        }
        Some(other) => panic!("SVD instance must not be Ready in PR1: {other:?}"),
        None => panic!("probe returned no result for VNI 100"),
    }

    let test_mac = mac(0x42);
    run(
        "bridge",
        &[
            "fdb",
            "replace",
            &mac_str(test_mac),
            "dev",
            "vxlan0",
            "self",
            "master",
            "extern_learn",
            "static",
            "vlan",
            "10",
            "dst",
            "127.0.0.20",
            "vni",
            "100",
            "src_vni",
            "100",
        ],
    );
    let fdb_dump = run("bridge", &["-d", "fdb", "show", "dev", "vxlan0"]);
    let fdb_dump = String::from_utf8_lossy(&fdb_dump.stdout);
    assert!(
        fdb_dump.contains("src_vni 100") || fdb_dump.contains("vni 100"),
        "SVD FDB dump did not expose explicit VNI attribution:\n{fdb_dump}"
    );

    let snapshot = dp.dump_snapshot().await.expect("dump snapshot");
    let entry = snapshot
        .find_fdb(vni(100), test_mac)
        .unwrap_or_else(|| panic!("src_vni FDB row missing from parsed snapshot: {snapshot:?}"));
    // On the tested kernel/iproute2 shape, `src_vni` is the row's VNI
    // attribution, while `NDA_VLAN` / `NDA_DST` do not round-trip in
    // the FDB dump for this SVD self row. Keep SVD Ready gated until a
    // follow-up can account for that runtime programming contract.
    assert_eq!(entry.dst, None);
    assert_eq!(entry.vlan, None);
    assert!(entry.flags.extern_learn);
}
