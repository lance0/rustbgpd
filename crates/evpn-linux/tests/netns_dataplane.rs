//! Privileged netns integration test for [`LinuxDataplane`].
//!
//! This test exercises the real netlink path against an isolated
//! Linux network namespace: creates a bridge + VXLAN port, programs
//! a remote-MAC FDB entry through the dataplane crate, dumps the FDB
//! via `bridge fdb show` (run as a subprocess inside the netns), and
//! verifies the entry lands with `extern_learn`. Then withdraws the
//! entry and asserts a pre-loaded foreign static entry survives the
//! drain (ADR-0054 §5/§7 foreign-entry preservation).
//!
//! ## Why gated
//!
//! Creating a netns and bridge requires `CAP_NET_ADMIN`. PR-CI
//! runners don't have it, so this test is gated by the
//! `EVPN_LINUX_NETNS=1` environment variable. It runs nightly on a
//! dedicated Linux runner; PR-CI skips it cleanly.
//!
//! Set the variable and run:
//!
//! ```bash
//! sudo -E env EVPN_LINUX_NETNS=1 \
//!   cargo test -p rustbgpd-evpn-linux --test netns_dataplane
//! ```
//!
//! The current process must already have CAP_NET_ADMIN — the test
//! does not attempt privilege escalation.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

use rustbgpd_evpn::{
    BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalMacObservation, MacAddress,
    RouteDistinguisher, RouteTarget,
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
        // Best-effort cleanup of leftovers from a previous failed run.
        try_run("ip", &["netns", "delete", &name]);

        run("ip", &["netns", "add", &name]);
        // Bring up loopback inside the netns so VXLAN binding to a
        // local IP succeeds.
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }

    /// Run a command inside the netns and return the captured stdout.
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

fn vni() -> EvpnInstanceId {
    EvpnInstanceId::new(2_000_100).unwrap()
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

fn table_with_vlan_instances(local_ip: &str) -> EvpnInstanceTable {
    let mut table = EvpnInstanceTable::new();
    for (raw_vni, vlan) in [(100, 10), (200, 20)] {
        let vni = EvpnInstanceId::new(raw_vni).unwrap();
        table
            .insert(
                EvpnInstance::new(
                    vni,
                    rd_for(vni),
                    vec![RouteTarget::TwoOctetAs {
                        asn: 65001,
                        value: raw_vni,
                    }],
                    local_ip.parse::<IpAddr>().unwrap(),
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

fn setup_vlan_aware_vxlan_topology(ns: &NetnsFixture, local_ip: &str) {
    ns.exec(
        "ip",
        &["addr", "add", &format!("{local_ip}/32"), "dev", "lo"],
    );
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
    for (vxlan, vni, vlan) in [("vxlan100", "100", "10"), ("vxlan200", "200", "20")] {
        ns.exec(
            "ip",
            &[
                "link",
                "add",
                "name",
                vxlan,
                "type",
                "vxlan",
                "id",
                vni,
                "local",
                local_ip,
                "dstport",
                "4789",
                "nolearning",
            ],
        );
        ns.exec("ip", &["link", "set", vxlan, "master", "brvlan"]);
        ns.exec("ip", &["link", "set", vxlan, "up"]);
        ns.exec(
            "bridge",
            &["vlan", "add", "vid", vlan, "dev", "brvlan", "self"],
        );
        ns.exec("bridge", &["vlan", "add", "vid", vlan, "dev", vxlan]);
    }
}

fn setup_vlan_access_port(ns: &NetnsFixture) {
    ns.exec(
        "ip",
        &[
            "link", "add", "swp1", "type", "veth", "peer", "name", "host1",
        ],
    );
    ns.exec("ip", &["link", "set", "swp1", "master", "brvlan"]);
    ns.exec("ip", &["link", "set", "swp1", "up"]);
    ns.exec("ip", &["link", "set", "host1", "up"]);
    ns.exec(
        "bridge",
        &["vlan", "add", "vid", "30", "dev", "brvlan", "self"],
    );
    for vlan in ["10", "20", "30"] {
        ns.exec("bridge", &["vlan", "add", "vid", vlan, "dev", "swp1"]);
    }
}

fn setup_vlan_upper_devices(ns: &NetnsFixture) {
    for vlan in ["10", "20"] {
        let dev = format!("brvlan.{vlan}");
        ns.exec(
            "ip",
            &[
                "link", "add", "link", "brvlan", "name", &dev, "type", "vlan", "id", vlan,
            ],
        );
        ns.exec("ip", &["link", "set", &dev, "up"]);
    }
}

async fn expect_learned(
    rx: &mut tokio::sync::mpsc::Receiver<LocalMacObservation>,
    want_vni: u32,
    want_mac: MacAddress,
) {
    let obs = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for local MAC observation")
        .expect("local MAC channel closed");
    assert!(
        matches!(
            obs,
            LocalMacObservation::Learned { vni, mac, .. }
                if vni.as_u32() == want_vni && mac == want_mac
        ),
        "unexpected observation: {obs:?}"
    );

    while let Ok(Some(extra)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
        assert!(
            matches!(
                extra,
                LocalMacObservation::Learned { vni, mac, .. }
                    if vni.as_u32() == want_vni && mac == want_mac
            ),
            "cross-VLAN or unrelated observation: {extra:?}"
        );
    }
}

async fn expect_ip_added(
    rx: &mut tokio::sync::mpsc::Receiver<LocalMacObservation>,
    want_vni: u32,
    want_mac: MacAddress,
    want_ip: IpAddr,
) {
    let obs = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for local MAC+IP observation")
        .expect("local MAC channel closed");
    assert!(
        matches!(
            obs,
            LocalMacObservation::IpAdded { vni, mac, ip }
                if vni.as_u32() == want_vni && mac == want_mac && ip == want_ip
        ),
        "unexpected observation: {obs:?}"
    );

    while let Ok(Some(extra)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
        assert!(
            matches!(
                extra,
                LocalMacObservation::IpAdded { vni, mac, ip }
                    if vni.as_u32() == want_vni && mac == want_mac && ip == want_ip
            ),
            "cross-VLAN or unrelated observation: {extra:?}"
        );
    }
}

async fn expect_no_observation(rx: &mut tokio::sync::mpsc::Receiver<LocalMacObservation>) {
    match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        Err(_) => {}
        Ok(None) => panic!("local MAC channel closed"),
        Ok(Some(obs)) => panic!("unexpected observation: {obs:?}"),
    }
}

fn fdb_dump_for_dev(dev: &str) -> String {
    let out = run("bridge", &["fdb", "show", "dev", dev]).stdout;
    String::from_utf8_lossy(&out).into_owned()
}

fn fdb_rows_for_mac(dump: &str, mac: MacAddress) -> Vec<&str> {
    let mac_string = mac_str(mac);
    dump.lines()
        .filter(|line| line.to_lowercase().contains(&mac_string))
        .collect()
}

fn row_has_key_value(row: &str, key: &str, value: &str) -> bool {
    let mut tokens = row.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == key && tokens.next() == Some(value) {
            return true;
        }
    }
    false
}

fn row_has_vlan(row: &str, vlan: u16) -> bool {
    row_has_key_value(row, "vlan", &vlan.to_string())
}

fn row_has_ownership_marker(row: &str) -> bool {
    row.contains("extern_learn") || row.contains("offload")
}

fn assert_vlan_remote_fdb_present(dev: &str, mac: MacAddress, vlan: u16, dst: &str) {
    let dump = fdb_dump_for_dev(dev);
    let rows = fdb_rows_for_mac(&dump, mac);
    assert!(
        !rows.is_empty(),
        "programmed MAC missing from bridge fdb show dev {dev}:\n{dump}"
    );

    assert!(
        rows.iter().any(|row| row_has_vlan(row, vlan)),
        "programmed MAC rows on {dev} are missing vlan {vlan}:\n{dump}"
    );
    assert!(
        rows.iter().any(|row| row.contains("master")
            && row_has_vlan(row, vlan)
            && row_has_ownership_marker(row)),
        "programmed MAC missing bridge-master row in vlan {vlan} on {dev}:\n{dump}"
    );
    assert!(
        rows.iter().any(|row| row.contains("self")
            && row_has_key_value(row, "dst", dst)
            && row_has_ownership_marker(row)),
        "programmed MAC missing VXLAN-self+dst row on {dev} (dst={dst}):\n{dump}"
    );
}

fn assert_vlan_remote_fdb_absent(dev: &str, mac: MacAddress, vlan: u16) {
    let dump = fdb_dump_for_dev(dev);
    let rows = fdb_rows_for_mac(&dump, mac);
    assert!(
        rows.is_empty(),
        "removed MAC still present on {dev} after vlan {vlan} delete:\n{dump}"
    );
}

#[tokio::test]
async fn linux_dataplane_programs_remote_mac_with_extern_learn() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let ns = NetnsFixture::create("program");
    let bridge = "br100";
    let vxlan = "vxlan100";
    let local_ip = "10.255.0.10";
    let remote_ip = "127.0.0.20";

    // Topology: dummy "lo" address binding for VXLAN local source +
    // bridge + VXLAN port (no learning, control-plane-owned FDB).
    ns.exec(
        "ip",
        &["addr", "add", &format!("{local_ip}/32"), "dev", "lo"],
    );
    ns.exec("ip", &["link", "add", "name", bridge, "type", "bridge"]);
    ns.exec("ip", &["link", "set", bridge, "up"]);
    ns.exec(
        "ip",
        &[
            "link",
            "add",
            "name",
            vxlan,
            "type",
            "vxlan",
            "id",
            "2000100",
            "local",
            local_ip,
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    ns.exec("ip", &["link", "set", vxlan, "master", bridge]);
    ns.exec("ip", &["link", "set", vxlan, "up"]);

    // Pre-load a foreign static entry that must survive the drain.
    let foreign_mac = mac_str(mac(0x99));
    ns.exec(
        "bridge",
        &[
            "fdb",
            "add",
            &foreign_mac,
            "dev",
            vxlan,
            "dst",
            "127.0.0.99",
            "permanent",
        ],
    );

    // Run the dataplane test code inside the netns. We achieve this
    // by re-execing ourselves with a marker env var; the inner
    // invocation does the actual test work.
    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").is_ok();
    if !inner_marker {
        let exe = std::env::current_exe().expect("self-exe");
        let test_name = "linux_dataplane_programs_remote_mac_with_extern_learn";
        let status = Command::new("ip")
            .args(["netns", "exec", &ns.name])
            .arg(&exe)
            .args(["--exact", "--nocapture", test_name])
            .env("RUSTBGPD_NETNS_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");

        // After the inner test completes, verify the foreign entry
        // survived from the parent netns context.
        let foreign_dump = ns.exec("bridge", &["fdb", "show", "dev", vxlan]);
        assert!(
            foreign_dump.contains(&foreign_mac),
            "foreign static FDB entry was not preserved: {foreign_dump}"
        );
        return;
    }

    // ── inner: actually open netlink and program FDB. ──
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    // Build an EvpnInstanceTable matching the topology we created
    // and run probe() first. probe() refreshes the LinuxDataplane's
    // internal link cache, which apply() reads to resolve
    // (VNI -> VXLAN ifindex). Without this, apply() would hit
    // LinkNotFound because the cache is empty at startup.
    let mut bytes = [0u8; 8];
    bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&vni().as_u32().to_be_bytes());
    let mut table = EvpnInstanceTable::new();
    table
        .insert(
            EvpnInstance::new(
                vni(),
                RouteDistinguisher::new(bytes),
                vec![RouteTarget::TwoOctetAs {
                    asn: 65001,
                    value: vni().as_u32(),
                }],
                local_ip.parse::<IpAddr>().unwrap(),
                Some(bridge.to_string()),
                false,
            )
            .expect("EvpnInstance"),
        )
        .expect("insert");

    let probes = dp.probe(&table).await;
    match probes.get(vni()) {
        Some(InstanceProbe::Ready) => {}
        Some(other) => panic!("instance not Ready in real netns: {other:?}"),
        None => panic!("probe returned no result for VNI"),
    }

    let test_mac = mac(0x42);
    let dst: IpAddr = remote_ip.parse().unwrap();

    dp.apply(&DataplaneOp::AddRemoteFdb {
        vni: vni(),
        mac: test_mac,
        vlan: None,
        dst,
    })
    .await
    .expect("AddRemoteFdb");

    let after_add = run("bridge", &["fdb", "show", "dev", vxlan]).stdout;
    let after_add = String::from_utf8_lossy(&after_add);
    let mac_string = mac_str(test_mac);
    let mac_rows: Vec<&str> = after_add
        .lines()
        .filter(|l| l.to_lowercase().contains(&mac_string))
        .collect();
    assert!(
        !mac_rows.is_empty(),
        "programmed MAC missing from bridge fdb show:\n{after_add}"
    );

    // The kernel must produce TWO rows from one RTM_NEWNEIGH that
    // carries NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED + dst:
    //
    //   1. bridge-master row: shows `master <bridge>` (no dst). Without
    //      this row the bridge would flood instead of unicasting through
    //      vxlanX — control plane works but data plane is wrong.
    //   2. VXLAN-self+dst row: shows `self` and `dst <remote>`. Without
    //      this row the VXLAN driver has no encap target for the MAC.
    //
    // Both rows must independently carry `extern_learn` (the kernel
    // propagates `NTF_EXT_LEARNED` to both legs of the combined-flag
    // RTM_NEWNEIGH). Asserting per-row rather than "any row" catches
    // regressions where extern_learn would be set on one leg only —
    // which would let kernel-learned entries spuriously match
    // rustbgpd-owned entries in the diff loop's classification.
    let extern_learn_or_offload = |l: &&str| l.contains("extern_learn") || l.contains("offload");
    let has_master_row_with_extern_learn = mac_rows
        .iter()
        .any(|l| l.contains("master") && extern_learn_or_offload(l));
    let has_self_dst_row_with_extern_learn = mac_rows
        .iter()
        .any(|l| l.contains("self") && l.contains(remote_ip) && extern_learn_or_offload(l));

    assert!(
        has_master_row_with_extern_learn,
        "programmed MAC missing the bridge-master row with extern_learn:\n{after_add}"
    );
    assert!(
        has_self_dst_row_with_extern_learn,
        "programmed MAC missing the VXLAN-self+dst row with extern_learn (dst={remote_ip}):\n{after_add}"
    );

    dp.apply(&DataplaneOp::RemoveRemoteFdb {
        vni: vni(),
        mac: test_mac,
        vlan: None,
    })
    .await
    .expect("RemoveRemoteFdb");

    let after_rem = run("bridge", &["fdb", "show", "dev", vxlan]).stdout;
    let after_rem = String::from_utf8_lossy(&after_rem);
    assert!(
        !after_rem.contains(&mac_str(test_mac)),
        "removed MAC still present:\n{after_rem}"
    );
}

#[tokio::test]
async fn linux_dataplane_programs_vlan_scoped_remote_mac_add_remove() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("vlan-fdb") {
        linux_dataplane_programs_vlan_scoped_remote_mac_add_remove_inner().await;
        return;
    }

    let ns = NetnsFixture::create("vlan-fdb");
    let local_ip = "10.255.0.10";
    setup_vlan_aware_vxlan_topology(&ns, local_ip);

    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "linux_dataplane_programs_vlan_scoped_remote_mac_add_remove";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "vlan-fdb")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn linux_dataplane_programs_vlan_scoped_remote_mac_add_remove_inner() {
    let local_ip = "10.255.0.10";
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let table = table_with_vlan_instances(local_ip);
    let probes = dp.probe(&table).await;
    for raw_vni in [100, 200] {
        let vni = EvpnInstanceId::new(raw_vni).unwrap();
        match probes.get(vni) {
            Some(InstanceProbe::Ready) => {}
            Some(other) => panic!("VNI {raw_vni} not Ready in real netns: {other:?}"),
            None => panic!("probe returned no result for VNI {raw_vni}"),
        }
    }

    let shared_mac = mac(0x72);
    let dst_vlan10 = "127.0.0.20";
    let dst_vlan20 = "127.0.0.30";

    dp.apply(&DataplaneOp::AddRemoteFdb {
        vni: EvpnInstanceId::new(100).unwrap(),
        mac: shared_mac,
        vlan: Some(10),
        dst: dst_vlan10.parse().unwrap(),
    })
    .await
    .expect("AddRemoteFdb vlan 10");
    assert_vlan_remote_fdb_present("vxlan100", shared_mac, 10, dst_vlan10);

    dp.apply(&DataplaneOp::AddRemoteFdb {
        vni: EvpnInstanceId::new(200).unwrap(),
        mac: shared_mac,
        vlan: Some(20),
        dst: dst_vlan20.parse().unwrap(),
    })
    .await
    .expect("AddRemoteFdb vlan 20");
    assert_vlan_remote_fdb_present("vxlan200", shared_mac, 20, dst_vlan20);

    dp.apply(&DataplaneOp::RemoveRemoteFdb {
        vni: EvpnInstanceId::new(100).unwrap(),
        mac: shared_mac,
        vlan: Some(10),
    })
    .await
    .expect("RemoveRemoteFdb vlan 10");

    assert_vlan_remote_fdb_absent("vxlan100", shared_mac, 10);
    assert_vlan_remote_fdb_present("vxlan200", shared_mac, 20, dst_vlan20);

    dp.apply(&DataplaneOp::RemoveRemoteFdb {
        vni: EvpnInstanceId::new(200).unwrap(),
        mac: shared_mac,
        vlan: Some(20),
    })
    .await
    .expect("RemoveRemoteFdb vlan 20");
    assert_vlan_remote_fdb_absent("vxlan200", shared_mac, 20);
}

#[tokio::test]
async fn linux_dataplane_attributes_vlan_local_mac_observations() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("vlan-local-mac") {
        linux_dataplane_attributes_vlan_local_mac_observations_inner().await;
        return;
    }

    let ns = NetnsFixture::create("vlan-local-mac");
    let local_ip = "10.255.0.10";
    setup_vlan_aware_vxlan_topology(&ns, local_ip);
    setup_vlan_access_port(&ns);

    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "linux_dataplane_attributes_vlan_local_mac_observations";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "vlan-local-mac")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn linux_dataplane_attributes_vlan_local_mac_observations_inner() {
    let local_ip = "10.255.0.10";
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let mut rx = dp.take_local_mac_rx().expect("local MAC receiver");
    let table = table_with_vlan_instances(local_ip);
    let probes = dp.probe(&table).await;
    for raw_vni in [100, 200] {
        let vni = EvpnInstanceId::new(raw_vni).unwrap();
        match probes.get(vni) {
            Some(InstanceProbe::Ready) => {}
            Some(other) => panic!("VNI {raw_vni} not Ready in real netns: {other:?}"),
            None => panic!("probe returned no result for VNI {raw_vni}"),
        }
    }

    let shared_mac = mac(0x63);
    let shared_mac_str = mac_str(shared_mac);
    run(
        "bridge",
        &[
            "fdb",
            "add",
            &shared_mac_str,
            "dev",
            "swp1",
            "master",
            "vlan",
            "10",
            "static",
        ],
    );
    expect_learned(&mut rx, 100, shared_mac).await;

    run(
        "bridge",
        &[
            "fdb",
            "add",
            &shared_mac_str,
            "dev",
            "swp1",
            "master",
            "vlan",
            "20",
            "static",
        ],
    );
    expect_learned(&mut rx, 200, shared_mac).await;

    let foreign_vlan_mac = mac(0x64);
    run(
        "bridge",
        &[
            "fdb",
            "add",
            &mac_str(foreign_vlan_mac),
            "dev",
            "swp1",
            "master",
            "vlan",
            "30",
            "static",
        ],
    );
    expect_no_observation(&mut rx).await;
}

#[tokio::test]
async fn linux_dataplane_attributes_vlan_mac_ip_observations() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("vlan-mac-ip") {
        linux_dataplane_attributes_vlan_mac_ip_observations_inner().await;
        return;
    }

    let ns = NetnsFixture::create("vlan-mac-ip");
    let local_ip = "10.255.0.10";
    setup_vlan_aware_vxlan_topology(&ns, local_ip);
    setup_vlan_upper_devices(&ns);

    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "linux_dataplane_attributes_vlan_mac_ip_observations";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "vlan-mac-ip")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn linux_dataplane_attributes_vlan_mac_ip_observations_inner() {
    let local_ip = "10.255.0.10";
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let mut rx = dp.take_local_mac_rx().expect("local MAC receiver");
    let table = table_with_vlan_instances(local_ip);
    let probes = dp.probe(&table).await;
    for raw_vni in [100, 200] {
        let vni = EvpnInstanceId::new(raw_vni).unwrap();
        match probes.get(vni) {
            Some(InstanceProbe::Ready) => {}
            Some(other) => panic!("VNI {raw_vni} not Ready in real netns: {other:?}"),
            None => panic!("probe returned no result for VNI {raw_vni}"),
        }
    }

    let shared_mac = mac(0x65);
    let shared_ip: IpAddr = "192.0.2.65".parse().unwrap();
    let shared_mac_str = mac_str(shared_mac);
    let shared_ip_str = shared_ip.to_string();

    run(
        "ip",
        &[
            "neigh",
            "replace",
            &shared_ip_str,
            "lladdr",
            &shared_mac_str,
            "dev",
            "brvlan.10",
            "nud",
            "reachable",
        ],
    );
    expect_ip_added(&mut rx, 100, shared_mac, shared_ip).await;

    run(
        "ip",
        &[
            "neigh",
            "replace",
            &shared_ip_str,
            "lladdr",
            &shared_mac_str,
            "dev",
            "brvlan.20",
            "nud",
            "reachable",
        ],
    );
    expect_ip_added(&mut rx, 200, shared_mac, shared_ip).await;

    run(
        "ip",
        &[
            "neigh",
            "replace",
            "192.0.2.66",
            "lladdr",
            &mac_str(mac(0x66)),
            "dev",
            "brvlan",
            "nud",
            "reachable",
        ],
    );
    expect_no_observation(&mut rx).await;
}
