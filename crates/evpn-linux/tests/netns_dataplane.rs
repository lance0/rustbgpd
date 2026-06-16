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

use rustbgpd_evpn::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RouteDistinguisher, RouteTarget,
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

#[tokio::test]
async fn linux_dataplane_programs_remote_mac_with_extern_learn() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let ns = NetnsFixture::create("program");
    let bridge = "br100";
    let vxlan = "vxlan100";
    let local_ip = "127.0.0.10";
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
