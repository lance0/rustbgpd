//! Privileged netns proof for ADR-0091 managed netdev lifecycle.
//!
//! Proves the real Linux netlink path for the bridge and fixed-VNI VXLAN
//! class slices:
//!
//! - create a bridge with the configured `vlan_filtering` value;
//! - stamp it with the durable `IFLA_ALT_IFNAME` ownership marker;
//! - treat a second create as restart adoption/idempotent success;
//! - reap the exact owned bridge on config removal;
//! - preserve a same-name unstamped foreign bridge.
//! - create a fixed-VNI VXLAN attached to an existing bridge;
//! - stamp/adopt/reap the exact owned VXLAN;
//! - preserve a same-name unstamped foreign VXLAN.

#![cfg(target_os = "linux")]

use std::process::Command;

use rustbgpd_evpn::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, ManagedVxlanNetdevSpec, RouteDistinguisher,
    RouteTarget,
};
use rustbgpd_evpn_linux::{Dataplane, DataplaneOp, FailureClass, InstanceProbe, LinuxDataplane};

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
}

#[tokio::test]
async fn managed_vxlan_create_adopt_and_reap_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("managed-vxlan") {
        managed_vxlan_create_adopt_and_reap_round_trip_inner().await;
        return;
    }

    let ns = NetnsFixture::create("managed-vxlan");
    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "managed_vxlan_create_adopt_and_reap_round_trip";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "managed-vxlan")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn managed_vxlan_create_adopt_and_reap_round_trip_inner() {
    run(
        "ip",
        &[
            "link",
            "add",
            "name",
            "br100",
            "type",
            "bridge",
            "vlan_filtering",
            "1",
        ],
    );

    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let create = DataplaneOp::CreateManagedVxlan {
        name: "vxmgd100".to_string(),
        spec: ManagedVxlanNetdevSpec {
            vni: 100,
            local_ip: "10.0.0.1".parse().unwrap(),
            dstport: 4789,
            bridge: "br100".to_string(),
        },
        ownership_stamp: "rustbgpd:vxlan:leaf-1:vxmgd100".to_string(),
    };
    dp.apply(&create).await.expect("create managed VXLAN");

    let first = dp.dump_snapshot().await.expect("dump after create");
    let link = first.vxlans.get("vxmgd100").expect("managed VXLAN exists");
    assert_eq!(link.vni, Some(100));
    assert_eq!(link.local_ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(link.dstport, Some(4789));
    assert_eq!(link.learning_disabled, Some(true));
    assert!(!link.collect_metadata);
    assert!(!link.vnifilter);
    assert_eq!(link.bridge.as_deref(), Some("br100"));
    assert_eq!(link.altnames, vec!["rustbgpd:vxlan:leaf-1:vxmgd100"]);
    let ifindex = link.ifindex;

    let mut restarted = LinuxDataplane::connect()
        .await
        .expect("fresh netlink connect inside netns");
    restarted
        .apply(&create)
        .await
        .expect("adopt existing managed VXLAN");
    let adopted = restarted.dump_snapshot().await.expect("dump after adopt");
    let link = adopted
        .vxlans
        .get("vxmgd100")
        .expect("managed VXLAN adopted");
    assert_eq!(link.ifindex, ifindex);
    assert_eq!(link.altnames, vec!["rustbgpd:vxlan:leaf-1:vxmgd100"]);

    restarted
        .apply(&DataplaneOp::RemoveManagedVxlan {
            name: "vxmgd100".to_string(),
            ownership_stamp: "rustbgpd:vxlan:leaf-1:vxmgd100".to_string(),
        })
        .await
        .expect("remove managed VXLAN");
    let removed = restarted.dump_snapshot().await.expect("dump after remove");
    assert!(!removed.vxlans.contains_key("vxmgd100"));

    run(
        "ip",
        &[
            "link",
            "add",
            "name",
            "vxforeign",
            "type",
            "vxlan",
            "id",
            "200",
            "local",
            "10.0.0.1",
            "dstport",
            "4789",
            "nolearning",
        ],
    );
    run(
        "ip",
        &["link", "set", "dev", "vxforeign", "master", "br100"],
    );
    let err = restarted
        .apply(&DataplaneOp::CreateManagedVxlan {
            name: "vxforeign".to_string(),
            spec: ManagedVxlanNetdevSpec {
                vni: 200,
                local_ip: "10.0.0.1".parse().unwrap(),
                dstport: 4789,
                bridge: "br100".to_string(),
            },
            ownership_stamp: "rustbgpd:vxlan:leaf-1:vxforeign".to_string(),
        })
        .await
        .expect_err("unstamped same-name VXLAN is foreign");
    assert_eq!(err.class(), FailureClass::Permanent);
    assert!(
        err.to_string().contains("ownership stamp"),
        "unexpected error: {err}"
    );
    let preserved = restarted
        .dump_snapshot()
        .await
        .expect("dump after foreign preserve");
    let link = preserved
        .vxlans
        .get("vxforeign")
        .expect("foreign VXLAN preserved");
    assert!(link.altnames.is_empty());
}

#[tokio::test]
async fn managed_bridge_and_vxlan_make_instance_ready_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("managed-ready") {
        managed_bridge_and_vxlan_make_instance_ready_round_trip_inner().await;
        return;
    }

    let ns = NetnsFixture::create("managed-ready");
    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "managed_bridge_and_vxlan_make_instance_ready_round_trip";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "managed-ready")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn managed_bridge_and_vxlan_make_instance_ready_round_trip_inner() {
    let instances = one_instance_table(instance(100, Some("brready"), "10.0.0.1"));
    let vni = EvpnInstanceId::new(100).unwrap();
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    let before = dp.probe(&instances).await;
    assert!(
        matches!(
            before.get(vni),
            Some(InstanceProbe::NotReady { reason }) if reason.contains("bridge brready not found")
        ),
        "instance unexpectedly ready before managed links exist: {:?}",
        before.get(vni)
    );

    dp.apply(&DataplaneOp::CreateManagedBridge {
        name: "brready".to_string(),
        vlan_filtering: false,
        ownership_stamp: "rustbgpd:bridge:leaf-1:brready".to_string(),
    })
    .await
    .expect("create managed bridge");
    dp.apply(&DataplaneOp::CreateManagedVxlan {
        name: "vxready100".to_string(),
        spec: ManagedVxlanNetdevSpec {
            vni: 100,
            local_ip: "10.0.0.1".parse().unwrap(),
            dstport: 4789,
            bridge: "brready".to_string(),
        },
        ownership_stamp: "rustbgpd:vxlan:leaf-1:vxready100".to_string(),
    })
    .await
    .expect("create managed VXLAN");

    let snapshot = dp.dump_snapshot().await.expect("dump managed topology");
    let bridge = snapshot
        .links
        .get("brready")
        .expect("managed bridge exists");
    assert!(!bridge.vlan_filtering);
    assert_eq!(bridge.altnames, vec!["rustbgpd:bridge:leaf-1:brready"]);
    let vxlan = snapshot
        .vxlans
        .get("vxready100")
        .expect("managed VXLAN exists");
    assert_eq!(vxlan.vni, Some(100));
    assert_eq!(vxlan.local_ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(vxlan.dstport, Some(4789));
    assert_eq!(vxlan.bridge.as_deref(), Some("brready"));
    assert_eq!(vxlan.learning_disabled, Some(true));
    assert!(!vxlan.collect_metadata);
    assert!(!vxlan.vnifilter);
    assert_eq!(vxlan.altnames, vec!["rustbgpd:vxlan:leaf-1:vxready100"]);

    let after = dp.probe(&instances).await;
    assert_eq!(after.get(vni), Some(&InstanceProbe::Ready));
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

fn rd(asn: u16, val: u32) -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[0..2].copy_from_slice(&[0, 0]);
    bytes[2..4].copy_from_slice(&asn.to_be_bytes());
    bytes[4..8].copy_from_slice(&val.to_be_bytes());
    RouteDistinguisher::new(bytes)
}

fn instance(v: u32, bridge: Option<&str>, vtep: &str) -> EvpnInstance {
    EvpnInstance::new(
        EvpnInstanceId::new(v).unwrap(),
        rd(65001, v),
        vec![RouteTarget::TwoOctetAs {
            asn: 65001,
            value: v,
        }],
        vtep.parse().unwrap(),
        bridge.map(String::from),
        false,
    )
    .unwrap()
}

fn one_instance_table(inst: EvpnInstance) -> EvpnInstanceTable {
    let mut table = EvpnInstanceTable::new();
    table.insert(inst).unwrap();
    table
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
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

#[tokio::test]
async fn managed_bridge_create_adopt_and_reap_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("managed-bridge") {
        managed_bridge_create_adopt_and_reap_round_trip_inner().await;
        return;
    }

    let ns = NetnsFixture::create("managed-bridge");
    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "managed_bridge_create_adopt_and_reap_round_trip";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "managed-bridge")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn managed_bridge_create_adopt_and_reap_round_trip_inner() {
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let create = DataplaneOp::CreateManagedBridge {
        name: "brmgd".to_string(),
        vlan_filtering: true,
        ownership_stamp: "rustbgpd:bridge:leaf-1:brmgd".to_string(),
    };
    dp.apply(&create).await.expect("create managed bridge");

    let first = dp.dump_snapshot().await.expect("dump after create");
    let link = first.links.get("brmgd").expect("managed bridge exists");
    assert!(link.vlan_filtering);
    assert_eq!(link.altnames, vec!["rustbgpd:bridge:leaf-1:brmgd"]);
    let ifindex = link.ifindex;

    // Simulate a daemon restart: a fresh dataplane connection sees the
    // existing stamped bridge and the same create op must adopt it as
    // already converged, not add a duplicate stamp or replace the link.
    let mut restarted = LinuxDataplane::connect()
        .await
        .expect("fresh netlink connect inside netns");
    restarted
        .apply(&create)
        .await
        .expect("adopt existing managed bridge");
    let adopted = restarted.dump_snapshot().await.expect("dump after adopt");
    let link = adopted.links.get("brmgd").expect("managed bridge adopted");
    assert_eq!(link.ifindex, ifindex);
    assert_eq!(link.altnames, vec!["rustbgpd:bridge:leaf-1:brmgd"]);

    run(
        "ip",
        &[
            "link",
            "set",
            "dev",
            "brmgd",
            "type",
            "bridge",
            "vlan_filtering",
            "0",
        ],
    );
    let err = restarted
        .apply(&create)
        .await
        .expect_err("vlan_filtering drift is owned-unsafe");
    assert_eq!(err.class(), FailureClass::Permanent);
    assert!(
        err.to_string().contains("vlan_filtering"),
        "unexpected error: {err}"
    );

    restarted
        .apply(&DataplaneOp::RemoveManagedBridge {
            name: "brmgd".to_string(),
            ownership_stamp: "rustbgpd:bridge:leaf-1:brmgd".to_string(),
        })
        .await
        .expect("remove managed bridge");
    let removed = restarted.dump_snapshot().await.expect("dump after remove");
    assert!(!removed.links.contains_key("brmgd"));

    run(
        "ip",
        &[
            "link",
            "add",
            "name",
            "brforeign",
            "type",
            "bridge",
            "vlan_filtering",
            "1",
        ],
    );
    let err = restarted
        .apply(&DataplaneOp::CreateManagedBridge {
            name: "brforeign".to_string(),
            vlan_filtering: true,
            ownership_stamp: "rustbgpd:bridge:leaf-1:brforeign".to_string(),
        })
        .await
        .expect_err("unstamped same-name bridge is foreign");
    assert!(
        err.to_string().contains("ownership stamp"),
        "unexpected error: {err}"
    );
    let preserved = restarted
        .dump_snapshot()
        .await
        .expect("dump after foreign preserve");
    let link = preserved
        .links
        .get("brforeign")
        .expect("foreign bridge preserved");
    assert!(link.altnames.is_empty());

    run("ip", &["link", "add", "name", "brdummy", "type", "dummy"]);
    let err = restarted
        .apply(&DataplaneOp::CreateManagedBridge {
            name: "brdummy".to_string(),
            vlan_filtering: true,
            ownership_stamp: "rustbgpd:bridge:leaf-1:brdummy".to_string(),
        })
        .await
        .expect_err("same-name non-bridge link is foreign");
    assert_eq!(err.class(), FailureClass::Permanent);
    assert!(
        err.to_string().contains("non-bridge link"),
        "unexpected error: {err}"
    );
    let preserved = restarted
        .dump_snapshot()
        .await
        .expect("dump after non-bridge preserve");
    assert!(preserved.link_name_exists("brdummy"));
    assert!(!preserved.links.contains_key("brdummy"));
}
