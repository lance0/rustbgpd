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
//! - preserve a same-name unstamped foreign VXLAN;
//! - create a VRF and L3VXLAN pair with the configured protected
//!   attributes;
//! - stamp/adopt/reap the exact owned VRF/L3VXLAN pair; and
//! - prove the managed pair can satisfy IP-VRF readiness.

#![cfg(target_os = "linux")]

use std::process::Command;

use rustbgpd_evpn::ip_vrf::IpVrfStatus;
use rustbgpd_evpn::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, IpVrf, IpVrfId, IpVrfTable, MacAddress,
    ManagedL3VxlanNetdevSpec, ManagedVlanUpperNetdevSpec, ManagedVrfNetdevSpec,
    ManagedVxlanNetdevSpec, RouteDistinguisher, RouteTarget,
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

#[tokio::test]
async fn managed_vlan_upper_create_adopt_and_reap_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("managed-vlan-upper") {
        managed_vlan_upper_create_adopt_and_reap_round_trip_inner().await;
        return;
    }

    let ns = NetnsFixture::create("managed-vlan-upper");
    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "managed_vlan_upper_create_adopt_and_reap_round_trip";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "managed-vlan-upper")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn managed_vlan_upper_create_adopt_and_reap_round_trip_inner() {
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
    run("ip", &["link", "set", "dev", "br100", "up"]);

    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");
    let create = DataplaneOp::CreateManagedVlanUpper {
        name: "br100.10".to_string(),
        spec: ManagedVlanUpperNetdevSpec {
            bridge: "br100".to_string(),
            vlan: 10,
        },
        ownership_stamp: "rustbgpd:vlan-upper:leaf-1:br100.10".to_string(),
    };
    dp.apply(&create).await.expect("create managed VLAN upper");

    let first = dp.dump_snapshot().await.expect("dump after create");
    let parent = first.links.get("br100").expect("parent bridge exists");
    let link = first
        .vlan_uppers
        .get("br100.10")
        .expect("managed VLAN upper exists");
    assert_eq!(link.vlan, Some(10));
    assert_eq!(link.bridge.as_deref(), Some("br100"));
    assert_eq!(link.lower_ifindex, Some(parent.ifindex));
    assert!(link.up);
    assert_eq!(link.altnames, vec!["rustbgpd:vlan-upper:leaf-1:br100.10"]);
    let ifindex = link.ifindex;

    let mut restarted = LinuxDataplane::connect()
        .await
        .expect("fresh netlink connect inside netns");
    restarted
        .apply(&create)
        .await
        .expect("adopt existing managed VLAN upper");
    let adopted = restarted.dump_snapshot().await.expect("dump after adopt");
    let link = adopted
        .vlan_uppers
        .get("br100.10")
        .expect("managed VLAN upper adopted");
    assert_eq!(link.ifindex, ifindex);
    assert_eq!(link.altnames, vec!["rustbgpd:vlan-upper:leaf-1:br100.10"]);

    restarted
        .apply(&DataplaneOp::RemoveManagedVlanUpper {
            name: "br100.10".to_string(),
            ownership_stamp: "rustbgpd:vlan-upper:leaf-1:br100.10".to_string(),
        })
        .await
        .expect("remove managed VLAN upper");
    let removed = restarted.dump_snapshot().await.expect("dump after remove");
    assert!(!removed.vlan_uppers.contains_key("br100.10"));

    run(
        "ip",
        &[
            "link", "add", "link", "br100", "name", "br100.20", "type", "vlan", "id", "20",
        ],
    );
    let err = restarted
        .apply(&DataplaneOp::CreateManagedVlanUpper {
            name: "br100.20".to_string(),
            spec: ManagedVlanUpperNetdevSpec {
                bridge: "br100".to_string(),
                vlan: 20,
            },
            ownership_stamp: "rustbgpd:vlan-upper:leaf-1:br100.20".to_string(),
        })
        .await
        .expect_err("unstamped same-name VLAN upper is foreign");
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
        .vlan_uppers
        .get("br100.20")
        .expect("foreign VLAN upper preserved");
    assert!(link.altnames.is_empty());
}

#[tokio::test]
async fn managed_vrf_and_l3vxlan_make_ip_vrf_ready_round_trip() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged netns test");
        return;
    }

    let inner_marker = std::env::var("RUSTBGPD_NETNS_INNER").ok();
    if inner_marker.as_deref() == Some("managed-ip-vrf-ready") {
        managed_vrf_and_l3vxlan_make_ip_vrf_ready_round_trip_inner().await;
        return;
    }

    let ns = NetnsFixture::create("managed-ip-vrf-ready");
    let exe = std::env::current_exe().expect("self-exe");
    let test_name = "managed_vrf_and_l3vxlan_make_ip_vrf_ready_round_trip";
    let status = Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "managed-ip-vrf-ready")
        .env("EVPN_LINUX_NETNS", "1")
        .status()
        .expect("spawn inner");
    assert!(status.success(), "inner test invocation failed");
}

async fn managed_vrf_and_l3vxlan_make_ip_vrf_ready_round_trip_inner() {
    let router_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x50, 0x00]);
    let l3vni = IpVrfId::new(5000).unwrap();
    let ip_vrfs = one_ip_vrf_table(ip_vrf(
        "tenant-blue",
        l3vni,
        "10.0.0.1",
        router_mac,
        "vrf5000",
        "l3vxlan5000",
        50_000,
    ));
    let mut dp = LinuxDataplane::connect()
        .await
        .expect("netlink connect inside netns");

    let before = dp.probe_ip_vrfs(&ip_vrfs).await;
    assert!(
        matches!(
            before.get(&l3vni),
            Some(IpVrfStatus::NotReady { reasons }) if !reasons.is_empty()
        ),
        "IP-VRF unexpectedly ready before managed links exist: {:?}",
        before.get(&l3vni)
    );

    let create_vrf = DataplaneOp::CreateManagedVrf {
        name: "vrf5000".to_string(),
        spec: ManagedVrfNetdevSpec { table_id: 50_000 },
        ownership_stamp: "rustbgpd:vrf:leaf-1:vrf5000".to_string(),
    };
    let create_l3vxlan = DataplaneOp::CreateManagedL3Vxlan {
        name: "l3vxlan5000".to_string(),
        spec: ManagedL3VxlanNetdevSpec {
            vni: 5000,
            local_ip: "10.0.0.1".parse().unwrap(),
            dstport: 4789,
            vrf: "vrf5000".to_string(),
            router_mac,
        },
        ownership_stamp: "rustbgpd:l3vxlan:leaf-1:l3vxlan5000".to_string(),
    };

    dp.apply(&create_vrf).await.expect("create managed VRF");
    dp.apply(&create_l3vxlan)
        .await
        .expect("create managed L3VXLAN");

    let snapshot = dp.dump_snapshot().await.expect("dump managed L3 topology");
    let vrf = snapshot.vrfs.get("vrf5000").expect("managed VRF exists");
    assert_eq!(vrf.table_id, Some(50_000));
    assert!(vrf.up);
    assert_eq!(vrf.altnames, vec!["rustbgpd:vrf:leaf-1:vrf5000"]);
    let vrf_ifindex = vrf.ifindex;

    let l3vxlan = snapshot
        .vxlans
        .get("l3vxlan5000")
        .expect("managed L3VXLAN exists");
    assert_eq!(l3vxlan.vni, Some(5000));
    assert_eq!(l3vxlan.local_ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(l3vxlan.dstport, Some(4789));
    assert_eq!(l3vxlan.learning_disabled, Some(true));
    assert!(!l3vxlan.collect_metadata);
    assert!(!l3vxlan.vnifilter);
    assert_eq!(l3vxlan.master.as_deref(), Some("vrf5000"));
    assert_eq!(l3vxlan.mac, Some(router_mac));
    assert!(l3vxlan.up);
    assert_eq!(
        l3vxlan.altnames,
        vec!["rustbgpd:l3vxlan:leaf-1:l3vxlan5000"]
    );
    let l3vxlan_ifindex = l3vxlan.ifindex;

    let after = dp.probe_ip_vrfs(&ip_vrfs).await;
    assert!(
        matches!(
            after.get(&l3vni),
            Some(IpVrfStatus::Ready {
                vrf_ifindex: observed_vrf,
                l3vxlan_ifindex: observed_l3vxlan,
                table_id: 50_000,
                router_mac: observed_mac,
            }) if *observed_vrf == vrf_ifindex
                && *observed_l3vxlan == l3vxlan_ifindex
                && *observed_mac == router_mac
        ),
        "IP-VRF did not become ready after managed links: {:?}",
        after.get(&l3vni)
    );

    let mut restarted = LinuxDataplane::connect()
        .await
        .expect("fresh netlink connect inside netns");
    restarted
        .apply(&create_vrf)
        .await
        .expect("adopt existing managed VRF");
    restarted
        .apply(&create_l3vxlan)
        .await
        .expect("adopt existing managed L3VXLAN");
    let adopted = restarted.dump_snapshot().await.expect("dump after adopt");
    assert_eq!(
        adopted.vrfs.get("vrf5000").map(|vrf| vrf.ifindex),
        Some(vrf_ifindex)
    );
    assert_eq!(
        adopted.vxlans.get("l3vxlan5000").map(|vxlan| vxlan.ifindex),
        Some(l3vxlan_ifindex)
    );

    restarted
        .apply(&DataplaneOp::RemoveManagedVrf {
            name: "vrf5000".to_string(),
            ownership_stamp: "rustbgpd:vrf:leaf-1:vrf5000".to_string(),
        })
        .await
        .expect_err("VRF remove must refuse while L3VXLAN is still enslaved");

    restarted
        .apply(&DataplaneOp::RemoveManagedL3Vxlan {
            name: "l3vxlan5000".to_string(),
            ownership_stamp: "rustbgpd:l3vxlan:leaf-1:l3vxlan5000".to_string(),
        })
        .await
        .expect("remove managed L3VXLAN");
    restarted
        .apply(&DataplaneOp::RemoveManagedVrf {
            name: "vrf5000".to_string(),
            ownership_stamp: "rustbgpd:vrf:leaf-1:vrf5000".to_string(),
        })
        .await
        .expect("remove managed VRF after L3VXLAN");
    let removed = restarted.dump_snapshot().await.expect("dump after remove");
    assert!(!removed.vxlans.contains_key("l3vxlan5000"));
    assert!(!removed.vrfs.contains_key("vrf5000"));
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

fn ip_vrf(
    name: &str,
    id: IpVrfId,
    local: &str,
    router_mac: MacAddress,
    vrf_device: &str,
    l3vxlan_device: &str,
    table_id: u32,
) -> IpVrf {
    IpVrf::new(
        name.to_string(),
        id,
        rd(65001, id.as_u32()),
        vec![RouteTarget::TwoOctetAs {
            asn: 65001,
            value: id.as_u32(),
        }],
        local.parse().unwrap(),
        router_mac,
        vrf_device.to_string(),
        l3vxlan_device.to_string(),
        table_id,
    )
    .unwrap()
}

fn one_ip_vrf_table(vrf: IpVrf) -> IpVrfTable {
    let mut table = IpVrfTable::new();
    table.insert(vrf).unwrap();
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
