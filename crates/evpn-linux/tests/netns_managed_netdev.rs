//! Privileged netns proof for ADR-0091 managed bridge lifecycle.
//!
//! Proves the real Linux netlink path for the bridge-class slice:
//!
//! - create a bridge with the configured `vlan_filtering` value;
//! - stamp it with the durable `IFLA_ALT_IFNAME` ownership marker;
//! - treat a second create as restart adoption/idempotent success;
//! - reap the exact owned bridge on config removal;
//! - preserve a same-name unstamped foreign bridge.

#![cfg(target_os = "linux")]

use std::process::Command;

use rustbgpd_evpn_linux::{Dataplane, DataplaneOp, FailureClass, LinuxDataplane};

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
