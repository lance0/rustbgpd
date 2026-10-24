//! Negative host-precondition cases run with the interface-only netns selector.

use super::*;

fn sysctl(ns: &str, setting: &str) {
    // ip netns exec creates a private mount namespace. Docker may mount
    // /proc/sys read-only, so make it writable only for this namespace call.
    ip(&[
        "netns",
        "exec",
        ns,
        "sh",
        "-c",
        "(test -w /proc/sys/net/ipv6/conf/veth/disable_ipv6 || mount -o remount,rw /proc/sys) && sysctl -qw \"$1\"",
        "sh",
        setting,
    ]);
}

fn address_state(ns: &str, state: &str) {
    let start = Instant::now();
    loop {
        let out = Command::new("ip")
            .args(["-n", ns, "-6", "addr", "show", "dev", "veth"])
            .output()
            .unwrap();
        assert!(out.status.success());
        if String::from_utf8_lossy(&out.stdout).contains(state) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "address never became {state}: {out:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn check_condition(ns: &str, daemon: &mut Daemon, dir: &Path, condition: &str, occurrence: usize) {
    daemon.wait(condition, Duration::from_secs(10), |daemon| {
        daemon
            .log()
            .lines()
            .filter(|line| line.contains(&format!("\"condition\":\"{condition}\"")))
            .count()
            == occurrence
    });
    let config = dir.join("rustbgpd.toml");
    for static_peer in [false, true] {
        let source = std::fs::read_to_string(&config).unwrap();
        let candidate = dir.join("check.toml");
        std::fs::write(
            &candidate,
            if static_peer {
                source.replace(
                    "interface = \"veth\"",
                    "interface = \"veth\"\naddress = \"fe80::b1\"",
                )
            } else {
                source
            },
        )
        .unwrap();
        // RA-default advisories apply only to interface-only discovery ports.
        if static_peer && condition == "ra_default_route" {
            continue;
        }
        for strict in [false, true] {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", ns])
                .arg(env!("CARGO_BIN_EXE_rustbgpd"))
                .arg("--check");
            if strict {
                cmd.arg("--strict");
            }
            let out = cmd.arg(&candidate).output().unwrap();
            assert_eq!(out.status.code(), Some(i32::from(strict)), "{out:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains(condition),
                "{out:?}"
            );
        }
    }
    let cli = std::env::var("CARGO_BIN_EXE_rbgp").expect("netns harness builds rbgp first");
    let out = Command::new("ip")
        .args(["netns", "exec", ns])
        .arg(cli)
        .args(["--addr", &daemon.grpc, "--json", "doctor", "--output"])
        .arg(dir.join("doctor.tar.gz"))
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("doctor did not return JSON: {out:?}"));
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == format!("interface.veth.{condition}"));
    assert!(
        check.is_some(),
        "missing doctor finding {condition}: {report}"
    );
    assert_eq!(
        check.unwrap()["status"],
        if condition == "ra_default_route" {
            "warn"
        } else {
            "fail"
        }
    );
    // Several monitor polls elapse while doctor and --check run. The condition
    // remains unchanged, so there must still be exactly one structured warning.
    assert_eq!(
        daemon
            .log()
            .lines()
            .filter(|line| line.contains(&format!("\"condition\":\"{condition}\"")))
            .count(),
        occurrence
    );
}

#[test]
fn host_ipv6_preconditions_warn_check_and_doctor_in_netns() {
    if !netns_enabled() {
        return;
    }
    let namespaces = Namespaces::create();
    let ns = &namespaces.a;
    sysctl(ns, "net.ipv6.conf.veth.accept_ra=0");
    let dir = private_tempdir();
    sysctl(ns, "net.ipv6.conf.veth.disable_ipv6=1");
    let mut daemon = Daemon::start(ns, dir.path(), 65001, "10.0.0.1");
    daemon.wait("control plane", Duration::from_secs(30), |daemon| {
        daemon.veth_rows().is_some()
    });

    check_condition(ns, &mut daemon, dir.path(), "ipv6_disabled", 1);
    sysctl(ns, "net.ipv6.conf.veth.disable_ipv6=0");
    // addrgenmode none is set by Namespaces::create, so enabling IPv6 does
    // not manufacture an address and the next state is deterministically missing.
    check_condition(ns, &mut daemon, dir.path(), "link_local_missing", 1);

    sysctl(ns, "net.ipv6.conf.veth.accept_dad=1");
    sysctl(ns, "net.ipv6.conf.veth.dad_transmits=1");
    sysctl(ns, "net.ipv6.neigh.veth.retrans_time_ms=60000");
    ip(&["-n", ns, "addr", "add", "fe80::dada/64", "dev", "veth"]);
    address_state(ns, "tentative");
    check_condition(ns, &mut daemon, dir.path(), "link_local_tentative", 1);
    ip(&["-n", ns, "addr", "del", "fe80::dada/64", "dev", "veth"]);

    sysctl(ns, "net.ipv6.neigh.veth.retrans_time_ms=100");
    ip(&[
        "-n",
        &namespaces.b,
        "addr",
        "add",
        "fe80::dead/64",
        "dev",
        "veth",
        "nodad",
    ]);
    ip(&["-n", ns, "addr", "add", "fe80::dead/64", "dev", "veth"]);
    address_state(ns, "dadfailed");
    check_condition(ns, &mut daemon, dir.path(), "link_local_dad_failed", 1);

    ip(&["-n", ns, "addr", "del", "fe80::dead/64", "dev", "veth"]);
    link_local(ns, "fe80::a1");
    daemon.wait(
        "recovered host prerequisites",
        Duration::from_secs(10),
        |daemon| daemon.log().contains("host IPv6 prerequisites recovered"),
    );
    sysctl(ns, "net.ipv6.conf.veth.forwarding=0");
    sysctl(ns, "net.ipv6.conf.veth.accept_ra_defrtr=1");
    sysctl(ns, "net.ipv6.conf.veth.accept_ra=1");
    check_condition(ns, &mut daemon, dir.path(), "ra_default_route", 1);
    let recoveries = daemon
        .log()
        .matches("host IPv6 prerequisites recovered")
        .count();
    sysctl(ns, "net.ipv6.conf.veth.accept_ra_defrtr=0");
    daemon.wait(
        "RA default warning cleared",
        Duration::from_secs(10),
        |daemon| {
            daemon
                .log()
                .matches("host IPv6 prerequisites recovered")
                .count()
                > recoveries
        },
    );
    sysctl(ns, "net.ipv6.conf.veth.forwarding=1");
    sysctl(ns, "net.ipv6.conf.veth.accept_ra=2");
    sysctl(ns, "net.ipv6.conf.veth.accept_ra_defrtr=1");
    check_condition(ns, &mut daemon, dir.path(), "ra_default_route", 2);
}

#[test]
fn host_ipv6_monitor_keeps_running_discovery_interfaces_after_reload() {
    if !netns_enabled() {
        return;
    }
    let namespaces = Namespaces::create();
    let ns = &namespaces.a;
    sysctl(ns, "net.ipv6.conf.veth.accept_ra=0");
    let dir = private_tempdir();
    // Interface-only neighbors follow a reload, except one whose effective
    // tcp_mss would change: that one keeps running until restart. Both
    // reloads below remove `veth` from the desired file while its clamp
    // keeps it running, so the monitor has to follow the running set, not
    // the desired file.
    let mut daemon = Daemon::start_with(ns, dir.path(), 65001, "10.0.0.1", "tcp_mss = 1400\n");
    daemon.wait("control plane", Duration::from_secs(30), |daemon| {
        daemon.veth_rows().is_some()
    });
    let config = dir.path().join("rustbgpd.toml");
    let original = std::fs::read_to_string(&config).unwrap();
    let mut previous_reload = serde_json::Value::Null;
    for (index, candidate) in [
        original.replace("interface = \"veth\"", "interface = \"future0\""),
        original.split_once("\n[[neighbors]]").unwrap().0.to_owned(),
    ]
    .into_iter()
    .enumerate()
    {
        std::fs::write(&config, candidate).unwrap();
        let out = Command::new("kill")
            .args(["-HUP", &daemon.child.id().to_string()])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        // The completed receipt is published after the desired snapshot's
        // bridge adoption, not merely after the runtime reload log line.
        daemon.wait(
            "accepted reload receipt",
            Duration::from_secs(30),
            |daemon| {
                let out = daemon.rbgp(&["--json", "config", "last-reload"]);
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
                    return false;
                };
                let record = &value["record"];
                if !out.status.success() || !record.is_object() || *record == previous_reload {
                    return false;
                }
                assert_eq!(record["outcome"], "complete", "{value}");
                previous_reload = record.clone();
                true
            },
        );
        let recoveries = daemon
            .log()
            .matches("host IPv6 prerequisites recovered")
            .count();
        sysctl(ns, "net.ipv6.conf.veth.disable_ipv6=1");
        daemon.wait("running port warning", Duration::from_secs(10), |daemon| {
            daemon
                .log()
                .matches("\"condition\":\"ipv6_disabled\"")
                .count()
                == index + 1
        });
        sysctl(ns, "net.ipv6.conf.veth.disable_ipv6=0");
        link_local(ns, "fe80::a1");
        // Two state observations after adoption rule out one stale in-flight
        // inspection satisfying the regression by chance.
        daemon.wait("running port recovery", Duration::from_secs(10), |daemon| {
            daemon
                .log()
                .matches("host IPv6 prerequisites recovered")
                .count()
                > recoveries
        });
    }
}
