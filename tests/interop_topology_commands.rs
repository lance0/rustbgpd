use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn interop_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop")
        .join(relative)
}

fn topology(relative: &str) -> serde_yaml::Value {
    let path = interop_path(relative);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|error| panic!("parse {} as YAML: {error}", path.display()))
}

fn rustbgpd_image_and_exec(topology: &serde_yaml::Value) -> (&str, Vec<&str>) {
    let rustbgpd = &topology["topology"]["nodes"]["rustbgpd"];
    let image = rustbgpd["image"]
        .as_str()
        .expect("rustbgpd topology node has a string image");
    let exec = rustbgpd["exec"]
        .as_sequence()
        .expect("rustbgpd topology node has an exec sequence")
        .iter()
        .map(|command| {
            command
                .as_str()
                .expect("rustbgpd topology exec command is a string")
        })
        .collect();
    (image, exec)
}

#[test]
fn route_server_topologies_have_exact_control_plane_setup() {
    // Destructive red proof: adding either former `sysctl -w
    // net.ipv4.ip_forward=1` command makes the corresponding exact exec list
    // differ and this test fail.
    let cases = [
        (
            "m19-routeserver-frr.clab.yml",
            vec![
                "ip addr add 10.0.0.1/24 dev eth1",
                "ip link set eth1 up",
                "ip addr add 10.0.1.1/24 dev eth2",
                "ip link set eth2 up",
            ],
        ),
        (
            "m83-routeserver-multistack.clab.yml",
            vec![
                "ip addr add 10.83.1.1/24 dev eth1",
                "ip link set eth1 up",
                "ip addr add 10.83.2.1/24 dev eth2",
                "ip link set eth2 up",
                "ip addr add 10.83.3.1/24 dev eth3",
                "ip link set eth3 up",
            ],
        ),
    ];

    for (relative, expected_exec) in cases {
        let topology = topology(relative);
        let (image, exec) = rustbgpd_image_and_exec(&topology);
        assert_eq!(image, "rustbgpd:dev", "{relative} rustbgpd image drifted");
        assert_eq!(
            exec, expected_exec,
            "{relative} rustbgpd setup must remain control-plane-only"
        );
    }
}

#[test]
fn m83_eor_order_rejects_same_frame_reversal() {
    // Destructive red proof: replacing tuple order with frame-only order makes
    // the script's reversed same-frame fixture pass and this test fail.
    let script = interop_path("scripts/test-m83-routeserver-multistack.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--self-test-eor-order")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "{} --self-test-eor-order failed\nstdout:\n{}\nstderr:\n{}",
        script.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn m83_reload_continuity_rejects_a_dropped_peer() {
    // Destructive red proof: replacing the production continuity oracle with
    // the former nonzero-and-unchanged connectionsEstablished predicate makes
    // the script's dropped-not-reconnected fixture pass and this test fail.
    let script = interop_path("scripts/test-m83-routeserver-multistack.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--self-test-session-continuity")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "{} --self-test-session-continuity failed\nstdout:\n{}\nstderr:\n{}",
        script.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn m83_capture_and_reload_receipts_cannot_become_no_ops() {
    // Destructive red proof: deleting the /proc signal, pcap validation, live
    // LP mutation, or generation probe makes the matching source fence fail.
    let script = interop_path("scripts/test-m83-routeserver-multistack.sh");
    let source = fs::read_to_string(&script)
        .unwrap_or_else(|error| panic!("read {}: {error}", script.display()));

    for required in [
        "/proc/[0-9]*/comm",
        "kill -INT \"$pid\"",
        "test -s /tmp/m83.pcap",
        "tshark -r /tmp/m83.pcap -c 1",
    ] {
        assert!(
            source.contains(required),
            "{} must retain receipt guard `{required}`",
            script.display()
        );
    }

    let reload = source
        .split_once("assert_reload_stability() {")
        .and_then(|(_, remainder)| remainder.split_once("# Main").map(|(body, _)| body))
        .expect("M83 reload receipt function has a bounded source section");
    for required in [
        "s/^set_local_pref = 100$/set_local_pref = 110/",
        "100.67.0.0/24",
        ".policy_generation",
        "state_before=$(rs_neighbor_state \"$FRR_ADDR\")",
        "state_after=$(rs_neighbor_state \"$FRR_ADDR\")",
        "check_session_continuity",
    ] {
        assert!(
            reload.contains(required),
            "{} must retain receipt guard `{required}`",
            script.display()
        );
    }
    assert!(
        !source.contains("pkill"),
        "{} must not depend on procps or broad process signaling",
        script.display()
    );
}
