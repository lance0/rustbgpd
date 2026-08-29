use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn interop_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/interop")
        .join(relative)
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
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
        (
            "m101-routeserver-bird332.clab.yml",
            vec![
                "ip addr add 10.101.1.1/24 dev eth1",
                "ip link set eth1 up",
                "ip addr add 10.101.2.1/24 dev eth2",
                "ip link set eth2 up",
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
fn m83_pins_refreshed_incumbent_images_and_preflights_before_capture() {
    let topology = topology("m83-routeserver-multistack.clab.yml");
    assert_eq!(
        topology["topology"]["nodes"]["bird"]["image"],
        "bird:v2.19.2-m83"
    );
    assert_eq!(
        topology["topology"]["nodes"]["gobgp"]["image"],
        "gobgp:v4.8.0-m83"
    );
    assert_eq!(
        topology["topology"]["nodes"]["frr"]["image"],
        "quay.io/frrouting/frr:10.3.1"
    );

    let script = fs::read_to_string(interop_path("scripts/test-m83-routeserver-multistack.sh"))
        .expect("read M83 script");
    for exact_version in [
        "BIRD version 2.19.2",
        "gobgp version 4.8.0",
        "gobgpd version 4.8.0",
    ] {
        assert!(
            script.contains(exact_version),
            "missing {exact_version} preflight"
        );
    }
    let preflight = script
        .rfind("if ! preflight_incumbent_versions; then")
        .expect("M83 main invokes exact version preflight");
    let capture = script
        .rfind("start_capture raw")
        .expect("M83 main starts raw capture");
    assert!(
        preflight < capture,
        "M83 must preflight versions before capture"
    );
}

#[test]
fn m86_pins_openbgpd_identity_and_preflights_every_daemon_start() {
    const IMAGE: &str =
        "openbgpd/openbgpd@sha256:b3d4413662098070d5643a0473a5a866f2922069ee9c75132c1cea3ac5914fa4";
    const AMD64_MANIFEST: &str =
        "sha256:85c443bcb16b1e1b2c6ea6bddcd540352d280f1eaed66b7a7cd0ea1122c866e6";
    const CONFIG: &str = "sha256:b38add7d3ec1a0d3caea8eb5dc799fda1925e60fb7689dc532cbada6551ee1a8";

    // Destructive red proof: replacing either topology image with the mutable
    // `:9.1` tag makes the exact node assertions fail.
    let topology = topology("m86-rr-openbgpd.clab.yml");
    for node in ["obgp1", "obgp2"] {
        assert_eq!(
            topology["topology"]["nodes"][node]["image"], IMAGE,
            "M86 {node} must use the reviewed OpenBGPD index"
        );
    }

    let workflow_path = repo_path(".github/workflows/interop.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", workflow_path.display()));
    let m86 = workflow
        .split_once("\n  m86:\n")
        .and_then(|(_, remainder)| remainder.split_once("\n  m25:\n").map(|(job, _)| job))
        .expect("interop workflow has a bounded M86 job");
    for required in [
        format!("OPENBGPD_IMAGE: {IMAGE}"),
        format!("OPENBGPD_AMD64_MANIFEST: {AMD64_MANIFEST}"),
        format!("OPENBGPD_CONFIG: {CONFIG}"),
        "docker buildx imagetools inspect --raw \"$OPENBGPD_IMAGE\"".to_owned(),
        "\"openbgpd/openbgpd@$amd64_manifest\"".to_owned(),
        "test \"$amd64_manifest\" = \"$OPENBGPD_AMD64_MANIFEST\"".to_owned(),
        "test \"$config_digest\" = \"$OPENBGPD_CONFIG\"".to_owned(),
        "docker pull \"$OPENBGPD_IMAGE\"".to_owned(),
    ] {
        assert!(m86.contains(&required), "M86 workflow lost `{required}`");
    }
    assert!(
        !m86.contains("openbgpd/openbgpd:9.1"),
        "M86 workflow must reject the mutable OpenBGPD tag"
    );

    let script_path = interop_path("scripts/test-m86-rr-openbgpd.sh");
    let script = fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", script_path.display()));
    for required in [
        format!("OPENBGPD_IMAGE=\"{IMAGE}\""),
        "OPENBGPD_VERSION=\"OpenBGPD 9.1\"".to_owned(),
        "OPENBGPD_IDENTITY_PREFLIGHTED=0".to_owned(),
    ] {
        assert!(script.contains(&required), "M86 driver lost `{required}`");
    }
    assert!(
        !script.contains("OPENBGPD_IMAGE=\"openbgpd/openbgpd:9.1\""),
        "M86 driver must reject the mutable OpenBGPD tag"
    );
    let preflight = script
        .split_once("preflight_openbgpd_identity() {")
        .and_then(|(_, remainder)| remainder.split_once("kill_bgpd() {").map(|(body, _)| body))
        .expect("M86 identity preflight has a bounded source section");
    for required in [
        "docker image inspect --format '{{.Id}}'",
        "docker inspect --format '{{.Config.Image}}'",
        "[ \"$configured_image\" != \"$OPENBGPD_IMAGE\" ]",
        "docker inspect --format '{{.Image}}'",
        "[ \"$local_image\" != \"$expected_local_image\" ]",
        "docker exec \"$container\" bgpd -V",
        "[ \"$version\" != \"$OPENBGPD_VERSION\" ]",
        "OPENBGPD_IDENTITY_PREFLIGHTED=1",
    ] {
        assert!(
            preflight.contains(required),
            "M86 preflight lost `{required}`"
        );
    }

    let start = script
        .split_once("start_bgpd() {")
        .and_then(|(_, remainder)| {
            remainder
                .split_once("preflight_openbgpd_identity() {")
                .map(|(body, _)| body)
        })
        .expect("M86 daemon-start helper has a bounded source section");
    let guard = start
        .find("[ \"$OPENBGPD_IDENTITY_PREFLIGHTED\" -ne 1 ]")
        .expect("M86 daemon start is identity-gated");
    let launch = start
        .find("bgpd -d -f /etc/bgpd/bgpd.conf")
        .expect("M86 daemon start retains the production launch");
    assert!(
        guard < launch,
        "M86 identity gate must precede daemon launch"
    );
    assert_eq!(
        script.matches("bgpd -d -f /etc/bgpd/bgpd.conf").count(),
        1,
        "every M86 OpenBGPD launch must use the gated helper"
    );
    assert_eq!(
        script.matches("start_bgpd \"$OBGP").count(),
        3,
        "M86 must retain its two initial starts and one controlled restart"
    );

    let main = script
        .split_once("main() {")
        .and_then(|(_, remainder)| remainder.split_once("\n}\n\nif [").map(|(body, _)| body))
        .expect("M86 main has a bounded source section");
    let preflight_call = main
        .find("preflight_openbgpd_identity || return 1")
        .expect("M86 main invokes the identity preflight");
    let first_openbgpd_start = main
        .find("start_bgpd \"$OBGP1\"")
        .expect("M86 main starts the first OpenBGPD client");
    assert!(
        preflight_call < first_openbgpd_start,
        "M86 identity preflight must complete before either initial daemon start"
    );
}

#[test]
fn m101_pins_peer_identity_and_real_wire_attribute_discard_contract() {
    const FRR_IMAGE: &str = "quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c";
    const BIRD_SHA256: &str = "21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c";

    let topology = topology("m101-routeserver-bird332.clab.yml");
    assert_eq!(
        topology["topology"]["nodes"]["bird"]["image"],
        "bird:v3.3.2-m101"
    );
    assert_eq!(topology["topology"]["nodes"]["frr"]["image"], FRR_IMAGE);
    for node in ["bird", "frr"] {
        assert_eq!(
            topology["topology"]["nodes"][node]["cmd"], "sleep infinity",
            "M101 {node} must remain asleep until identity preflight completes"
        );
    }

    let dockerfile = fs::read_to_string(interop_path("Dockerfile.bird-v332"))
        .expect("read M101 BIRD Dockerfile");
    for required in [
        "ARG BIRD_VERSION=3.3.2",
        "ARG BIRD_SHA256=21297d7a02edd700ae82de5a630055a9cb88a99e2e7e45551bc7d6c1e5b4de2c",
        "sha256sum --check --strict",
        "test \"$(bird --version 2>&1)\" = \"BIRD version ${BIRD_VERSION}\"",
    ] {
        assert!(
            dockerfile.contains(required),
            "M101 BIRD build lost `{required}`"
        );
    }
    assert!(dockerfile.contains(BIRD_SHA256));

    let bird_config =
        fs::read_to_string(interop_path("configs/bird-m101.conf")).expect("read M101 BIRD config");
    for required in [
        "attribute bgp 40 bytestring m101_bad;",
        "m101_bad = hex:00;",
        "route 198.51.100.0/24 blackhole;",
        "local role rs_client;",
        "enforce first as off;",
    ] {
        assert!(
            bird_config.contains(required),
            "M101 BIRD config lost `{required}`"
        );
    }

    let script_path = interop_path("scripts/test-m101-routeserver-bird332.sh");
    let script = fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", script_path.display()));
    for required in [
        format!("FRR_IMAGE=\"{FRR_IMAGE}\""),
        "BIRD_VERSION=\"BIRD version 3.3.2\"".to_owned(),
        "FRR_VERSION=\"bgpd version 10.3.1_git\"".to_owned(),
        "[ \"$command\" = '[\"sleep\",\"infinity\"]' ]".to_owned(),
        "type-40 tuple mismatch".to_owned(),
        "e0280100".to_owned(),
        "counter_delta_is attribute_discard \"$M101_DISCARD_BEFORE\" 1".to_owned(),
        "counter_delta_is treat_as_withdraw \"$M101_TAW_BEFORE\" 0".to_owned(),
        "counter_delta_is session_reset \"$M101_RESET_BEFORE\" 0".to_owned(),
        "birdc disable malformed_probe".to_owned(),
        "[ \"$pass\" -ne 27 ] || [ \"$fail\" -ne 0 ]".to_owned(),
    ] {
        assert!(script.contains(&required), "M101 driver lost `{required}`");
    }
    assert_eq!(
        script.matches("        ok \"").count(),
        26,
        "M101 must retain 26 local assertions plus shared gRPC readiness"
    );

    let main = script
        .split_once("main() {")
        .and_then(|(_, remainder)| {
            remainder
                .split_once("\n}\n\nmain \"$@\"")
                .map(|(body, _)| body)
        })
        .expect("M101 main has a bounded source section");
    let identity = main
        .find("preflight_identities_and_configs")
        .expect("M101 main preflights both peer identities");
    let capture = main.find("start_capture").expect("M101 main arms capture");
    let rust_start = main
        .find("start_rustbgpd")
        .expect("M101 main starts rustbgpd");
    let frr_start = main.find("start_frr").expect("M101 main starts FRR");
    let bird_start = main.find("start_bird").expect("M101 main starts BIRD");
    assert!(
        identity < capture && capture < rust_start && capture < frr_start && capture < bird_start,
        "M101 identity preflight and capture must precede every daemon start"
    );
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
fn m83_gobgp_readiness_is_structured_and_exact() {
    let script = interop_path("scripts/test-m83-routeserver-multistack.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--self-test-gobgp-readiness")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "{} --self-test-gobgp-readiness failed\nstdout:\n{}\nstderr:\n{}",
        script.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let source = fs::read_to_string(&script).expect("read M83 script");
    let wait = source
        .split_once("wait_gobgp_established() {")
        .and_then(|(_, remainder)| remainder.split_once("# Poll until").map(|(body, _)| body))
        .expect("M83 GoBGP wait helper has a bounded source section");
    assert!(wait.contains("gobgp_neighbor_established \"$RS_GOBGP_ADDR\""));
    for forbidden in ["grep", "awk", "$4 ==", "BGP state =", "state = ESTABLISHED"] {
        assert!(
            !wait.contains(forbidden),
            "structured wait contains `{forbidden}`"
        );
    }
    assert!(source.contains("docker exec \"$GOBGP\" gobgp --json neighbor \"$peer\""));
}

#[test]
fn m83_term_preserves_failure_artifacts_and_exits_nonzero() {
    // Destructive red proof: routing TERM through the EXIT-status handler
    // makes the subprocess observe status 0 and no copied sentinel, so this
    // self-test exits nonzero.
    let script = interop_path("scripts/test-m83-routeserver-multistack.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--self-test-signal-artifacts")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "{} --self-test-signal-artifacts failed\nstdout:\n{}\nstderr:\n{}",
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
        "kill -INT \"$capture_pid\"",
        "test -s \"$M83_CAPTURE_PATH\"",
        "tshark -r \"$M83_CAPTURE_PATH\" -c 1",
    ] {
        assert!(
            source.contains(required),
            "{} must retain receipt guard `{required}`",
            script.display()
        );
    }
    let stop_capture = source
        .split_once("stop_capture() {")
        .and_then(|(_, remainder)| remainder.split_once("start_bird() {").map(|(body, _)| body))
        .expect("M83 capture stop function has a bounded source section");
    let exact_one = stop_capture
        .find("[ \"$found\" -eq 1 ]")
        .expect("capture stop must require exactly one tshark");
    let signal = stop_capture
        .find("kill -INT \"$capture_pid\"")
        .expect("capture stop must signal the selected tshark");
    // Load-bearing ordering proof: moving the signal back into the scan, before
    // exact-one validation, makes this assertion red and can kill unrelated
    // captures before the receipt notices the ambiguity.
    assert!(
        exact_one < signal,
        "M83 must validate exactly one tshark before signaling it"
    );

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
