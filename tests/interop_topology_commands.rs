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

#[test]
fn route_server_accepted_absence_requires_successful_snapshot() {
    for script in [
        "scripts/test-m104-arouteserver-current-rs-differential.sh",
        "scripts/test-m106-rs-white-list-control-differential.sh",
    ] {
        let source = fs::read_to_string(interop_path(script)).unwrap();
        let (_, helpers) = source.split_once("rs_accepted_has()").unwrap();
        let (helpers, _) = helpers.split_once("\n\n").unwrap();
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
set -euo pipefail
eval "rs_accepted_has()$HELPERS"
peer=192.0.2.1 prefix=203.0.113.0/24
rs_ctl() {
    [[ "$*" == "rib received $peer" ]] || return 99
    printf '%s' "$reply"
    return "$producer_exit"
}
for producer_exit in 0 42; do
    for reply in '' '192.0.2.0/24' '203.0.113.' "$prefix"; do
        expected=$producer_exit
        if [ "$producer_exit" -eq 0 ] && [ "$reply" = "$prefix" ]; then
            expected=1
        fi
        status=0
        rs_accepted_lacks "$peer" "$prefix" || status=$?
        if [ "$status" -ne "$expected" ]; then
            printf 'producer=%s reply=%q: expected status %s, got %s\n' \
                "$producer_exit" "$reply" "$expected" "$status" >&2
            exit 1
        fi
    done
done
"#,
            ])
            .env("HELPERS", helpers)
            .output()
            .expect("run offline accepted-route absence regression");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn route_server_cli_predicates_drain_output_and_preserve_errors() {
    for script in [
        "scripts/test-m102-routeserver-openbgpd92.sh",
        "scripts/test-m104-arouteserver-current-rs-differential.sh",
        "scripts/test-m106-rs-white-list-control-differential.sh",
    ] {
        let source = fs::read_to_string(interop_path(script)).unwrap();
        let line = source
            .lines()
            .find(|line| line.contains("rs_ctl ") && line.contains("| grep "))
            .expect("live route-server CLI predicate");
        let predicate = &line[line.find("rs_ctl ").unwrap()..];
        let predicate = predicate
            .split(" && ")
            .next()
            .unwrap()
            .trim_end_matches("; }");
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
set -euo pipefail
FRR_ADDR=192.0.2.1 EXPORT_DENY=203.0.113.0/24
set -- "$FRR_ADDR" m102-export-to-frr
rs_ctl() {
    printf '%s\n' "$reply" || return $?
    # More than a pipe buffer after the matching first line makes early
    # consumer exit fail the producer deterministically, without sleeps.
    printf '%*s\n' 1048576 '' || return $?
    return "$producer_exit"
}
reply=m102-export-to-frr producer_exit=0
old=${PREDICATE/grep /grep -q }
if eval "$old" >/dev/null 2>&1; then
    echo 'early-closing negative control unexpectedly passed' >&2
    exit 1
fi
eval "$PREDICATE"
reply=unrelated-output
if eval "$PREDICATE"; then
    echo 'nonmatching output was accepted' >&2
    exit 1
fi
reply=m102-export-to-frr producer_exit=7
status=0
eval "$PREDICATE" || status=$?
test "$status" -eq 7
"#,
            ])
            .env("PREDICATE", predicate)
            .output()
            .expect("run offline CLI predicate regression");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
fn m16_ipv6_addresses_disable_dad_on_both_nodes() {
    // Destructive red proof: removing `nodad` from either node makes that
    // node's exact IPv6 address command differ and this test fail.
    let topology = topology("m16-llgr-frr.clab.yml");
    for (node, expected) in [
        ("rustbgpd", "ip -6 addr add fd00:16::1/64 dev eth1 nodad"),
        ("frr", "ip -6 addr add fd00:16::2/64 dev eth1 nodad"),
    ] {
        let ipv6_commands: Vec<_> = topology["topology"]["nodes"][node]["exec"]
            .as_sequence()
            .unwrap_or_else(|| panic!("M16 {node} exec must be a sequence"))
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .filter(|command| command.starts_with("ip -6 addr add "))
            .collect();
        assert_eq!(
            ipv6_commands,
            [expected],
            "M16 {node} must disable IPv6 DAD before starting its session",
        );
    }
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
        (
            "m102-routeserver-openbgpd92.clab.yml",
            vec![
                "ip addr add 10.102.1.1/24 dev eth1",
                "ip -6 addr add 2001:db8:102:1::1/64 dev eth1 nodad",
                "ip link set eth1 up",
                "ip addr add 10.102.2.1/24 dev eth2",
                "ip -6 addr add 2001:db8:102:2::1/64 dev eth2 nodad",
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
fn m100_pins_released_receivers_and_exact_twenty_cell_contract() {
    let topology = topology("m100-partial-receiver.clab.yml");
    for (node, image) in [
        (
            "rustbgpd",
            "ghcr.io/lance0/rustbgpd@sha256:cc6207fe950ee15f6793ca0119d531067c7b358b6c6193b0fda929495714c9da",
        ),
        ("bird", "bird:v2.19.2-m100"),
        (
            "openbgpd",
            "openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9",
        ),
        (
            "frr",
            "quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c",
        ),
        ("raw", "bmpsink:m100"),
        ("switch", "bmpsink:m100"),
    ] {
        assert_eq!(
            topology["topology"]["nodes"][node]["image"], image,
            "M100 {node} image drifted"
        );
    }

    let topology_source = fs::read_to_string(interop_path("m100-partial-receiver.clab.yml"))
        .expect("read M100 topology");
    for fixture in [
        "configs/rustbgpd-m100-receiver.toml",
        "configs/bird-m100-receiver.conf",
        "configs/bgpd-m100-receiver.conf",
        "configs/frr-bgpd-m100-receiver.conf",
        "scripts/m100_partial_raw_peer.py",
    ] {
        assert!(
            topology_source.contains(fixture),
            "M100 topology lost `{fixture}`"
        );
    }

    let peer = fs::read_to_string(interop_path("scripts/m100_partial_raw_peer.py"))
        .expect("read M100 raw peer");
    for expected in [
        r#"("rustbgpd", "med"): "accepted""#,
        r#"("rustbgpd", "originator_id"): "accepted""#,
        r#"("rustbgpd", "cluster_list"): "accepted""#,
        r#"("rustbgpd", "mp_reach"): "reset""#,
        r#"("rustbgpd", "mp_unreach"): "reset""#,
        r#"("bird", "med"): "accepted""#,
        r#"("bird", "originator_id"): "accepted""#,
        r#"("bird", "cluster_list"): "accepted""#,
        r#"("bird", "mp_reach"): "accepted""#,
        r#"("bird", "mp_unreach"): "same_session_withdrawal""#,
        r#"("openbgpd", "med"): "reset""#,
        r#"("openbgpd", "originator_id"): "reset""#,
        r#"("openbgpd", "cluster_list"): "reset""#,
        r#"("openbgpd", "mp_reach"): "reset""#,
        r#"("openbgpd", "mp_unreach"): "reset""#,
        r#"("frr", "med"): "treat_as_withdraw""#,
        r#"("frr", "originator_id"): "treat_as_withdraw""#,
        r#"("frr", "cluster_list"): "treat_as_withdraw""#,
        r#"("frr", "mp_reach"): "reset""#,
        r#"("frr", "mp_unreach"): "reset""#,
    ] {
        assert!(peer.contains(expected), "M100 matrix lost `{expected}`");
    }
    for exact in [
        r#""med": "a0040400000064""#,
        r#""originator_id": "a00904c0000209""#,
        r#""cluster_list": "a00a04c000020a""#,
        r#""mp_reach": "a00e0d000101040a69000a0018c63364""#,
        r#""mp_unreach": "a00f0700010118c63364""#,
        "if cursor + length > attributes_end:",
        "negative flag mutation was accepted",
        "inverted outcome negative test was accepted",
        "malformed snapshot negative test was accepted",
        "M100 exact 20-cell contract verified",
    ] {
        assert!(peer.contains(exact), "M100 oracle lost `{exact}`");
    }

    let driver = fs::read_to_string(interop_path("scripts/test-m100-partial-receiver.sh"))
        .expect("read M100 driver");
    for required in [
        "CASES=(med originator_id cluster_list mp_reach mp_unreach)",
        "RECEIVERS=(rustbgpd bird openbgpd frr)",
        "M100 produced exactly 20 unique cells",
        "--verify-results",
        "M100 exact observed matrix and evidence",
    ] {
        assert!(driver.contains(required), "M100 driver lost `{required}`");
    }
}

#[test]
fn m76_pins_gobgp48_identity_before_preserving_the_orr_contract() {
    let topology = topology("m76-orr-divergent-best-gobgp.clab.yml");
    assert_eq!(topology["name"], "m76-orr-divergent-best-gobgp");
    let nodes = topology["topology"]["nodes"].as_mapping().unwrap();
    assert_eq!(
        nodes.len(),
        6,
        "M76 must retain one RR and five GoBGP peers"
    );
    assert_eq!(nodes["rustbgpd"]["image"], "rustbgpd:dev");
    for peer in [
        "gobgp-src",
        "gobgp-pe1",
        "gobgp-pe2",
        "gobgp-c1",
        "gobgp-c2",
    ] {
        assert_eq!(
            nodes[peer]["image"], "gobgp:v4.8.0-m76",
            "M76 {peer} image drifted"
        );
    }

    let script = fs::read_to_string(interop_path("scripts/test-m76-orr-divergent-best-gobgp.sh"))
        .expect("read M76 driver");
    for required in [
        "GOBGP_IMAGE=\"gobgp:v4.8.0-m76\"",
        "GOBGP_VERSION=\"gobgp version 4.8.0\"",
        "GOBGPD_VERSION=\"gobgpd version 4.8.0\"",
        "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
        "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97",
        "docker image inspect -f '{{.Architecture}}' \"$GOBGP_IMAGE\"",
        "docker inspect -f '{{.Config.Image}}' \"$container\"",
        "docker inspect -f '{{.Image}}' \"$container\"",
        "docker exec \"$container\" uname -m",
        "docker exec \"$container\" gobgp --version",
        "docker exec \"$container\" gobgpd --version",
        "sha256sum /usr/local/bin/gobgp",
        "sha256sum /usr/local/bin/gobgpd",
        "assert_family_negotiated \"$GOBGP_SRC\" \"10.0.0.1\" \"ls\" \"source\"",
        "wait_topology_counts 4 4 \"square injected\"",
        "wait_vantages_resolved true \"square injected\"",
        "wait_client_best \"$GOBGP_C1\" \"$NH_X\" \"$PE1_ADDR\"",
        "wait_client_best \"$GOBGP_C2\" \"$NH_Y\" \"$PE2_ADDR\"",
        "gobgp \"$GOBGP_SRC\" global rib add -a ls $(ls_link_a_x 100)",
        "if [ \"$c2_updates_after\" = \"$c2_updates\" ]; then",
        "assert_no_flap \"$C1_ADDR\" \"$c1_flaps\" \"flip/c1\"",
        "assert_no_flap \"$C2_ADDR\" \"$c2_flaps\" \"flip/c2\"",
        "wait_topology_counts 0 0 \"square withdrawn\"",
        "wait_vantages_resolved false \"square withdrawn\"",
        "wait_client_best \"$GOBGP_C1\" \"$NH_X\" \"$PE1_ADDR\" \"c1 fallback\"",
        "wait_client_best \"$GOBGP_C2\" \"$NH_X\" \"$PE1_ADDR\" \"c2 fallback\"",
        "capture_ip_routes mpls \"$RUSTBGPD\" MPLS -M",
        "capture_ip_routes ipv4 \"$RUSTBGPD\" IPv4",
        "wait_topology_counts 4 4 \"square re-injected\"",
        "assert_no_flap \"$SRC_ADDR\" \"$src_flaps\" \"src (linkstate-only)\"",
    ] {
        assert!(script.contains(required), "M76 driver lost `{required}`");
    }
    for historical in ["gobgp:bgpls", "Dockerfile.gobgp-bgpls", "GoBGP v4.6.0"] {
        assert!(
            !script.contains(historical),
            "M76 driver regained historical seam `{historical}`"
        );
    }
    let main = script.rfind("\nmain() {").expect("M76 main exists");
    let main = &script[main..];
    let identity = main
        .find("    preflight_gobgp_identity\n")
        .expect("M76 main invokes the exact GoBGP identity preflight");
    let first_start = main
        .find("    start_gobgpd \"$GOBGP_SRC\"\n")
        .expect("M76 main starts the BGP-LS source");
    assert!(
        identity < first_start,
        "M76 must preflight exact GoBGP identity before any daemon start"
    );
}

#[test]
fn m77_pins_gobgp48_identity_before_preserving_the_gr_llgr_contract() {
    let topology = topology("m77-gr-llgr-rr-gobgp.clab.yml");
    assert_eq!(topology["name"], "m77-gr-llgr-rr-gobgp");
    let nodes = topology["topology"]["nodes"].as_mapping().unwrap();
    assert_eq!(nodes["rustbgpd"]["image"], "rustbgpd:dev");
    for peer in ["gobgp-pe", "gobgp-client", "gobgp-ls"] {
        assert_eq!(
            nodes[peer]["image"], "gobgp:v4.8.0-m77",
            "M77 {peer} image drifted"
        );
    }

    let script_path = interop_path("scripts/test-m77-gr-llgr-rr-gobgp.sh");
    let script = fs::read_to_string(&script_path).expect("read M77 driver");
    for required in [
        "GOBGP_IMAGE=\"gobgp:v4.8.0-m77\"",
        "GOBGP_VERSION=\"gobgp version 4.8.0\"",
        "GOBGPD_VERSION=\"gobgpd version 4.8.0\"",
        "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
        "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97",
        "docker image inspect -f '{{.Architecture}}' \"$GOBGP_IMAGE\"",
        "docker inspect -f '{{.Config.Image}}' \"$container\"",
        "docker inspect -f '{{.Image}}' \"$container\"",
        "docker exec \"$container\" uname -m",
        "docker exec \"$container\" gobgp --version",
        "docker exec \"$container\" gobgpd --version",
        "sha256sum /usr/local/bin/gobgp",
        "sha256sum /usr/local/bin/gobgpd",
        "select(.key == \"default\" or .key == \"0:0:0/0\")",
        ".[\"peer-address\"] == $rr",
        "and (.attrs | length) == 4",
        ".type == 2 and .as_paths == []",
        ".type == 14",
        ".nexthop == $rr",
        ".afi == 1",
        ".safi == 132",
        ".value[0].NLRI.prefix == $prefix",
        "--self-test-default-rtc-parser",
        "parser self-test passed (8 cases)",
    ] {
        assert!(script.contains(required), "M77 driver lost `{required}`");
    }
    assert!(
        !script.contains("gobgp:bgpls"),
        "M77 driver regained the historical source-build image"
    );
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("--self-test-default-rtc-parser")
        .output()
        .expect("run M77 RTC parser self-test");
    assert!(
        output.status.success(),
        "M77 RTC parser self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let main = script.rfind("\nmain() {").expect("M77 main exists");
    let main = &script[main..];
    let identity = main
        .find("    preflight_gobgp_identity\n")
        .expect("M77 main invokes the exact GoBGP identity preflight");
    let first_start = main
        .find("    start_gobgpd \"$GOBGP_PE\"\n")
        .expect("M77 main starts the PE");
    assert!(
        identity < first_start,
        "M77 must preflight exact GoBGP identity before any daemon start"
    );

    let dockerfile = fs::read_to_string(interop_path("Dockerfile.gobgp-v47"))
        .expect("read checksum-built GoBGP Dockerfile");
    let checksum = dockerfile
        .find("sha256sum -c -")
        .expect("GoBGP archive checksum is verified");
    let extract = dockerfile
        .find("tar -xzf /tmp/gobgp.tar.gz")
        .expect("GoBGP archive is extracted");
    assert!(
        checksum < extract,
        "GoBGP archive must be verified before extraction"
    );
    for required in [
        "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/",
        "gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz",
        "test \"$(gobgp --version)\" = \"gobgp version ${GOBGP_VERSION}\"",
        "test \"$(gobgpd --version)\" = \"gobgpd version ${GOBGP_VERSION}\"",
    ] {
        assert!(
            dockerfile.contains(required),
            "checksum-built GoBGP image lost `{required}`"
        );
    }
}

#[test]
fn m83_pins_refreshed_incumbent_images_and_preflights_before_capture() {
    const FRR_IMAGE: &str = "quay.io/frrouting/frr@sha256:a0ed0e4f8727631c8303dd9a4e8199b47464a17a5253135a2c622286aeaec46b";
    let topology = topology("m83-routeserver-multistack.clab.yml");
    assert_eq!(
        topology["topology"]["nodes"]["bird"]["image"],
        "bird:v2.19.2-m83"
    );
    assert_eq!(
        topology["topology"]["nodes"]["gobgp"]["image"],
        "gobgp:v4.8.0-m83"
    );
    assert_eq!(topology["topology"]["nodes"]["frr"]["image"], FRR_IMAGE);

    let frr_config =
        fs::read_to_string(interop_path("configs/frr-bgpd-m83.conf")).expect("read M83 FRR config");
    assert!(
        frr_config.starts_with("frr version 10.7.0\n"),
        "M83 FRR config must select the refreshed runtime profile"
    );

    let dockerfile = fs::read_to_string(interop_path("Dockerfile.bird-v2192"))
        .expect("read M83 BIRD Dockerfile");
    for required in [
        "ARG BIRD_VERSION=2.19.2",
        "ARG BIRD_SHA256=aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660",
        "COPY bird3-archive/ /tmp/bird-archive/",
        "if [ ! -f \"${target}\" ]; then",
        "if [ \"${attempt}\" -ge 3 ]; then",
        "sha256sum --check --strict",
        "test \"$(bird --version 2>&1)\" = \"BIRD version ${BIRD_VERSION}\"",
    ] {
        assert!(
            dockerfile.contains(required),
            "M83 BIRD build lost `{required}`"
        );
    }
    let copy = dockerfile
        .find("COPY bird3-archive/ /tmp/bird-archive/")
        .expect("M83 copies the staged archive directory");
    let checksum = dockerfile
        .rfind("sha256sum --check --strict")
        .expect("M83 checks the staged archive");
    let extract = dockerfile
        .find("tar -xzf \"${target}\" -C /tmp/bird --strip-components=1")
        .expect("M83 extracts the checked archive");
    assert!(copy < checksum && checksum < extract);

    let script = fs::read_to_string(interop_path("scripts/test-m83-routeserver-multistack.sh"))
        .expect("read M83 script");
    for exact_version in [
        "BIRD version 2.19.2",
        "gobgp version 4.8.0",
        "gobgpd version 4.8.0",
        "bgpd version 10.7.0_git",
    ] {
        assert!(
            script.contains(exact_version),
            "missing {exact_version} preflight"
        );
    }
    for identity_seam in [
        format!("FRR_IMAGE=\"{FRR_IMAGE}\""),
        "frr_image_id=$(docker image inspect -f '{{.Id}}' \"$FRR_IMAGE\")".to_owned(),
        "frr_config_image=$(docker inspect -f '{{.Config.Image}}' \"$FRR\")".to_owned(),
        "frr_container_image_id=$(docker inspect -f '{{.Image}}' \"$FRR\")".to_owned(),
        "[ \"$frr_config_image\" = \"$FRR_IMAGE\" ]".to_owned(),
        "[ \"$frr_container_image_id\" = \"$frr_image_id\" ]".to_owned(),
    ] {
        assert!(
            script.contains(&identity_seam),
            "missing M83 FRR identity preflight `{identity_seam}`"
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
        "COPY bird3-archive/ /tmp/bird-archive/",
        "if [ ! -f \"${target}\" ]; then",
        "if [ \"${attempt}\" -ge 3 ]; then",
        "sha256sum --check --strict",
        "test \"$(bird --version 2>&1)\" = \"BIRD version ${BIRD_VERSION}\"",
    ] {
        assert!(
            dockerfile.contains(required),
            "M101 BIRD build lost `{required}`"
        );
    }
    assert!(dockerfile.contains(BIRD_SHA256));
    let copy = dockerfile
        .find("COPY bird3-archive/ /tmp/bird-archive/")
        .expect("M101 copies the staged archive directory");
    let checksum = dockerfile
        .rfind("sha256sum --check --strict")
        .expect("M101 checks the staged archive");
    let extract = dockerfile
        .find("tar -xzf \"${target}\" -C /tmp/bird --strip-components=1")
        .expect("M101 extracts the checked archive");
    assert!(copy < checksum && checksum < extract);

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
fn m102_pins_openbgpd92_route_server_member_contract() {
    const OPENBGPD_IMAGE: &str =
        "openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9";
    const FRR_IMAGE: &str = "quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c";
    let topology = topology("m102-routeserver-openbgpd92.clab.yml");
    assert_eq!(
        topology["topology"]["nodes"]["openbgpd"]["image"],
        OPENBGPD_IMAGE
    );
    assert_eq!(topology["topology"]["nodes"]["frr"]["image"], FRR_IMAGE);
    for node in ["openbgpd", "frr"] {
        assert_eq!(topology["topology"]["nodes"][node]["cmd"], "sleep infinity");
    }
    let topology_source = fs::read_to_string(interop_path("m102-routeserver-openbgpd92.clab.yml"))
        .expect("read M102 topology");
    assert_eq!(
        topology_source.matches("accept_dad=0").count(),
        4,
        "M102 peer images use their supported DAD sysctls, while rustbgpd uses nodad"
    );
    let rust_exec = topology["topology"]["nodes"]["rustbgpd"]["exec"]
        .as_sequence()
        .expect("M102 rustbgpd exec is a sequence");
    assert!(
        rust_exec.iter().all(|command| {
            command
                .as_str()
                .is_some_and(|command| !command.contains("sysctl"))
        }),
        "M102 rustbgpd startup must not depend on sysctl being installed"
    );
    assert_eq!(
        rust_exec
            .iter()
            .filter_map(|command| command.as_str())
            .filter(|command| command.contains("ip -6 addr add") && command.ends_with(" nodad"))
            .count(),
        2,
        "M102 rustbgpd must make both IPv6 addresses usable with iproute2 nodad"
    );
    let open_config = fs::read_to_string(interop_path("configs/bgpd-m102-member.conf"))
        .expect("read M102 OpenBGPD config");
    for required in [
        "AS 4200000201",
        "remote-as 4200000102",
        "announce policy enforce",
        "announce as-4byte enforce",
        "enforce neighbor-as no",
        "role rs-client",
        "announce IPv4 unicast enforce",
        "announce IPv6 unicast enforce",
    ] {
        assert!(
            open_config.contains(required),
            "M102 OpenBGPD config lost `{required}`"
        );
    }
    let rust_config = fs::read_to_string(interop_path("configs/rustbgpd-m102-rs.toml"))
        .expect("read M102 rustbgpd config");
    for required in [
        "config_epoch = 2",
        "asn = 4200000102",
        "ebgp_requires_policy = true",
        "remote_asn = 4200000201",
        "remote_asn = 4200000202",
        "strict_role = true",
        "import_policy_chain",
        "export_policy_chain",
    ] {
        assert!(
            rust_config.contains(required),
            "M102 rustbgpd config lost `{required}`"
        );
    }
    let script_path = interop_path("scripts/test-m102-routeserver-openbgpd92.sh");
    let script = fs::read_to_string(&script_path).expect("read M102 driver");
    for required in [
        "OpenBGPD 9.2",
        "bgpctl network add",
        "bgpctl network delete",
        "CAPTURE_IMAGE=bmpsink:m102",
        "CAPTURE_CONTAINER=m102-raw-capture",
        "CAPTURE_VOLUME=m102-raw-capture-data",
        "for b in docker python3 jq timeout",
        "capture tshark is not 4.4.x",
        "docker volume create --label rustbgpd.interop.milestone=M102",
        "--network \"container:$RUSTBGPD\"",
        "--cap-add=NET_ADMIN --cap-add=NET_RAW",
        "--mount \"type=volume,src=$CAPTURE_VOLUME,dst=/capture\"",
        "\"$CAPTURE_IMAGE\" tshark -p -i any",
        "docker logs \"$CAPTURE_CONTAINER\"",
        "Capturing on",
        "docker kill --signal=SIGINT \"$CAPTURE_CONTAINER\"",
        "timeout 10 docker wait \"$CAPTURE_CONTAINER\"",
        "/tmp/m102-rustbgpd.log",
        "mkdir -p /run/bgpd",
        "/tmp/m102-bgpd.log",
        "/tmp/m102-bgpd.pid",
        "kill -0 \"$pid\"",
        "bgpctl show",
        "bgpctl show neighbor 10.102.1.1",
        "docker top \"$FRR\"",
        "rm -f /tmp/m102-bgpd.pid /tmp/m102-bgpd.log",
        "/run/bgpd/bgpd.sock.*",
        "/run/bgpd/bgpd.rsock.*",
        "OpenBGPD startup or control-socket readiness failed",
        "start_m102_rustbgpd",
        "trap - EXIT INT TERM HUP",
        "pass=$((pass + 1))",
        "open_absent",
        "frr_absent",
        "still present or uninspectable",
        "open_session_json_valid",
        "open_route_json_valid",
        "open_absence_json_valid",
        "open_communities_json_valid",
        "rs_presence_json_valid",
        "rs_absence_json_valid",
        "frr_communities_json_valid",
        "frr_absence_json_valid",
        "neighbor_state_json_valid",
        ".config.remoteAsn == $expected_asn",
        "bgpctl -j show rib detail \"$prefix\"",
        "frr_inventory_json_valid",
        "[.[].routes | keys[]] | sort",
        "emit_session_mismatch",
        "emit_community_mismatch",
        "emit_inventory_mismatch",
        "inventory_row_matches",
        ".neighbors[0].remote_addr == \"10.102.1.1\"",
        ".rib[0].exit_nexthop == $nh",
        ".paths[0].community.string",
        ".paths[0].largeCommunity.string",
        "--self-test-openbgpd-json",
        "dump_m102_control_plane_diagnostics",
        "dump_m102_capture_diagnostics",
        "packet summary (first 80 BGP TCP packets)",
        "TCP conversation summary",
        "-z conv,tcp",
        "capture volume retained for idempotent trap cleanup",
        "0|130",
        "--mount \"type=volume,src=$CAPTURE_VOLUME,dst=/capture,readonly\"",
        "test -s /capture/m102.pcap",
        "tshark -r /capture/m102.pcap",
        "tcp.seq_raw",
        "--self-test-oracle",
        "--self-test-oracle-conflict",
        "--self-test-oracle-gap",
        "--self-test-oracle-capability",
        "--self-test-oracle-update",
        "--self-test-oracle-trailing",
        "--self-test-oracle-marker",
        "4200000201",
        "expected exactly one OpenBGPD-to-rustbgpd TCP stream",
        "conflicting TCP overlap",
        "capability 65 ASN mismatch",
        "role capability 9 mismatch",
        "exact UPDATE attributes absent",
        "BGP marker is not at stream cursor",
        "unexplained trailing partial BGP bytes",
        "2001:db8:1102::/48",
        "2001:db8:2102::/48",
        "f[1]==\"10.102.1.2\" and f[2]==\"10.102.1.1\"",
        "OpenBGPD member is Established",
        "FRR member is Established",
        "rustbgpd reports exact remote ASNs and negotiated Roles",
        "rs_loc_inventory_exact",
        "open_inventory_exact",
        "frr_inventory_exact",
        "Rust Adj-RIB-In contains OpenBGPD IPv4",
        "Rust Adj-RIB-In contains OpenBGPD IPv6",
        "Rust Loc-RIB contains OpenBGPD IPv4",
        "Rust Loc-RIB contains OpenBGPD IPv6",
        "FRR IPv4 has exact OpenBGPD AS_PATH/NEXT_HOP",
        "FRR IPv6 has exact OpenBGPD AS_PATH/NEXT_HOP",
        "OpenBGPD IPv4 has exact FRR AS_PATH/NEXT_HOP",
        "OpenBGPD IPv6 has exact FRR AS_PATH/NEXT_HOP",
        "raw OPEN uses AS_TRANS",
        "raw capability 65 carries ASN 4200000201",
        "raw capability 9 carries rs-client role",
        "raw OPEN carries exact IPv4/IPv6 MP tuples",
        "raw UPDATE has exact AS_PATH/NEXT_HOP",
        "raw UPDATE has exact standard/Large Communities",
        "standard and Large Communities survive both directions",
        "global import policy denies its prefix",
        "import explain names m102-import",
        "export-denied route remains in Loc-RIB",
        "FRR advertised view omits export deny",
        "export explain names m102-export-to-frr",
        "policy positive controls pass both directions",
        "OpenBGPD, FRR, and Rust inventories are exact with no extras",
        "OpenBGPD IPv4 leaves Rust Adj-RIB-In/Loc-RIB and FRR",
        "OpenBGPD IPv6 leaves Rust Adj-RIB-In/Loc-RIB and FRR",
        "FRR IPv4 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD",
        "FRR IPv6 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD",
        "OpenBGPD remains Established without a flap",
        "FRR remains Established without a flap",
        "m102-import",
        "m102-export-to-frr",
        "[ \"$pass\" -eq 32 ] && [ \"$fail\" -eq 0 ]",
    ] {
        assert!(script.contains(required), "M102 driver lost `{required}`");
    }
    for forbidden in ["sudo", "nsenter", "command -v tshark"] {
        assert!(
            !script.contains(forbidden),
            "M102 sidecar driver regained forbidden host seam `{forbidden}`"
        );
    }
    for forbidden in [
        ".neighbors|length==1 and",
        ".nexthop==",
        ".nexthop ==",
        "|tostring|contains",
        "! rs_loc",
        "! rs_received",
        "! rs_advertised",
        ".paths // []",
        "$os.remoteAsn",
        "$fs.remoteAsn",
        "..|objects|select(has(\"prefix\"))",
        "sort -u",
    ] {
        assert!(
            !script.contains(forbidden),
            "M102 JSON proof regained forbidden legacy seam `{forbidden}`"
        );
    }
    assert_eq!(
        script.matches("ok \"").count(),
        31,
        "M102 must retain 31 local assertions plus shared gRPC readiness"
    );
    let ledger_rows = [
        "OpenBGPD member is Established",
        "FRR member is Established",
        "rustbgpd reports exact remote ASNs and negotiated Roles",
        "Rust Adj-RIB-In contains OpenBGPD IPv4",
        "Rust Adj-RIB-In contains OpenBGPD IPv6",
        "Rust Loc-RIB contains OpenBGPD IPv4",
        "Rust Loc-RIB contains OpenBGPD IPv6",
        "FRR IPv4 has exact OpenBGPD AS_PATH/NEXT_HOP",
        "FRR IPv6 has exact OpenBGPD AS_PATH/NEXT_HOP",
        "OpenBGPD IPv4 has exact FRR AS_PATH/NEXT_HOP",
        "OpenBGPD IPv6 has exact FRR AS_PATH/NEXT_HOP",
        "standard and Large Communities survive both directions",
        "global import policy denies its prefix",
        "import explain names m102-import",
        "export-denied route remains in Loc-RIB",
        "FRR advertised view omits export deny",
        "export explain names m102-export-to-frr",
        "policy positive controls pass both directions",
        "raw OPEN uses AS_TRANS",
        "raw capability 65 carries ASN 4200000201",
        "raw capability 9 carries rs-client role",
        "raw OPEN carries exact IPv4/IPv6 MP tuples",
        "raw UPDATE has exact AS_PATH/NEXT_HOP",
        "raw UPDATE has exact standard/Large Communities",
        "OpenBGPD, FRR, and Rust inventories are exact with no extras",
        "OpenBGPD IPv4 leaves Rust Adj-RIB-In/Loc-RIB and FRR",
        "OpenBGPD IPv6 leaves Rust Adj-RIB-In/Loc-RIB and FRR",
        "FRR IPv4 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD",
        "FRR IPv6 leaves Rust Adj-RIB-In/Loc-RIB and OpenBGPD",
        "OpenBGPD remains Established without a flap",
        "FRR remains Established without a flap",
    ];
    assert_eq!(ledger_rows.len(), 31);
    for row in ledger_rows {
        assert_eq!(
            script.matches(&format!("ok \"{row}\"")).count(),
            1,
            "M102 ledger row `{row}` must appear exactly once"
        );
    }
    assert_eq!(
        script.matches("\npreflight() {").count(),
        0,
        "M102 must not override the shared test-lib preflight"
    );
    assert_eq!(
        script
            .matches("\npreflight_identities_and_configs() {")
            .count(),
        1,
        "M102 must define exactly one uniquely named identity/config preflight"
    );
    let source = script
        .find("source \"$SCRIPT_DIR/test-lib.sh\"")
        .expect("M102 sources shared test-lib");
    let self_test_dispatch = script
        .find("case \"${1:-}\" in")
        .expect("M102 dispatches offline oracle self-tests");
    let capture_allocation = script
        .find("PAYLOADS=\"$(mktemp /tmp/m102.XXXXXX.tsv)\"")
        .expect("M102 allocates host payload state");
    let custom_trap = script
        .find("trap on_exit EXIT INT TERM HUP")
        .expect("M102 installs its composed cleanup trap");
    let main_invoke = script.rfind("main \"$@\"").expect("M102 invokes main");
    assert!(
        self_test_dispatch < source
            && source < capture_allocation
            && capture_allocation < custom_trap
            && custom_trap < main_invoke,
        "M102 must dispatch offline self-tests before shared preflight, then allocate capture state and install its final trap before main"
    );
    let on_exit = script
        .split_once("on_exit() {")
        .expect("M102 composed cleanup helper")
        .1
        .split_once("\n}")
        .expect("M102 cleanup helper has a bounded source section")
        .0;
    let capture_cleanup = on_exit
        .find("cleanup_capture || capture_status=$?")
        .expect("M102 cleanup records capture status");
    let temp_cleanup = on_exit
        .find("rm -f \"$PAYLOADS\"")
        .expect("M102 cleanup removes host payload state");
    let shared_cleanup = on_exit
        .find("_cleanup_on_exit")
        .expect("M102 cleanup composes shared topology cleanup");
    let status_propagation = on_exit
        .find("[ \"$status\" -eq 0 ] && [ \"$capture_status\" -ne 0 ] && status=$capture_status")
        .expect("M102 cleanup propagates capture failure after successful main");
    let status_exit = on_exit
        .find("exit \"$status\"")
        .expect("M102 cleanup preserves final status");
    assert!(
        capture_cleanup < temp_cleanup
            && temp_cleanup < shared_cleanup
            && shared_cleanup < status_propagation
            && status_propagation < status_exit,
        "M102 must stop capture, remove temp state, run shared cleanup, propagate capture status, and preserve the final exit status"
    );
    let capture_cleanup_body = script
        .split_once("cleanup_capture() {")
        .expect("M102 cleanup capture helper")
        .1
        .split_once("\n}")
        .expect("M102 cleanup capture helper is bounded")
        .0;
    let cleanup_stop = capture_cleanup_body
        .find("stop_capture_container")
        .expect("M102 cleanup bounded-stops the sidecar");
    let cleanup_container = capture_cleanup_body
        .find("timeout 10 docker rm -f \"$CAPTURE_CONTAINER\"")
        .expect("M102 cleanup removes the sidecar");
    let cleanup_volume = capture_cleanup_body
        .find("timeout 10 docker volume rm -f \"$CAPTURE_VOLUME\"")
        .expect("M102 cleanup removes the capture volume");
    assert!(
        cleanup_stop < cleanup_container && cleanup_container < cleanup_volume,
        "M102 cleanup must stop/remove the sidecar before removing its volume"
    );
    let stop_capture_container = script
        .split_once("stop_capture_container() {")
        .expect("M102 stop capture helper")
        .1
        .split_once("\n}")
        .expect("M102 stop capture helper is bounded")
        .0;
    let signal = stop_capture_container
        .find("timeout 10 docker kill --signal=SIGINT")
        .expect("M102 sends bounded SIGINT to tshark PID 1");
    let wait = stop_capture_container
        .find("timeout 10 docker wait")
        .expect("M102 bounded-waits for tshark");
    let remove = stop_capture_container
        .find("timeout 10 docker rm -f")
        .expect("M102 removes the stopped sidecar");
    assert!(
        signal < wait && wait < remove,
        "M102 must signal, wait for, then remove the capture sidecar"
    );
    let start_capture = script
        .split_once("start_capture() {")
        .expect("M102 start capture helper")
        .1
        .split_once("\n}")
        .expect("M102 start capture helper is bounded")
        .0;
    let stale_container = start_capture
        .find("timeout 10 docker rm -f \"$CAPTURE_CONTAINER\"")
        .expect("M102 removes a stale sidecar");
    let stale_volume = start_capture
        .find("timeout 10 docker volume rm -f \"$CAPTURE_VOLUME\"")
        .expect("M102 removes a stale capture volume");
    let create_volume = start_capture
        .find("docker volume create --label rustbgpd.interop.milestone=M102")
        .expect("M102 creates a labeled capture volume");
    let run_sidecar = start_capture
        .find("docker run -d --name \"$CAPTURE_CONTAINER\"")
        .expect("M102 starts the capture sidecar");
    let ready_running = start_capture
        .find("'{{.State.Running}}'")
        .expect("M102 readiness checks the sidecar state");
    let ready_log = start_capture
        .find("Capturing on")
        .expect("M102 readiness checks tshark output");
    assert!(
        stale_container < stale_volume
            && stale_volume < create_volume
            && create_volume < run_sidecar
            && run_sidecar < ready_running
            && ready_running < ready_log,
        "M102 must clean stale state, create its volume, then start and verify the sidecar"
    );
    let stop_capture = script
        .split_once("stop_capture() {")
        .expect("M102 capture decode helper")
        .1
        .split_once("\n}")
        .expect("M102 capture decode helper is bounded")
        .0;
    let stopped = stop_capture
        .find("stop_capture_container")
        .expect("M102 decode first stops and removes the sidecar");
    let readonly = stop_capture
        .find("dst=/capture,readonly")
        .expect("M102 decode mounts capture read-only");
    let nonempty_capture = stop_capture
        .find("test -s /capture/m102.pcap")
        .expect("M102 decode checks the in-container capture");
    let decode = stop_capture
        .find("tshark -r /capture/m102.pcap")
        .expect("M102 decodes with the sidecar image");
    let nonempty_payloads = stop_capture
        .find("[ -s \"$PAYLOADS\" ]")
        .expect("M102 requires decoded payload rows");
    let remove_volume = stop_capture
        .find("timeout 10 docker volume rm \"$CAPTURE_VOLUME\"")
        .expect("M102 removes the capture volume after decode");
    assert!(
        stopped < readonly
            && readonly < nonempty_capture
            && nonempty_capture < decode
            && decode < nonempty_payloads
            && nonempty_payloads < remove_volume,
        "M102 must stop, decode read-only, validate payloads, then remove its volume"
    );
    let capture_diagnostics = script
        .split_once("dump_m102_capture_diagnostics() {")
        .expect("M102 capture diagnostics helper")
        .1
        .split_once("\n}")
        .expect("M102 capture diagnostics helper is bounded")
        .0;
    let diagnostic_stop = capture_diagnostics
        .find("stop_capture_container")
        .expect("M102 diagnostics stops the capture sidecar");
    let diagnostic_readonly = capture_diagnostics
        .find("dst=/capture,readonly")
        .expect("M102 diagnostics mounts the retained capture read-only");
    let packet_summary = capture_diagnostics
        .find("packet summary (first 80 BGP TCP packets)")
        .expect("M102 diagnostics emits a bounded BGP packet summary");
    let conversation_summary = capture_diagnostics
        .find("-z conv,tcp")
        .expect("M102 diagnostics emits a TCP conversation summary");
    let retained = capture_diagnostics
        .find("capture volume retained for idempotent trap cleanup")
        .expect("M102 diagnostics leaves the volume to trap cleanup");
    assert!(
        diagnostic_stop < diagnostic_readonly
            && diagnostic_readonly < packet_summary
            && packet_summary < conversation_summary
            && conversation_summary < retained,
        "M102 failure capture must stop, decode read-only, summarize packets/conversations, then retain the volume for cleanup"
    );
    assert!(
        !capture_diagnostics.contains("raw_oracle")
            && !capture_diagnostics.contains("docker volume rm"),
        "M102 failure diagnostics must neither run the strict receipt oracle nor remove retained capture state"
    );
    let diagnostics = script
        .split_once("dump_m102_diagnostics() {")
        .expect("M102 diagnostic coordinator")
        .1
        .split_once("\n}")
        .expect("M102 diagnostic coordinator is bounded")
        .0;
    let idempotence = diagnostics
        .find("[ \"$DIAGNOSTICS_DUMPED\" -eq 0 ] || return 0")
        .expect("M102 diagnostics are idempotent");
    let control_diagnostics = diagnostics
        .find("dump_m102_control_plane_diagnostics")
        .expect("M102 emits control-plane diagnostics");
    let capture_diagnostics_call = diagnostics
        .find("dump_m102_capture_diagnostics")
        .expect("M102 emits capture diagnostics");
    assert!(
        idempotence < control_diagnostics && control_diagnostics < capture_diagnostics_call,
        "M102 must emit control-plane diagnostics before stopping and decoding its capture"
    );
    let diagnostic_die = script
        .split_once("diagnostic_die() {")
        .expect("M102 diagnostic failure helper")
        .1
        .split_once("\n}")
        .expect("M102 diagnostic failure helper is bounded")
        .0;
    assert!(
        diagnostic_die
            .find("dump_m102_diagnostics")
            .expect("M102 failure invokes diagnostics")
            < diagnostic_die
                .find("die \"$message\"")
                .expect("M102 failure exits after diagnostics"),
        "M102 failures must emit diagnostics before exiting"
    );
    let control_plane_diagnostics = script
        .split_once("dump_m102_control_plane_diagnostics() {")
        .expect("M102 control-plane diagnostic helper")
        .1
        .split_once("\n}")
        .expect("M102 control-plane diagnostic helper is bounded")
        .0;
    let open_neighbor = control_plane_diagnostics
        .find("timeout 5 docker exec \"$OPENBGPD\" bgpctl show neighbor 10.102.1.1")
        .expect("M102 captures the exact OpenBGPD neighbor view");
    let frr_process = control_plane_diagnostics
        .find("timeout 5 docker top \"$FRR\"")
        .expect("M102 captures the bounded FRR process view");
    let frr_neighbor = control_plane_diagnostics
        .find("timeout 5 docker exec \"$FRR\" vtysh")
        .expect("M102 captures the bounded FRR neighbor view");
    assert!(
        open_neighbor < frr_process && frr_process < frr_neighbor,
        "M102 control-plane diagnostics must include the exact OpenBGPD neighbor plus FRR process and neighbor views"
    );
    assert!(
        !script.contains("wait_absent()"),
        "M102 must not use a negated generic absence poll"
    );
    for helper in [
        "wait_for() {",
        "wait_open_absent() {",
        "wait_frr_absent() {",
    ] {
        let body = script
            .split_once(helper)
            .expect("M102 wait helper")
            .1
            .split_once("\n}")
            .expect("M102 wait helper is bounded")
            .0;
        assert!(
            body.contains("diagnostic_die"),
            "M102 wait helper `{helper}` must diagnose before failing"
        );
    }
    let open_absent = script
        .split_once("open_absent() {")
        .expect("M102 OpenBGPD absence inspector")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD absence inspector is bounded")
        .0;
    let open_json = open_absent
        .find("output=$(timeout 5 docker exec")
        .expect("M102 requires a successful bounded OpenBGPD inspection");
    let full_rib = open_absent
        .find("bgpctl -j show rib)")
        .expect("M102 inspects the full OpenBGPD RIB for absence");
    let open_valid = open_absent
        .find("open_absence_json_valid \"$output\" \"$prefix\"")
        .expect("M102 delegates to the pure full-RIB absence validator");
    assert!(
        open_json <= full_rib && full_rib < open_valid,
        "M102 OpenBGPD withdrawal inspection must successfully fetch the full RIB before pure JSON validation"
    );
    assert!(
        !open_absent.contains("show rib \"$prefix\""),
        "M102 OpenBGPD absence must not query an exact-prefix view"
    );
    let open_absence_validator = script
        .split_once("open_absence_json_valid() {")
        .expect("M102 pure OpenBGPD absence validator")
        .1
        .split_once("\n}")
        .expect("M102 pure OpenBGPD absence validator is bounded")
        .0;
    for required in [
        "(type == \"object\")",
        "((keys | length) == 0)",
        "(keys == [\"rib\"])",
        "((.rib | type) == \"array\")",
        "all(.rib[];",
        "(.prefix | type) == \"string\"",
        "all(.rib[]; .prefix != $p)",
    ] {
        assert!(
            open_absence_validator.contains(required),
            "M102 pure OpenBGPD absence validator lost `{required}`"
        );
    }
    assert!(
        !open_absence_validator.contains("docker")
            && !open_absence_validator.contains("timeout")
            && !open_absence_validator.contains("bgpctl"),
        "M102 OpenBGPD absence JSON validator must remain pure"
    );
    for validator in [
        "open_session_json_valid() {",
        "open_prefix_json_valid() {",
        "open_route_json_valid() {",
        "open_absence_json_valid() {",
        "open_communities_json_valid() {",
        "rs_presence_json_valid() {",
        "rs_absence_json_valid() {",
        "frr_communities_json_valid() {",
        "frr_absence_json_valid() {",
        "neighbor_state_json_valid() {",
        "frr_inventory_json_valid() {",
    ] {
        let body = script
            .split_once(validator)
            .expect("M102 pure JSON validator")
            .1
            .split_once("\n}")
            .expect("M102 pure JSON validator is bounded")
            .0;
        for forbidden in ["docker", "bgpctl", "vtysh", "rs_ctl", "grpcurl", "timeout"] {
            assert!(
                !body.contains(forbidden),
                "M102 JSON validator `{validator}` regained live seam `{forbidden}`"
            );
        }
    }
    let open_session_validator = script
        .split_once("open_session_json_valid() {")
        .expect("M102 OpenBGPD session JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD session JSON validator is bounded")
        .0;
    for required in [
        "(type == \"object\")",
        "and ((.neighbors | type) == \"array\")",
        "and ((.neighbors | length) == 1)",
        "and (.neighbors[0].remote_addr == \"10.102.1.1\")",
        "and (.neighbors[0].state == \"Established\")",
    ] {
        assert!(
            open_session_validator.contains(required),
            "M102 exact OpenBGPD session validator lost `{required}`"
        );
    }
    let open_route_validator = script
        .split_once("open_route_json_valid() {")
        .expect("M102 OpenBGPD route JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD route JSON validator is bounded")
        .0;
    for required in [
        "and ((.rib | length) == 1)",
        "and (.rib[0].prefix == $p)",
        "and (.rib[0].valid == true)",
        "and (.rib[0].aspath == $path)",
        "and (.rib[0].exit_nexthop == $nh)",
    ] {
        assert!(
            open_route_validator.contains(required),
            "M102 exact OpenBGPD route validator lost `{required}`"
        );
    }
    assert!(
        !open_route_validator.contains(".nexthop"),
        "M102 OpenBGPD route validator must use exit_nexthop, not a nonexistent nexthop field"
    );
    let rs_presence_validator = script
        .split_once("rs_presence_json_valid() {")
        .expect("M102 rust presence JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 rust presence JSON validator is bounded")
        .0;
    let rs_absence_validator = script
        .split_once("rs_absence_json_valid() {")
        .expect("M102 rust absence JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 rust absence JSON validator is bounded")
        .0;
    for validator in [rs_presence_validator, rs_absence_validator] {
        for required in [
            "(type == \"array\")",
            "all(.[]; valid_row)",
            "(.prefix | type) == \"string\"",
        ] {
            assert!(
                validator.contains(required),
                "M102 rust route JSON validator lost `{required}`"
            );
        }
    }
    let open_communities_validator = script
        .split_once("open_communities_json_valid() {")
        .expect("M102 OpenBGPD community JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD community JSON validator is bounded")
        .0;
    for required in [
        "((.rib[0].communities | type) == \"array\")",
        "all(.rib[0].communities[]; type == \"string\")",
        "((.rib[0].communities | sort | unique) == ($standard | tokens))",
        "((.rib[0].large_communities | type) == \"array\")",
        "((.rib[0].large_communities | sort | unique) == ($large | tokens))",
    ] {
        assert!(
            open_communities_validator.contains(required),
            "M102 OpenBGPD exact-community validator lost `{required}`"
        );
    }
    let frr_communities_validator = script
        .split_once("frr_communities_json_valid() {")
        .expect("M102 FRR community JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 FRR community JSON validator is bounded")
        .0;
    for required in [
        ".paths[0].community.string",
        ".paths[0].largeCommunity.string",
        "== ($standard | tokens)",
        "== ($large | tokens)",
    ] {
        assert!(
            frr_communities_validator.contains(required),
            "M102 FRR documented-community validator lost `{required}`"
        );
    }
    let neighbor_state_validator = script
        .split_once("neighbor_state_json_valid() {")
        .expect("M102 NeighborState JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 NeighborState JSON validator is bounded")
        .0;
    for required in [
        "(type == \"object\")",
        "((.config | type) == \"object\")",
        "(.config.remoteAsn == $expected_asn)",
        "(.roleNegotiated == true)",
    ] {
        assert!(
            neighbor_state_validator.contains(required),
            "M102 NeighborState validator lost `{required}`"
        );
    }
    assert!(
        !neighbor_state_validator.contains("and (.remoteAsn == $expected_asn)"),
        "M102 NeighborState validator must not accept the old top-level remoteAsn seam"
    );
    let frr_inventory_validator = script
        .split_once("frr_inventory_json_valid() {")
        .expect("M102 FRR inventory JSON validator")
        .1
        .split_once("\n}")
        .expect("M102 FRR inventory JSON validator is bounded")
        .0;
    for required in [
        "(length == 2)",
        "and all(.[];",
        "((.routes | type) == \"object\")",
        "([.[].routes | keys[]] | sort)",
        "($expected | sort)",
    ] {
        assert!(
            frr_inventory_validator.contains(required),
            "M102 FRR inventory validator lost `{required}`"
        );
    }
    assert!(
        !frr_inventory_validator.contains("..") && !frr_inventory_validator.contains("sort -u"),
        "M102 FRR inventory validator must use only the two top-level routes-key multisets"
    );
    let open_community_wrapper = script
        .split_once("open_communities_exact() {")
        .expect("M102 OpenBGPD community live wrapper")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD community live wrapper is bounded")
        .0;
    assert!(
        open_community_wrapper.contains("OPEN_COMMUNITY_OBS=$(timeout 5 docker exec \"$OPENBGPD\"")
            && open_community_wrapper.contains("bgpctl -j show rib detail \"$prefix\"")
            && open_community_wrapper.contains(") || return 1")
            && open_community_wrapper.contains("open_communities_json_valid"),
        "M102 OpenBGPD community wrapper must command-gate the exact detail view before route-level validation"
    );
    assert!(
        !open_community_wrapper.contains("bgpctl -j show rib \"$prefix\""),
        "M102 OpenBGPD community wrapper must not use the non-detail route view"
    );
    let frr_community_wrapper = script
        .split_once("frr_communities_exact() {")
        .expect("M102 FRR community live wrapper")
        .1
        .split_once("\n}")
        .expect("M102 FRR community live wrapper is bounded")
        .0;
    assert!(
        frr_community_wrapper.contains("FRR_COMMUNITY_OBS=$(frr_json")
            && frr_community_wrapper.contains(") || return 1")
            && frr_community_wrapper.contains("frr_communities_json_valid"),
        "M102 FRR community wrapper must retain a command-gated observation for projection and validation"
    );
    for (wrapper, validator) in [
        ("open_established() {", "open_session_json_valid"),
        ("open_has() {", "open_prefix_json_valid"),
        ("open_route_matches() {", "open_route_json_valid"),
        ("open_absent() {", "open_absence_json_valid"),
        ("frr_absent() {", "frr_absence_json_valid"),
        ("rs_received() {", "rs_presence_json_valid"),
        ("rs_received_absent() {", "rs_absence_json_valid"),
        ("rs_loc() {", "rs_presence_json_valid"),
        ("rs_loc_absent() {", "rs_absence_json_valid"),
        ("rs_advertised() {", "rs_presence_json_valid"),
        ("rs_advertised_absent() {", "rs_absence_json_valid"),
    ] {
        let body = script
            .split_once(wrapper)
            .expect("M102 live JSON wrapper")
            .1
            .split_once("\n}")
            .expect("M102 live JSON wrapper is bounded")
            .0;
        assert!(
            body.contains("output=$(")
                && body.contains(") || return 1")
                && body.contains(validator),
            "M102 live wrapper `{wrapper}` must fail closed before pure `{validator}` validation"
        );
    }
    let frr_absent = script
        .split_once("frr_absent() {")
        .expect("M102 FRR absence inspector")
        .1
        .split_once("\n}")
        .expect("M102 FRR absence inspector is bounded")
        .0;
    let frr_json = frr_absent
        .find("output=$(timeout 5 docker exec \"$FRR\" vtysh")
        .expect("M102 requires a successful bounded FRR inspection");
    let frr_valid = frr_absent
        .find("frr_absence_json_valid \"$output\"")
        .expect("M102 delegates to the pure FRR absence validator");
    assert!(
        frr_json < frr_valid,
        "M102 FRR withdrawal inspection must succeed before pure JSON validation"
    );
    let frr_absence_validator = script
        .split_once("frr_absence_json_valid() {")
        .expect("M102 pure FRR absence validator")
        .1
        .split_once("\n}")
        .expect("M102 pure FRR absence validator is bounded")
        .0;
    for required in [
        "(type == \"object\")",
        "((keys | length) == 0)",
        "(keys == [\"paths\"])",
        "((.paths | type) == \"array\")",
        "((.paths | length) == 0)",
    ] {
        assert!(
            frr_absence_validator.contains(required),
            "M102 pure FRR absence validator lost `{required}`"
        );
    }
    assert!(
        !frr_absence_validator.contains(".paths // []"),
        "M102 FRR absence validator must not normalize error objects into empty paths"
    );
    for (helper, inspector) in [
        ("wait_open_absent() {", "open_absent \"$prefix\" && return"),
        (
            "wait_frr_absent() {",
            "frr_absent \"$family\" \"$prefix\" && return",
        ),
    ] {
        let body = script
            .split_once(helper)
            .expect("M102 positive absence wait helper")
            .1
            .split_once("\n}")
            .expect("M102 positive absence wait helper is bounded")
            .0;
        assert!(
            body.contains(inspector) && !body.contains("do !"),
            "M102 absence wait helper `{helper}` must only accept a successful positive inspector"
        );
    }
    let open_start = script
        .split_once("start_openbgpd() {")
        .expect("M102 OpenBGPD startup helper")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD startup helper is bounded")
        .0;
    let run_dir = open_start
        .find("mkdir -p /run/bgpd")
        .expect("M102 creates OpenBGPD runtime state");
    let stale_cleanup = open_start
        .find("rm -f /tmp/m102-bgpd.pid /tmp/m102-bgpd.log")
        .expect("M102 removes stale milestone-local OpenBGPD state");
    let log_file = open_start
        .find(": > /tmp/m102-bgpd.log")
        .expect("M102 truncates its local OpenBGPD log");
    let daemon = open_start
        .find("bgpd -d -f /etc/bgpd.conf")
        .expect("M102 starts the pinned OpenBGPD daemon");
    let pid_file = daemon
        + open_start[daemon..]
            .find("> /tmp/m102-bgpd.pid")
            .expect("M102 records the OpenBGPD PID");
    let alive = open_start
        .find("kill -0 \"$pid\"")
        .expect("M102 fail-fast checks the OpenBGPD PID");
    let control_ready = open_start
        .find("bgpctl show")
        .expect("M102 waits for the OpenBGPD control socket");
    assert!(
        run_dir < stale_cleanup
            && stale_cleanup < log_file
            && log_file < daemon
            && daemon < pid_file
            && pid_file < alive
            && alive < control_ready,
        "M102 must create runtime state, start/log/record OpenBGPD, then require process and control-socket readiness"
    );
    let cleanup_clause = &open_start[stale_cleanup..log_file];
    for required in [
        "/tmp/m102-bgpd.pid",
        "/tmp/m102-bgpd.log",
        "/run/bgpd/bgpd.sock.*",
        "/run/bgpd/bgpd.rsock",
        "/run/bgpd/bgpd.rsock.*",
    ] {
        assert!(
            cleanup_clause.contains(required),
            "M102 stale OpenBGPD cleanup lost `{required}`"
        );
    }
    assert!(
        !cleanup_clause.contains("/etc/bgpd.conf"),
        "M102 stale control-state cleanup must not touch the mounted config"
    );
    let peer_start = script
        .split_once("start_peers() {")
        .expect("M102 peer startup helper")
        .1
        .split_once("\n}")
        .expect("M102 peer startup helper is bounded")
        .0;
    assert_eq!(
        peer_start.matches("diagnostic_die").count(),
        2,
        "M102 must diagnose both FRR and OpenBGPD startup failures"
    );
    let rust_start = script
        .split_once("start_m102_rustbgpd() {")
        .expect("M102 isolated rustbgpd startup helper")
        .1
        .split_once("\n}")
        .expect("M102 isolated rustbgpd startup helper is bounded")
        .0;
    let subshell = rust_start
        .find("if ! (")
        .expect("M102 runs shared rustbgpd startup in a subshell");
    let cleared_traps = rust_start
        .find("trap - EXIT INT TERM HUP")
        .expect("M102 clears inherited cleanup traps in the startup subshell");
    let shared_start = rust_start
        .find("start_rustbgpd")
        .expect("M102 invokes the shared rustbgpd startup helper");
    let parent_diagnostics = rust_start
        .find("diagnostic_die \"rustbgpd gRPC startup failed\"")
        .expect("M102 diagnoses shared startup failure in the parent");
    let parent_ledger = rust_start
        .find("pass=$((pass + 1))")
        .expect("M102 restores the shared readiness ledger in the parent");
    assert!(
        subshell < cleared_traps
            && cleared_traps < shared_start
            && shared_start < parent_diagnostics
            && parent_diagnostics < parent_ledger,
        "M102 must isolate shared startup exits, diagnose failure in the parent, then restore the successful shared ledger increment"
    );
    assert_eq!(
        rust_start.matches("pass=$((pass + 1))").count(),
        1,
        "M102 must restore exactly one shared gRPC readiness ledger increment"
    );
    assert!(
        !rust_start.contains("ok \"") && !rust_start.contains("fail \""),
        "M102 parent ledger restoration must not duplicate shared PASS output or claims"
    );
    let session_assertion = script
        .split_once("assert_sessions() {")
        .expect("M102 combined session assertion")
        .1
        .split_once("\n}")
        .expect("M102 combined session assertion is bounded")
        .0;
    let open_state = session_assertion
        .find("os=$(rs_state \"$OPENBGPD_ADDR\" 2>/dev/null) || os_rc=$?")
        .expect("M102 command-gates the OpenBGPD NeighborState observation");
    let frr_state = session_assertion
        .find("fs=$(rs_state \"$FRR_ADDR\" 2>/dev/null) || fs_rc=$?")
        .expect("M102 command-gates the FRR NeighborState observation");
    let open_validation = session_assertion
        .find("neighbor_state_json_valid \"$os\" 4200000201")
        .expect("M102 validates the nested OpenBGPD remote ASN and Role");
    let frr_validation = session_assertion
        .find("neighbor_state_json_valid \"$fs\" 4200000202")
        .expect("M102 validates the nested FRR remote ASN and Role");
    let session_projection = session_assertion
        .find("emit_session_mismatch \"$os\" \"$fs\"")
        .expect("M102 emits a compact session mismatch projection");
    let session_fail = session_assertion
        .find("fail \"rustbgpd ASN/Role state mismatch\"")
        .expect("M102 retains the existing session ledger failure");
    assert!(
        open_state < frr_state
            && frr_state < open_validation
            && open_validation < frr_validation
            && frr_validation < session_projection
            && session_projection < session_fail,
        "M102 combined session row must command-gate, validate nested state, then project only on failure"
    );
    let community_match = script
        .split_once("community_row_matches() {")
        .expect("M102 combined community matcher")
        .1
        .split_once("\n}")
        .expect("M102 combined community matcher is bounded")
        .0;
    assert!(
        community_match.contains("frr_communities_exact")
            && community_match.contains("open_communities_exact")
            && community_match.matches("|| rc=1").count() == 2,
        "M102 combined community matcher must retain both observations even when one fails"
    );
    let reverse_assertion = script
        .split_once("assert_reverse() {")
        .expect("M102 reverse assertion helper")
        .1
        .split_once("\n}")
        .expect("M102 reverse assertion helper is bounded")
        .0;
    assert!(
        reverse_assertion.contains("if community_row_matches; then")
            && reverse_assertion.contains("emit_community_mismatch")
            && reverse_assertion.contains("fail \"bidirectional communities missing\""),
        "M102 combined community row must emit its compact projection only in the failure branch"
    );
    let inventory_match = script
        .split_once("inventory_row_matches() {")
        .expect("M102 combined inventory matcher")
        .1
        .split_once("\n}")
        .expect("M102 combined inventory matcher is bounded")
        .0;
    assert_eq!(
        inventory_match.matches("rs_inventory_exact").count(),
        8,
        "M102 combined inventory matcher must evaluate all eight rust received/advertised surfaces"
    );
    for required in [
        "rs_loc_inventory_exact",
        "open_inventory_exact",
        "frr_inventory_exact",
    ] {
        assert!(
            inventory_match.contains(required),
            "M102 combined inventory matcher lost `{required}`"
        );
    }
    for helper in [
        "rs_inventory_exact() {",
        "rs_loc_inventory_exact() {",
        "open_inventory_exact() {",
        "frr_inventory_exact() {",
    ] {
        let body = script
            .split_once(helper)
            .expect("M102 exact inventory helper")
            .1
            .split_once("\n}")
            .expect("M102 exact inventory helper is bounded")
            .0;
        assert!(
            body.contains("emit_inventory_mismatch")
                && !body.contains("ok \"")
                && !body.contains("fail \"")
                && !body.contains("dump_m102"),
            "M102 inventory helper `{helper}` must emit only its failing compact surface projection"
        );
    }
    let frr_inventory_wrapper = script
        .split_once("frr_inventory_exact() {")
        .expect("M102 FRR inventory live wrapper")
        .1
        .split_once("\n}")
        .expect("M102 FRR inventory live wrapper is bounded")
        .0;
    assert!(
        frr_inventory_wrapper.contains("output=$(timeout 10 docker exec \"$FRR\" vtysh")
            && frr_inventory_wrapper.contains("frr_inventory_json_valid \"$output\" \"$@\""),
        "M102 FRR inventory wrapper must command-gate two sequential documents before pure validation"
    );
    for helper in [
        "emit_session_mismatch() {",
        "emit_community_mismatch() {",
        "emit_inventory_mismatch() {",
    ] {
        let body = script
            .split_once(helper)
            .expect("M102 compact row projection")
            .1
            .split_once("\n}")
            .expect("M102 compact row projection is bounded")
            .0;
        assert!(
            !body.contains("ok \"")
                && !body.contains("fail \"")
                && !body.contains("dump_m102")
                && !body.contains("docker"),
            "M102 projection `{helper}` must add no ledger row or heavyweight diagnostics"
        );
    }
    let withdrawals = script
        .split_once("assert_withdrawals() {")
        .expect("M102 withdrawal assertion helper")
        .1
        .split_once("\n}")
        .expect("M102 withdrawal assertion helper is bounded")
        .0;
    assert_eq!(
        withdrawals.matches("wait_frr_absent").count(),
        2,
        "M102 must use the fail-closed FRR absence inspector for both families"
    );
    assert_eq!(
        withdrawals.matches("wait_open_absent").count(),
        2,
        "M102 must use the fail-closed OpenBGPD absence inspector for both families"
    );
    assert!(
        !withdrawals.contains("wait_absent")
            && !withdrawals.contains("! frr_has")
            && !withdrawals.contains("! rs_"),
        "M102 withdrawal proof must not regain a negated command-as-absence seam"
    );
    assert_eq!(
        withdrawals.matches("rs_received_absent").count(),
        4,
        "M102 must prove all four rust Adj-RIB-In withdrawals with positive absence validators"
    );
    assert_eq!(
        withdrawals.matches("rs_loc_absent").count(),
        4,
        "M102 must prove all four rust Loc-RIB withdrawals with positive absence validators"
    );
    let json_self_test = script
        .split_once("self_test_openbgpd_json() {")
        .expect("M102 OpenBGPD JSON offline self-test")
        .1
        .split_once("\n}")
        .expect("M102 OpenBGPD JSON offline self-test is bounded")
        .0;
    for required in [
        "session exact neighbor",
        "session wrong peer",
        "session wrong state",
        "neighbor state nested ASN ignores top-level decoy",
        "neighbor state missing config",
        "neighbor state wrong nested ASN despite top-level decoy",
        "neighbor state false role",
        "neighbor state malformed config",
        "neighbor state malformed JSON",
        "route exact tuple",
        "route nonexistent nexthop field",
        "absence missing rib",
        "absence empty rib",
        "absence unrelated route",
        "absence error-only object",
        "absence failed status object",
        "absence empty rib plus error",
        "absence arbitrary extra key",
        "absence target present",
        "absence malformed JSON",
        "rust presence exact row",
        "rust presence malformed row",
        "rust absence empty array",
        "rust absence target present",
        "FRR absence exact empty object",
        "FRR absence exact empty paths",
        "FRR absence error-only object",
        "FRR absence failed status object",
        "FRR absence empty paths plus error",
        "FRR absence arbitrary extra key",
        "FRR absence nonempty paths",
        "FRR absence malformed JSON",
        "FRR inventory exact dual documents ignores nested decoys",
        "FRR inventory one document",
        "FRR inventory three documents",
        "FRR inventory missing routes",
        "FRR inventory non-object routes",
        "FRR inventory wrong keys",
        "FRR inventory missing key",
        "FRR inventory extra key",
        "FRR inventory non-object root",
        "FRR inventory malformed JSON",
        "Open communities normalized exact sets",
        "Open communities standard extra",
        "Open communities large extra",
        "FRR communities normalized exact sets",
        "FRR communities standard extra",
        "FRR communities large extra",
    ] {
        assert!(
            json_self_test.contains(required),
            "M102 OpenBGPD JSON self-test lost fixture `{required}`"
        );
    }
    for forbidden in [
        "docker",
        "containerlab",
        "grpcurl",
        "rs_ctl",
        "mktemp",
        "/tmp/",
    ] {
        assert!(
            !json_self_test.contains(forbidden),
            "M102 OpenBGPD JSON self-test regained external seam `{forbidden}`"
        );
    }
    assert_eq!(
        script.matches("--self-test-openbgpd-json").count(),
        1,
        "M102 must expose exactly one synthetic OpenBGPD JSON self-test mode"
    );
    let main = script
        .split_once("main() {")
        .expect("M102 main")
        .1
        .split_once("\n}\ncase ")
        .expect("M102 main has a bounded source section")
        .0;
    let shared_preflight = main
        .find("preflight;")
        .expect("M102 main invokes shared preflight");
    let identity_preflight = main
        .find("preflight_identities_and_configs;")
        .expect("M102 main invokes identity/config preflight");
    let capture = main.find("start_capture").expect("M102 capture");
    let rust_start = main
        .find("start_m102_rustbgpd")
        .expect("M102 isolated rust start");
    let peers = main.find("start_peers").expect("M102 peer start");
    assert!(
        shared_preflight < identity_preflight
            && identity_preflight < capture
            && capture < rust_start
            && rust_start < peers
            && capture < peers,
        "M102 shared and identity/config preflights must precede capture and daemon starts"
    );
    for mode in [
        "--self-test-oracle",
        "--self-test-oracle-conflict",
        "--self-test-oracle-gap",
        "--self-test-oracle-capability",
        "--self-test-oracle-update",
        "--self-test-oracle-trailing",
        "--self-test-oracle-marker",
        "--self-test-openbgpd-json",
    ] {
        let output = Command::new("bash")
            .arg(&script_path)
            .arg(mode)
            .output()
            .expect("run M102 oracle self-test");
        assert!(
            output.status.success(),
            "M102 oracle self-test {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn m103_gobgp48_differential_is_exact_and_keeps_m92_immutable() {
    fn sha256(path: &Path) -> String {
        let output = Command::new("sha256sum")
            .arg(path)
            .output()
            .unwrap_or_else(|error| panic!("sha256sum {}: {error}", path.display()));
        assert!(
            output.status.success(),
            "sha256sum failed for {}",
            path.display()
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }

    assert_eq!(
        sha256(&interop_path("m92-gobgp-v47-rs-differential.clab.yml")),
        "ee7e41f42bdc034c625f33217c400fddae9ce7986d85d4ad8f397b6d28a878f0",
        "M103 must not edit the M92 topology"
    );
    assert_eq!(
        sha256(&interop_path(
            "scripts/test-m92-gobgp-v47-rs-differential.sh"
        )),
        "60980d52db0d12df0d821b25cf7b724636d056ef708c59cee4041dcb51bf7ea1",
        "M103 must not edit the M92 driver"
    );

    let topology = topology("m103-gobgp-v48-rs-differential.clab.yml");
    let nodes = topology["topology"]["nodes"].as_mapping().unwrap();
    for name in ["gobgp-rs", "source1", "source2"] {
        assert_eq!(
            nodes[name]["image"].as_str(),
            Some("gobgp:v4.8.0-m103"),
            "M103 {name} image drifted"
        );
    }
    assert_eq!(nodes["target"]["image"].as_str(), Some("bird:2-bookworm"));
    assert_eq!(nodes["rustbgpd"]["image"].as_str(), Some("rustbgpd:dev"));
    for (name, config) in [
        (
            "rustbgpd",
            "./configs/rustbgpd-m92-rs.toml:/config/rustbgpd.toml:ro",
        ),
        (
            "gobgp-rs",
            "./configs/gobgp-m92-rs.toml:/config/gobgp.toml:ro",
        ),
        (
            "source1",
            "./configs/gobgp-m92-source1.toml:/config/gobgp.toml:ro",
        ),
        (
            "source2",
            "./configs/gobgp-m92-source2.toml:/config/gobgp.toml:ro",
        ),
        (
            "target",
            "./configs/bird-m92-target.conf:/config/bird.conf:ro",
        ),
    ] {
        let binds: Vec<_> = nodes[name]["binds"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect();
        assert!(
            binds.contains(&config),
            "M103 {name} lost read-only M92 input {config}"
        );
    }

    let script_path = interop_path("scripts/test-m103-gobgp-v48-rs-differential.sh");
    let script = fs::read_to_string(&script_path).expect("read M103 driver");
    let m92_script = fs::read_to_string(interop_path(
        "scripts/test-m92-gobgp-v47-rs-differential.sh",
    ))
    .expect("read immutable M92 driver");
    assert_eq!(
        script.matches("ok \"").count(),
        m92_script.matches("ok \"").count(),
        "M103 must preserve every M92 positive ledger row"
    );
    assert_eq!(
        script.matches("    poll ").count(),
        m92_script.matches("    poll ").count(),
        "M103 must preserve every M92 polled ledger row"
    );
    for required in [
        "gobgp version 4.8.0",
        "gobgpd version 4.8.0",
        "docker exec \"$container\" gobgp --version",
        "docker exec \"$container\" gobgpd --version",
        "BIRD version 2.0.12",
        "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
        "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97",
        "ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141",
        "957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a",
        "gobgp-v47-m92-adjout.json",
        "gobgp-v48-m103-adjout.json",
        "gobgp-v48-m103.expected.ndjson",
        "--source m103-gobgp-v4.8-incumbent --generation 103",
        "expected_pass=56",
        "expected_pass=17",
        "M103_COMPLETENESS_NEGATIVE",
        "M103_ARTIFACT_DIR",
        "artifact-manifest.sha256",
        "identities.json",
        "ledger.json",
        "transcript.log",
        "negative-candidate-verifier.txt",
        "negative-incumbent-verifier.txt",
        "--self-test-artifact-export",
    ] {
        assert!(script.contains(required), "M103 driver lost `{required}`");
    }
    assert_eq!(
        script.matches("del(.age)").count(),
        1,
        "M103 raw comparison must delete only the one recursive age field"
    );
    for forbidden in [
        "del(.uptime)",
        "del(.timestamp)",
        "del(.best)",
        "del(.stale)",
    ] {
        assert!(
            !script.contains(forbidden),
            "M103 regained forbidden normalization `{forbidden}`"
        );
    }
    let main = script
        .split_once("main() {")
        .unwrap()
        .1
        .split_once("\n}\n\nif [ \"$SELF_TEST_MODE\"")
        .unwrap()
        .0;
    let identity = main.find("preflight_m103_identity_and_inputs").unwrap();
    let baseline = main.find("run_round baseline").unwrap();
    assert!(
        identity < baseline,
        "M103 identity/input preflight must precede daemon rounds"
    );
    let round = script
        .split_once("run_round() {")
        .unwrap()
        .1
        .split_once("run_completeness_negative() {")
        .unwrap()
        .0;
    assert!(
        round
            .find("check_eor_order \"$WORK/${round}-incumbent.pdml\"")
            .unwrap()
            < round.find("if run_diff \"$round\"").unwrap(),
        "M103 must authorize the incumbent EoR before capture/diff"
    );
    let negative = script
        .split_once("run_completeness_negative() {")
        .unwrap()
        .1
        .split_once("main() {")
        .unwrap()
        .0;
    assert!(!negative.contains("run_diff"));
    assert!(!negative.contains("capture_incumbent"));
    assert!(negative.contains("v4_eor=0 v6_eor=0"));
    let summary = main.find("print_summary").unwrap();
    let ledger = main.find("write_ledger").unwrap();
    let export = main.find("export_success_artifacts").unwrap();
    assert!(
        summary < ledger && ledger < export,
        "M103 must finish its exact ledger, record it, then export before returning to EXIT cleanup"
    );
    assert!(!main.contains("rm -rf \"$WORK\""));
    let cleanup = script
        .split_once("cleanup_m103() {")
        .unwrap()
        .1
        .split_once("write_self_test_identity() {")
        .unwrap()
        .0;
    assert!(cleanup.contains("rm -rf \"$WORK\""));
    assert!(cleanup.contains("[ -z \"$ARTIFACT_STAGE\" ] || rm -rf \"$ARTIFACT_STAGE\""));

    let output = Command::new("bash")
        .arg(&script_path)
        .arg("--self-test-artifact-export")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run M103 artifact export self-test");
    assert!(
        output.status.success(),
        "M103 artifact export self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn m104_current_arouteserver_differential_is_exact_and_keeps_m90_immutable() {
    fn sha256(path: &Path) -> String {
        let output = Command::new("sha256sum")
            .arg(path)
            .output()
            .unwrap_or_else(|error| panic!("sha256sum {}: {error}", path.display()));
        assert!(
            output.status.success(),
            "sha256sum failed for {}",
            path.display()
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }

    for (relative, expected) in [
        (
            "m90-differential.clab.yml",
            "61e0bae1b47b82f71e6865daec01351f9326a506c898dc9e1fa6f9bdd1ec058a",
        ),
        (
            "scripts/test-m90-differential.sh",
            "c2a878d51ea09422ffcabd4641de5a0a880d9c43f482016a46423dc49740c230",
        ),
        (
            "m90-differential/README.md",
            "c965a7f95e916fb40fc9cae35f776782af3e01694c6caab17ea436aebe66279c",
        ),
        (
            "m90-differential/prove-context-ingestion.sh",
            "638d50ee11b4ff4b55ae888d69ecde0225d4d69a6b6f6b9d7a1250b54e2b2270",
        ),
        (
            "m90-differential/general.yml",
            "c47fed81ba4c7b3671d8c3f3a26955037e5cef67e7c7b7650dc9bf3ceaeb214d",
        ),
        (
            "m90-differential/clients.yml",
            "08ceca5f9bafb13139538096a94595d075b7a7dae9342deb26d7f5adfc337e1e",
        ),
        (
            "m90-differential/context.yml",
            "f979b7b72f9385bf5e10258b967c22da0ec1bd5b214ad9f42197fcd104471eda",
        ),
        (
            "m90-differential/context-sectioned.yml",
            "f61c2a6d88aae1bb11c9ea95a4dd73abfb3c2f2577df69316f10d49e436b8790",
        ),
        (
            "m90-differential/announcements.json",
            "e55a7faea278b962139a17fe5daf81026761b6eef57cb8bb7807005c12f8164a",
        ),
        (
            "m90-differential/bogons.yml",
            "26e7c313a41fd7a854f73c656a77415fd9c2bb9057b625a7592bd436ee26dfe5",
        ),
        (
            "m90-differential/arouteserver.yml",
            "c3b85f1af54c437ae50b0d4e1502b3a6e95cb2c4b12c255ac1c90cfc9eec5b19",
        ),
        (
            "m90-differential/bgpq4-stub.sh",
            "cebb06da5c9adff5184652bca877ab7956f137c5d9cd425b7c449ad0e950bb84",
        ),
        (
            "m90-differential/policy-explain.toml",
            "811634752dee124d80be1b0836c61f1a5f20af32b3c94c7fb48536573fd98030",
        ),
        (
            "configs/gobgp-m90-member1.toml",
            "b7d897cb35aa657d469dbc7c35d9bdff2b346dc7169bcf820a331a06866f33e2",
        ),
        (
            "configs/gobgp-m90-member2.toml",
            "1cfea7eee37eb764a5ab8f090d7f3f25d252ed18d8ff0b9b7f9dbf5e2defd329",
        ),
        (
            "configs/gobgp-m90-member3.toml",
            "27e3955e743203ba352f177eb5e0899d061520bd14e7c0412a02007073c74f72",
        ),
    ] {
        assert_eq!(
            sha256(&interop_path(relative)),
            expected,
            "M104 must not edit immutable M90 asset {relative}"
        );
    }

    let topology = topology("m104-arouteserver-current-rs-differential.clab.yml");
    assert_eq!(
        topology["name"],
        "m104-arouteserver-current-rs-differential"
    );
    let nodes = topology["topology"]["nodes"].as_mapping().unwrap();
    assert_eq!(nodes["rustbgpd"]["image"], "rustbgpd:dev");
    assert_eq!(nodes["bird"]["image"], "bird:v2.19.2-m104");
    for member in ["member1", "member2", "member3"] {
        assert_eq!(
            nodes[member]["image"], "gobgp:v4.8.0-m104",
            "M104 {member} image drifted"
        );
        let binds: Vec<_> = nodes[member]["binds"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect();
        assert_eq!(binds.len(), 1, "M104 {member} must have one read-only bind");
        assert!(binds[0].ends_with(":/config/gobgp.toml:ro"));
        assert!(binds[0].contains(&format!("gobgp-m90-{member}.toml")));
    }

    let script_path = interop_path("scripts/test-m104-arouteserver-current-rs-differential.sh");
    let script = fs::read_to_string(&script_path).expect("read M104 driver");
    for required in [
        "M104_BASE_SHA=\"350eb813b7a2a71ccfae2084d033253e96419cea\"",
        "ARS_MANIFEST_DIGEST=\"sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66\"",
        "ARS_IMAGE=\"pierky/arouteserver@$ARS_MANIFEST_DIGEST\"",
        "sha256:4a08ef740f00a119f5897b0f834da9ff172a282c93d47fdff636c3b50c9aec93",
        "ARS_VERSION=\"1.23.2\"",
        "ARS_TAG_COMMIT=\"85f24252564822556bd93cb9eba1f73d1e8268ea\"",
        "BIRD_IMAGE=\"bird:v2.19.2-m104\"",
        "BIRD_VERSION=\"BIRD version 2.19.2\"",
        "BIRD_TARGET_VERSION=\"2.16\"",
        "GOBGP_IMAGE=\"gobgp:v4.8.0-m104\"",
        "5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b",
        "710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97",
        "--target-version \"$BIRD_TARGET_VERSION\"",
        "bird -p -c /etc/bird/bird.conf",
        "reject-irrdb-prefix-filtered",
        "require_equal \"$pass\" 74",
        "require_equal \"$fail\" 0",
        "local exit_code=$? topo_file",
        "return \"$exit_code\"",
        "--self-test-offline-contract",
        "--preflight-arouteserver-image",
        "docker buildx imagetools inspect --raw \"$ARS_IMAGE\"",
        "ARouteServer registry config digest",
        "ARouteServer containerd descriptor digest",
        "ARouteServer containerd descriptor digest is missing",
    ] {
        assert!(script.contains(required), "M104 driver lost `{required}`");
    }
    for forbidden in ["M90_ARS_IMAGE", "M90_BIRD_TARGET_VERSION", "2.0.11"] {
        assert!(
            !script.contains(forbidden),
            "M104 driver regained historical override `{forbidden}`"
        );
    }
    for destructive_fixture in [
        "classic",
        "containerd",
        "swapped",
        "wrong_manifest",
        "ambiguous",
        "unrelated",
        "missing_descriptor",
        "missing_repo",
        "wrong_id",
        "wrong_config",
        "missing_config",
    ] {
        assert!(
            script.contains(destructive_fixture),
            "M104 identity self-test lost {destructive_fixture} representation"
        );
    }

    let main = script
        .split_once("main() {")
        .unwrap()
        .1
        .split_once("\n}\n\ncase \"$SELF_TEST_MODE\"")
        .unwrap()
        .0;
    let inputs = main.find("preflight_m104_inputs").unwrap();
    let identities = main.find("preflight_runtime_identities").unwrap();
    let bird_render = main.find("render_bird_config").unwrap();
    let rust_render = main.find("render_rustbgpd_config").unwrap();
    let start = main.find("start_daemons").unwrap();
    assert!(
        inputs < identities
            && identities < bird_render
            && bird_render < rust_render
            && rust_render < start,
        "M104 must freeze inputs and identities before render and daemon start"
    );

    let workflow =
        fs::read_to_string(repo_path(".github/workflows/interop.yml")).expect("read workflow");
    let m104 = workflow
        .split_once("\n  m104:\n")
        .and_then(|(_, rest)| rest.split_once("\n  check:\n").map(|(job, _)| job))
        .expect("interop workflow has bounded M104 job");
    let context = m104
        .find("Run immutable M90 context proof (exact 23/23)")
        .unwrap();
    let protobuf = m104
        .find("uses: ./.github/actions/install-protobuf")
        .unwrap();
    let live = m104
        .find("Run M104 (single-attempt current-daemon differential)")
        .unwrap();
    assert!(
        protobuf < context && context < live,
        "M104 must install protoc before the context proof and run that proof before live"
    );
    for required in [
        "needs: [grpcurl_archive, bird2192_archive, prime_dev_image]",
        "PROOF PASS: 23 checks",
        "M104_EXPECTED_GIT_SHA: ${{ github.sha }}",
        "max_attempts: \"1\"",
        "--preflight-arouteserver-image",
    ] {
        assert!(m104.contains(required), "M104 workflow lost `{required}`");
    }
    let pull = m104.find("docker pull \"$AROUTESERVER_IMAGE\"").unwrap();
    let identity = m104.find("--preflight-arouteserver-image").unwrap();
    let package = m104.find("importlib.metadata.version").unwrap();
    assert!(
        pull < identity && identity < package,
        "M104 must validate local manifest/config identity after pull and before package use"
    );
    assert!(
        !m104.contains("docker image inspect -f '{{.Id}}' \"$AROUTESERVER_IMAGE\""),
        "M104 workflow must not conflate a store-dependent local ID with the config digest"
    );

    let output = Command::new("bash")
        .arg(&script_path)
        .arg("--self-test-offline-contract")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run M104 offline contract self-test");
    assert!(
        output.status.success(),
        "M104 offline self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
