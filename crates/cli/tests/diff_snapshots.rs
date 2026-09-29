//! Offline wire-view comparison keeps the existing 0/1/2 contract.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::{Command, Output};
use std::time::UNIX_EPOCH;

use rustbgpd_bmp::codec::{encode_initiation, encode_peer_up, encode_route_monitoring};
use rustbgpd_bmp::{BmpPeerInfo, BmpPeerType, BmpVersion};
use rustbgpd_wire::{Capability, OpenMessage};
use serde_json::{Value, json};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", "unix:///absent-ribdiff-daemon.sock", "--no-color"])
        .args(args)
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .output()
        .unwrap()
}

fn update(attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(
        &u16::try_from(23 + attrs.len() + nlri.len())
            .unwrap()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&[2, 0, 0]);
    bytes.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(attrs);
    bytes.extend_from_slice(nlri);
    bytes
}

/// One reflected IPv4 route, with actual BMP framing and negotiated OPENs.
fn capture(originator: u8, cluster: u8, eor: bool) -> Vec<u8> {
    let info = BmpPeerInfo {
        peer_addr: "192.0.2.30".parse().unwrap(),
        peer_asn: 65001,
        peer_bgp_id: Ipv4Addr::new(192, 0, 2, 30),
        peer_type: BmpPeerType::Global,
        is_ipv6: false,
        is_post_policy: true,
        is_rib_out: true,
        is_as4: true,
        timestamp: UNIX_EPOCH,
    };
    let mut open = Vec::new();
    OpenMessage {
        version: 4,
        my_as: 65001,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
        capabilities: vec![Capability::FourOctetAs { asn: 65001 }],
    }
    .encode(&mut open)
    .unwrap();
    let mut bytes = encode_initiation("rr", "reflection fixture", BmpVersion::V3).to_vec();
    bytes.extend(encode_peer_up(
        &info,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        179,
        40000,
        &open,
        &open,
        BmpVersion::V3,
    ));
    let attrs = [
        64, 1, 1, 0, // ORIGIN IGP
        64, 2, 0, // empty iBGP AS_PATH
        64, 3, 4, 192, 0, 2, 20, // unchanged NEXT_HOP
        64, 5, 4, 0, 0, 0, 100, // LOCAL_PREF
        128, 9, 4, 192, 0, 2, originator, // ORIGINATOR_ID
        128, 10, 4, 192, 0, 2, cluster, // CLUSTER_LIST
    ];
    bytes.extend(encode_route_monitoring(
        &info,
        &update(&attrs, &[24, 198, 51, 100]),
        None,
        BmpVersion::V3,
    ));
    if eor {
        bytes.extend(encode_route_monitoring(
            &info,
            &update(&[], &[]),
            None,
            BmpVersion::V3,
        ));
    }
    bytes
}

fn from_bmp(dir: &Path, name: &str, bytes: &[u8]) -> Output {
    let file = dir.join(format!("{name}.bmp"));
    std::fs::write(&file, bytes).unwrap();
    run(&[
        "diff",
        "snapshot",
        "from-bmp",
        file.to_str().unwrap(),
        "--generation",
        "7",
    ])
}

fn compare(dir: &Path, incumbent: &[u8], rustbgpd: &[u8], extra: &[&str]) -> Output {
    let left = dir.join("incumbent.ndjson");
    let right = dir.join("rustbgpd.ndjson");
    std::fs::write(&left, incumbent).unwrap();
    std::fs::write(&right, rustbgpd).unwrap();
    let mut args = vec![
        "diff",
        "snapshots",
        left.to_str().unwrap(),
        right.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

fn baseline(dir: &Path) -> Vec<u8> {
    let output = from_bmp(dir, "baseline", &capture(20, 1, true));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    output.stdout
}

#[test]
fn bmp_reflection_round_trip_compares_all_wire_attributes_without_a_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let incumbent = baseline(dir.path());
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ribsnap/rr-from-bmp.expected.ndjson");
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&golden, &incumbent).unwrap();
    }
    assert_eq!(incumbent, std::fs::read(golden).unwrap());
    let identical = from_bmp(dir.path(), "identical", &capture(20, 1, true));
    assert!(identical.status.success());
    let output = compare(dir.path(), &incumbent, &identical.stdout, &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "rbgp-ribdiff/1");
    assert_eq!(report["verdict"], "in_sync");
    assert!(report.get("live_source_notes").is_none());
    assert_eq!(report["summaries"][0]["matched"], 1);

    for (originator, cluster, type_code) in [(21, 1, 9), (20, 2, 10)] {
        let changed = from_bmp(dir.path(), "changed", &capture(originator, cluster, true));
        assert!(changed.status.success());
        let output = compare(dir.path(), &incumbent, &changed.stdout, &["--json"]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["verdict"], "divergent");
        let delta = &report["entries"][0]["attribute_deltas"][0];
        assert_eq!(delta["attribute"], "unknown");
        for side in ["incumbent", "rustbgpd"] {
            let attr = delta[side]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["type_code"] == type_code)
                .unwrap();
            assert_eq!(attr["flags"], 128);
            let last = if type_code == 9 {
                if side == "incumbent" { 20 } else { originator }
            } else if side == "incumbent" {
                1
            } else {
                cluster
            };
            assert_eq!(attr["value"], json!([192, 0, 2, last]));
        }
        let human = compare(dir.path(), &incumbent, &changed.stdout, &[]);
        let human = String::from_utf8(human.stdout).unwrap();
        assert!(human.starts_with("diff snapshots:"), "{human}");
        assert!(human.contains("unknown:"), "{human}");
        assert!(!human.contains("live-source"), "{human}");
    }

    let escaped_source = String::from_utf8(incumbent.clone())
        .unwrap()
        .replace("from-bmp/1", "\\u001b[2J\\nsource");
    let human = compare(dir.path(), &incumbent, escaped_source.as_bytes(), &[]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(!human.contains('\u{1b}'), "{human:?}");
    assert!(human.contains("\\u{1b}[2J\\nsource"), "{human:?}");

    let next_hop = String::from_utf8(incumbent.clone())
        .unwrap()
        .replace("\"next_hop\":\"192.0.2.20\"", "\"next_hop\":\"192.0.2.21\"");
    let output = compare(dir.path(), &incumbent, next_hop.as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["entries"][0]["attribute_deltas"][0]["attribute"],
        "next_hop"
    );
}

#[test]
fn snapshots_compare_the_peer_union_and_refuse_asn_conflicts() {
    let dir = tempfile::tempdir().unwrap();
    let left = String::from_utf8(baseline(dir.path())).unwrap();
    let right = left.replace("192.0.2.30", "192.0.2.31");
    let output = compare(dir.path(), left.as_bytes(), right.as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["entries"].as_array().unwrap().len(), 2);
    assert_eq!(report["entries"][0]["class"], "incumbent_only");
    assert_eq!(report["entries"][1]["class"], "rustbgpd_only");
    let right = left.replace("\"peer_asn\":65001", "\"peer_asn\":65002");
    let output = compare(dir.path(), left.as_bytes(), right.as_bytes(), &[]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("ASN mismatch"));
}

#[test]
fn snapshots_refuse_incomplete_malformed_overlimit_or_mixed_generation_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let good = String::from_utf8(baseline(dir.path())).unwrap();
    let missing_trailer = good.lines().take(2).collect::<Vec<_>>().join("\n") + "\n";
    for bad in [
        missing_trailer,
        good.replace("\"origin\":0", "\"origin\":9"),
    ] {
        for (left, right) in [(&bad, &good), (&good, &bad)] {
            let output = compare(dir.path(), left.as_bytes(), right.as_bytes(), &["--json"]);
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(output.stdout.is_empty());
        }
    }
    for flags in [["--max-routes", "0"], ["--max-input-bytes", "1"]] {
        let output = compare(dir.path(), good.as_bytes(), good.as_bytes(), &flags);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    // Exercise the second input's limits after the first input was accepted.
    let rows: Vec<_> = good.lines().collect();
    let two_routes = format!(
        "{}\n{}\n{}\n{{\"record\":\"trailer\",\"routes\":2}}\n",
        rows[0], rows[1], rows[1]
    );
    let padded = good.replace("from-bmp/1", &"x".repeat(good.len()));
    for (bad, flag, bound) in [
        (two_routes, "--max-routes", "1".to_string()),
        (padded, "--max-input-bytes", good.len().to_string()),
    ] {
        let output = compare(dir.path(), good.as_bytes(), bad.as_bytes(), &[flag, &bound]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rustbgpd.ndjson"));
    }
    let changed = good.replace("\"generation\":7", "\"generation\":8");
    let output = compare(dir.path(), good.as_bytes(), changed.as_bytes(), &["--json"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verdict"], "incomparable");
    assert!(
        report["incomparable_reasons"][0]
            .as_str()
            .unwrap()
            .contains("generation mismatch")
    );
    let output = from_bmp(dir.path(), "missing-eor", &capture(20, 1, false));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("End-of-RIB"));
}
