//! Exact EVPN selectors and explain output through the real binary and RPC.
use rustbgpd_api::proto;
use std::process::Command;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

fn run(addr: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr])
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rbgp")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_selectors_forward_typed_keys_without_fallback() {
    let server = test_support::spawn_mock_server(None).await;
    let esi = "00:11:22:33:44:55:66:77:88:99";
    for (selector, fields, expected) in [
        (
            "mac-ip",
            vec!["--mac", "AA:BB:CC:DD:EE:FF"],
            serde_json::json!({"mac_ip": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "", "ethernet_tag": 0}}),
        ),
        (
            "mac-ip",
            vec![
                "--mac",
                "aa:bb:cc:dd:ee:ff",
                "--ip",
                "192.0.2.9",
                "--ethernet-tag",
                "7",
            ],
            serde_json::json!({"mac_ip": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.9", "ethernet_tag": 7}}),
        ),
        (
            "mac-ip",
            vec!["--mac", "aa:bb:cc:dd:ee:ff", "--ip", "2001:db8::9"],
            serde_json::json!({"mac_ip": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "2001:db8::9", "ethernet_tag": 0}}),
        ),
        (
            "imet",
            vec!["--originator-ip", "2001:db8::3", "--ethernet-tag", "42"],
            serde_json::json!({"imet": {"originator_ip": "2001:db8::3", "ethernet_tag": 42}}),
        ),
        (
            "es",
            vec!["--esi", esi, "--originator-ip", "192.0.2.4"],
            serde_json::json!({"es": {"esi": esi, "originator_ip": "192.0.2.4"}}),
        ),
        (
            "ip-prefix",
            vec!["--prefix", "198.51.100.0/24", "--ethernet-tag", "99"],
            serde_json::json!({"ip_prefix": {"prefix": "198.51.100.0/24", "ethernet_tag": 99}}),
        ),
        (
            "ip-prefix",
            vec!["--prefix", "2001:db8::/48"],
            serde_json::json!({"ip_prefix": {"prefix": "2001:db8::/48", "ethernet_tag": 0}}),
        ),
        (
            "ead-per-es",
            vec!["--esi", esi],
            serde_json::json!({"ead_per_es": {"esi": esi, "ethernet_tag": u32::MAX}}),
        ),
        (
            "ead-per-evi",
            vec!["--esi", esi, "--ethernet-tag", "4294967294"],
            serde_json::json!({"ead_per_evi": {"esi": esi, "ethernet_tag": u32::MAX - 1}}),
        ),
    ] {
        let mut args = vec![
            "--json",
            "evpn",
            "explain",
            selector,
            "--rd",
            "65000:100",
            "--received-from",
            "fe80::2%eth0",
            "--advertised-to",
            "fe80::3%eth1",
        ];
        args.extend(fields);
        let result = run(&server.addr, &args);
        assert!(result.status.success(), "{args:?}: {result:?}");
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let mut expected = expected;
        expected["rd"] = serde_json::json!("65000:100");
        assert_eq!(value["key"], expected);
        assert_eq!(value["received_from"], "fe80::2%eth0");
        let request = server.state.last_explain_evpn.lock().await.clone().unwrap();
        assert_eq!(request.received_from, "fe80::2");
        assert_eq!(request.advertised_to, "fe80::3");
        assert_eq!(request.key.unwrap().rd, "65000:100");
    }
    *server.state.explain_evpn_error.lock().await =
        Some((tonic::Code::Unimplemented, "older daemon".into()));
    let result = run(
        &server.addr,
        &[
            "evpn",
            "explain",
            "imet",
            "--rd",
            "65000:100",
            "--originator-ip",
            "192.0.2.3",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("not supported by this daemon")
    );
    assert!(server.state.last_list_evpn.lock().await.is_none());
    assert!(server.state.last_explain_best_path.lock().await.is_none());
    assert!(server.state.last_explain_advertised.lock().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_distinguishes_fresh_selection_retained_source_and_committed_export() {
    let server = test_support::spawn_mock_server(None).await;
    let route = |peer: &str| proto::EvpnRouteEntry {
        route_type: 2,
        rd: "65000:100".into(),
        mac: "aa:bb:cc:dd:ee:ff".into(),
        peer_address: peer.into(),
        next_hop: peer.into(),
        prefix_sid: Some(Box::new(test_support::mock_prefix_sid())),
        ..Default::default()
    };
    *server.state.explain_evpn_response.lock().await = proto::ExplainEvpnRouteResponse {
        best: Some(route("192.0.2.1")),
        selection_best: Some(route("192.0.2.2")),
        compared: Some(route("192.0.2.1")),
        candidate_count: 2,
        selection_deferred: true,
        selection_reason: Some(proto::ExplainReason {
            code: "mac_mobility_sequence".into(),
            message: "higher MAC mobility sequence".into(),
        }),
        export: Some(proto::ExplainEvpnExport {
            peer_address: "192.0.2.9".into(),
            decision: proto::ExplainDecision::Deny as i32,
            reasons: vec![proto::ExplainReason {
                code: "policy_denied".into(),
                message: "term block".into(),
            }],
            gates: vec![proto::ExportGateStep {
                gate: "export_policy".into(),
                code: "policy_denied".into(),
                verdict: proto::ExportGateVerdict::Stop as i32,
                detail: "term block".into(),
            }],
            modifications: Some(proto::ExplainModifications {
                set_med: Some(0),
                ..Default::default()
            }),
            advertised: Some(route("192.0.2.1")),
            outbound_dirty: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let args = [
        "evpn",
        "explain",
        "mac-ip",
        "--rd",
        "65000:100",
        "--mac",
        "aa:bb:cc:dd:ee:ff",
        "--received-from",
        "192.0.2.7",
        "--advertised-to",
        "192.0.2.9",
    ];
    let result = run(&server.addr, &args);
    assert!(result.status.success(), "{result:?}");
    let text = String::from_utf8(result.stdout).unwrap();
    for expected in [
        "sid-value=fc00:0:1:: behavior=65535",
        "structure=40/24/16/0/16/64",
        "Installed best:",
        "Fresh selection:",
        "Retained accepted source 192.0.2.7: absent",
        "Import rejection history is not retained",
        "Selection reason [mac_mobility_sequence]: higher MAC mobility sequence",
        "Selection deferred: true",
        "Current export to 192.0.2.9: deny (dry run; no state changed)",
        "[stop] export_policy [policy_denied]: term block",
        "Current staged export: absent",
        "Committed local Adj-RIB-Out:",
        "outbound dirty: true",
        "does not prove remote receipt or installation",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    let result = run(&server.addr, &[vec!["--json"], args.to_vec()].concat());
    assert!(result.status.success(), "{result:?}");
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    for row in [
        &value["best"],
        &value["selection_best"],
        &value["compared"],
        &value["export"]["advertised"],
    ] {
        assert_eq!(row["prefix_sid"]["raw_value"], "deadbeef");
        assert_eq!(
            row["prefix_sid"]["services"][0]["sids"][0]["endpoint_behavior"],
            65535
        );
    }
    assert_eq!(value["best"]["peer"], "192.0.2.1");
    assert_eq!(value["selection_best"]["peer"], "192.0.2.2");
    assert!(value["received"].is_null());
    assert_eq!(value["export"]["decision"], "deny");
    assert!(value["export"]["staged"].is_null());
    assert_eq!(value["export"]["advertised"]["peer"], "192.0.2.1");
    assert_eq!(value["export"]["outbound_dirty"], true);
    assert_eq!(value["export"]["modifications"]["set_med"], 0);
    assert_eq!(value["export"]["gates"][0]["code"], "policy_denied");
    {
        let mut response = server.state.explain_evpn_response.lock().await;
        response.received = Some(route("192.0.2.7"));
        let export = response.export.as_mut().unwrap();
        export.staged = Some(route("192.0.2.1"));
        export.decision = proto::ExplainDecision::Advertise as i32;
        export.reasons.clear();
        export.gates.clear();
        export.already_advertised = true;
        export.outbound_dirty = false;
    }
    let result = run(&server.addr, &args);
    assert!(result.status.success(), "{result:?}");
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Retained accepted source 192.0.2.7:\n"));
    assert!(!text.contains("Import rejection history is not retained"));
    assert!(text.contains("Current staged export:\n"));
    assert!(text.contains("Already advertised: true; outbound dirty: false"));
}

#[test]
fn malformed_keys_fail_before_connecting() {
    let esi = "00:11:22:33:44:55:66:77:88:99";
    for fields in [
        vec!["mac-ip", "--mac", "zz:bb:cc:dd:ee:ff"],
        vec!["mac-ip", "--mac", "+a:bb:cc:dd:ee:ff"],
        vec!["mac-ip", "--mac", "aa:bb:cc:dd:ee:ff", "--ip", ""],
        vec!["imet", "--originator-ip", "192.0.2.1/32"],
        vec!["es", "--esi", "00:11", "--originator-ip", "192.0.2.1"],
        vec!["ip-prefix", "--prefix", "192.0.2.1/24"],
        vec!["ip-prefix", "--prefix", "2001:db8::1/64"],
        vec!["ip-prefix", "--prefix", "192.0.2.1"],
        vec!["ip-prefix", "--prefix", "::/129"],
        vec!["ead-per-es", "--esi", esi, "--ethernet-tag", "1"],
        vec!["ead-per-evi", "--esi", esi, "--ethernet-tag", "4294967295"],
        vec!["ead-per-evi", "--esi", esi],
        vec![
            "imet",
            "--originator-ip",
            "192.0.2.1",
            "--received-from",
            "peer",
        ],
        vec![
            "imet",
            "--originator-ip",
            "192.0.2.1",
            "--advertised-to",
            "2001:db8::1%eth0",
        ],
    ] {
        let mut args = vec!["evpn", "explain"];
        args.extend(fields);
        args.extend(["--rd", "65000:100"]);
        let result = run("http://127.0.0.1:1", &args);
        assert_eq!(result.status.code(), Some(2), "{args:?}: {result:?}");
        assert!(
            !String::from_utf8(result.stderr)
                .unwrap()
                .contains("cannot reach rustbgpd")
        );
    }
    for rd in ["", "not-rd", "65000:4294967296"] {
        let result = run(
            "http://127.0.0.1:1",
            &[
                "evpn",
                "explain",
                "imet",
                "--rd",
                rd,
                "--originator-ip",
                "192.0.2.3",
            ],
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
    }
    let result = run(
        "http://127.0.0.1:1",
        &[
            "evpn",
            "--peer",
            "192.0.2.1",
            "explain",
            "imet",
            "--rd",
            "65000:100",
            "--originator-ip",
            "192.0.2.3",
        ],
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        !String::from_utf8(result.stderr)
            .unwrap()
            .contains("cannot reach rustbgpd")
    );
}
