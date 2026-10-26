//! Retained ineligible candidates through the real CLI binary and RPC.
use std::process::Command;

use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertised_explain_shows_deny_validation_in_text_and_json() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.explain_advertised_response.lock().await =
        Some(proto::ExplainAdvertisedRouteResponse {
            decision: proto::ExplainDecision::Deny as i32,
            peer_address: "192.0.2.1".into(),
            prefix: "203.0.113.0".into(),
            prefix_length: 24,
            deny_validation: vec!["rpki_invalid".into(), "aspa_unknown".into()],
            gates: vec![proto::ExportGateStep {
                gate: "export_policy".into(),
                code: "policy_denied".into(),
                verdict: proto::ExportGateVerdict::Stop as i32,
                detail: "export policy denied this route".into(),
            }],
            ..Default::default()
        });
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
        command.args(["--addr", &server.addr]);
        if json {
            command.arg("--json");
        }
        let output = command
            .args([
                "rib",
                "--prefix",
                "203.0.113.0/24",
                "advertised",
                "192.0.2.1",
                "--explain",
            ])
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        if json {
            let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(
                value["deny_validation"],
                serde_json::json!(["rpki_invalid", "aspa_unknown"])
            );
        } else {
            assert!(stdout.contains("[STOP] export_policy  export policy denied this route (rpki_invalid, aspa_unknown)"), "{stdout}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn srv6_invalid_only_explain_keeps_candidate_details_in_text_and_json() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.explain_best_path_response.lock().await = Some(proto::ExplainBestPathResponse {
        prefix: "203.0.113.0".to_string(),
        prefix_length: 24,
        candidates: vec![proto::BestPathCandidate {
            route: Some(proto::Route {
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                peer_address: "192.0.2.11".to_string(),
                next_hop: "2001:db8::11".to_string(),
                ..Default::default()
            }),
            vs_best_reason: "srv6_sid_invalid".to_string(),
            vs_best_detail: "no semantically valid applicable SRv6 service SID".to_string(),
            vs_best_ordering: "worse".to_string(),
            multipath: "none".to_string(),
            advertised_path_id: 0,
        }],
        ..Default::default()
    });
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
        command.args(["--addr", &server.addr]);
        if json {
            command.arg("--json");
        }
        let output = command
            .args(["rib", "--prefix", "203.0.113.0/24", "--explain"])
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("srv6_sid_invalid"));
        assert!(stdout.contains("192.0.2.11"));
        if json {
            let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert!(value["best_route"].is_null());
            assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
        } else {
            assert!(stdout.contains("No eligible best route"));
            assert!(!stdout.contains("Selected:"));
            assert!(stdout.contains("no semantically valid applicable SRv6 service SID"));
        }
    }
    for retained_invalid in [true, false] {
        {
            let mut response = server.state.explain_best_path_response.lock().await;
            let response = response.as_mut().unwrap();
            response.best_route = Some(proto::Route {
                peer_address: "192.0.2.10".to_string(),
                ..Default::default()
            });
            response.best_reason = "only_path".to_string();
            if !retained_invalid {
                response.candidates.clear();
            }
        }
        let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args([
                "--addr",
                &server.addr,
                "rib",
                "--prefix",
                "203.0.113.0/24",
                "--explain",
            ])
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(if retained_invalid {
            "Selected:   only eligible path for this prefix"
        } else {
            "Selected:   only path for this prefix"
        }));
    }
    assert!(server.state.last_explain_best_path.lock().await.is_some());
}
