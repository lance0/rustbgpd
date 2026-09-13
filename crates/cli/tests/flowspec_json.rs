//! FlowSpec JSON projection through the existing mock gRPC server.

use std::process::Command;

use rustbgpd_api::proto;

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_json_preserves_raw_extended_communities_and_component_details() {
    let server = test_support::spawn_mock_server(None).await;
    let raw = vec![0x800c_fde8_3f80_0000, u64::MAX, 0x800c_fde8_3f80_0000, 0];
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        routes: vec![
            proto::FlowSpecRouteEntry {
                components: vec![
                    proto::FlowSpecComponent {
                        r#type: 1,
                        prefix: "2001:db8::/32".into(),
                        offset: 0,
                        ..Default::default()
                    },
                    proto::FlowSpecComponent {
                        r#type: 2,
                        prefix: "::1234:5678:9a00:0/104".into(),
                        offset: 64,
                        ..Default::default()
                    },
                    proto::FlowSpecComponent {
                        r#type: 4,
                        value: "=443".into(),
                        ..Default::default()
                    },
                    proto::FlowSpecComponent {
                        r#type: 99,
                        value: "opaque".into(),
                        offset: 17,
                        ..Default::default()
                    },
                ],
                actions: vec![proto::FlowSpecAction {
                    action: Some(proto::flow_spec_action::Action::TrafficRate(
                        proto::FlowSpecTrafficRate { rate: 0.0 },
                    )),
                }],
                peer_address: "192.0.2.1".into(),
                afi_safi: proto::AddressFamily::Ipv6Flowspec.into(),
                as_path: vec![65001],
                communities: vec![(65000 << 16) | 100],
                extended_communities: raw.clone(),
            },
            proto::FlowSpecRouteEntry::default(),
        ],
    };
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &server.addr])
            .args(args)
            .env("NO_COLOR", "1")
            .output()
            .expect("run rbgp")
    };
    let output = run(&["--json", "flowspec"]);
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert_eq!(rows[0]["extended_communities"], serde_json::json!(raw));
    assert_eq!(rows[1]["extended_communities"], serde_json::json!([]));
    assert_eq!(rows[1]["component_details"], serde_json::json!([]));
    assert_eq!(
        rows[0]["components"],
        serde_json::json!([
            "dest=2001:db8::/32",
            "src=::1234:5678:9a00:0/104",
            "port==443",
            "unknown=opaque",
        ])
    );
    assert_eq!(
        rows[0]["component_details"],
        serde_json::json!([
            {"type": 1, "prefix": "2001:db8::/32", "value": "", "offset": 0},
            {"type": 2, "prefix": "::1234:5678:9a00:0/104", "value": "", "offset": 64},
            {"type": 4, "prefix": "", "value": "=443", "offset": 0},
            {"type": 99, "prefix": "", "value": "opaque", "offset": 17},
        ])
    );
    assert_eq!(rows[0]["actions"], serde_json::json!(["drop"]));
    assert_eq!(rows[0]["peer_address"], "192.0.2.1");
    assert_eq!(rows[0]["as_path"], serde_json::json!([65001]));
    assert_eq!(rows[0]["communities"], serde_json::json!(["65000:100"]));

    server
        .state
        .list_flowspec_response
        .lock()
        .await
        .routes
        .truncate(1);
    let output = run(&["flowspec"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "  match [dest=2001:db8::/32, src=::1234:5678:9a00:0/104, port==443, unknown=opaque] action [drop] from 192.0.2.1 (ipv6_flowspec)\n"
    );
    server
        .state
        .list_flowspec_response
        .lock()
        .await
        .routes
        .clear();
    let output = run(&["--json", "flowspec"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
}
