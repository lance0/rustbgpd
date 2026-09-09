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
async fn flowspec_json_preserves_raw_extended_communities() {
    let server = test_support::spawn_mock_server(None).await;
    let raw = vec![0x800c_fde8_3f80_0000, u64::MAX, 0x800c_fde8_3f80_0000, 0];
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        routes: vec![
            proto::FlowSpecRouteEntry {
                components: vec![proto::FlowSpecComponent {
                    r#type: 1,
                    prefix: "192.0.2.0/24".into(),
                    ..Default::default()
                }],
                actions: vec![proto::FlowSpecAction {
                    action: Some(proto::flow_spec_action::Action::TrafficRate(
                        proto::FlowSpecTrafficRate { rate: 0.0 },
                    )),
                }],
                peer_address: "192.0.2.1".into(),
                afi_safi: proto::AddressFamily::Ipv4Flowspec.into(),
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
    assert_eq!(
        rows[0]["components"],
        serde_json::json!(["dest=192.0.2.0/24"])
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
        "  match [dest=192.0.2.0/24] action [drop] from 192.0.2.1 (ipv4_flowspec)\n"
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
