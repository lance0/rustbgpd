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
async fn flowspec_json_covers_proto_fields() {
    let server = test_support::spawn_mock_server(None).await;
    let raw = vec![0x800c_fde8_3f80_0000, u64::MAX, 0x800c_fde8_3f80_0000, 0];
    // Keep generated route, component, and action fixtures exhaustive: a new
    // API field must prompt a projection decision and an expected-output update.
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        received_routes: Vec::new(),
        received_view: false,
        routes: vec![
            proto::FlowSpecRouteEntry {
                components: vec![
                    proto::FlowSpecComponent {
                        r#type: 1,
                        prefix: "2001:db8::/32".into(),
                        offset: 0,
                        value: String::new(),
                    },
                    proto::FlowSpecComponent {
                        r#type: 2,
                        prefix: "::1234:5678:9a00:0/104".into(),
                        offset: 64,
                        value: String::new(),
                    },
                    proto::FlowSpecComponent {
                        r#type: 4,
                        value: "=443".into(),
                        prefix: String::new(),
                        offset: 0,
                    },
                    proto::FlowSpecComponent {
                        r#type: 99,
                        value: "opaque".into(),
                        offset: 17,
                        prefix: String::new(),
                    },
                ],
                actions: vec![
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::TrafficRate(
                            proto::FlowSpecTrafficRate { rate: 0.0 },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::TrafficRate(
                            proto::FlowSpecTrafficRate { rate: 1024.0 },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::TrafficAction(
                            proto::FlowSpecTrafficAction {
                                sample: true,
                                terminal: false,
                            },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::TrafficAction(
                            proto::FlowSpecTrafficAction {
                                sample: false,
                                terminal: true,
                            },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::TrafficMarking(
                            proto::FlowSpecTrafficMarking { dscp: 46 },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::Redirect(
                            proto::FlowSpecRedirect {
                                route_target: "65000:200".into(),
                            },
                        )),
                    },
                    proto::FlowSpecAction { action: None },
                ],
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
    assert_eq!(
        rows[0],
        serde_json::json!({
            "components": [
                "dest=2001:db8::/32",
                "src=::1234:5678:9a00:0/104",
                "port==443",
                "unknown=opaque",
            ],
            "component_details": [
                {"type": 1, "prefix": "2001:db8::/32", "value": "", "offset": 0},
                {"type": 2, "prefix": "::1234:5678:9a00:0/104", "value": "", "offset": 64},
                {"type": 4, "prefix": "", "value": "=443", "offset": 0},
                {"type": 99, "prefix": "", "value": "opaque", "offset": 17},
            ],
            // Curated action strings are intentional; raw communities preserve
            // values outside the typed action projection, their order and duplicates.
            "actions": ["drop", "rate=1024", "sample", "terminal", "mark-dscp=46", "redirect=65000:200", "none"],
            "peer_address": "192.0.2.1",
            "afi_safi": "ipv6_flowspec",
            "as_path": [65001],
            "communities": ["65000:100"],
            "extended_communities": raw,
        })
    );
    assert_eq!(
        rows[1],
        serde_json::json!({
            "components": [], "component_details": [], "actions": [],
            "peer_address": "", "afi_safi": "unknown", "as_path": [],
            "communities": [], "extended_communities": [],
        })
    );

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
        "  match [dest=2001:db8::/32, src=::1234:5678:9a00:0/104, port==443, unknown=opaque] action [drop, rate=1024, sample, terminal, mark-dscp=46, redirect=65000:200, none] from 192.0.2.1 (ipv6_flowspec)\n"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_flowspec_json_projection_covers_proto_fields_and_pending_results() {
    let server = test_support::spawn_mock_server(None).await;
    let states = [
        (proto::FlowSpecValidationStatus::Disabled, "disabled", false),
        (proto::FlowSpecValidationStatus::Pending, "pending", true),
        (proto::FlowSpecValidationStatus::Local, "local", false),
        (proto::FlowSpecValidationStatus::Feasible, "feasible", true),
        (
            proto::FlowSpecValidationStatus::Infeasible,
            "infeasible",
            true,
        ),
        (
            proto::FlowSpecValidationStatus::Unspecified,
            "unknown",
            false,
        ),
    ];
    // The nested selected-route projection is covered exhaustively above.
    // These literals pin every received wrapper and response field separately.
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        routes: Vec::new(),
        received_routes: states
            .iter()
            .map(|(status, _, pending)| proto::ReceivedFlowSpecRouteEntry {
                route: Some(proto::FlowSpecRouteEntry {
                    components: Vec::new(),
                    actions: Vec::new(),
                    peer_address: "2001:db8::1".into(),
                    afi_safi: proto::AddressFamily::Ipv6Flowspec as i32,
                    as_path: vec![65001],
                    communities: Vec::new(),
                    extended_communities: vec![u64::MAX],
                }),
                path_id: u32::MAX,
                selected: *status == proto::FlowSpecValidationStatus::Feasible,
                validation: *status as i32,
                reason: if *status == proto::FlowSpecValidationStatus::Infeasible {
                    "no_covering_unicast".into()
                } else {
                    String::new()
                },
                pending: *pending,
            })
            .collect(),
        received_view: true,
    };
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &server.addr])
            .args(args)
            .env("NO_COLOR", "1")
            .output()
            .expect("run rbgp")
    };
    let args = [
        "--json",
        "flowspec",
        "received",
        "2001:db8::1",
        "-a",
        "ipv6_flowspec",
    ];
    let output = run(&args);
    assert!(output.status.success(), "{output:?}");
    let expected: Vec<_> = states
        .iter()
        .map(|(status, name, pending)| {
            serde_json::json!({
                "route": {
                    "components": [], "component_details": [], "actions": [],
                    "peer_address": "2001:db8::1", "afi_safi": "ipv6_flowspec",
                    "as_path": [65001], "communities": [], "extended_communities": [u64::MAX],
                },
                "path_id": u32::MAX,
                "selected": *status == proto::FlowSpecValidationStatus::Feasible,
                "validation": name,
                "reason": if *status == proto::FlowSpecValidationStatus::Infeasible {
                    "no_covering_unicast"
                } else { "" },
                "pending": pending,
            })
        })
        .collect();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!(expected)
    );
    assert_eq!(
        *server.state.last_list_flowspec.lock().await,
        Some(proto::ListFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv6Flowspec as i32,
            received_peer_address: "2001:db8::1".into(),
        })
    );

    let output = run(&["flowspec", "received", "2001:db8::1"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("path-id=4294967295 selected=true validation=feasible pending=true reason=-")
    );
    assert!(text.contains("path-id=4294967295 selected=false validation=infeasible pending=true reason=no_covering_unicast"));

    // The transport acknowledgement is consumed before output, not exposed as
    // an extra JSON envelope. The standard version wrapper still owns framing.
    let output = run(&[
        "--json-version",
        "1",
        "--json",
        "flowspec",
        "received",
        "2001:db8::1",
    ]);
    assert!(output.status.success(), "{output:?}");
    let versioned: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(versioned["format_version"], "1.0");
    assert_eq!(versioned["data"], serde_json::json!(expected));

    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        routes: Vec::new(),
        received_routes: vec![proto::ReceivedFlowSpecRouteEntry {
            route: None,
            path_id: 0,
            selected: false,
            validation: 99,
            reason: String::new(),
            pending: false,
        }],
        received_view: true,
    };
    let output = run(&args);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([{"route": null, "path_id": 0, "selected": false,
            "validation": "unknown", "reason": "", "pending": false}])
    );

    server
        .state
        .list_flowspec_response
        .lock()
        .await
        .received_routes
        .clear();
    let output = run(&args);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let output = run(&["flowspec", "received", "2001:db8::1"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "No received FlowSpec routes\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_flowspec_rejects_unacknowledged_old_server_view_without_output() {
    let server = test_support::spawn_mock_server(None).await;
    // Older servers ignore the request's new selector, returning selected rows
    // or an empty table. Neither is evidence about retained received routes.
    for routes in [vec![proto::FlowSpecRouteEntry::default()], Vec::new()] {
        *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
            routes,
            received_routes: Vec::new(),
            received_view: false,
        };
        for flags in [
            vec![],
            vec!["--json"],
            vec!["--json", "--json-version", "1"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
                .args(["--addr", &server.addr])
                .args(flags)
                .args(["flowspec", "received", "192.0.2.1"])
                .output()
                .expect("run rbgp");
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("received FlowSpec diagnostics require a newer daemon")
            );
        }
    }
}
