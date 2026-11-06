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
    let raw_ipv6 = vec![vec![0xff; 20], vec![0; 20], vec![0xff; 20]];
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
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::RedirectIp(
                            proto::FlowSpecRedirectIp {
                                address: "192.0.2.10".into(),
                                copy: false,
                            },
                        )),
                    },
                    proto::FlowSpecAction {
                        action: Some(proto::flow_spec_action::Action::RedirectIp(
                            proto::FlowSpecRedirectIp {
                                address: "2001:db8::10".into(),
                                copy: true,
                            },
                        )),
                    },
                ],
                peer_address: "192.0.2.1".into(),
                afi_safi: proto::AddressFamily::Ipv6Flowspec.into(),
                as_path: vec![65001],
                communities: vec![(65000 << 16) | 100],
                extended_communities: raw.clone(),
                injection_owner: String::new(),
                lease_generation: None,
                lease_remaining_ms: None,
                ipv6_extended_communities: raw_ipv6.clone(),
                admission_revision: None,
                rd: String::new(),
                route_targets: vec![],
            },
            proto::FlowSpecRouteEntry::default(),
        ],
        advertised_view: false,
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
            "actions": ["drop", "rate=1024", "sample", "terminal", "mark-dscp=46", "redirect=65000:200", "none", "redirect-to-ip=192.0.2.10", "copy-to-ip=2001:db8::10"],
            "peer_address": "192.0.2.1",
            "afi_safi": "ipv6_flowspec",
            "as_path": [65001],
            "communities": ["65000:100"],
            "extended_communities": raw,
            "ipv6_extended_communities": raw_ipv6,
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
        "  match [dest=2001:db8::/32, src=::1234:5678:9a00:0/104, port==443, unknown=opaque] action [drop, rate=1024, sample, terminal, mark-dscp=46, redirect=65000:200, none, redirect-to-ip=192.0.2.10, copy-to-ip=2001:db8::10] from 192.0.2.1 (ipv6_flowspec)\n"
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
async fn vpn_flowspec_rows_preserve_scope_in_json_and_text() {
    let server = test_support::spawn_mock_server(None).await;
    let rd = "0x00020000fde80028";
    let route_targets = ["0.65000:777", "192.0.2.1:9"];
    let raw = vec![0x0202_0000_fde8_0309, 0x0102_c000_0201_0009];
    for (family, label) in [
        (
            proto::AddressFamily::L3vpnIpv4Flowspec,
            "l3vpn_ipv4_flowspec",
        ),
        (
            proto::AddressFamily::L3vpnIpv6Flowspec,
            "l3vpn_ipv6_flowspec",
        ),
    ] {
        *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
            routes: vec![proto::FlowSpecRouteEntry {
                afi_safi: family as i32,
                peer_address: "0.0.0.0".into(),
                rd: rd.into(),
                route_targets: route_targets.iter().map(ToString::to_string).collect(),
                extended_communities: raw.clone(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let run = |json: bool| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
            command.args(["--addr", &server.addr]);
            if json {
                command.arg("--json");
            }
            command
                .args(["flowspec", "--family", label])
                .env("NO_COLOR", "1")
                .output()
                .expect("run rbgp")
        };
        let output = run(true);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!([{
                "components": [], "component_details": [], "actions": [],
                "peer_address": "0.0.0.0", "afi_safi": label,
                "as_path": [], "communities": [], "extended_communities": raw,
                "rd": rd, "route_targets": route_targets,
            }])
        );
        let output = run(false);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "  match [] action [] from 0.0.0.0 ({label}) rd {rd} rt [0.65000:777, 192.0.2.1:9]\n"
            )
        );
        assert_eq!(
            *server.state.last_list_flowspec.lock().await,
            Some(proto::ListFlowSpecRequest {
                afi_safi: family as i32,
                ..Default::default()
            })
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_mutations_preserve_family_scope_and_global_defaults() {
    let server = test_support::spawn_mock_server(None).await;
    for (label, family, prefix, rd) in [
        (
            "ipv4_flowspec",
            proto::AddressFamily::Ipv4Flowspec,
            "192.0.2.0/24",
            "",
        ),
        (
            "ipv6_flowspec",
            proto::AddressFamily::Ipv6Flowspec,
            "2001:db8::/48",
            "",
        ),
        (
            "l3vpn_ipv4_flowspec",
            proto::AddressFamily::L3vpnIpv4Flowspec,
            "192.0.2.0/24",
            "44407:40",
        ),
        (
            "l3vpn-ipv6-flowspec",
            proto::AddressFamily::L3vpnIpv6Flowspec,
            "2001:db8::/48",
            "44407:40",
        ),
    ] {
        let component = format!("dest={prefix}");
        let mut args = vec![
            "flowspec", "add", "--family", label, "--match", &component, "--action", "drop",
        ];
        let targets = if rd.is_empty() {
            vec![]
        } else {
            args.extend([
                "--rd",
                rd,
                "--route-target",
                "44407:777",
                "--route-target",
                "0.65000:9",
            ]);
            vec!["44407:777".to_string(), "0.65000:9".to_string()]
        };
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_rbgp"))
                .args(["--addr", &server.addr])
                .args(args)
                .env("NO_COLOR", "1")
                .output()
                .expect("run rbgp")
        };
        let output = run(&args);
        assert!(output.status.success(), "{label}: {output:?}");
        let components = vec![proto::FlowSpecComponent {
            r#type: 1,
            prefix: prefix.into(),
            ..Default::default()
        }];
        assert_eq!(
            *server.state.last_add_flowspec.lock().await,
            Some(proto::AddFlowSpecRequest {
                afi_safi: family as i32,
                rd: rd.into(),
                route_targets: targets,
                components: components.clone(),
                actions: vec![proto::FlowSpecAction {
                    action: Some(proto::flow_spec_action::Action::TrafficRate(
                        proto::FlowSpecTrafficRate { rate: 0.0 },
                    )),
                }],
                ..Default::default()
            })
        );
        let mut args = vec![
            "flowspec",
            "delete",
            "--family",
            label,
            "--match",
            &component,
            "--allow-missing",
            "--owner",
            "controller",
        ];
        if !rd.is_empty() {
            args.extend(["--rd", rd]);
        }
        let output = run(&args);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            *server.state.last_delete_flowspec.lock().await,
            Some(proto::DeleteFlowSpecRequest {
                afi_safi: family as i32,
                components,
                rd: rd.into(),
                allow_missing: true,
                owner: "controller".into(),
                override_owner: false,
            })
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_add_rejects_vpn_scope_on_non_vpn_families_before_rpc() {
    let server = test_support::spawn_mock_server(None).await;
    for family in ["ipv4_flowspec", "ipv6-flowspec", "ipv4_unicast"] {
        for scope in [
            vec!["--rd", "44407:40"],
            vec!["--route-target", "44407:777"],
            vec!["--rd", "44407:40", "--route-target", "44407:777"],
        ] {
            let mut args = vec!["flowspec", "add", "--match", "port==80", "--action", "drop"];
            args.extend(["--family", family]);
            args.extend(scope);
            let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
                .args(["--addr", &server.addr])
                .args(&args)
                .env("NO_COLOR", "1")
                .output()
                .expect("run rbgp");
            assert!(
                server.state.last_add_flowspec.lock().await.is_none(),
                "invalid scope reached AddFlowSpec: {args:?}"
            );
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("require l3vpn_ipv4_flowspec")
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_delete_rejects_vpn_scope_on_non_vpn_families_before_rpc() {
    let server = test_support::spawn_mock_server(None).await;
    for family in ["ipv4_flowspec", "ipv6-flowspec", "ipv4_unicast"] {
        let mut args = vec![
            "flowspec", "delete", "--match", "port==80", "--rd", "44407:40",
        ];
        args.extend(["--family", family]);
        let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", &server.addr])
            .args(&args)
            .env("NO_COLOR", "1")
            .output()
            .expect("run rbgp");
        assert!(
            server.state.last_delete_flowspec.lock().await.is_none(),
            "invalid scope reached DeleteFlowSpec: {args:?}"
        );
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("require l3vpn_ipv4_flowspec"));
    }
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
                    injection_owner: String::new(),
                    lease_generation: None,
                    lease_remaining_ms: None,
                    ipv6_extended_communities: vec![],
                    admission_revision: None,
                    rd: String::new(),
                    route_targets: vec![],
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
        advertised_view: false,
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
            advertised_peer_address: String::new(),
        })
    );

    // A link-local peer is sent with its scope, which the daemon requires.
    for (view, peer) in [("received", "fe80::1%eth0"), ("advertised", "fe80::2%eth1")] {
        let output = run(&["--json", "flowspec", view, peer]);
        let request = server
            .state
            .last_list_flowspec
            .lock()
            .await
            .clone()
            .unwrap();
        let sent = if view == "received" {
            request.received_peer_address
        } else {
            request.advertised_peer_address
        };
        assert_eq!(sent, peer, "{output:?}");
    }

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
    assert_eq!(versioned["format_version"], "1.1");
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
        advertised_view: false,
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
            advertised_view: false,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertised_flowspec_rejects_unacknowledged_old_server_view_without_output() {
    let server = test_support::spawn_mock_server(None).await;
    // Older servers ignore the request's new selector, returning selected rows
    // or an empty table. Neither is evidence about committed advertised routes.
    for routes in [vec![proto::FlowSpecRouteEntry::default()], Vec::new()] {
        *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
            routes,
            received_routes: Vec::new(),
            received_view: false,
            advertised_view: false,
        };
        for flags in [
            vec![],
            vec!["--json"],
            vec!["--json", "--json-version", "1"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
                .args(["--addr", &server.addr])
                .args(flags)
                .args(["flowspec", "advertised", "192.0.2.1"])
                .output()
                .expect("run rbgp");
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("advertised FlowSpec view requires a newer daemon")
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_add_reports_injection_outcome() {
    let server = test_support::spawn_mock_server(None).await;
    let add = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
        command.args(["--addr", &server.addr]);
        if json {
            command.arg("--json");
        }
        command
            .args([
                "flowspec",
                "add",
                "-a",
                "ipv4_flowspec",
                "--match",
                "dest=192.0.2.0/24",
                "--action",
                "drop",
            ])
            .env("NO_COLOR", "1")
            .output()
            .expect("run rbgp")
    };
    for (outcome, name) in [
        (proto::FlowSpecInjectOutcome::Created, "created"),
        (proto::FlowSpecInjectOutcome::Replaced, "replaced"),
        (proto::FlowSpecInjectOutcome::Unchanged, "unchanged"),
        (proto::FlowSpecInjectOutcome::Unspecified, "unknown"),
    ] {
        *server.state.add_flowspec_response.lock().await = proto::AddFlowSpecResponse {
            outcome: outcome as i32,
        };
        let output = add(true);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({"ok": true, "action": "add_flowspec", "target": "", "outcome": name})
        );
        let output = add(false);
        assert!(output.status.success(), "{output:?}");
        // An older daemon reports no outcome; keep the original line for it.
        let expected = if name == "unknown" {
            "FlowSpec rule added\n".to_string()
        } else {
            format!("FlowSpec rule added ({name})\n")
        };
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flowspec_delete_allow_missing_reports_not_present() {
    let server = test_support::spawn_mock_server(None).await;
    let delete = |json: bool, allow_missing: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
        command.args(["--addr", &server.addr]);
        if json {
            command.arg("--json");
        }
        command.args([
            "flowspec",
            "delete",
            "-a",
            "ipv4_flowspec",
            "--match",
            "dest=192.0.2.0/24",
        ]);
        if allow_missing {
            command.arg("--allow-missing");
        }
        command.env("NO_COLOR", "1").output().expect("run rbgp")
    };
    let expect = |output: std::process::Output, outcome: &str, text: Option<&str>| {
        assert!(output.status.success(), "{output:?}");
        match text {
            Some(text) => assert_eq!(String::from_utf8(output.stdout).unwrap(), text),
            None => assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
                serde_json::json!({"ok": true, "action": "delete_flowspec", "target": "",
                    "outcome": outcome})
            ),
        }
    };

    *server.state.delete_flowspec_matches.lock().await = true;
    for allow_missing in [false, true] {
        expect(delete(true, allow_missing), "deleted", None);
        expect(
            delete(false, allow_missing),
            "deleted",
            Some("FlowSpec rule deleted\n"),
        );
    }

    *server.state.delete_flowspec_matches.lock().await = false;
    expect(delete(true, true), "not_present", None);
    expect(
        delete(false, true),
        "not_present",
        Some("FlowSpec rule not present\n"),
    );
    // Without the flag, a missing rule stays an error.
    let output = delete(false, false);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");

    // An older daemon ignores the flag and reports no outcome. It returns OK
    // only after removing a rule, so that is never reported as not present.
    *server.state.delete_flowspec_legacy.lock().await = true;
    *server.state.delete_flowspec_matches.lock().await = true;
    for allow_missing in [false, true] {
        expect(delete(true, allow_missing), "unknown", None);
        expect(
            delete(false, allow_missing),
            "unknown",
            Some("FlowSpec rule deleted (the daemon did not report an outcome)\n"),
        );
    }
    *server.state.delete_flowspec_matches.lock().await = false;
    let output = delete(false, true);
    assert!(!output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertised_flowspec_projects_rows_and_selector() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.list_flowspec_response.lock().await = proto::ListFlowSpecResponse {
        advertised_view: true,
        routes: vec![proto::FlowSpecRouteEntry {
            peer_address: "0.0.0.0".into(),
            afi_safi: proto::AddressFamily::Ipv6Flowspec as i32,
            communities: vec![(65000 << 16) | 0x002a],
            ..Default::default()
        }],
        ..Default::default()
    };
    let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args([
            "--addr",
            &server.addr,
            "--json",
            "flowspec",
            "advertised",
            "2001:db8::1",
            "-a",
            "ipv6_flowspec",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows[0]["peer_address"], "0.0.0.0");
    assert_eq!(rows[0]["communities"], serde_json::json!(["65000:42"]));
    assert_eq!(
        *server.state.last_list_flowspec.lock().await,
        Some(proto::ListFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv6Flowspec as i32,
            advertised_peer_address: "2001:db8::1".into(),
            ..Default::default()
        })
    );
}
