//! Peer EVPN command output and exit-code contracts over the existing mock server.

use std::process::Command;

use rustbgpd_api::proto;

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
async fn peer_evpn_output_and_rpc_errors() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.list_peer_evpn_response.lock().await = proto::ListPeerEvpnRoutesResponse {
        routes: vec![proto::EvpnRouteEntry {
            route_type: 3,
            rd: "65000:100".into(),
            next_hop: "192.0.2.1".into(),
            peer_address: "192.0.2.1".into(),
            ..Default::default()
        }],
        next_page_token: "opaque-next-page".into(),
        total_count: 2,
        page_version: Some(proto::RoutePageVersion {
            epoch: 1,
            generation: 2,
        }),
    };
    let output = run(
        &server.addr,
        &["evpn", "advertised", "192.0.2.2", "--page-size", "1"],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "Committed EVPN routes advertised to 192.0.2.2\n",
            "[imet] rd=65000:100 via 192.0.2.1 from 192.0.2.1\n",
            "Total matching rows: 2\n",
            "Next page token: opaque-next-page\n",
        )
    );
    server.state.list_peer_evpn_response.lock().await.routes[0].peer_address = "fe80::2".into();
    let output = run(
        &server.addr,
        &["--json", "evpn", "received", "fe80::2%eth0"],
    );
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["view"], "received");
    assert_eq!(value["neighbor"], "fe80::2%eth0");
    assert_eq!(value["routes"][0]["peer"], "fe80::2%eth0");
    assert_eq!(value["total_count"], 2);
    assert_eq!(value["next_page_token"], "opaque-next-page");
    assert_eq!(value["page_version"]["generation"], 2);
    assert_eq!(
        server
            .state
            .last_list_received_evpn
            .lock()
            .await
            .as_ref()
            .unwrap()
            .neighbor_address,
        "fe80::2"
    );
    for (code, prefix) in [
        (tonic::Code::Unimplemented, "not supported by this daemon"),
        (tonic::Code::Aborted, "aborted"),
        (tonic::Code::InvalidArgument, "invalid argument"),
    ] {
        *server.state.list_peer_evpn_error.lock().await = Some((code, "restart query".into()));
        let output = run(&server.addr, &["evpn", "advertised", "192.0.2.2"]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr).unwrap().contains(prefix));
    }
    assert!(server.state.last_list_evpn.lock().await.is_none());
}

#[test]
fn invalid_peer_view_arguments_fail_before_connecting() {
    for args in [
        vec!["evpn", "received", "invalid"],
        vec!["evpn", "received", "192.0.2.1", "--rd", "invalid"],
        vec!["evpn", "--peer", "192.0.2.1", "advertised", "192.0.2.2"],
        vec!["evpn", "advertised", "192.0.2.1", "--page-size", "1001"],
    ] {
        let output = run("http://127.0.0.1:1", &args);
        let expected = if args.contains(&"--page-size") { 2 } else { 1 };
        assert_eq!(output.status.code(), Some(expected), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("cannot reach rustbgpd")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn srv6_prefix_sid_survives_vpn_and_evpn_rpc_output() {
    let server = test_support::spawn_mock_server(None).await;
    let view = test_support::mock_prefix_sid();
    *server.state.list_vpn_response.lock().await = Some(proto::ListVpnRoutesResponse {
        routes: vec![proto::VpnRouteEntry {
            prefix_sid: Some(view.clone()),
            ..Default::default()
        }],
    });
    *server.state.list_peer_evpn_response.lock().await = proto::ListPeerEvpnRoutesResponse {
        routes: vec![proto::EvpnRouteEntry {
            prefix_sid: Some(view),
            ..Default::default()
        }],
        ..Default::default()
    };
    for args in [
        vec!["rib", "vpn"],
        vec!["evpn", "received", "192.0.2.1"],
        vec!["evpn", "advertised", "192.0.2.1"],
    ] {
        let mut json_args = vec!["--json"];
        json_args.extend(&args);
        let output = run(&server.addr, &json_args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let row = if value.is_array() {
            &value[0]
        } else {
            &value["routes"][0]
        };
        assert_eq!(row["prefix_sid"]["raw_value"], "deadbeef");
        assert_eq!(
            row["prefix_sid"]["services"][0]["sids"][0]["endpoint_behavior"],
            65535
        );
        let output = run(&server.addr, &args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("sid-value=fc00:0:1:: behavior=65535"),
            "{text}"
        );
        assert!(text.contains("structure=40/24/16/0/16/64"), "{text}");
    }
}
