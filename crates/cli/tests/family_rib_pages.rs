//! Bounded family-query output and request contracts over real CLI processes.
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

#[test]
fn family_page_peer_errors_precede_endpoint_connection() {
    let directory = tempfile::tempdir().unwrap();
    let addr = format!(
        "unix://{}",
        directory.path().join("no-server.sock").display()
    );
    for family in ["vpn", "labeled", "rtc"] {
        for view in ["received", "advertised"] {
            let output = run(&addr, &["rib", family, view, "invalid", "--json"]);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{family} {view}: {stderr}");
            assert!(stderr.contains("expected a peer IP address"), "{stderr}");
            assert!(!stderr.contains("cannot reach rustbgpd"), "{stderr}");
            assert!(output.stdout.is_empty());
        }
    }
}

fn assert_page(value: &serde_json::Value, view: &str, neighbor: &str) {
    assert_eq!(value["view"], view);
    assert_eq!(value["neighbor"], neighbor);
    assert!(value["routes"].is_array());
    assert_eq!(value["total_count"], 2);
    assert_eq!(value["next_page_token"], "next");
    assert_eq!(
        value["page_version"],
        serde_json::json!({"epoch": 1, "generation": 2})
    );
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "neighbor",
            "next_page_token",
            "page_version",
            "routes",
            "total_count",
            "view"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_pages_preserve_output_and_source_identity_and_send_filters() {
    let server = test_support::spawn_mock_server(None).await;
    let version = Some(proto::RoutePageVersion {
        epoch: 1,
        generation: 2,
    });
    *server.state.list_vpn_page_response.lock().await = proto::ListVpnRoutesPageResponse {
        routes: vec![proto::VpnRouteEntry {
            peer_address: "192.0.2.1".into(),
            route_distinguisher_str: "65000:100".into(),
            prefix: "10.0.0.0/24".into(),
            labels: vec![100],
            ..Default::default()
        }],
        total_count: 2,
        next_page_token: "next".into(),
        page_version: version,
    };
    *server.state.list_labeled_page_response.lock().await = proto::ListLabeledRoutesPageResponse {
        routes: vec![proto::LabeledRouteEntry {
            peer_address: "192.0.2.1".into(),
            prefix: "10.0.0.0/24".into(),
            labels: vec![100],
            path_id: 7,
            ..Default::default()
        }],
        total_count: 2,
        next_page_token: "next".into(),
        page_version: version,
    };
    *server.state.list_rtc_page_response.lock().await = proto::ListRtcRoutesPageResponse {
        routes: vec![proto::RtcRouteEntry {
            peer_address: "192.0.2.1".into(),
            origin_as: 65000,
            route_target: "RT:65000:100".into(),
            prefix_len: 96,
            ..Default::default()
        }],
        total_count: 2,
        next_page_token: "next".into(),
        page_version: version,
    };
    *server.state.list_evpn_page_response.lock().await = proto::ListEvpnRoutesPageResponse {
        routes: vec![proto::EvpnRouteEntry {
            peer_address: "192.0.2.1".into(),
            route_type: 2,
            rd: "65000:100".into(),
            mac: "00:11:22:33:44:55".into(),
            label: 100,
            ..Default::default()
        }],
        total_count: 2,
        next_page_token: "next".into(),
        page_version: version,
    };
    let output = run(
        &server.addr,
        &[
            "--json",
            "rib",
            "vpn",
            "advertised",
            "192.0.2.2",
            "--rd",
            "0x00020000FDE80064",
            "--prefix",
            "10.0.0.0/24",
            "-a",
            "vpnv4",
            "--limit",
            "1",
            "--page-token",
            "before",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_page(&value, "advertised", "192.0.2.2");
    assert_eq!(value["routes"][0]["peer_address"], "192.0.2.1");
    let request = server
        .state
        .last_list_vpn_page
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!(request.view, proto::FamilyRouteView::Advertised as i32);
    assert_eq!(request.peer_filter, "192.0.2.2");
    assert_eq!(request.afi_safi, "l3vpn_ipv4_unicast");
    assert_eq!(request.prefix_filter, "10.0.0.0/24");
    assert_eq!(request.rd_filter, "0x00020000fde80064");
    assert_eq!(request.page_size, 1);
    assert_eq!(request.page_token, "before");
    assert!(
        server.state.last_list_vpn.lock().await.is_none(),
        "paged query must not call legacy whole-table RPC"
    );

    let output = run(
        &server.addr,
        &[
            "--json",
            "rib",
            "labeled",
            "received",
            "fe80::1%eth0",
            "--prefix",
            "10.0.0.0/24",
            "-a",
            "labeled-v4",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_page(&value, "received", "fe80::1%eth0");
    assert_eq!(value["routes"][0]["path_id"], 7);
    let request = server
        .state
        .last_list_labeled_page
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!(request.peer_filter, "fe80::1");
    assert_eq!(request.page_size, 100);
    assert_eq!(request.view, proto::FamilyRouteView::Received as i32);
    assert!(server.state.last_list_labeled.lock().await.is_none());

    let output = run(
        &server.addr,
        &[
            "--json",
            "rib",
            "rtc",
            "received",
            "192.0.2.1",
            "--route-target",
            "0x02020000fde80064",
            "--origin-as",
            "65000",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_page(
        &serde_json::from_slice(&output.stdout).unwrap(),
        "received",
        "192.0.2.1",
    );
    let request = server
        .state
        .last_list_rtc_page
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!(request.route_target_filter, "0x02020000fde80064");
    assert_eq!(request.origin_as_filter, Some(65000));
    assert_eq!(request.page_size, 100);

    let output = run(
        &server.addr,
        &[
            "--json",
            "evpn",
            "best",
            "--neighbor",
            "192.0.2.1",
            "--mac",
            "00:11:22:33:44:55",
            "--esi",
            "00:01:02:03:04:05:06:07:08:09",
            "--vni",
            "100",
            "--rd",
            "65000:100",
            "--route-type",
            "2",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_page(
        &serde_json::from_slice(&output.stdout).unwrap(),
        "best",
        "192.0.2.1",
    );
    let request = server
        .state
        .last_list_evpn_page
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!(request.vni_filter, Some(100));
    assert_eq!(request.mac_filter, "00:11:22:33:44:55");
    assert_eq!(request.esi_filter, "00:01:02:03:04:05:06:07:08:09");
    assert_eq!(request.page_size, 100);
    assert!(server.state.last_list_evpn.lock().await.is_none());

    let output = run(
        &server.addr,
        &[
            "--json",
            "evpn",
            "best",
            "--neighbor",
            "192.0.2.1",
            "--rd",
            "0x00020000FDE80064",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        server
            .state
            .last_list_evpn_page
            .lock()
            .await
            .as_ref()
            .unwrap()
            .rd_filter,
        "0x00020000fde80064"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_page_rpc_errors_do_not_fall_back_to_best_or_print_rows() {
    let server = test_support::spawn_mock_server(None).await;
    for code in [
        tonic::Code::Unimplemented,
        tonic::Code::Aborted,
        tonic::Code::InvalidArgument,
        tonic::Code::FailedPrecondition,
    ] {
        *server.state.family_page_error.lock().await = Some((code, "restart pagination".into()));
        for args in [
            vec!["--json", "rib", "vpn", "received", "192.0.2.1"],
            vec!["--json", "rib", "labeled", "advertised", "192.0.2.1"],
            vec!["--json", "rib", "rtc", "received", "192.0.2.1"],
            vec!["--json", "evpn", "best"],
        ] {
            let output = run(&server.addr, &args);
            assert!(!output.status.success(), "{output:?}");
            assert!(
                output.stdout.is_empty(),
                "error must not print an apparently successful page"
            );
            assert!(!output.stderr.is_empty());
        }
        assert!(server.state.last_list_vpn.lock().await.is_none());
        assert!(server.state.last_list_labeled.lock().await.is_none());
        assert!(server.state.last_list_rtc.lock().await.is_none());
        assert!(server.state.last_list_evpn.lock().await.is_none());
    }
}
