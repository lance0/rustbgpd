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
            assert_eq!(output.status.code(), Some(64), "{family} {view}: {stderr}");
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
    *server.state.list_vpn_page_response.lock().await = proto::ListVpnRibRoutesResponse {
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
    *server.state.list_labeled_page_response.lock().await = proto::ListLabeledRibRoutesResponse {
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
    *server.state.list_rtc_page_response.lock().await = proto::ListRtcRibRoutesResponse {
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
    *server.state.list_evpn_page_response.lock().await = proto::ListBestEvpnRoutesResponse {
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
    assert_eq!(request.neighbor_address, "192.0.2.2");
    assert!(request.source_peer_filter.is_empty());
    assert_eq!(
        request.afi_safi,
        proto::AddressFamily::L3vpnIpv4Unicast as i32
    );
    assert_eq!(request.prefix_filter, "10.0.0.0");
    assert_eq!(request.prefix_filter_length, 24);
    assert!(!request.longer_prefixes);
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
    assert_eq!(request.neighbor_address, "fe80::1%eth0");
    assert!(request.source_peer_filter.is_empty());
    assert_eq!(
        request.afi_safi,
        proto::AddressFamily::Ipv4LabeledUnicast as i32
    );
    assert_eq!(request.prefix_filter, "10.0.0.0");
    assert_eq!(request.prefix_filter_length, 24);
    assert!(!request.longer_prefixes);
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
    assert_eq!(request.neighbor_address, "192.0.2.1");
    assert!(request.source_peer_filter.is_empty());
    assert_eq!(request.afi_safi, proto::AddressFamily::Unspecified as i32);
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
    assert_eq!(request.source_peer_filter, "192.0.2.1");
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
async fn family_best_pages_send_source_filters_and_typed_exact_or_longer_prefixes() {
    let server = test_support::spawn_mock_server(None).await;
    for (family, selector, afi_safi, prefix, address, length) in [
        (
            "vpn",
            "vpnv4",
            proto::AddressFamily::L3vpnIpv4Unicast,
            "10.0.0.0/16",
            "10.0.0.0",
            16,
        ),
        (
            "vpn",
            "vpnv6",
            proto::AddressFamily::L3vpnIpv6Unicast,
            "2001:0db8::/32",
            "2001:db8::",
            32,
        ),
        (
            "labeled",
            "labeled-v4",
            proto::AddressFamily::Ipv4LabeledUnicast,
            "10.0.0.0/16",
            "10.0.0.0",
            16,
        ),
        (
            "labeled",
            "labeled-v6",
            proto::AddressFamily::Ipv6LabeledUnicast,
            "2001:0db8::/32",
            "2001:db8::",
            32,
        ),
    ] {
        for longer in [false, true] {
            let mut args = vec![
                "--json",
                "rib",
                family,
                "--neighbor",
                "fe80::1%eth0",
                "-a",
                selector,
                "--prefix",
                prefix,
            ];
            if longer {
                args.push("--longer");
            }
            let output = run(&server.addr, &args);
            assert!(output.status.success(), "{output:?}");
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["view"], "best");
            assert_eq!(value["neighbor"], "fe80::1%eth0");
            let fields = if family == "vpn" {
                let request = server
                    .state
                    .last_list_vpn_page
                    .lock()
                    .await
                    .clone()
                    .unwrap();
                (
                    request.view,
                    request.neighbor_address,
                    request.source_peer_filter,
                    request.afi_safi,
                    request.prefix_filter,
                    request.prefix_filter_length,
                    request.longer_prefixes,
                )
            } else {
                let request = server
                    .state
                    .last_list_labeled_page
                    .lock()
                    .await
                    .clone()
                    .unwrap();
                (
                    request.view,
                    request.neighbor_address,
                    request.source_peer_filter,
                    request.afi_safi,
                    request.prefix_filter,
                    request.prefix_filter_length,
                    request.longer_prefixes,
                )
            };
            assert_eq!(
                fields,
                (
                    proto::FamilyRouteView::Best as i32,
                    String::new(),
                    "fe80::1%eth0".into(),
                    afi_safi as i32,
                    address.into(),
                    length,
                    longer
                )
            );
        }
    }
    let output = run(
        &server.addr,
        &[
            "--json",
            "rib",
            "rtc",
            "--neighbor",
            "192.0.2.1",
            "--limit",
            "1",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let request = server
        .state
        .last_list_rtc_page
        .lock()
        .await
        .clone()
        .unwrap();
    assert_eq!(request.view, proto::FamilyRouteView::Best as i32);
    assert!(request.neighbor_address.is_empty());
    assert_eq!(request.source_peer_filter, "192.0.2.1");
    assert_eq!(request.afi_safi, proto::AddressFamily::Unspecified as i32);
    assert!(server.state.last_list_vpn.lock().await.is_none());
    assert!(server.state.last_list_labeled.lock().await.is_none());
    assert!(server.state.last_list_rtc.lock().await.is_none());
}

// Plain listings (`rib vpn|labeled|rtc`, `evpn`) and `evpn diagnose` over the
// bounded page RPCs.
//
// The canned tables are written in each bounded RPC's key order, because
// that is the order a daemon returns them in. The mock pages the rows as
// given, so these tests cannot show how a daemon orders its table; the RIB
// and API page tests pin that. What they prove is that the CLI prints every
// row of every page with the row content and JSON shape the whole-table
// listing printed for the same rows: the files under
// `fixtures/plain-family-listings` are that listing's output for these
// tables, captured before the listings moved to the page walk.

fn plain_vpn_table() -> Vec<proto::VpnRouteEntry> {
    let row = |rd: u8, prefix: &str| proto::VpnRouteEntry {
        afi_safi: "l3vpn_ipv4_unicast".into(),
        route_distinguisher: vec![0, 0, 0xfd, 0xe8, 0, 0, 0, rd],
        route_distinguisher_str: format!("65000:{rd}"),
        prefix: prefix.into(),
        labels: vec![24000 + u32::from(rd)],
        next_hop: "192.0.2.1".into(),
        peer_address: "fe80::1".into(),
        as_path: vec![64512, 64513],
        communities: vec!["64512:100".into()],
        extended_communities: vec![format!("RT:65000:{rd}")],
        ..Default::default()
    };
    vec![
        row(1, "10.1.0.0/24"),
        proto::VpnRouteEntry {
            stale: true,
            path_id: 7,
            ..row(1, "10.2.0.0/24")
        },
        row(2, "10.1.0.0/24"),
    ]
}

fn plain_labeled_table() -> Vec<proto::LabeledRouteEntry> {
    let row = |prefix: &str, label: u32| proto::LabeledRouteEntry {
        afi_safi: "ipv4_labeled_unicast".into(),
        prefix: prefix.into(),
        labels: vec![label],
        next_hop: "192.0.2.1".into(),
        peer_address: "192.0.2.1".into(),
        as_path: vec![64512],
        ..Default::default()
    };
    vec![
        row("10.1.0.0/24", 100),
        proto::LabeledRouteEntry {
            llgr_stale: true,
            communities: vec!["64512:200".into()],
            ..row("10.2.0.0/16", 200)
        },
        row("10.3.0.0/24", 300),
    ]
}

fn plain_rtc_table() -> Vec<proto::RtcRouteEntry> {
    let row = |origin_as: u32| proto::RtcRouteEntry {
        origin_as,
        route_target: "RT:65001:100".into(),
        prefix_len: 96,
        next_hop: "192.0.2.1".into(),
        peer_address: "192.0.2.1".into(),
        as_path: vec![64512],
        ..Default::default()
    };
    vec![
        proto::RtcRouteEntry {
            is_default: true,
            next_hop: "0.0.0.0".into(),
            peer_address: "0.0.0.0".into(),
            ..Default::default()
        },
        row(65001),
        row(65002),
    ]
}

fn plain_evpn_table() -> Vec<proto::EvpnRouteEntry> {
    let row = |route_type: u32| proto::EvpnRouteEntry {
        route_type,
        rd: "65000:100".into(),
        ethernet_tag: "0".into(),
        label: 10100,
        next_hop: "192.0.2.1".into(),
        peer_address: "192.0.2.1".into(),
        tunnel_type: 8,
        ..Default::default()
    };
    let mac_ip = |mac: &str, ip: &str| proto::EvpnRouteEntry {
        mac: mac.into(),
        ip: ip.into(),
        ..row(2)
    };
    let imet = |ip: &str| proto::EvpnRouteEntry {
        ip: ip.into(),
        ..row(3)
    };
    vec![
        mac_ip("02:aa:bb:cc:dd:01", ""),
        mac_ip("02:aa:bb:cc:dd:02", "10.0.0.2"),
        mac_ip("02:aa:bb:cc:dd:03", ""),
        imet("10.0.0.1"),
        imet("10.0.0.2"),
    ]
}

async fn plain_listing_server() -> test_support::MockServerHandle {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.vpn_table.lock().await = plain_vpn_table();
    *server.state.labeled_table.lock().await = plain_labeled_table();
    *server.state.rtc_table.lock().await = plain_rtc_table();
    *server.state.evpn_table.lock().await = plain_evpn_table();
    server
}

/// The command's text and JSON output are byte-for-byte the whole-table
/// listing's output for the same rows.
fn assert_whole_table_output(addr: &str, args: &[&str], golden: &str) {
    for (extension, json) in [("txt", false), ("json", true)] {
        let mut args = args.to_vec();
        if json {
            args.push("--json");
        }
        let output = run(addr, &args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        let path = format!(
            "{}/tests/fixtures/plain-family-listings/{golden}.{extension}",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            std::fs::read_to_string(&path).unwrap(),
            "{args:?}"
        );
    }
}

const VPN_ARGS: &[&str] = &["rib", "vpn", "-a", "vpnv4", "--neighbor", "fe80::1%eth0"];
const LABELED_ARGS: &[&str] = &[
    "rib",
    "labeled",
    "-a",
    "labeled-v4",
    "--neighbor",
    "192.0.2.1",
];
const RTC_ARGS: &[&str] = &["rib", "rtc", "--neighbor", "192.0.2.1"];
const EVPN_ARGS: &[&str] = &[
    "evpn",
    "--route-type",
    "2",
    "--neighbor",
    "192.0.2.1",
    "--rd",
    "65000:100",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_vpn_listing_prints_every_page_like_the_whole_table_listing() {
    let server = plain_listing_server().await;
    assert_whole_table_output(&server.addr, VPN_ARGS, "vpn");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_labeled_listing_prints_every_page_like_the_whole_table_listing() {
    let server = plain_listing_server().await;
    assert_whole_table_output(&server.addr, LABELED_ARGS, "labeled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_rtc_listing_prints_every_page_like_the_whole_table_listing() {
    let server = plain_listing_server().await;
    assert_whole_table_output(&server.addr, RTC_ARGS, "rtc");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_evpn_listing_prints_every_page_like_the_whole_table_listing() {
    let server = plain_listing_server().await;
    assert_whole_table_output(&server.addr, &["evpn"], "evpn");
    assert_whole_table_output(&server.addr, EVPN_ARGS, "evpn-type2");
}

/// Three Type 2 rows are more than one mock page and more than the one row
/// `evpn diagnose` asks for, so the counts can only come from `total_count`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evpn_diagnose_counts_match_the_whole_table_listing() {
    let server = plain_listing_server().await;
    assert_whole_table_output(&server.addr, &["evpn", "diagnose"], "diagnose");
}

/// The page tokens of one walk: an empty token, then each continuation, with
/// every other request field unchanged.
fn assert_walk<R: Clone + PartialEq + std::fmt::Debug>(
    requests: &[R],
    token: impl Fn(&mut R) -> &mut String,
    expected_tokens: &[&str],
) {
    let mut requests = requests.to_vec();
    let tokens: Vec<_> = requests
        .iter_mut()
        .map(|request| std::mem::take(token(request)))
        .collect();
    assert_eq!(tokens, expected_tokens);
    assert!(requests.iter().all(|request| *request == requests[0]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_vpn_listing_walks_every_page_with_its_filters() {
    let server = plain_listing_server().await;
    assert!(run(&server.addr, VPN_ARGS).status.success());
    let requests = server.state.vpn_page_requests.lock().await.clone();
    assert_walk(&requests, |r| &mut r.page_token, &["", "after-2"]);
    assert_eq!(
        requests[0],
        proto::ListVpnRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            source_peer_filter: "fe80::1%eth0".into(),
            afi_safi: proto::AddressFamily::L3vpnIpv4Unicast as i32,
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(run(&server.addr, &["rib", "vpn"]).status.success());
    assert_eq!(
        server.state.vpn_page_requests.lock().await[2],
        proto::ListVpnRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(server.state.last_list_vpn.lock().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_labeled_listing_walks_every_page_with_its_filters() {
    let server = plain_listing_server().await;
    assert!(run(&server.addr, LABELED_ARGS).status.success());
    let requests = server.state.labeled_page_requests.lock().await.clone();
    assert_walk(&requests, |r| &mut r.page_token, &["", "after-2"]);
    assert_eq!(
        requests[0],
        proto::ListLabeledRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            source_peer_filter: "192.0.2.1".into(),
            afi_safi: proto::AddressFamily::Ipv4LabeledUnicast as i32,
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(run(&server.addr, &["rib", "labeled"]).status.success());
    assert_eq!(
        server.state.labeled_page_requests.lock().await[2],
        proto::ListLabeledRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(server.state.last_list_labeled.lock().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_rtc_listing_walks_every_page_with_its_filters() {
    let server = plain_listing_server().await;
    assert!(run(&server.addr, RTC_ARGS).status.success());
    let requests = server.state.rtc_page_requests.lock().await.clone();
    assert_walk(&requests, |r| &mut r.page_token, &["", "after-2"]);
    assert_eq!(
        requests[0],
        proto::ListRtcRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            source_peer_filter: "192.0.2.1".into(),
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(run(&server.addr, &["rib", "rtc"]).status.success());
    assert_eq!(
        server.state.rtc_page_requests.lock().await[2],
        proto::ListRtcRibRoutesRequest {
            view: proto::FamilyRouteView::Best as i32,
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(server.state.last_list_rtc.lock().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_evpn_listing_walks_every_page_with_its_filters() {
    let server = plain_listing_server().await;
    assert!(run(&server.addr, EVPN_ARGS).status.success());
    let requests = server.state.evpn_page_requests.lock().await.clone();
    assert_walk(&requests, |r| &mut r.page_token, &["", "after-2"]);
    assert_eq!(
        requests[0],
        proto::ListBestEvpnRoutesRequest {
            route_type_filter: 2,
            source_peer_filter: "192.0.2.1".into(),
            rd_filter: "65000:100".into(),
            page_size: 1000,
            ..Default::default()
        }
    );
    server.state.evpn_page_requests.lock().await.clear();
    assert!(run(&server.addr, &["evpn"]).status.success());
    let requests = server.state.evpn_page_requests.lock().await.clone();
    assert_walk(
        &requests,
        |r| &mut r.page_token,
        &["", "after-2", "after-4"],
    );
    assert_eq!(
        requests[0],
        proto::ListBestEvpnRoutesRequest {
            page_size: 1000,
            ..Default::default()
        }
    );
    assert!(server.state.last_list_evpn.lock().await.is_none());
}

/// `evpn diagnose` asks for one smallest page per route type and follows no
/// continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evpn_diagnose_reads_each_count_from_one_smallest_page() {
    let server = plain_listing_server().await;
    assert!(run(&server.addr, &["evpn", "diagnose"]).status.success());
    let type_count = |route_type_filter| proto::ListBestEvpnRoutesRequest {
        route_type_filter,
        page_size: 1,
        ..Default::default()
    };
    assert_eq!(
        *server.state.evpn_page_requests.lock().await,
        [type_count(2), type_count(3)]
    );
    assert!(server.state.last_list_evpn.lock().await.is_none());
}

/// A table that changes between two pages fails the listing with the
/// daemon's ABORTED, exactly as `rib bgpls` does: no retry and no partial
/// rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_listings_fail_without_rows_when_the_table_changes_mid_walk() {
    let server = plain_listing_server().await;
    server
        .state
        .family_table_changes_mid_walk
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for args in [VPN_ARGS, LABELED_ARGS, RTC_ARGS, EVPN_ARGS] {
        for json in [false, true] {
            let mut args = args.to_vec();
            if json {
                args.push("--json");
            }
            let output = run(&server.addr, &args);
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{args:?}: partial rows printed");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(
                    "aborted: route table changed during pagination; restart with an empty page_token"
                ),
                "{args:?}: {output:?}"
            );
        }
    }
    assert_eq!(server.state.vpn_page_requests.lock().await.len(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evpn_peer_filters_require_server_ack_before_output() {
    let server = test_support::spawn_mock_server(None).await;
    server
        .state
        .list_peer_evpn_filters_legacy
        .store(true, std::sync::atomic::Ordering::SeqCst);
    *server.state.list_peer_evpn_response.lock().await = proto::ListPeerEvpnRoutesResponse {
        routes: vec![proto::EvpnRouteEntry {
            route_type: 2,
            mac: "00:11:22:33:44:66".into(),
            peer_address: "192.0.2.1".into(),
            ..Default::default()
        }],
        total_count: 1,
        ..Default::default()
    };
    for view in ["received", "advertised"] {
        for json in [false, true] {
            for (flag, value) in [
                ("--mac", "00:11:22:33:44:55"),
                ("--esi", "00:01:02:03:04:05:06:07:08:09"),
                ("--vni", "0"),
            ] {
                let mut args = vec!["evpn", view, "192.0.2.1", flag, value];
                if json {
                    args.push("--json");
                }
                let output = run(&server.addr, &args);
                assert_eq!(output.status.code(), Some(1), "{output:?}");
                assert!(
                    output.stdout.is_empty(),
                    "unsupported filters must print no rows: {output:?}"
                );
                assert!(
                    String::from_utf8(output.stderr)
                        .unwrap()
                        .contains("does not acknowledge EVPN peer filters")
                );
            }
        }
        let output = run(&server.addr, &["evpn", view, "192.0.2.1", "--json"]);
        assert!(
            output.status.success(),
            "old unfiltered requests remain supported: {output:?}"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["total_count"],
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evpn_peer_pages_forward_raw_rd_and_mac_esi_vni_without_changing_json() {
    let server = test_support::spawn_mock_server(None).await;
    *server.state.list_peer_evpn_response.lock().await = proto::ListPeerEvpnRoutesResponse {
        routes: vec![proto::EvpnRouteEntry {
            peer_address: "192.0.2.1".into(),
            route_type: 2,
            ..Default::default()
        }],
        total_count: 2,
        next_page_token: "next".into(),
        page_version: Some(proto::RoutePageVersion {
            epoch: 1,
            generation: 2,
        }),
    };
    for (view, peer) in [("received", "192.0.2.1"), ("advertised", "fe80::2%eth0")] {
        let output = run(
            &server.addr,
            &[
                "--json",
                "evpn",
                view,
                peer,
                "--rd",
                "0x00020000FDE80064",
                "--mac",
                "00:11:22:33:44:55",
                "--esi",
                "00:01:02:03:04:05:06:07:08:09",
                "--vni",
                "100",
                "--limit",
                "1",
                "--page-token",
                "previous",
            ],
        );
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_page(&value, view, peer);
        assert_eq!(value["routes"][0]["peer"], "192.0.2.1");
        let request = if view == "received" {
            server
                .state
                .last_list_received_evpn
                .lock()
                .await
                .clone()
                .unwrap()
        } else {
            server
                .state
                .last_list_advertised_evpn
                .lock()
                .await
                .clone()
                .unwrap()
        };
        assert_eq!(request.neighbor_address, peer);
        assert_eq!(request.rd_filter, "0x00020000fde80064");
        assert_eq!(request.mac_filter, "00:11:22:33:44:55");
        assert_eq!(request.esi_filter, "00:01:02:03:04:05:06:07:08:09");
        assert_eq!(request.vni_filter, Some(100));
        assert_eq!(request.page_size, 1);
        assert_eq!(request.page_token, "previous");
        assert!(server.state.last_list_evpn.lock().await.is_none());
        assert!(server.state.last_list_evpn_page.lock().await.is_none());
    }
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
        *server.state.list_peer_evpn_error.lock().await = Some((code, "restart pagination".into()));
        for args in [
            vec!["--json", "rib", "vpn", "received", "192.0.2.1"],
            vec!["--json", "rib", "labeled", "advertised", "192.0.2.1"],
            vec!["--json", "rib", "rtc", "received", "192.0.2.1"],
            vec!["--json", "evpn", "best"],
            vec!["--json", "evpn", "received", "192.0.2.1"],
            vec!["--json", "evpn", "advertised", "192.0.2.1"],
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

/// `rib bgpls` follows every continuation with unchanged filters and prints
/// all pages as one listing; a failed continuation fails the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bgpls_listing_walks_every_page_with_unchanged_filters() {
    let server = test_support::spawn_mock_server(None).await;
    let row = |nlri_type: u32| proto::BgpLsRouteEntry {
        afi_safi: proto::AddressFamily::BgpLs as i32,
        nlri_type,
        peer_address: "192.0.2.1".to_string(),
        ..Default::default()
    };
    *server.state.bgpls_pages.lock().await = vec![
        proto::ListBgpLsRibRoutesResponse {
            routes: vec![row(1), row(2)],
            next_page_token: "first".to_string(),
            total_count: 3,
            ..Default::default()
        },
        proto::ListBgpLsRibRoutesResponse {
            routes: vec![row(3)],
            total_count: 3,
            ..Default::default()
        },
    ];
    let addr = server.addr.clone();
    let args = [
        "rib",
        "bgpls",
        "-a",
        "linkstate",
        "--neighbor",
        "192.0.2.1",
        "--nlri-type",
        "2",
        "--json",
    ];
    let output = run(&addr, &args);
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let types: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["nlri_type"].as_u64().unwrap())
        .collect();
    assert_eq!(types, [1, 2, 3]);
    let requests = server.state.bgpls_page_requests.lock().await.clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].page_token, "");
    assert_eq!(requests[1].page_token, "first");
    assert_eq!(requests[0].nlri_type_filter, 2);
    assert_eq!(requests[0].source_peer_filter, "192.0.2.1");
    assert_eq!(
        proto::ListBgpLsRibRoutesRequest {
            page_token: String::new(),
            ..requests[1].clone()
        },
        requests[0]
    );

    server.state.bgpls_pages.lock().await.truncate(1);
    server.state.bgpls_page_requests.lock().await.clear();
    let output = run(&addr, &args);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "a partial walk must not print rows"
    );
    assert_eq!(server.state.bgpls_page_requests.lock().await.len(), 2);
}

/// `topology nodes` and `topology links` follow every continuation and print
/// all pages as one JSON array; a failed continuation fails the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topology_listings_walk_every_page() {
    let server = test_support::spawn_mock_server(None).await;
    let node = |key: &str| proto::TopologyNodeEntry {
        key: key.to_string(),
        ..Default::default()
    };
    let link = |cost: u32| proto::TopologyLinkEntry {
        local_key: "02aa".to_string(),
        remote_key: "02bb".to_string(),
        cost,
        ..Default::default()
    };
    *server.state.orr_node_pages.lock().await = vec![
        proto::ListOrrTopologyNodesResponse {
            nodes: vec![node("02aa"), node("02bb")],
            next_page_token: "nodes".to_string(),
            total_count: 3,
            ..Default::default()
        },
        proto::ListOrrTopologyNodesResponse {
            nodes: vec![node("02cc")],
            total_count: 3,
            ..Default::default()
        },
    ];
    *server.state.orr_link_pages.lock().await = vec![
        proto::ListOrrTopologyLinksResponse {
            links: vec![link(1)],
            next_page_token: "links".to_string(),
            total_count: 2,
            ..Default::default()
        },
        proto::ListOrrTopologyLinksResponse {
            links: vec![link(2)],
            total_count: 2,
            ..Default::default()
        },
    ];
    let output = run(&server.addr, &["topology", "nodes", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let keys: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(keys, ["02aa", "02bb", "02cc"]);
    let requests = server.state.orr_node_page_requests.lock().await.clone();
    let tokens: Vec<_> = requests.iter().map(|r| r.page_token.as_str()).collect();
    assert_eq!(tokens, ["", "nodes"]);
    assert!(requests.iter().all(|r| r.page_size == 1000));

    let output = run(&server.addr, &["topology", "links", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let costs: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["cost"].as_u64().unwrap())
        .collect();
    assert_eq!(costs, [1, 2]);
    let requests = server.state.orr_link_page_requests.lock().await.clone();
    let tokens: Vec<_> = requests.iter().map(|r| r.page_token.as_str()).collect();
    assert_eq!(tokens, ["", "links"]);

    server.state.orr_link_pages.lock().await.truncate(1);
    server.state.orr_link_page_requests.lock().await.clear();
    let output = run(&server.addr, &["topology", "links", "--json"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "a partial walk must not print rows"
    );
}
