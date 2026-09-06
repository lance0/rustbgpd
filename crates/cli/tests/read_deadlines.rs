//! Real-process response deadlines, including a response whose headers already arrived.

#![cfg(unix)]

use std::process::{Output, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rustbgpd_api::proto;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

fn start(addr: &str, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", addr])
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start rbgp")
}

async fn finish(mut child: Child) -> Output {
    if tokio::time::timeout(Duration::from_secs(45), child.wait())
        .await
        .is_err()
    {
        child
            .kill()
            .await
            .expect("kill CLI after regression timeout");
        let output = child.wait_with_output().await.expect("reap killed CLI");
        panic!("CLI exceeded its 30-second response deadline: {output:?}");
    }
    child.wait_with_output().await.expect("collect CLI output")
}

fn assert_read_timeout(output: &Output, rpc: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "partial stdout: {output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("deadline exceeded"), "{error}");
    assert!(error.contains(rpc), "{error}");
    assert!(error.contains("response timed out"), "{error}");
}

#[tokio::test]
async fn evpn_explain_stops_at_response_deadline() {
    let server = test_support::spawn_mock_server(None).await;
    server
        .state
        .explain_evpn_read_stall
        .store(true, Ordering::SeqCst);
    let output = finish(start(
        &server.addr,
        &[
            "evpn",
            "explain",
            "mac-ip",
            "--rd",
            "65000:100",
            "--mac",
            "02:00:00:00:00:01",
        ],
    ))
    .await;
    assert_read_timeout(&output, "ExplainEvpnRoute");
    assert!(server.state.last_explain_evpn.lock().await.is_some());
    assert!(server.state.last_list_evpn.lock().await.is_none());
}

#[tokio::test]
async fn config_status_and_history_have_lightweight_read_deadlines() {
    let server = test_support::spawn_mock_server(None).await;
    server
        .state
        .config_snapshot_read_stall
        .store(true, Ordering::SeqCst);
    let (status, history) = tokio::join!(
        finish(start(&server.addr, &["--json", "config", "status"])),
        finish(start(&server.addr, &["config", "history"])),
    );
    assert_read_timeout(&status, "GetConfigTransactionStatus");
    assert_read_timeout(&history, "ListConfigHistory");
    assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.config_history_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn established_tcp_and_unix_requests_stop_at_response_deadline() {
    let tcp = test_support::spawn_mock_server(None).await;
    let directory = tempfile::tempdir().unwrap();
    let uds = test_support::spawn_mock_uds_server(&directory.path().join("read.sock"), None).await;
    tcp.state.global_read_stall.store(true, Ordering::SeqCst);
    uds.state.global_read_stall.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let (tcp_output, uds_output) = tokio::join!(
        finish(start(&tcp.addr, &["global"])),
        finish(start(&uds.addr, &["global"])),
    );
    assert_read_timeout(&tcp_output, "GetGlobal");
    assert_read_timeout(&uds_output, "GetGlobal");
    assert!(started.elapsed() >= Duration::from_secs(25));
    assert_eq!(tcp.state.global_calls.load(Ordering::SeqCst), 1);
    assert_eq!(uds.state.global_calls.load(Ordering::SeqCst), 1);
}

// Minimal HTTP/2 fixture for the one boundary tonic's unary service cannot
// expose: successful response headers followed by an incomplete gRPC body.
async fn stall_response_body<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    stream
        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
        .await
        .unwrap(); // SETTINGS
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let mut saw_headers = false;
    let stream_id = loop {
        let mut header = [0; 9];
        stream.read_exact(&mut header).await.unwrap();
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await.unwrap();
        let kind = header[3];
        let flags = header[4];
        let id: [u8; 4] = header[5..9].try_into().unwrap();
        if kind == 4 && flags & 1 == 0 {
            stream
                .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
                .await
                .unwrap(); // SETTINGS ACK
        }
        saw_headers |= kind == 1 && id != [0; 4];
        if id != [0; 4] && matches!(kind, 0 | 1) && flags & 1 != 0 {
            break id;
        }
    };
    assert!(saw_headers, "complete RPC request must reach the fixture");
    // HPACK: indexed :status=200, literal content-type=application/grpc.
    // END_HEADERS deliberately omits END_STREAM.
    let mut headers = vec![0, 0, 20, 1, 4];
    headers.extend_from_slice(&stream_id);
    headers.extend_from_slice(b"\x88\x0f\x10\x10application/grpc");
    stream.write_all(&headers).await.unwrap();
    // An uncompressed 32-byte gRPC message is promised but never delivered.
    let mut data = vec![0, 0, 5, 0, 0];
    data.extend_from_slice(&stream_id);
    data.extend_from_slice(&[0, 0, 0, 0, 32]);
    stream.write_all(&data).await.unwrap();
    // Hold the response open until the CLI deadline closes the connection.
    let mut buffer = [0; 256];
    while let Ok(length) = stream.read(&mut buffer).await {
        if length == 0 {
            break;
        }
    }
}

#[tokio::test]
async fn response_headers_do_not_end_tcp_or_unix_deadline() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = format!("http://{}", tcp.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("body.sock");
    let uds = tokio::net::UnixListener::bind(&path).unwrap();
    let uds_addr = format!("unix://{}", path.display());
    let tcp_server = tokio::spawn(async move {
        stall_response_body(tcp.accept().await.unwrap().0).await;
    });
    let uds_server = tokio::spawn(async move {
        stall_response_body(uds.accept().await.unwrap().0).await;
    });
    let (tcp_output, uds_output) = tokio::join!(
        finish(start(&tcp_addr, &["global"])),
        finish(start(&uds_addr, &["global"])),
    );
    // Both child processes have exited; the socket readers must now finish.
    tcp_server.await.unwrap();
    uds_server.await.unwrap();
    assert_read_timeout(&tcp_output, "GetGlobal");
    assert_read_timeout(&uds_output, "GetGlobal");
}

async fn later_page_stalls(json: bool) {
    let server = test_support::spawn_mock_server(None).await;
    server
        .state
        .list_route_continuation_stall
        .store(true, Ordering::SeqCst);
    server
        .state
        .list_route_pages
        .lock()
        .await
        .push(proto::ListRoutesResponse {
            routes: vec![proto::Route {
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                peer_address: "192.0.2.1".into(),
                ..Default::default()
            }],
            next_page_token: "second-page".into(),
            total_count: 2,
            page_version: None,
        });
    let mut args = vec!["rib", "received", "192.0.2.1"];
    if json {
        args.push("--json");
    }
    let output = finish(start(&server.addr, &args)).await;
    assert_read_timeout(&output, "ListReceivedRoutes");
    let requests = server.state.list_route_requests.lock().await;
    assert_eq!(requests.len(), 2, "no retries after the stalled page");
    assert!(requests[0].page_token.is_empty());
    assert_eq!(requests[1].page_token, "second-page");
}

#[tokio::test]
async fn later_rib_page_timeout_never_prints_a_partial_listing() {
    tokio::join!(later_page_stalls(false), later_page_stalls(true));
}

async fn seed_first_route_page(server: &test_support::MockServerHandle) {
    server
        .state
        .list_route_pages
        .lock()
        .await
        .push(proto::ListRoutesResponse {
            routes: vec![proto::Route {
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                peer_address: "192.0.2.1".into(),
                path_id: 7,
                ..Default::default()
            }],
            next_page_token: "second-page".into(),
            total_count: 2,
            page_version: None,
        });
}

#[tokio::test]
async fn json_lines_emits_route_before_stalled_page_and_omits_end_on_timeout() {
    let server = test_support::spawn_mock_server(None).await;
    seed_first_route_page(&server).await;
    server
        .state
        .list_route_continuation_stall
        .store(true, Ordering::SeqCst);
    let mut child = start(
        &server.addr,
        &["--json-lines", "rib", "received", "192.0.2.1"],
    );
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut first_records = String::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        reader.read_line(&mut first_records).await.unwrap();
        reader.read_line(&mut first_records).await.unwrap();
    })
    .await
    .expect("header AND first route must arrive before the continuation finishes");
    let records: Vec<serde_json::Value> = first_records
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["type"], "header");
    assert_eq!(records[1]["type"], "route");
    assert_eq!(records[1]["route"]["prefix"], "203.0.113.0/24");
    assert!(
        child.try_wait().unwrap().is_none(),
        "route arrived only after process exit"
    );
    let output = finish(child).await;
    assert_read_timeout(&output, "ListReceivedRoutes");
    let mut remaining = String::new();
    reader.read_to_string(&mut remaining).await.unwrap();
    assert!(
        remaining.is_empty(),
        "failed stream must not emit an end record"
    );
    assert_eq!(server.state.list_route_requests.lock().await.len(), 2);
}

#[tokio::test]
async fn later_page_abort_preserves_legacy_atomicity_and_leaves_stream_unfinished() {
    for view in [
        vec!["rib"],
        vec!["rib", "received", "192.0.2.1"],
        vec!["rib", "advertised", "192.0.2.1"],
    ] {
        for mode in ["--json", "--json-lines"] {
            let server = test_support::spawn_mock_server(None).await;
            seed_first_route_page(&server).await;
            *server.state.list_route_continuation_error.lock().await =
                Some((tonic::Code::Aborted, "RIB changed".into()));
            let mut args = vec![mode];
            args.extend(view.iter().copied());
            let output = finish(start(&server.addr, &args)).await;
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("RIB changed"));
            if mode == "--json" {
                assert!(output.stdout.is_empty());
            } else {
                let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(records.len(), 2);
                assert_eq!(records[1]["type"], "route");
            }
            assert_eq!(
                server.state.list_route_requests.lock().await.len(),
                2,
                "no restart or retry"
            );
        }
    }
}

#[tokio::test]
async fn legacy_json_array_and_limited_envelope_keep_their_shapes() {
    for limited in [false, true] {
        let server = test_support::spawn_mock_server(None).await;
        seed_first_route_page(&server).await;
        server
            .state
            .list_route_pages
            .lock()
            .await
            .push(proto::ListRoutesResponse {
                routes: vec![proto::Route {
                    prefix: "203.0.113.0".into(),
                    prefix_length: 24,
                    peer_address: "192.0.2.1".into(),
                    path_id: 8,
                    ..Default::default()
                }],
                next_page_token: String::new(),
                total_count: 2,
                page_version: None,
            });
        let mut args = vec!["--json", "rib", "received", "192.0.2.1"];
        if limited {
            args.extend(["--limit", "1"]);
        }
        let output = finish(start(&server.addr, &args)).await;
        assert!(output.status.success(), "{output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if limited {
            let keys: Vec<_> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                ["complete", "returned_count", "routes", "total_count"]
            );
            assert_eq!(value["returned_count"], 1);
            assert_eq!(value["total_count"], 2);
            assert_eq!(value["complete"], false);
            assert_eq!(value["routes"][0]["path_id"], 7);
        } else {
            let routes = value
                .as_array()
                .expect("ordinary JSON must remain an array");
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0]["path_id"], 7);
            assert_eq!(routes[1]["path_id"], 8);
        }
        assert_eq!(
            server.state.list_route_requests.lock().await.len(),
            if limited { 1 } else { 2 }
        );
    }
}

#[tokio::test]
async fn json_lines_rejects_unsupported_offline_and_route_commands_before_connect() {
    for args in [
        vec!["--json-lines", "completions", "bash"],
        vec!["--json-lines", "man"],
        vec!["--json-lines", "doctor"],
        vec!["--json-lines", "global"],
        vec!["--json-lines", "rib", "--count"],
        vec!["--json-lines", "rib", "--age"],
        vec!["--json-lines", "rib", "received", "192.0.2.1", "--rejected"],
        vec!["--json-lines", "rib", "advertised", "192.0.2.1", "--age"],
        vec!["--json-lines", "rib", "--family", "ipv4_flowspec"],
        vec!["--json-lines", "--pager", "always", "rib"],
    ] {
        let output = finish(start("unix:///nonexistent/rbgp-json-lines.sock", &args)).await;
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("cannot reach"), "{args:?}: {error}");
        assert!(!error.is_empty());
        if args.contains(&"--pager") {
            assert!(
                error.contains("--pager always cannot be combined with --json or --json-lines"),
                "{error}"
            );
        }
    }
}

#[tokio::test]
async fn successful_authenticated_read_keeps_its_output() {
    let server = test_support::spawn_mock_server(Some("read-secret")).await;
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "read-secret\n").unwrap();
    let output = finish(start(
        &server.addr,
        &["--token-file", token.to_str().unwrap(), "--json", "global"],
    ))
    .await;
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "asn": 65001,
            "router_id": "10.0.0.1",
            "listen_port": 179,
            "tcp_ao_support": "supported",
        })
    );
    assert_eq!(server.state.global_calls.load(Ordering::SeqCst), 1);
}
