#![cfg(unix)]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use rustbgpd_api::proto;
use rustbgpd_api::proto::global_service_server::{GlobalService, GlobalServiceServer};
use rustbgpd_api::proto::{GetGlobalRequest, GlobalState};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[path = "../src/test_support.rs"]
#[allow(
    dead_code,
    reason = "shared CLI mock includes services unused by this contract"
)]
mod test_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_lines_closed_stdout_is_quiet_and_fetches_no_routes() {
    let server = test_support::spawn_mock_server(None).await;
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let writer: OwnedFd = writer.into();
    let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", &server.addr, "--json-lines", "rib"])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .env_remove("RUSTBGPD_TOKEN_FILE")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(server.state.list_route_requests.lock().await.is_empty());
}

struct MockGlobalService;

#[tonic::async_trait]
impl GlobalService for MockGlobalService {
    async fn get_global(
        &self,
        _request: Request<GetGlobalRequest>,
    ) -> Result<Response<GlobalState>, Status> {
        Ok(Response::new(GlobalState {
            asn: 65001,
            router_id: "10.0.0.1".to_string(),
            listen_port: 179,
            ..Default::default()
        }))
    }
}

/// Serve `GlobalService` from a background thread for the lifetime of the
/// test process; returns the address to pass as `--addr`.
fn spawn_global_service() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            tonic::transport::Server::builder()
                .add_service(GlobalServiceServer::new(MockGlobalService))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
    });
    addr
}

fn run_with_closed_stdout(args: &[&str]) {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let writer: OwnedFd = writer.into();
    let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(args)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("panicked"));
    assert!(!stderr.contains("stack backtrace"));
}

#[test]
fn offline_commands_quietly_handle_closed_stdout() {
    run_with_closed_stdout(&["completions", "bash"]);
    run_with_closed_stdout(&[
        "policy",
        "check",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/route-server/hygiene.rpol"
        ),
    ]);
    run_with_closed_stdout(&[
        "config",
        "import",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/import/frr.conf"
        ),
    ]);
}

#[test]
fn connected_human_output_quietly_handles_closed_stdout() {
    let addr = spawn_global_service();
    run_with_closed_stdout(&["--addr", &addr, "global"]);
}
