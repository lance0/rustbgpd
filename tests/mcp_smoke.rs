//! Live MCP export explanation through the actual stdio binary and daemon.
//!
//! Focused invocation: first `cargo build --locked -p rustbgpd-mcp --bins`,
//! then `cargo test --locked -p rustbgpd --test mcp_smoke`.
//! `cargo test --workspace` builds both executables before running tests.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustbgpd_api::proto;
use rustbgpd_wire::{Capability, Message, OpenMessage};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tonic::transport::Endpoint;
use tonic::{Code, Request};

pub mod support;

const PREFIX: &str = "203.0.113.0";
const TOKEN: &str = "mcp-smoke-observer";
const LADDER: &[&str] = &[
    "best_route",
    "split_horizon",
    "rr_reflection",
    "family",
    "llgr",
    "orf",
    "export_policy",
    "otc",
    "adj_rib_out",
];

struct Process {
    child: Child,
    output: Option<mpsc::Receiver<Result<Value, String>>>,
    reader: Option<JoinHandle<()>>,
}

impl Process {
    fn spawn(command: &mut Command) -> Self {
        Self {
            child: command.spawn().expect("start fixture process"),
            output: None,
            reader: None,
        }
    }

    fn read_protocol(&mut self, transcript: PathBuf) {
        let stdout = self.child.stdout.take().expect("MCP stdout is piped");
        let (tx, rx) = mpsc::channel(4);
        self.output = Some(rx);
        self.reader = Some(std::thread::spawn(move || {
            let mut transcript = std::fs::File::create(transcript).expect("MCP transcript");
            for line in BufReader::new(stdout).lines() {
                let parsed = line.map_err(|error| error.to_string()).and_then(|line| {
                    writeln!(transcript, "{line}").expect("retain MCP response");
                    serde_json::from_str(&line)
                        .map_err(|error| format!("non-JSON stdout: {error}: {line}"))
                });
                if tx.blocking_send(parsed).is_err() {
                    break;
                }
            }
        }));
    }

    fn send(&mut self, request: &Value) {
        let stdin = self.child.stdin.as_mut().expect("MCP stdin is piped");
        writeln!(stdin, "{request}").expect("send MCP request");
        stdin.flush().expect("flush MCP request");
    }

    async fn request(&mut self, request: Value) -> Value {
        self.send(&request);
        let response = tokio::time::timeout(
            Duration::from_secs(35),
            self.output.as_mut().unwrap().recv(),
        )
        .await
        .expect("MCP response deadline")
        .expect("MCP stdout closed")
        .expect("stdout must contain only JSON-RPC");
        assert_eq!(response["jsonrpc"], "2.0", "{response}");
        assert_eq!(
            response["id"], request["id"],
            "unexpected MCP message: {response}"
        );
        assert!(
            response.get("error").is_none(),
            "MCP protocol error: {response}"
        );
        response["result"].clone()
    }

    async fn finish(mut self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            drop(self.child.stdin.take());
            // EOF must not hide output emitted after the last expected reply.
            // This fixed fixture expects no asynchronous server notifications.
            if let Some(item) = self.output.as_mut().unwrap().recv().await {
                let unexpected = item.expect("trailing stdout must still be JSON-RPC");
                panic!("unexpected MCP output after final response: {unexpected}");
            }
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "MCP shutdown failed: {status}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.reader
                .take()
                .unwrap()
                .join()
                .expect("MCP reader must finish cleanly");
        })
        .await
        .expect("MCP did not close stdout and exit within the shutdown deadline");
    }

    async fn tool(&mut self, id: u32, name: &str, arguments: Value) -> Value {
        let response = self.request(json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{"name":name,"arguments":arguments}})).await;
        assert_eq!(response["isError"], false, "{response}");
        let structured = response["structuredContent"].clone();
        assert!(
            structured.is_object(),
            "missing structured tool result: {response}"
        );
        let text = response["content"][0]["text"]
            .as_str()
            .expect("JSON text result");
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), structured);
        structured
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Closing the receiver also releases a reader blocked on a full channel.
        if let Some(output) = &mut self.output {
            output.close();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn config(directory: &Path, deny: bool) -> String {
    format!(
        r#"
config_epoch = {epoch}
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 0
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{dir}/state"
ebgp_requires_policy = true
[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:0"
[global.telemetry.grpc_tcp]
address = "127.0.0.1:0"
token_file = "{dir}/observer.token"
principal = "rustbgpd://observer/mcp-test"
max_tier = "sensitive_read"
[global.telemetry.grpc_uds]
path = "{dir}/operator.sock"
mode = 0o600
principal = "fixture-operator"
[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://observer/mcp-test" = "observer"
fixture-operator = "operator"
[policy]
import_chain = ["permit-all"]
export_chain = ["{export}"]
[policy.definitions.permit-all]
default_action = "permit"
[policy.definitions.block-doc-prefix]
default_action = "permit"
[[policy.definitions.block-doc-prefix.statements]]
action = "deny"
prefix = "203.0.113.0/24"
[[neighbors]]
address = "127.0.0.1"
remote_asn = 65002
graceful_restart = false
hold_time = 0
families = ["ipv4_unicast"]
"#,
        dir = directory.display(),
        epoch = if deny { 2 } else { 1 },
        export = if deny {
            "block-doc-prefix"
        } else {
            "permit-all"
        }
    )
}

async fn daemon_ports(daemon: &mut Process, log: &Path) -> (u16, u16) {
    loop {
        let content = std::fs::read_to_string(log).unwrap_or_default();
        let mut grpc = None;
        let mut bgp = None;
        for line in content.lines() {
            let Ok(entry) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let fields = &entry["fields"];
            let port = |name: &str| {
                fields[name]
                    .as_str()
                    .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
                    .map(|addr| addr.port())
                    .filter(|port| *port != 0)
            };
            grpc = grpc.or_else(|| port("bound_addr"));
            if fields["message"]
                .as_str()
                .is_some_and(|message| message.contains("BGP listener"))
            {
                bgp = bgp.or_else(|| port("addr"));
            }
        }
        if let (Some(grpc), Some(bgp)) = (grpc, bgp) {
            return (grpc, bgp);
        }
        assert!(
            daemon.child.try_wait().unwrap().is_none(),
            "daemon exited: {content}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn route(prefix: &str) -> proto::AddPathRequest {
    proto::AddPathRequest {
        prefix: prefix.into(),
        prefix_length: 24,
        next_hop: "192.0.2.254".into(),
        ..Default::default()
    }
}

async fn explain(mcp: &mut Process, id: u32, prefix: &str) -> Value {
    mcp.tool(
        id,
        "rbgp_explain_export",
        json!({"peer_address":"127.0.0.1", "prefix":prefix, "prefix_length":24}),
    )
    .await
}

fn assert_ladder(result: &Value, deny: bool) {
    assert_eq!(result["decision"], if deny { "deny" } else { "advertise" });
    assert_eq!(result["prefix"], "203.0.113.0/24");
    assert_eq!(result["peer_address"], "127.0.0.1");
    assert_eq!(
        result["stopped_at_gate"],
        if deny {
            json!("export_policy")
        } else {
            Value::Null
        }
    );
    let gates = result["gates"].as_array().unwrap();
    let expected = if deny { &LADDER[..7] } else { LADDER };
    assert_eq!(gates.len(), expected.len(), "{result}");
    for (index, (gate, name)) in gates.iter().zip(expected).enumerate() {
        assert_eq!(gate["step"], index + 1);
        assert_eq!(gate["gate"], *name);
        let verdict = if deny && *name == "export_policy" {
            "stop"
        } else if matches!(*name, "orf" | "otc") {
            "not_applicable"
        } else {
            "pass"
        };
        assert_eq!(gate["verdict"], verdict, "{gate}");
    }
    if deny {
        assert_eq!(gates[6]["code"], "policy_denied");
        assert!(
            gates[6]["detail"]
                .as_str()
                .unwrap()
                .contains("block-doc-prefix")
        );
    } else {
        assert_eq!(gates[6]["code"], "policy_permitted");
        assert_eq!(result["already_advertised"], true);
    }
}

async fn run_fixture(path: &Path) {
    let mcp_binary = Path::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .parent()
        .unwrap()
        .join("rustbgpd-mcp");
    assert!(
        mcp_binary.is_file(),
        "missing {}; build it first with cargo build --locked -p rustbgpd-mcp --bins (cargo test --workspace builds both binaries)",
        mcp_binary.display()
    );
    std::fs::write(path.join("observer.token"), format!("{TOKEN}\n")).unwrap();
    let config_path = path.join("rustbgpd.toml");
    std::fs::write(&config_path, config(path, false)).unwrap();
    let log = path.join("daemon.stdout.log");
    let mut daemon = Process::spawn(
        Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg(&config_path)
            .stdout(std::fs::File::create(&log).unwrap())
            .stderr(std::fs::File::create(path.join("daemon.stderr.log")).unwrap()),
    );
    let (grpc_port, bgp_port) = daemon_ports(&mut daemon, &log).await;
    let endpoint = format!("http://127.0.0.1:{grpc_port}");
    let operator_endpoint =
        Endpoint::from_shared(format!("unix://{}", path.join("operator.sock").display()))
            .unwrap()
            .connect_timeout(Duration::from_secs(2));
    let operator = loop {
        if let Ok(channel) = operator_endpoint.connect().await {
            break channel;
        }
        assert!(
            daemon.child.try_wait().unwrap().is_none(),
            "daemon exited before operator listener readiness"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut injection = proto::injection_service_client::InjectionServiceClient::new(operator);
    injection.add_path(route(PREFIX)).await.unwrap();

    let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", bgp_port))
        .await
        .unwrap();
    // A single receiver is enough for a locally injected route. Hold time
    // zero keeps this bounded fixture independent of keepalive scheduling.
    for message in [
        Message::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 0,
            bgp_identifier: "10.0.0.2".parse().unwrap(),
            capabilities: vec![Capability::FourOctetAs { asn: 65002 }],
        }),
        Message::Keepalive,
    ] {
        peer.write_all(&rustbgpd_wire::encode_message(&message).unwrap())
            .await
            .unwrap();
    }
    let mut mcp = Process::spawn(
        Command::new(mcp_binary)
            .args(["--grpc-addr", &endpoint, "--grpc-token-file"])
            .arg(path.join("observer.token"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(path.join("mcp.stderr.log")).unwrap()),
    );
    mcp.read_protocol(path.join("mcp.stdout.jsonl"));
    mcp.request(json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"live-test", "version":"0"}}})).await;
    mcp.send(&json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
    loop {
        let peers = mcp.tool(2, "rbgp_list_peers", json!({})).await;
        if peers["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|peer| peer["address"] == "127.0.0.1" && peer["state"] == "established")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    loop {
        let result = explain(&mut mcp, 3, PREFIX).await;
        if result["already_advertised"] == true {
            assert_ladder(&result, false);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let observer = Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut observer = proto::injection_service_client::InjectionServiceClient::new(observer);
    let mut attempt = Request::new(route("198.51.100.0"));
    attempt
        .metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let error = observer.add_path(attempt).await.unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert!(
        error.message().contains("listener max_tier sensitive_read"),
        "{error}"
    );
    assert_eq!(
        explain(&mut mcp, 4, "198.51.100.0").await["decision"],
        "no_best_route"
    );

    let replacement = path.join("next.toml");
    std::fs::write(&replacement, config(path, true)).unwrap();
    std::fs::rename(replacement, &config_path).unwrap();
    kill(
        Pid::from_raw(i32::try_from(daemon.child.id()).unwrap()),
        Signal::SIGHUP,
    )
    .unwrap();
    loop {
        let result = explain(&mut mcp, 5, PREFIX).await;
        if result["decision"] == "deny" {
            assert_ladder(&result, true);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    mcp.finish().await;
}

#[tokio::test]
async fn live_export_explain_and_observer_mutation_denial() {
    let directory = support::RetainOnPanic::new(tempfile::tempdir().unwrap());
    // Canceling the fixture drops its guards, kills and waits for every child,
    // and joins the protocol reader before a timeout is reported as failure.
    tokio::time::timeout(Duration::from_secs(120), run_fixture(directory.path()))
        .await
        .expect("live MCP fixture exceeded its whole-test deadline");
}
