//! End-to-end stdio JSON-RPC handshake against the real compiled binary.
//!
//! Covers the two properties a stdio MCP server must hold before any tool
//! matters: the handshake completes, and stdout carries JSON-RPC and nothing
//! else. The second assertion is what catches a stray `println!` added later.
//!
//! No daemon is needed — the gRPC channel is lazy, and `initialize` /
//! `tools/list` never touch it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

/// The tool surface this server is allowed to expose, in sorted order.
const EXPECTED_TOOLS: &[&str] = &[
    "rbgp_explain_best_path",
    "rbgp_explain_export",
    "rbgp_explain_import",
    "rbgp_get_health",
    "rbgp_list_peers",
    "rbgp_list_rejected",
];

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn initialize_then_list_tools_over_stdio() {
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_rustbgpd-mcp"))
            // Never connected: the channel is lazy and neither request in this
            // handshake reaches the daemon.
            .args(["--grpc-addr", "http://127.0.0.1:1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the compiled rustbgpd-mcp binary starts"),
    );

    let mut stdin = server.0.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(server.0.stdout.take().expect("piped stdout"));

    let send = |stdin: &mut std::process::ChildStdin, line: &str| {
        writeln!(stdin, "{line}").expect("the server accepts a request line");
        stdin.flush().expect("request flushes");
    };
    let recv = |stdout: &mut BufReader<std::process::ChildStdout>| -> serde_json::Value {
        let mut line = String::new();
        let read = stdout.read_line(&mut line).expect("the server answers");
        assert!(read > 0, "the server closed stdout before answering");
        // Every stdout line must be JSON-RPC. A stray `println!` anywhere in
        // the binary fails here rather than silently corrupting the stream.
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line:?}"))
    };

    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "contract-test", "version": "0" }
            }
        })
        .to_string(),
    );
    let initialized = recv(&mut stdout);
    assert_eq!(initialized["id"], 1, "{initialized}");
    assert_eq!(
        initialized["result"]["serverInfo"]["name"], "rustbgpd-mcp",
        "{initialized}"
    );
    assert!(
        initialized["result"]["capabilities"]["tools"].is_object(),
        "the server must advertise the tools capability: {initialized}"
    );

    send(
        &mut stdin,
        &serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
    );

    send(
        &mut stdin,
        &serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
    );
    let listed = recv(&mut stdout);
    assert_eq!(listed["id"], 2, "{listed}");

    let mut names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list returns an array: {listed}"))
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .unwrap_or_else(|| panic!("every tool has a name: {tool}"))
                .to_string()
        })
        .collect();
    names.sort();

    let mut expected: Vec<String> = EXPECTED_TOOLS.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "the stdio tool surface must be exactly the six read-only tools"
    );

    // Every tool must declare an input schema; a host cannot call one without.
    for tool in listed["result"]["tools"].as_array().expect("array") {
        assert!(
            tool["inputSchema"].is_object(),
            "tool {} has no input schema: {tool}",
            tool["name"]
        );
    }
}
