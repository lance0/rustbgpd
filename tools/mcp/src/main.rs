//! stdio entry point for the read-only rustbgpd MCP server.
//!
//! stdout carries newline-delimited JSON-RPC and nothing else; every log line
//! goes to stderr. A stray `println!` here corrupts the protocol stream, so
//! `tests/stdio_e2e.rs` asserts every stdout line parses as JSON.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::path::PathBuf;

use clap::Parser;
use rmcp::ServiceExt;
use rustbgpd_mcp::{
    BearerInterceptor, RustbgpdMcp, load_bearer_authorization, parse_daemon_endpoint, print_config,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Endpoint;

#[derive(Parser, Debug)]
#[command(
    name = "rustbgpd-mcp",
    about = "Read-only MCP server over a running rustbgpd's gRPC explain surfaces",
    long_about = "Speaks MCP over stdio and answers from one daemon's live explain RPCs. \
                  Intended to run on the operator's workstation, spawned by an MCP host, \
                  against a listener capped at `max_tier = \"sensitive_read\"`."
)]
struct Args {
    /// rustbgpd gRPC endpoint: `http://host:port`, `https://host:port`, or
    /// `unix:///absolute/path`.
    #[arg(
        long,
        env = "RUSTBGPD_GRPC_ADDR",
        default_value = "http://127.0.0.1:50051"
    )]
    grpc_addr: String,

    /// File holding the bearer token for gRPC authentication.
    #[arg(long, env = "RUSTBGPD_GRPC_TOKEN_FILE")]
    grpc_token_file: Option<PathBuf>,

    /// Print paste-ready `mcpServers` JSON for an MCP host and exit. The token
    /// path is rendered as a placeholder; no token value is ever echoed.
    #[arg(long)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.print_config {
        let command = std::env::current_exe().map_or_else(
            |_| "rustbgpd-mcp".to_string(),
            |path| path.display().to_string(),
        );
        println!(
            "{}",
            print_config(&command, &args.grpc_addr, args.grpc_token_file.is_some())
        );
        return Ok(());
    }

    // stderr, always: stdout is the JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let endpoint = parse_daemon_endpoint(&args.grpc_addr)?;
    tracing::info!(grpc_addr = %args.grpc_addr, "connecting to rustbgpd");
    // Lazy so the server can start before the daemon is reachable; the MCP
    // host spawns it at its own convenience and tool calls report the
    // connection failure when it matters.
    let channel = Endpoint::from_shared(endpoint.channel_uri())?.connect_lazy();
    let authorization = load_bearer_authorization(args.grpc_token_file.as_deref())?;
    let upstream = InterceptedService::new(channel, BearerInterceptor::new(authorization));

    let service = RustbgpdMcp::new(upstream)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}
