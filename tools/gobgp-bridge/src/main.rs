//! `rustbgpd-gobgp-bridge`: serve GoBGP v3 `AddPath` on loopback and apply
//! each request through a rustbgpd daemon's injection API.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use rustbgpd_gobgp_bridge::{
    Bridge, DAEMON_RPC_TIMEOUT, DEFAULT_MAX_TRACKED, DaemonEndpoint, check_listen, daemon_channel,
    load_token, serve,
};

#[derive(Parser, Debug)]
#[command(
    name = "rustbgpd-gobgp-bridge",
    version,
    about = "Serve GoBGP v3 AddPath (binary unicast announce/withdraw) and apply it through rustbgpd",
    long_about = "Serves GoBGP v3 `apipb.GobgpApi/AddPath` over plaintext gRPC so RTBH detectors \
                  that drive GoBGP can announce and withdraw blackholes through rustbgpd. Any \
                  process that can reach the listen address can announce routes."
)]
struct Args {
    /// Address to serve the GoBGP API on, for example 127.0.0.1:50051.
    #[arg(long)]
    listen: SocketAddr,

    /// rustbgpd gRPC endpoint: `unix:///absolute/path` or `http://host:port`.
    #[arg(long)]
    daemon: DaemonEndpoint,

    /// File holding the daemon's bearer token (required by TCP listeners).
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Allow serving the unauthenticated GoBGP API on a non-loopback address.
    #[arg(long)]
    allow_non_loopback: bool,

    /// Seconds between passes that re-add every tracked ban and retry
    /// pending withdrawals, so a restarted daemon gets its bans back.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    reconcile_interval_secs: u64,
}

async fn run(args: Args) -> Result<(), String> {
    check_listen(args.listen, args.allow_non_loopback)?;
    let bearer = args.token_file.as_deref().map(load_token).transpose()?;
    let channel = daemon_channel(&args.daemon, DAEMON_RPC_TIMEOUT)?;
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    tracing::info!(listen = %listener.local_addr().map_err(|e| e.to_string())?, daemon = ?args.daemon, "serving GoBGP AddPath");
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let bridge = Bridge::new(channel, bearer, DEFAULT_MAX_TRACKED);
    bridge.spawn_reconcile(Duration::from_secs(args.reconcile_interval_secs));
    serve(listener, bridge, shutdown)
        .await
        .map_err(|e| format!("gRPC server failed: {e}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustbgpd-gobgp-bridge: {error}");
            ExitCode::FAILURE
        }
    }
}
