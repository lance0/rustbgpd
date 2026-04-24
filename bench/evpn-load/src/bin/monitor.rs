//! evpn-monitor — observe reflected Type 2 EVPN routes, measure convergence.
//!
//! Opens an iBGP session to a target rustbgpd RR as a non-originating
//! observer. Counts EVPN Type 2 announcements and withdrawals received
//! off the wire and reports convergence as JSON to stdout.
//!
//! "Converged" = count reaches `expect` and stays within tolerance for
//! `stable-sec` seconds.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::too_many_lines)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::Parser;
use rustbgpd_evpn_load::{PeerConfig, establish};
use rustbgpd_wire::attribute::PathAttribute;
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::evpn::EvpnRoute;
use rustbgpd_wire::message::Message;
use rustbgpd_wire::update::UpdateMessage;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "evpn-monitor")]
#[command(about = "observe reflected EVPN Type 2 routes and measure convergence")]
struct Args {
    /// Local listen address (RR dials us here). BGP = port 179.
    #[arg(long, default_value = "0.0.0.0:179")]
    listen: SocketAddr,

    /// Local AS number.
    #[arg(long, default_value_t = 65000)]
    local_as: u32,

    /// Local router-id.
    #[arg(long)]
    router_id: Ipv4Addr,

    /// Expected Type 2 count at convergence.
    #[arg(long)]
    expect: u32,

    /// Seconds of stability (count == expect, no change) before declaring converged.
    #[arg(long, default_value_t = 5)]
    stable_sec: u64,

    /// Overall timeout (seconds) — abort + exit non-zero if not converged.
    #[arg(long, default_value_t = 120)]
    timeout_sec: u64,

    /// How long to keep observing *after* convergence (churn window).
    #[arg(long, default_value_t = 0)]
    observe_sec: u64,

    /// Hold time advertised in OPEN.
    #[arg(long, default_value_t = 180)]
    hold_time: u16,
}

#[derive(Serialize, Debug)]
struct Report {
    converged: bool,
    expected: u32,
    final_count: i64,
    convergence_sec: f64,
    total_announcements: u64,
    total_withdrawals: u64,
    updates_received: u64,
    observed_elapsed_sec: f64,
    timed_out: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    tracing::info!(
        listen = %args.listen,
        local_as = args.local_as,
        router_id = %args.router_id,
        expect = args.expect,
        "starting evpn-monitor"
    );

    let cfg = PeerConfig {
        listen: args.listen,
        local_as: args.local_as,
        router_id: args.router_id,
        hold_time: args.hold_time,
        families: vec![(Afi::L2Vpn, Safi::Evpn)],
    };

    let mut handle = establish(cfg).await?;
    tracing::info!("session established, observing");

    let session_start = Instant::now();
    let mut count: i64 = 0;
    let mut announcements: u64 = 0;
    let mut withdrawals: u64 = 0;
    let mut updates: u64 = 0;
    let mut last_change = Instant::now();

    let mut converged_at: Option<Instant> = None;
    let timeout = Duration::from_secs(args.timeout_sec);
    let stable = Duration::from_secs(args.stable_sec);
    let observe = Duration::from_secs(args.observe_sec);

    loop {
        let now = Instant::now();
        let deadline = if let Some(t) = converged_at {
            t + observe
        } else if session_start.elapsed() >= timeout {
            break;
        } else {
            session_start + timeout
        };
        let remaining = deadline.saturating_duration_since(now);
        let recv =
            tokio::time::timeout(remaining.min(Duration::from_millis(500)), handle.rx.recv());
        match recv.await {
            Ok(Some(Message::Update(u))) => {
                updates += 1;
                let (added, removed) = count_evpn_type2(&u);
                count += i64::from(added) - i64::from(removed);
                announcements += u64::from(added);
                withdrawals += u64::from(removed);
                if added > 0 || removed > 0 {
                    last_change = Instant::now();
                }
            }
            Ok(Some(_)) | Err(_) => {
                // Non-UPDATE inbound or timeout — fall through to stability/deadline check.
            }
            Ok(None) => {
                tracing::warn!("session closed by peer");
                break;
            }
        }

        if converged_at.is_none()
            && count == i64::from(args.expect)
            && last_change.elapsed() >= stable
        {
            converged_at = Some(Instant::now());
            tracing::info!(
                convergence_sec = session_start.elapsed().as_secs_f64(),
                "converged"
            );
            if observe.is_zero() {
                break;
            }
        }

        if let Some(t) = converged_at
            && t.elapsed() >= observe
        {
            break;
        }

        if converged_at.is_none() && session_start.elapsed() >= timeout {
            break;
        }
    }

    let elapsed = session_start.elapsed().as_secs_f64();
    let convergence_sec =
        converged_at.map_or(f64::NAN, |t| t.duration_since(session_start).as_secs_f64());
    let report = Report {
        converged: converged_at.is_some(),
        expected: args.expect,
        final_count: count,
        convergence_sec,
        total_announcements: announcements,
        total_withdrawals: withdrawals,
        updates_received: updates,
        observed_elapsed_sec: elapsed,
        timed_out: converged_at.is_none(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    if !report.converged {
        std::process::exit(2);
    }
    Ok(())
}

/// Count Type 2 announcements and withdrawals in this UPDATE. All other
/// EVPN route types are ignored — the monitor is scoped to Type 2
/// scale.
fn count_evpn_type2(u: &UpdateMessage) -> (u32, u32) {
    let Ok(parsed) = u.parse(true, false, &[]) else {
        return (0, 0);
    };
    let mut a = 0u32;
    let mut w = 0u32;
    for attr in &parsed.attributes {
        match attr {
            PathAttribute::MpReachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                a += u32::try_from(
                    mp.evpn_announced
                        .iter()
                        .filter(|r| matches!(r, EvpnRoute::MacIp(_)))
                        .count(),
                )
                .unwrap_or(u32::MAX);
            }
            PathAttribute::MpUnreachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                w += u32::try_from(
                    mp.evpn_withdrawn
                        .iter()
                        .filter(|r| matches!(r, EvpnRoute::MacIp(_)))
                        .count(),
                )
                .unwrap_or(u32::MAX);
            }
            _ => {}
        }
    }
    (a, w)
}
