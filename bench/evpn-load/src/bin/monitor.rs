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

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::Parser;
use rustbgpd_evpn_load::{PeerConfig, establish};
use rustbgpd_wire::attribute::PathAttribute;
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::evpn::{EvpnRoute, EvpnRouteKey};
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
    /// Number of distinct EVPN Type 2 keys currently live in the
    /// monitor's view. Incremented on announces that introduce a new
    /// key; decremented on withdraws that remove one. Re-advertisements
    /// of an already-present key are idempotent.
    final_count: i64,
    /// Seconds from session-Established to the FIRST moment the live
    /// key set reached `expect`. This is the real convergence number
    /// — how fast the RR flooded the set through to the observer.
    initial_convergence_sec: f64,
    /// Seconds from session-Established to when the live key set
    /// stabilized at `expect` for at least `stable_sec` continuous
    /// seconds. This is later than `initial_convergence_sec` if
    /// churn was running (each withdraw+readd resets the timer).
    stable_convergence_sec: f64,
    /// Every announce message counted, including idempotent
    /// re-advertisements (so churn shows up here but not in
    /// `final_count`).
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
    let mut live_keys: HashSet<EvpnRouteKey> = HashSet::new();
    let mut announcements: u64 = 0;
    let mut withdrawals: u64 = 0;
    let mut updates: u64 = 0;
    let mut last_change = Instant::now();

    let mut initial_convergence_at: Option<Instant> = None;
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
                let before = live_keys.len();
                let (anns, withs) = apply_evpn_type2(&u, &mut live_keys);
                announcements += anns;
                withdrawals += withs;
                if live_keys.len() != before {
                    last_change = Instant::now();
                    if initial_convergence_at.is_none() && live_keys.len() == args.expect as usize {
                        initial_convergence_at = Some(Instant::now());
                    }
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
            && live_keys.len() == args.expect as usize
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
    let initial_convergence_sec =
        initial_convergence_at.map_or(f64::NAN, |t| t.duration_since(session_start).as_secs_f64());
    let stable_convergence_sec =
        converged_at.map_or(f64::NAN, |t| t.duration_since(session_start).as_secs_f64());
    let report = Report {
        converged: converged_at.is_some(),
        expected: args.expect,
        final_count: i64::try_from(live_keys.len()).unwrap_or(i64::MAX),
        initial_convergence_sec,
        stable_convergence_sec,
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

/// Apply Type 2 announces (insert keys) and withdraws (remove keys)
/// from this UPDATE to `live_keys`. Returns `(announcement_events,
/// withdrawal_events)` — raw event counts including idempotent
/// re-advertisements, useful for churn accounting. Other EVPN route
/// types are ignored; the monitor is scoped to Type 2 scale.
fn apply_evpn_type2(u: &UpdateMessage, live_keys: &mut HashSet<EvpnRouteKey>) -> (u64, u64) {
    let Ok(parsed) = u.parse(true, false, &[]) else {
        return (0, 0);
    };
    let mut a: u64 = 0;
    let mut w: u64 = 0;
    for attr in &parsed.attributes {
        match attr {
            PathAttribute::MpReachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                for r in &mp.evpn_announced {
                    if matches!(r, EvpnRoute::MacIp(_)) {
                        live_keys.insert(r.key());
                        a += 1;
                    }
                }
            }
            PathAttribute::MpUnreachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                for r in &mp.evpn_withdrawn {
                    if matches!(r, EvpnRoute::MacIp(_)) {
                        live_keys.remove(&r.key());
                        w += 1;
                    }
                }
            }
            _ => {}
        }
    }
    (a, w)
}
