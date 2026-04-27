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

use clap::{Parser, ValueEnum};
use rustbgpd_evpn_load::{PeerConfig, establish};
use rustbgpd_wire::attribute::PathAttribute;
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::evpn::{EvpnRoute, EvpnRouteKey};
use rustbgpd_wire::message::Message;
use rustbgpd_wire::update::UpdateMessage;
use serde::Serialize;

/// Which route type the monitor counts toward `expect`. Mirrors the
/// tester's `--route-type` flag so M32b can gate on Type 1 EAD-per-EVI
/// reflection while M33 stays on Type 2.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum RouteType {
    MacIp,
    EadPerEvi,
}

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

    /// Route type to count toward `expect`. Defaults to `mac-ip` so M33's
    /// existing invocation is unchanged; set `ead-per-evi` for M32b.
    #[arg(long, value_enum, default_value_t = RouteType::MacIp)]
    route_type: RouteType,

    /// Bisection flag for the M33 saturation investigation (ADR-0051
    /// follow-up). Parses every UPDATE the same way `--apply` would
    /// but skips the `HashSet<EvpnRouteKey>` insert/remove. If
    /// saturation disappears under this flag, the `HashSet` update is
    /// the bottleneck. The live-set never reaches `expect`, so
    /// convergence won't fire — runs use the timeout exit path.
    #[arg(long, default_value_t = false)]
    no_live_set: bool,

    /// Bisection flag: receive `Message::Update` from the BGP session
    /// task but skip `apply_evpn` entirely (no `UpdateMessage::parse`,
    /// no NLRI walk, no `HashSet` ops). If saturation disappears under
    /// this flag, parsing or NLRI iteration is the bottleneck. The
    /// live-set never updates, so convergence won't fire.
    #[arg(long, default_value_t = false)]
    no_parse: bool,

    /// Period (seconds) for the per-period throughput log line. Set
    /// to 0 to disable periodic logging (final-report stats still
    /// emit). Default 5 — a 1h soak gets ~720 stats lines.
    #[arg(long, default_value_t = 5)]
    stats_period_sec: u64,
}

/// Counters accumulated over one stats period (default 5s) and
/// emitted as a `stats` log line for offline bisection.
#[derive(Default)]
struct PeriodStats {
    updates: u64,
    nlris: u64,
    parse_errors: u64,
    max_apply_us: u64,
}

/// Lifetime stats reported in the final JSON. Useful even outside
/// the bisection: the M33 +49-min wedge correlates with throughput
/// stalls on the monitor side, which these counters surface
/// post-mortem.
#[derive(Default, Serialize, Debug)]
struct LifetimeStats {
    /// Peak time spent in a single `apply_evpn` call (microseconds).
    apply_max_us: u64,
    /// Peak NLRIs processed in one `apply_evpn` call.
    apply_max_nlris: u64,
    /// Total `UpdateMessage::parse` failures (likely a wire bug if
    /// non-zero against rustbgpd).
    parse_errors: u64,
    /// True when `--no-live-set` was active for this run — JSON
    /// consumers should treat `final_count` and `converged` as
    /// not-meaningful.
    no_live_set: bool,
    /// True when `--no-parse` was active for this run.
    no_parse: bool,
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
    /// key set reached `expect`. `None` (serialized as `null`) when
    /// convergence never occurred — a non-finite `f64` would crash
    /// `serde_json` and prevent the report from being emitted at all
    /// on timeout, which is exactly when the diagnostic is most
    /// useful.
    initial_convergence_sec: Option<f64>,
    /// Seconds from session-Established to when the live key set
    /// stabilized at `expect` for at least `stable_sec` continuous
    /// seconds. This is later than `initial_convergence_sec` if
    /// churn was running (each withdraw+readd resets the timer).
    /// `None` (serialized as `null`) when stable convergence never
    /// occurred.
    stable_convergence_sec: Option<f64>,
    /// Every announce message counted, including idempotent
    /// re-advertisements (so churn shows up here but not in
    /// `final_count`).
    total_announcements: u64,
    total_withdrawals: u64,
    updates_received: u64,
    observed_elapsed_sec: f64,
    timed_out: bool,
    /// Lifetime instrumentation counters for the saturation
    /// investigation (ADR-0051 follow-up). Always present; null-ish
    /// values when no traffic was observed.
    stats: LifetimeStats,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing output goes to stderr so stdout is reserved for the JSON
    // report — interop scripts redirect `1>monitor.json 2>monitor.log`
    // and parse the JSON with `jq`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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

    let mut period = PeriodStats::default();
    let mut period_start = Instant::now();
    let stats_period = Duration::from_secs(args.stats_period_sec);
    let mut lifetime = LifetimeStats {
        no_live_set: args.no_live_set,
        no_parse: args.no_parse,
        ..LifetimeStats::default()
    };

    if args.no_live_set || args.no_parse {
        tracing::warn!(
            no_live_set = args.no_live_set,
            no_parse = args.no_parse,
            "bisection mode active — convergence will NOT fire and final_count is not meaningful"
        );
    }

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
                period.updates += 1;
                if args.no_parse {
                    // Skip the entire parse + NLRI walk + HashSet path.
                    // The Message::Update has already been frame-decoded
                    // by `establish`; this just measures the cost of
                    // *not* doing the apply_evpn work.
                } else {
                    let before = live_keys.len();
                    let apply_start = Instant::now();
                    let (anns, withs, nlris, parse_failed) = apply_evpn_instrumented(
                        &u,
                        &mut live_keys,
                        args.route_type,
                        args.no_live_set,
                    );
                    let apply_us =
                        u64::try_from(apply_start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    period.max_apply_us = period.max_apply_us.max(apply_us);
                    period.nlris += nlris;
                    if parse_failed {
                        period.parse_errors += 1;
                        lifetime.parse_errors += 1;
                    }
                    lifetime.apply_max_us = lifetime.apply_max_us.max(apply_us);
                    lifetime.apply_max_nlris = lifetime.apply_max_nlris.max(nlris);
                    announcements += anns;
                    withdrawals += withs;
                    if live_keys.len() != before {
                        last_change = Instant::now();
                        if initial_convergence_at.is_none()
                            && live_keys.len() == args.expect as usize
                        {
                            initial_convergence_at = Some(Instant::now());
                        }
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

        // Periodic throughput log. Skipped when stats_period_sec is 0
        // — useful for low-noise interop runs that don't need the
        // per-period detail.
        if !stats_period.is_zero() && period_start.elapsed() >= stats_period {
            let elapsed_sec = period_start.elapsed().as_secs_f64().max(0.001);
            // Rates are display-only; saturating-as-f64 via u32 cap
            // keeps clippy happy without #[allow] noise. A period that
            // overflows u32 events would mean ~4.3 G updates/period,
            // which we'd never see.
            let updates_capped = u32::try_from(period.updates).unwrap_or(u32::MAX);
            let nlris_capped = u32::try_from(period.nlris).unwrap_or(u32::MAX);
            tracing::info!(
                updates_per_sec = f64::from(updates_capped) / elapsed_sec,
                nlris_per_sec = f64::from(nlris_capped) / elapsed_sec,
                parse_errors = period.parse_errors,
                max_apply_us = period.max_apply_us,
                live = live_keys.len(),
                total_updates = updates,
                "stats"
            );
            period = PeriodStats::default();
            period_start = Instant::now();
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
        initial_convergence_at.map(|t| t.duration_since(session_start).as_secs_f64());
    let stable_convergence_sec =
        converged_at.map(|t| t.duration_since(session_start).as_secs_f64());
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
        stats: lifetime,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    if !report.converged {
        std::process::exit(2);
    }
    Ok(())
}

/// Instrumented variant of the original `apply_evpn`. Returns:
///   - `announcements`: counted matches in `MP_REACH_NLRI`
///   - `withdrawals`: counted matches in `MP_UNREACH_NLRI`
///   - `nlris`: total EVPN routes walked across both directions (for
///     periodic throughput stats)
///   - `parse_failed`: true when `UpdateMessage::parse` returned `Err`,
///     which would normally mean a wire-codec bug
///
/// `skip_live_set` parses + walks but skips `HashSet` insert/remove,
/// so the bisection flag `--no-live-set` can quickly answer "is the
/// `HashSet` update the bottleneck?"
fn apply_evpn_instrumented(
    u: &UpdateMessage,
    live_keys: &mut HashSet<EvpnRouteKey>,
    route_type: RouteType,
    skip_live_set: bool,
) -> (u64, u64, u64, bool) {
    let Ok(parsed) = u.parse(true, false, &[]) else {
        return (0, 0, 0, true);
    };
    let matches_type = |r: &EvpnRoute| match route_type {
        RouteType::MacIp => matches!(r, EvpnRoute::MacIp(_)),
        RouteType::EadPerEvi => matches!(r, EvpnRoute::EadPerEvi(_)),
    };
    let mut a: u64 = 0;
    let mut w: u64 = 0;
    let mut nlris: u64 = 0;
    for attr in &parsed.attributes {
        match attr {
            PathAttribute::MpReachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                for r in &mp.evpn_announced {
                    nlris += 1;
                    if matches_type(r) {
                        if !skip_live_set {
                            live_keys.insert(r.key());
                        }
                        a += 1;
                    }
                }
            }
            PathAttribute::MpUnreachNlri(mp) if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn => {
                for r in &mp.evpn_withdrawn {
                    nlris += 1;
                    if matches_type(r) {
                        if !skip_live_set {
                            live_keys.remove(&r.key());
                        }
                        w += 1;
                    }
                }
            }
            _ => {}
        }
    }
    (a, w, nlris, false)
}
