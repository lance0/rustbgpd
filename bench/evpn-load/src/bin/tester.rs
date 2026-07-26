//! evpn-tester — bulk Type 2 EVPN route generator.
//!
//! Opens an iBGP session to a target rustbgpd RR, advertises a
//! configurable number of Type 2 (MAC/IP) routes at a controlled rate,
//! then optionally runs a churn phase (withdraw + re-advertise).
//!
//! All routes share one RD (built from local-as:1), one ethernet-tag,
//! one next-hop (the local router-id). MACs are deterministic from
//! [`rustbgpd_evpn_load::synth_mac`] keyed by index.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::too_many_lines,
    reason = "the test driver keeps scenario construction and reporting in one entrypoint"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use rustbgpd_evpn_load::{PeerConfig, establish, synth_esi, synth_mac, v4_next_hop};
use rustbgpd_wire::attribute::{AsPath, MpReachNlri, Origin, PathAttribute};
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::constants::MAX_MESSAGE_LEN;
use rustbgpd_wire::evpn::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEvi, EvpnMacIp, EvpnRoute, MacAddress,
    MplsLabel, RouteDistinguisher,
};
use rustbgpd_wire::message::{Message, encode_message};
use rustbgpd_wire::update::UpdateMessage;

/// Which RFC 7432 route type the tester originates.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum RouteType {
    /// Type 2 — MAC/IP advertisement. The historical M33 default.
    MacIp,
    /// Type 1 — EAD-per-EVI. Each route carries a synthetic non-zero ESI
    /// derived from index, a non-MAX_ET ethernet-tag, and the configured
    /// VNI. Used by the M32b harness to gate end-to-end Type 1 EAD
    /// reflection through the RR without needing FRR's VLAN-aware
    /// bridge + SVI setup.
    EadPerEvi,
}

#[derive(Copy, Clone)]
struct RouteParams {
    vni: u32,
    ethernet_tag: u32,
    router_id: Ipv4Addr,
    rd: RouteDistinguisher,
    route_type: RouteType,
}

#[derive(Copy, Clone)]
struct PhaseParams {
    count: u32,
    rate: u32,
    batch: u32,
}

#[derive(Parser, Debug)]
#[command(name = "evpn-tester")]
#[command(about = "bulk Type 2 EVPN route generator for rustbgpd RR scale validation")]
struct Args {
    /// Local listen address (RR dials us here). BGP = port 179.
    #[arg(long, default_value = "0.0.0.0:179")]
    listen: SocketAddr,

    /// Local AS number.
    #[arg(long, default_value_t = 65000)]
    local_as: u32,

    /// Local router-id (also used as Type 2 next-hop).
    #[arg(long)]
    router_id: Ipv4Addr,

    /// Number of Type 2 routes to advertise.
    #[arg(long, default_value_t = 10_000)]
    count: u32,

    /// Advertisement rate in routes/sec. 0 = as fast as possible.
    #[arg(long, default_value_t = 1000)]
    rate: u32,

    /// Routes per UPDATE message (keeps bundles reasonable to fit 4KB).
    #[arg(long, default_value_t = 40)]
    batch: u32,

    /// VNI to put in the primary MPLS label field.
    #[arg(long, default_value_t = 100)]
    vni: u32,

    /// Ethernet-tag to use on every Type 2 route.
    #[arg(long, default_value_t = 0)]
    ethernet_tag: u32,

    /// After reaching `count`, run churn phase: withdraw+re-advertise
    /// `churn-rate` routes/sec for `churn-duration-sec` seconds.
    #[arg(long, default_value_t = 0)]
    churn_duration_sec: u64,

    /// Churn rate in routes/sec.
    #[arg(long, default_value_t = 1000)]
    churn_rate: u32,

    /// How long to keep the session open after the injection phase is
    /// complete (gives time for monitor to see convergence). Independent
    /// of `churn-duration-sec`.
    #[arg(long, default_value_t = 30)]
    linger_sec: u64,

    /// Hold time advertised in OPEN.
    #[arg(long, default_value_t = 180)]
    hold_time: u16,

    /// Route type to originate.
    #[arg(long, value_enum, default_value_t = RouteType::MacIp)]
    route_type: RouteType,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing output to stderr so harness scripts that capture stdout
    // (the rare case for the tester, but routine for the monitor) get
    // a clean stream. Mirrors evpn-monitor.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    validate_workload(&args)?;
    let rd = make_rd(args.router_id);
    let route_params = RouteParams {
        vni: args.vni,
        ethernet_tag: args.ethernet_tag,
        router_id: args.router_id,
        rd,
        route_type: args.route_type,
    };
    preflight_workload(&args, route_params)?;
    tracing::info!(
        listen = %args.listen,
        local_as = args.local_as,
        router_id = %args.router_id,
        count = args.count,
        rate = args.rate,
        "starting evpn-tester"
    );

    let cfg = PeerConfig {
        listen: args.listen,
        local_as: args.local_as,
        router_id: args.router_id,
        hold_time: args.hold_time,
        families: vec![(Afi::L2Vpn, Safi::Evpn)],
    };

    let mut handle = establish(cfg).await?;
    tracing::info!("session established");

    // Drain inbound traffic so the reader task in evpn-load's
    // `establish()` doesn't back-pressure on its bounded `rx_tx`
    // channel (currently 65 536). Without this drainer, RR-side
    // reflections of the *other* tester's churn (~25 UPDATE/sec at
    // 1 k rps) fill the channel in roughly 65 536 / 25 ≈ 44 minutes,
    // the reader parks on send, the kernel TCP receive buffer fills,
    // RR's writer task parks on `write_all`, and the
    // ADR-0051 saturation handler fires `Cease/8` — what the M33 soak
    // harness was attributing to a "monitor saturation" bug in
    // rustbgpd. The bug was always in this binary: a write-only
    // synthetic peer that ignored its rx side. See
    // `evpn_load::PeerHandle` rustdoc.
    let mut rx = std::mem::replace(&mut handle.rx, {
        let (_, rx_placeholder) = tokio::sync::mpsc::channel(1);
        rx_placeholder
    });
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            // discard — the tester is write-only.
        }
    });

    // Build shared attribute set — identical across all routes except for
    // the NLRI payload itself. That keeps per-route CPU to a minimum on
    // the generator side so the RR's scale is what we measure.
    inject_phase(
        &handle.tx,
        PhaseParams {
            count: args.count,
            rate: args.rate,
            batch: args.batch,
        },
        route_params,
        false,
    )
    .await?;

    tracing::info!(
        "inject phase complete: {} routes advertised ({:?})",
        args.count,
        args.route_type
    );

    if args.churn_duration_sec > 0 {
        tracing::info!(
            duration_sec = args.churn_duration_sec,
            rate = args.churn_rate,
            "starting churn phase"
        );
        run_churn(
            &handle.tx,
            PhaseParams {
                count: args.count,
                rate: args.churn_rate,
                batch: args.batch,
            },
            route_params,
            Duration::from_secs(args.churn_duration_sec),
        )
        .await?;
        tracing::info!("churn phase complete");
    }

    tokio::time::sleep(Duration::from_secs(args.linger_sec)).await;
    Ok(())
}

fn validate_workload(args: &Args) -> anyhow::Result<()> {
    anyhow::ensure!(args.batch > 0, "--batch must be greater than zero");
    anyhow::ensure!(
        args.vni <= 0x00ff_ffff,
        "--vni must fit the 24-bit MPLS label field (maximum 16777215)"
    );
    if args.route_type == RouteType::MacIp {
        anyhow::ensure!(
            args.count <= 0x0100_0000,
            "--count exceeds the 16777216 unique MAC addresses available to --route-type mac-ip"
        );
    }
    anyhow::ensure!(
        args.hold_time == 0 || args.hold_time >= 3,
        "--hold-time must be 0 (disabled) or at least 3 seconds"
    );
    if args.churn_duration_sec > 0 {
        anyhow::ensure!(
            args.count > 0,
            "--count must be greater than zero when churn is enabled"
        );
        anyhow::ensure!(
            args.churn_rate > 0,
            "--churn-rate must be greater than zero when churn is enabled"
        );
    }
    Ok(())
}

fn preflight_workload(args: &Args, route_params: RouteParams) -> anyhow::Result<()> {
    if args.count == 0 {
        return Ok(());
    }

    let inject_chunk = effective_chunk_size(args.batch, args.rate, 1).min(args.count);
    let churn_chunk = (args.churn_duration_sec > 0)
        .then(|| effective_chunk_size(args.batch, args.churn_rate, 2).min(args.count));
    let advertised_chunk = churn_chunk.map_or(inject_chunk, |chunk| chunk.max(inject_chunk));
    validate_encoded_chunk(advertised_chunk, route_params, false, "advertisement")?;

    if let Some(churn_chunk) = churn_chunk {
        validate_encoded_chunk(churn_chunk, route_params, true, "churn withdrawal")?;
    }
    Ok(())
}

fn validate_encoded_chunk(
    chunk_count: u32,
    route_params: RouteParams,
    withdraw: bool,
    phase: &str,
) -> anyhow::Result<()> {
    let mut routes = Vec::new();
    for index in 0..chunk_count {
        routes.push(build_route(index, route_params));
        let message = if withdraw {
            build_update(vec![], routes.clone(), route_params)
        } else {
            build_update(routes.clone(), vec![], route_params)
        };
        let encoded_len = encode_message(&message)
            .map_err(|error| {
                anyhow::anyhow!(
                    "{phase} chunk configured for {chunk_count} routes exceeds the standard 4096-byte BGP message limit at route {}: {error}; reduce --batch or the phase rate",
                    routes.len()
                )
            })?
            .len();
        anyhow::ensure!(
            encoded_len <= usize::from(MAX_MESSAGE_LEN),
            "{phase} chunk configured for {chunk_count} routes exceeds the standard 4096-byte BGP message limit at route {} ({encoded_len} bytes); reduce --batch or the phase rate",
            routes.len()
        );
    }
    Ok(())
}

fn make_rd(router_id: Ipv4Addr) -> RouteDistinguisher {
    // RD type 1: 4-byte admin IPv4 + 2-byte assigned. Anchored on the
    // local router-id so each tester's routes have distinct RDs and
    // don't collide at the RR's keyspace. Using type 2 + ASN would
    // collapse all testers to the same RD.
    let ip = router_id.octets();
    RouteDistinguisher::new([0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0x00, 0x01])
}

fn build_type2(index: u32, rd: RouteDistinguisher, ethernet_tag: u32, vni: u32) -> EvpnRoute {
    EvpnRoute::MacIp(EvpnMacIp {
        rd,
        esi: EthernetSegmentIdentifier([0u8; 10]),
        ethernet_tag: EthernetTagId(ethernet_tag),
        mac: MacAddress(synth_mac(index)),
        ip: None,
        label1: MplsLabel::new(vni),
        label2: None,
    })
}

/// Build a Type 1 EAD-per-EVI route. Distinct ESIs per index so the RR's
/// keyspace doesn't collapse, and a non-MAX_ET ethernet-tag (the per-ES
/// discriminator) so the route survives encode → decode as `EadPerEvi`.
fn build_ead_per_evi(
    index: u32,
    rd: RouteDistinguisher,
    base_ethernet_tag: u32,
    vni: u32,
) -> EvpnRoute {
    // Force a non-MAX_ET tag — MAX_ET (0xFFFF_FFFF) would flip the route
    // identity into EadPerEs at the wire boundary.
    let mut tag = base_ethernet_tag.wrapping_add(index).wrapping_add(1);
    if tag == EthernetTagId::MAX_ET.0 {
        tag = tag.wrapping_sub(1);
    }
    EvpnRoute::EadPerEvi(EvpnEadPerEvi {
        rd,
        esi: EthernetSegmentIdentifier(synth_esi(index)),
        ethernet_tag: EthernetTagId(tag),
        label: MplsLabel::new(vni),
    })
}

fn build_route(index: u32, route_params: RouteParams) -> EvpnRoute {
    match route_params.route_type {
        RouteType::MacIp => build_type2(
            index,
            route_params.rd,
            route_params.ethernet_tag,
            route_params.vni,
        ),
        RouteType::EadPerEvi => build_ead_per_evi(
            index,
            route_params.rd,
            route_params.ethernet_tag,
            route_params.vni,
        ),
    }
}

fn build_update(
    routes: Vec<EvpnRoute>,
    withdraws: Vec<EvpnRoute>,
    route_params: RouteParams,
) -> Message {
    use rustbgpd_wire::attribute::MpUnreachNlri;

    let mut attrs: Vec<PathAttribute> = Vec::new();
    if !routes.is_empty() {
        attrs.push(PathAttribute::Origin(Origin::Igp));
        // Empty AS_PATH for this iBGP test peer; four-octet AS support is
        // negotiated by the session and does not alter UPDATE construction.
        attrs.push(PathAttribute::AsPath(AsPath { segments: vec![] }));
        attrs.push(PathAttribute::LocalPref(100));
        attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: v4_next_hop(route_params.router_id),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: routes,
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![],
            rtc_announced: vec![],
        }));
    }
    if !withdraws.is_empty() {
        attrs.push(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: withdraws,
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }));
    }
    let update = UpdateMessage::build(
        &[],
        &[],
        &attrs,
        true,
        false,
        rustbgpd_wire::update::Ipv4UnicastMode::Body,
    );
    Message::Update(update)
}

async fn inject_phase(
    tx: &tokio::sync::mpsc::Sender<Message>,
    phase_params: PhaseParams,
    route_params: RouteParams,
    is_withdraw: bool,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut sent = 0u64;
    let mut idx = 0u32;
    let chunk_size = effective_chunk_size(phase_params.batch, phase_params.rate, 1);

    while idx < phase_params.count {
        let end = chunk_end(idx, phase_params.count, chunk_size);
        let chunk: Vec<EvpnRoute> = (idx..end).map(|i| build_route(i, route_params)).collect();
        let msg = if is_withdraw {
            build_update(vec![], chunk, route_params)
        } else {
            build_update(chunk, vec![], route_params)
        };

        sent += u64::from(end - idx);
        if phase_params.rate > 0 {
            let send_at = start + pacing_offset(sent, phase_params.rate);
            tokio::time::sleep_until(send_at.into()).await;
        }
        if tx.send(msg).await.is_err() {
            anyhow::bail!("send channel closed before inject complete");
        }
        idx = end;
    }
    tracing::info!(
        sent,
        elapsed_ms = start.elapsed().as_millis(),
        "batch injection done"
    );
    Ok(())
}

async fn run_churn(
    tx: &tokio::sync::mpsc::Sender<Message>,
    phase_params: PhaseParams,
    route_params: RouteParams,
    total: Duration,
) -> anyhow::Result<()> {
    anyhow::ensure!(phase_params.count > 0, "cannot churn a zero-route workload");
    anyhow::ensure!(phase_params.batch > 0, "churn batch must be non-zero");
    anyhow::ensure!(phase_params.rate > 0, "churn rate must be non-zero");
    let start_time = Instant::now();
    let deadline = start_time + total;
    let mut idx = 0u32;
    let mut emitted_events = 0u64;
    let chunk_size = effective_chunk_size(phase_params.batch, phase_params.rate, 2);

    loop {
        let start = idx % phase_params.count;
        let end = chunk_end(start, phase_params.count, chunk_size);
        let chunk: Vec<EvpnRoute> = (start..end).map(|i| build_route(i, route_params)).collect();
        let next_event_count = emitted_events + u64::from(end - start) * 2;
        if !scheduled_within_deadline(next_event_count, phase_params.rate, total) {
            break;
        }
        let send_at = start_time + pacing_offset(next_event_count, phase_params.rate);
        debug_assert!(send_at <= deadline);
        tokio::time::sleep_until(send_at.into()).await;
        // Withdraw + re-advertise as two UPDATEs back-to-back.
        let withdraw = build_update(vec![], chunk.clone(), route_params);
        let advertise = build_update(chunk, vec![], route_params);
        if tx.send(withdraw).await.is_err() || tx.send(advertise).await.is_err() {
            anyhow::bail!("send channel closed during churn");
        }
        emitted_events = next_event_count;
        idx = end;
    }
    Ok(())
}

fn pacing_offset(events: u64, rate: u32) -> Duration {
    if rate == 0 {
        return Duration::ZERO;
    }
    let numerator = u128::from(events) * 1_000_000_000;
    let denominator = u128::from(rate);
    let nanos = numerator.div_ceil(denominator).min(u128::from(u64::MAX));
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn effective_chunk_size(batch: u32, rate: u32, events_per_route: u32) -> u32 {
    if rate == 0 {
        batch
    } else {
        batch.min((rate / events_per_route).max(1))
    }
}

fn chunk_end(start: u32, count: u32, chunk_size: u32) -> u32 {
    start.saturating_add(chunk_size).min(count)
}

fn scheduled_within_deadline(events: u64, rate: u32, total: Duration) -> bool {
    pacing_offset(events, rate) <= total
}

#[allow(dead_code)]
fn _unused_ipaddr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            listen: "127.0.0.1:1179".parse().unwrap(),
            local_as: 65_000,
            router_id: Ipv4Addr::new(192, 0, 2, 1),
            count: 10_000,
            rate: 1_000,
            batch: 40,
            vni: 100,
            ethernet_tag: 0,
            churn_duration_sec: 0,
            churn_rate: 1_000,
            linger_sec: 30,
            hold_time: 180,
            route_type: RouteType::MacIp,
        }
    }

    fn route_params(route_type: RouteType) -> RouteParams {
        let router_id = Ipv4Addr::new(192, 0, 2, 1);
        RouteParams {
            vni: 100,
            ethernet_tag: 0,
            router_id,
            rd: make_rd(router_id),
            route_type,
        }
    }

    #[test]
    fn validates_session_only_and_unlimited_injection_modes() {
        let mut input = args();
        input.count = 0;
        input.rate = 0;
        input.hold_time = 0;
        assert!(validate_workload(&input).is_ok());
    }

    #[test]
    fn rejects_unsafe_workload_shapes_before_session_setup() {
        let mut input = args();
        input.batch = 0;
        assert_eq!(
            validate_workload(&input).unwrap_err().to_string(),
            "--batch must be greater than zero"
        );

        input = args();
        input.hold_time = 2;
        assert!(validate_workload(&input).is_err());

        input = args();
        input.count = 0;
        input.churn_duration_sec = 1;
        assert!(validate_workload(&input).is_err());

        input = args();
        input.churn_duration_sec = 1;
        input.churn_rate = 0;
        assert!(validate_workload(&input).is_err());
    }

    #[test]
    fn validates_vni_boundaries() {
        let mut input = args();
        input.vni = 0;
        assert!(validate_workload(&input).is_ok());
        input.vni = 0x00ff_ffff;
        assert!(validate_workload(&input).is_ok());
        input.vni = 0x0100_0000;
        assert!(validate_workload(&input).is_err());
    }

    #[test]
    fn mac_ip_count_is_bounded_by_unique_mac_space() {
        let mut input = args();
        input.count = 0x0100_0000;
        assert!(validate_workload(&input).is_ok());
        input.count = 0x0100_0001;
        assert!(validate_workload(&input).is_err());

        input.route_type = RouteType::EadPerEvi;
        input.count = u32::MAX;
        assert!(validate_workload(&input).is_ok());
    }

    #[test]
    fn encoded_chunk_preflight_accepts_defaults_and_rejects_oversize() {
        let input = args();
        assert!(preflight_workload(&input, route_params(RouteType::MacIp)).is_ok());
        assert!(preflight_workload(&input, route_params(RouteType::EadPerEvi)).is_ok());

        let mut oversized = args();
        oversized.count = 1_000;
        oversized.batch = 1_000;
        oversized.rate = 0;
        let error = preflight_workload(&oversized, route_params(RouteType::MacIp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("advertisement chunk configured for 1000 routes"));
        assert!(error.contains("4096-byte BGP message limit"));
    }

    #[test]
    fn encoded_chunk_preflight_checks_active_churn_withdrawals() {
        let mut input = args();
        input.churn_duration_sec = 1;
        assert!(preflight_workload(&input, route_params(RouteType::MacIp)).is_ok());

        let error = validate_encoded_chunk(
            1_000,
            route_params(RouteType::MacIp),
            true,
            "churn withdrawal",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("churn withdrawal chunk configured for 1000 routes"));
    }

    #[test]
    fn zero_count_skips_encoded_chunk_preflight() {
        let mut input = args();
        input.count = 0;
        input.batch = u32::MAX;
        assert!(preflight_workload(&input, route_params(RouteType::MacIp)).is_ok());
    }

    #[test]
    fn chunk_end_handles_partial_and_u32_boundary_chunks() {
        assert_eq!(chunk_end(80, 100, 40), 100);
        assert_eq!(chunk_end(40, 100, 40), 80);
        assert_eq!(chunk_end(u32::MAX - 5, u32::MAX, 40), u32::MAX);
        assert_eq!(chunk_end(0, u32::MAX, u32::MAX), u32::MAX);
    }

    #[test]
    fn pacing_uses_the_cumulative_event_budget() {
        assert_eq!(pacing_offset(0, 1_000), Duration::ZERO);
        assert_eq!(pacing_offset(40, 1_000), Duration::from_millis(40));
        assert_eq!(pacing_offset(80, 1_000), Duration::from_millis(80));
        assert_eq!(pacing_offset(100, 25), Duration::from_secs(4));
        assert_eq!(pacing_offset(1, 3), Duration::from_nanos(333_333_334));
        assert_eq!(pacing_offset(2, 3), Duration::from_nanos(666_666_667));
        assert_eq!(pacing_offset(3, 3), Duration::from_secs(1));
        assert_eq!(pacing_offset(40, 100_000), Duration::from_micros(400));
    }

    #[test]
    fn zero_rate_has_no_pacing_delay() {
        assert_eq!(pacing_offset(u64::MAX, 0), Duration::ZERO);
    }

    #[test]
    fn effective_chunks_prevent_low_rate_bursts() {
        assert_eq!(effective_chunk_size(40, 10, 1), 10);
        assert_eq!(effective_chunk_size(40, 1, 1), 1);
        assert_eq!(effective_chunk_size(40, 1_000, 1), 40);
        assert_eq!(effective_chunk_size(40, 10, 2), 5);
        assert_eq!(effective_chunk_size(40, 1, 2), 1);
        assert_eq!(effective_chunk_size(40, 0, 1), 40);
    }

    #[test]
    fn churn_suppresses_pairs_beyond_the_total_deadline() {
        assert!(scheduled_within_deadline(2, 2, Duration::from_secs(1)));
        assert!(!scheduled_within_deadline(4, 2, Duration::from_secs(1)));
        assert!(scheduled_within_deadline(1, 0, Duration::ZERO));
    }
}
