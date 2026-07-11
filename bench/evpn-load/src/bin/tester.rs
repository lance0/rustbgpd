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
#![allow(clippy::too_many_lines)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use rustbgpd_evpn_load::{PeerConfig, establish, synth_esi, synth_mac, v4_next_hop};
use rustbgpd_wire::attribute::{AsPath, MpReachNlri, Origin, PathAttribute};
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::evpn::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEvi, EvpnMacIp, EvpnRoute, MacAddress,
    MplsLabel, RouteDistinguisher,
};
use rustbgpd_wire::message::Message;
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
    let rd = make_rd(args.router_id);
    let route_params = RouteParams {
        vni: args.vni,
        ethernet_tag: args.ethernet_tag,
        router_id: args.router_id,
        rd,
        route_type: args.route_type,
    };

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
    let batch_per_sec = if phase_params.rate == 0 {
        u32::MAX
    } else {
        phase_params.rate / phase_params.batch.max(1)
    };
    let mut sent = 0u32;
    let mut idx = 0u32;
    let mut next_tick = Instant::now();
    let tick = if batch_per_sec == 0 {
        Duration::from_millis(1)
    } else {
        Duration::from_millis(1000 / u64::from(batch_per_sec.max(1)))
    };

    while idx < phase_params.count {
        let end = idx
            .saturating_add(phase_params.batch)
            .min(phase_params.count);
        let chunk: Vec<EvpnRoute> = (idx..end)
            .map(|i| match route_params.route_type {
                RouteType::MacIp => build_type2(
                    i,
                    route_params.rd,
                    route_params.ethernet_tag,
                    route_params.vni,
                ),
                RouteType::EadPerEvi => build_ead_per_evi(
                    i,
                    route_params.rd,
                    route_params.ethernet_tag,
                    route_params.vni,
                ),
            })
            .collect();
        let msg = if is_withdraw {
            build_update(vec![], chunk, route_params)
        } else {
            build_update(chunk, vec![], route_params)
        };
        if tx.send(msg).await.is_err() {
            anyhow::bail!("send channel closed before inject complete");
        }
        sent += end - idx;
        idx = end;

        if phase_params.rate > 0 {
            next_tick += tick;
            let now = Instant::now();
            if next_tick > now {
                tokio::time::sleep(next_tick - now).await;
            }
        }
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
    let deadline = Instant::now() + total;
    // `rate` is route-events per second. Each tick of this loop emits
    // 2 * batch events (one withdraw + one re-advertise of the same chunk),
    // so the per-tick budget is `rate / (2 * batch)` ticks per second.
    // Without the factor of 2 the effective churn rate is doubled — the
    // RR sees 2x what the operator configured, which is fine for the
    // M33 reflection-throughput shape but misleading in the report.
    let ops_per_tick = u64::from(phase_params.batch.max(1)) * 2;
    let ticks_per_sec = u64::from(phase_params.rate.max(1)) / ops_per_tick;
    let tick = Duration::from_millis(1000 / ticks_per_sec.max(1));
    let mut idx = 0u32;

    while Instant::now() < deadline {
        let start = idx % phase_params.count;
        let end = start
            .saturating_add(phase_params.batch)
            .min(phase_params.count);
        let chunk: Vec<EvpnRoute> = (start..end)
            .map(|i| match route_params.route_type {
                RouteType::MacIp => build_type2(
                    i,
                    route_params.rd,
                    route_params.ethernet_tag,
                    route_params.vni,
                ),
                RouteType::EadPerEvi => build_ead_per_evi(
                    i,
                    route_params.rd,
                    route_params.ethernet_tag,
                    route_params.vni,
                ),
            })
            .collect();
        // Withdraw + re-advertise as two UPDATEs back-to-back.
        let withdraw = build_update(vec![], chunk.clone(), route_params);
        let advertise = build_update(chunk, vec![], route_params);
        if tx.send(withdraw).await.is_err() || tx.send(advertise).await.is_err() {
            anyhow::bail!("send channel closed during churn");
        }
        idx = end;
        tokio::time::sleep(tick).await;
    }
    Ok(())
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
}
