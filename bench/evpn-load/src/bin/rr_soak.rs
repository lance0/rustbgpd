//! evpn-rr-soak — long-running EVPN route-reflector soak driver.
//!
//! Dials N iBGP route-reflector-client sessions (EVPN only) into a running
//! rustbgpd and holds them for a fixed number of epochs. Each client
//! originates a sliding window of Type 2 (MAC/IP) and Type 5 (IP prefix)
//! routes. Every epoch:
//!
//! - optionally rewrites the live config to the next generation and sends
//!   SIGHUP to the daemon (by exact PID), then verifies one `complete`
//!   reload outcome and no other outcome on `/metrics`;
//! - optionally flaps one client (Cease/Administrative Reset, reconnect,
//!   re-announce) — client 0 never flaps;
//! - shifts every other client's windows (announce new, withdraw old),
//!   paced across the churn phase;
//! - waits until every client's reflected view equals the exact expected
//!   set: every other client's current windows, nothing else.
//!
//! Machine-read stdout lines (the soak runner copies them to cycles.log):
//! `converged (initial) ...`, `reload N issued`, `reload N complete`,
//! `evpn_flap n=K client=I down|up ...`, `evpn_epoch n=E ...`,
//! `evpn_receipt ...`, `evpn_session_lost ...` and `FAIL: ...`.
//!
//! Addressing matches `bench/scale/reloadstall/gen-scenario.py`: client
//! `i` binds `127.1.(i/200).(i%200+1)` and uses BGP identifier
//! `240.1.(i/200).(i%200+1)`, above the daemon's router-id so the inbound
//! connection wins collision resolution against the daemon's active dial.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use rustbgpd_evpn_load::{PeerConfig, establish_stream, synth_mac};
use rustbgpd_wire::attribute::{
    AsPath, ExtendedCommunity, MpReachNlri, MpUnreachNlri, Origin, PathAttribute,
};
use rustbgpd_wire::capability::{Afi, Safi};
use rustbgpd_wire::notification::cease_subcode;
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp,
    EvpnRoute, Ipv4Prefix, MacAddress, Message, MplsLabel, NotificationCode, NotificationMessage,
    RouteDistinguisher, UpdateMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

/// Routes per UPDATE; a Type 2 MAC/IP NLRI is 37 bytes, so 40 fit 4096.
const BATCH: usize = 40;
/// Route Target 64512:100 and the RFC 9012 VXLAN encapsulation community.
const ROUTE_TARGET: u64 = 0x0002_FC00_0000_0064;
const ENCAP_VXLAN: u64 = 0x030C_0000_0000_0008;
const L2_VNI: u32 = 10_100;
const L3_VNI: u32 = 50_000;
const RELOAD_OUTCOMES: [&str; 5] = [
    "complete",
    "known_partial",
    "rejected_no_effect",
    "ignored_in_flight",
    "task_failed",
];

#[derive(Parser, Debug)]
#[command(name = "evpn-rr-soak")]
#[command(about = "EVPN route-reflector soak driver: Type 2/5 churn, client flaps, reloads")]
struct Args {
    /// Daemon passive listener.
    #[arg(long, default_value = "127.0.0.1:1790")]
    daemon: SocketAddr,
    /// Number of route-reflector clients.
    #[arg(long)]
    clients: u32,
    /// Shared iBGP AS (u16, carried in the OPEN `my_as` field).
    #[arg(long, default_value_t = 64512)]
    asn: u16,
    /// Type 2 routes each client advertises at any time.
    #[arg(long)]
    type2: u32,
    /// Type 5 routes each client advertises at any time.
    #[arg(long)]
    type5: u32,
    /// Type 2 routes each client replaces per epoch.
    #[arg(long)]
    shift2: u32,
    /// Type 5 routes each client replaces per epoch.
    #[arg(long)]
    shift5: u32,
    /// Epochs to run after the initial convergence.
    #[arg(long)]
    epochs: u32,
    /// Nominal epoch length.
    #[arg(long)]
    epoch_secs: u64,
    /// Window over which the per-client churn of one epoch is spread.
    #[arg(long)]
    churn_secs: u64,
    /// Bound on post-churn convergence per epoch.
    #[arg(long, default_value_t = 60)]
    converge_cap_secs: u64,
    /// Bound on the initial table convergence.
    #[arg(long, default_value_t = 900)]
    initial_cap_secs: u64,
    /// Flap one client every N epochs (0 disables).
    #[arg(long, default_value_t = 0)]
    flap_every: u32,
    /// Reload every N epochs (0 disables).
    #[arg(long, default_value_t = 0)]
    reload_every: u32,
    /// Daemon PID to SIGHUP (required when reloading).
    #[arg(long)]
    daemon_pid: Option<u32>,
    /// Live config path the daemon reloads.
    #[arg(long)]
    config_live: Option<PathBuf>,
    /// Config generations copied over the live file in turn.
    #[arg(long, num_args = 2)]
    config_gens: Vec<PathBuf>,
    /// Daemon metrics endpoint (reload outcome evidence).
    #[arg(long)]
    metrics: Option<SocketAddr>,
    /// Finish handshake directory: write `ready`, wait for `ack`, then Cease.
    #[arg(long)]
    evidence_dir: Option<PathBuf>,
    /// Bound on waiting for the runner's `ack`.
    #[arg(long, default_value_t = 600)]
    finish_ack_secs: u64,
    /// Bound on a flapped client's reconnect.
    #[arg(long, default_value_t = 120)]
    reestablish_cap_secs: u64,
    /// Hold time advertised in OPEN.
    #[arg(long, default_value_t = 90)]
    hold_time: u16,
}

#[derive(Clone, Copy)]
struct Shape {
    clients: u32,
    type2: u32,
    type5: u32,
    shift2: u32,
    shift5: u32,
}

impl Shape {
    /// Type 2 pool per client; the window slides through it.
    fn pool2(self) -> u32 {
        2 * self.type2
    }
    fn pool5(self) -> u32 {
        2 * self.type5
    }
    fn block(self) -> usize {
        (self.pool2() + self.pool5()) as usize
    }
    fn expected(self) -> u64 {
        u64::from(self.clients - 1) * u64::from(self.type2 + self.type5)
    }
    /// Pool indexes of client windows after `shifts` churn steps.
    fn window2(self, shifts: u64) -> impl Iterator<Item = u32> {
        window(shifts, self.shift2, self.type2, self.pool2())
    }
    fn window5(self, shifts: u64) -> impl Iterator<Item = u32> {
        window(shifts, self.shift5, self.type5, self.pool5())
    }
}

fn window(shifts: u64, shift: u32, width: u32, pool: u32) -> impl Iterator<Item = u32> {
    let start = u32::try_from(shifts * u64::from(shift) % u64::from(pool)).unwrap_or(0);
    (0..width).map(move |j| (start + j) % pool)
}

fn validate(args: &Args) -> anyhow::Result<()> {
    anyhow::ensure!(
        (3..=10_000).contains(&args.clients),
        "--clients must be in 3..=10000"
    );
    anyhow::ensure!(
        args.type2 > 0 && args.type5 > 0,
        "--type2 and --type5 must be positive"
    );
    anyhow::ensure!(
        args.type2 <= 0x0080_0000 && args.type5 <= 0x0020_0000,
        "--type2 must be <= 8388608 and --type5 <= 2097152 (pool encoding)"
    );
    anyhow::ensure!(
        (1..=args.type2).contains(&args.shift2) && (1..=args.type5).contains(&args.shift5),
        "--shift2/--shift5 must be in 1..=window"
    );
    anyhow::ensure!(args.epoch_secs > 0, "--epoch-secs must be positive");
    anyhow::ensure!(
        args.churn_secs < args.epoch_secs,
        "--churn-secs must be shorter than --epoch-secs"
    );
    if args.reload_every > 0 {
        anyhow::ensure!(
            args.daemon_pid.is_some()
                && args.config_live.is_some()
                && args.config_gens.len() == 2
                && args.metrics.is_some(),
            "--reload-every needs --daemon-pid, --config-live, --config-gens A B and --metrics"
        );
    }
    anyhow::ensure!(
        args.hold_time == 0 || args.hold_time >= 3,
        "--hold-time must be 0 or at least 3"
    );
    Ok(())
}

fn octets(i: u32) -> (u8, u8) {
    (
        u8::try_from(i / 200).unwrap_or(u8::MAX),
        u8::try_from(i % 200 + 1).unwrap_or(u8::MAX),
    )
}

fn source_addr(i: u32) -> Ipv4Addr {
    let (x, y) = octets(i);
    Ipv4Addr::new(127, 1, x, y)
}

fn router_id(i: u32) -> Ipv4Addr {
    let (x, y) = octets(i);
    Ipv4Addr::new(240, 1, x, y)
}

fn next_hop(i: u32) -> IpAddr {
    let (x, y) = octets(i);
    IpAddr::V4(Ipv4Addr::new(10, 1, x, y))
}

fn rd(i: u32) -> RouteDistinguisher {
    let (x, y) = octets(i);
    RouteDistinguisher::new([0, 1, 240, 1, x, y, 0, 1])
}

fn rd_origin(rd: RouteDistinguisher, clients: u32) -> Option<u32> {
    let [t0, t1, a, b, x, y, v0, v1] = rd.octets();
    if [t0, t1, a, b, v0, v1] != [0, 1, 240, 1, 0, 1] || !(1..=200).contains(&y) {
        return None;
    }
    let origin = u32::from(x) * 200 + u32::from(y) - 1;
    (origin < clients).then_some(origin)
}

fn type2_ip(idx: u32) -> Ipv4Addr {
    let [_, a, b, c] = idx.to_be_bytes();
    Ipv4Addr::new(10, a, b, c)
}

fn type5_prefix(idx: u32) -> Ipv4Prefix {
    let [_, a, b, c] = idx.to_be_bytes();
    Ipv4Prefix::new(Ipv4Addr::new(100, 64 + a, b, c), 32)
}

fn type2_route(origin: u32, idx: u32) -> EvpnRoute {
    EvpnRoute::MacIp(EvpnMacIp {
        rd: rd(origin),
        esi: EthernetSegmentIdentifier([0; 10]),
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress(synth_mac(idx)),
        ip: Some(IpAddr::V4(type2_ip(idx))),
        label1: MplsLabel::new(L2_VNI),
        label2: None,
    })
}

fn type5_route(origin: u32, idx: u32) -> EvpnRoute {
    EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
        rd: rd(origin),
        esi: EthernetSegmentIdentifier([0; 10]),
        ethernet_tag: EthernetTagId(0),
        prefix: EvpnIpPrefixValue::V4(type5_prefix(idx)),
        gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        label: MplsLabel::new(L3_VNI),
    })
}

/// Map a received route to its (origin client, bit within the origin's
/// block); `None` for anything this driver never originates.
fn classify(route: &EvpnRoute, shape: Shape) -> Option<(u32, usize)> {
    match route {
        EvpnRoute::MacIp(r) => {
            let origin = rd_origin(r.rd, shape.clients)?;
            let [m0, m1, m2, a, b, c] = r.mac.0;
            let idx = u32::from_be_bytes([0, a, b, c]);
            let exact = [m0, m1, m2] == [2, 0, 0]
                && idx < shape.pool2()
                && r.ethernet_tag == EthernetTagId(0)
                && r.ip == Some(IpAddr::V4(type2_ip(idx)));
            exact.then_some((origin, idx as usize))
        }
        EvpnRoute::IpPrefix(r) => {
            let origin = rd_origin(r.rd, shape.clients)?;
            let EvpnIpPrefixValue::V4(prefix) = r.prefix else {
                return None;
            };
            let [p0, p1, b, c] = prefix.addr.octets();
            if p0 != 100 || !(64..128).contains(&p1) || prefix.len != 32 {
                return None;
            }
            let idx = u32::from_be_bytes([0, p1 - 64, b, c]);
            (idx < shape.pool5()).then_some((origin, (shape.pool2() + idx) as usize))
        }
        _ => None,
    }
}

fn build_update(origin: u32, announce: Vec<EvpnRoute>, withdraw: Vec<EvpnRoute>) -> Message {
    let mut attrs = Vec::new();
    if !announce.is_empty() {
        attrs.push(PathAttribute::Origin(Origin::Igp));
        attrs.push(PathAttribute::AsPath(AsPath { segments: vec![] }));
        attrs.push(PathAttribute::LocalPref(100));
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::new(ROUTE_TARGET),
            ExtendedCommunity::new(ENCAP_VXLAN),
        ]));
        attrs.push(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: next_hop(origin),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: announce,
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![],
            rtc_announced: vec![],
        })));
    }
    if !withdraw.is_empty() {
        attrs.push(PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: withdraw,
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![],
            rtc_withdrawn: vec![],
        })));
    }
    Message::Update(UpdateMessage::build(
        &[],
        &[],
        &attrs,
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    ))
}

fn updates(origin: u32, routes: &[EvpnRoute], withdraw: bool) -> Vec<Message> {
    routes
        .chunks(BATCH)
        .map(|chunk| {
            if withdraw {
                build_update(origin, vec![], chunk.to_vec())
            } else {
                build_update(origin, chunk.to_vec(), vec![])
            }
        })
        .collect()
}

/// One client's reflected view: a bit per (origin, pool index).
struct View {
    bits: Vec<u64>,
    live: u64,
    invalid: u64,
    parse_errors: u64,
    self_reflected: u64,
}

impl View {
    fn new(shape: Shape) -> Self {
        let total = shape.clients as usize * shape.block();
        Self {
            bits: vec![0; total.div_ceil(64)],
            live: 0,
            invalid: 0,
            parse_errors: 0,
            self_reflected: 0,
        }
    }

    fn has(&self, bit: usize) -> bool {
        self.bits[bit / 64] & (1 << (bit % 64)) != 0
    }

    fn apply(&mut self, me: u32, shape: Shape, route: &EvpnRoute, present: bool) {
        let Some((origin, offset)) = classify(route, shape) else {
            self.invalid += 1;
            return;
        };
        if origin == me {
            self.self_reflected += 1;
            return;
        }
        let bit = origin as usize * shape.block() + offset;
        let mask = 1u64 << (bit % 64);
        let word = &mut self.bits[bit / 64];
        if present && *word & mask == 0 {
            *word |= mask;
            self.live += 1;
        } else if !present && *word & mask != 0 {
            *word &= !mask;
            self.live -= 1;
        }
    }
}

struct Client {
    index: u32,
    tx: Option<mpsc::Sender<Message>>,
    view: Arc<Mutex<View>>,
    up: Arc<AtomicBool>,
    expect_down: Arc<AtomicBool>,
    shifts: u64,
}

fn wall_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros())
}

fn fail(message: &str) -> ! {
    println!("FAIL: {message}");
    std::process::exit(1)
}

async fn dial(args: &Args, i: u32) -> anyhow::Result<rustbgpd_evpn_load::PeerHandle> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(IpAddr::V4(source_addr(i)), 0))?;
    let stream: TcpStream = socket.connect(args.daemon).await?;
    stream.set_nodelay(true)?;
    let cfg = PeerConfig {
        listen: args.daemon,
        local_as: u32::from(args.asn),
        router_id: router_id(i),
        hold_time: args.hold_time,
        families: vec![(Afi::L2Vpn, Safi::Evpn)],
    };
    Ok(establish_stream(stream, cfg).await?)
}

async fn connect(
    args: &Args,
    shape: Shape,
    client: &mut Client,
    lost: &Arc<AtomicBool>,
    cap: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + cap;
    let handle = loop {
        match dial(args, client.index).await {
            Ok(handle) => break handle,
            Err(error) if Instant::now() < deadline => {
                tracing::debug!(client = client.index, %error, "dial retry");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => anyhow::bail!("client {} did not establish: {error}", client.index),
        }
    };
    let view = Arc::new(Mutex::new(View::new(shape)));
    let up = Arc::new(AtomicBool::new(true));
    let expect_down = Arc::new(AtomicBool::new(false));
    let mut rx = handle.rx;
    let (me, task_view, task_up, task_expect, task_lost) = (
        client.index,
        view.clone(),
        up.clone(),
        expect_down.clone(),
        lost.clone(),
    );
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Message::Update(update) = message else {
                continue;
            };
            let parsed = update.parse(true, false, &[]);
            let mut view = task_view
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Ok(parsed) = parsed else {
                view.parse_errors += 1;
                continue;
            };
            for attr in &parsed.attributes {
                match attr {
                    PathAttribute::MpReachNlri(mp) if mp.safi == Safi::Evpn => {
                        for route in &mp.evpn_announced {
                            view.apply(me, shape, route, true);
                        }
                    }
                    PathAttribute::MpUnreachNlri(mp) if mp.safi == Safi::Evpn => {
                        for route in &mp.evpn_withdrawn {
                            view.apply(me, shape, route, false);
                        }
                    }
                    _ => {}
                }
            }
        }
        task_up.store(false, Ordering::SeqCst);
        if !task_expect.load(Ordering::SeqCst) {
            println!("evpn_session_lost client={me} wall_us={}", wall_us());
            task_lost.store(true, Ordering::SeqCst);
        }
    });
    client.tx = Some(handle.tx);
    client.view = view;
    client.up = up;
    client.expect_down = expect_down;
    Ok(())
}

async fn send_all(client: &Client, messages: Vec<Message>) {
    let Some(tx) = &client.tx else {
        fail(&format!("client {} has no session", client.index));
    };
    for message in messages {
        if tx.send(message).await.is_err() {
            fail(&format!("client {} writer closed", client.index));
        }
    }
}

async fn announce_window(shape: Shape, client: &Client) {
    let i = client.index;
    let routes: Vec<EvpnRoute> = shape
        .window2(client.shifts)
        .map(|idx| type2_route(i, idx))
        .chain(shape.window5(client.shifts).map(|idx| type5_route(i, idx)))
        .collect();
    send_all(client, updates(i, &routes, false)).await;
}

/// Replace the oldest `shift` routes of each type with the next ones.
async fn churn(shape: Shape, client: &mut Client) -> u64 {
    let i = client.index;
    let pool2 = shape.pool2();
    let pool5 = shape.pool5();
    let start2 = shape.window2(client.shifts).next().unwrap_or(0);
    let start5 = shape.window5(client.shifts).next().unwrap_or(0);
    let new: Vec<EvpnRoute> = (0..shape.shift2)
        .map(|j| type2_route(i, (start2 + shape.type2 + j) % pool2))
        .chain((0..shape.shift5).map(|j| type5_route(i, (start5 + shape.type5 + j) % pool5)))
        .collect();
    let old: Vec<EvpnRoute> = (0..shape.shift2)
        .map(|j| type2_route(i, (start2 + j) % pool2))
        .chain((0..shape.shift5).map(|j| type5_route(i, (start5 + j) % pool5)))
        .collect();
    let mut messages = updates(i, &new, false);
    messages.extend(updates(i, &old, true));
    send_all(client, messages).await;
    client.shifts += 1;
    u64::from(shape.shift2 + shape.shift5) * 2
}

struct Check {
    receivers: u32,
    min_live: u64,
    max_live: u64,
    exact: bool,
    invalid: u64,
    parse_errors: u64,
    self_reflected: u64,
}

fn check(shape: Shape, clients: &[Client]) -> Check {
    let expected = shape.expected();
    let mut out = Check {
        receivers: 0,
        min_live: u64::MAX,
        max_live: 0,
        exact: true,
        invalid: 0,
        parse_errors: 0,
        self_reflected: 0,
    };
    let windows: Vec<(Vec<u32>, Vec<u32>)> = clients
        .iter()
        .map(|c| {
            (
                shape.window2(c.shifts).collect(),
                shape.window5(c.shifts).collect(),
            )
        })
        .collect();
    for client in clients {
        let view = client
            .view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if client.up.load(Ordering::SeqCst) {
            out.receivers += 1;
        } else {
            out.exact = false;
        }
        out.min_live = out.min_live.min(view.live);
        out.max_live = out.max_live.max(view.live);
        out.invalid += view.invalid;
        out.parse_errors += view.parse_errors;
        out.self_reflected += view.self_reflected;
        if view.live != expected {
            out.exact = false;
        }
        // Equal count plus every expected bit set is set equality.
        if out.exact {
            for (origin, (w2, w5)) in windows.iter().enumerate() {
                if u32::try_from(origin).ok() == Some(client.index) {
                    continue;
                }
                let base = origin * shape.block();
                let all = w2.iter().all(|&idx| view.has(base + idx as usize))
                    && w5
                        .iter()
                        .all(|&idx| view.has(base + (shape.pool2() + idx) as usize));
                if !all {
                    out.exact = false;
                    break;
                }
            }
        }
    }
    out
}

/// Poll until every client's reflected view is exact, or the cap expires.
async fn converge(
    shape: Shape,
    clients: &[Client],
    lost: &AtomicBool,
    cap: Duration,
) -> (bool, Check, u128) {
    let started = Instant::now();
    loop {
        if lost.load(Ordering::SeqCst) {
            fail("a client session was lost unexpectedly");
        }
        let result = check(shape, clients);
        let ok = result.exact
            && result.invalid == 0
            && result.parse_errors == 0
            && result.receivers == shape.clients;
        if ok || started.elapsed() >= cap {
            return (ok, result, started.elapsed().as_millis());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn fetch_metrics(addr: SocketAddr) -> anyhow::Result<String> {
    let mut stream =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await??;
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut body)).await??;
    let text = String::from_utf8(body)?;
    anyhow::ensure!(text.starts_with("HTTP/1."), "not an HTTP response");
    anyhow::ensure!(
        text.split(' ').nth(1) == Some("200"),
        "metrics status is not 200"
    );
    Ok(text)
}

fn reload_outcomes(body: &str) -> anyhow::Result<[u64; 5]> {
    let mut out = [0; 5];
    for (slot, outcome) in out.iter_mut().zip(RELOAD_OUTCOMES) {
        let series = format!("bgp_sighup_reload_outcomes_total{{outcome=\"{outcome}\"}} ");
        let line = body
            .lines()
            .find(|line| line.starts_with(&series))
            .ok_or_else(|| anyhow::anyhow!("missing {series}"))?;
        *slot = line[series.len()..].trim().parse::<u64>()?;
    }
    Ok(out)
}

async fn issue_reload(args: &Args, n: u32) -> [u64; 5] {
    let metrics = args
        .metrics
        .unwrap_or_else(|| fail("reload without --metrics"));
    let before = fetch_metrics(metrics)
        .await
        .and_then(|body| reload_outcomes(&body))
        .unwrap_or_else(|error| fail(&format!("reload {n} baseline evidence: {error}")));
    let gen_path = &args.config_gens[(n as usize - 1) % 2];
    let live = args.config_live.as_deref().unwrap_or_else(|| Path::new(""));
    if let Err(error) = std::fs::copy(gen_path, live) {
        fail(&format!("reload {n} config copy: {error}"));
    }
    let pid = args
        .daemon_pid
        .unwrap_or_else(|| fail("reload without --daemon-pid"));
    let status = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status();
    if !status.is_ok_and(|s| s.success()) {
        fail(&format!("reload {n} could not deliver SIGHUP to {pid}"));
    }
    println!("reload {n} issued");
    before
}

async fn settle_reload(args: &Args, n: u32, before: [u64; 5]) {
    let metrics = args
        .metrics
        .unwrap_or_else(|| fail("reload without --metrics"));
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let after = fetch_metrics(metrics)
            .await
            .and_then(|body| reload_outcomes(&body))
            .unwrap_or_else(|error| fail(&format!("reload {n} settlement evidence: {error}")));
        for (index, outcome) in RELOAD_OUTCOMES.iter().enumerate() {
            let Some(delta) = after[index].checked_sub(before[index]) else {
                fail(&format!("reload {n}: outcome counter {outcome} decreased"));
            };
            if index > 0 && delta > 0 {
                fail(&format!("reload {n}: daemon outcome {outcome} (+{delta})"));
            }
            if index == 0 && delta > 1 {
                fail(&format!("reload {n}: multiple completions for one SIGHUP"));
            }
        }
        if after[0] > before[0] {
            println!("reload {n} complete");
            return;
        }
        if Instant::now() >= deadline {
            fail(&format!("reload {n} did not complete within 120 s"));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn cease(subcode: u8) -> Message {
    Message::Notification(NotificationMessage::new(
        NotificationCode::Cease,
        subcode,
        bytes::Bytes::new(),
    ))
}

async fn wait_down(client: &Client, cap: Duration) -> bool {
    let deadline = Instant::now() + cap;
    while client.up.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

async fn flap(args: &Args, shape: Shape, client: &mut Client, n: u32, lost: &Arc<AtomicBool>) {
    let i = client.index;
    client.expect_down.store(true, Ordering::SeqCst);
    let started = Instant::now();
    if let Some(tx) = client.tx.take() {
        let _ = tx.send(cease(cease_subcode::ADMINISTRATIVE_RESET)).await;
    }
    println!("evpn_flap n={n} client={i} down wall_us={}", wall_us());
    if !wait_down(client, Duration::from_secs(30)).await {
        fail(&format!("flap {n}: client {i} session did not close"));
    }
    let cap = Duration::from_secs(args.reestablish_cap_secs);
    if let Err(error) = connect(args, shape, client, lost, cap).await {
        fail(&format!("flap {n}: {error}"));
    }
    announce_window(shape, client).await;
    println!(
        "evpn_flap n={n} client={i} up wall_us={} reestablish_ms={}",
        wall_us(),
        started.elapsed().as_millis()
    );
}

async fn finish(args: &Args, clients: &mut [Client]) {
    if let Some(dir) = &args.evidence_dir {
        if let Err(error) = std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::write(dir.join("ready"), b"ready\n"))
        {
            fail(&format!("finish handshake: {error}"));
        }
        let deadline = Instant::now() + Duration::from_secs(args.finish_ack_secs);
        while !dir.join("ack").is_file() {
            if Instant::now() >= deadline {
                fail("finish handshake: no ack");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    for client in clients.iter_mut() {
        client.expect_down.store(true, Ordering::SeqCst);
        if let Some(tx) = client.tx.take() {
            let _ = tx.send(cease(cease_subcode::ADMINISTRATIVE_SHUTDOWN)).await;
        }
    }
    for client in clients.iter() {
        if !wait_down(client, Duration::from_secs(30)).await {
            fail(&format!(
                "client {} did not close after Cease",
                client.index
            ));
        }
    }
}

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "the soak schedule reads top to bottom in one entrypoint"
)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    let args = Args::parse();
    validate(&args)?;
    let shape = Shape {
        clients: args.clients,
        type2: args.type2,
        type5: args.type5,
        shift2: args.shift2,
        shift5: args.shift5,
    };
    let lost = Arc::new(AtomicBool::new(false));
    let mut clients: Vec<Client> = (0..args.clients)
        .map(|index| Client {
            index,
            tx: None,
            view: Arc::new(Mutex::new(View::new(shape))),
            up: Arc::new(AtomicBool::new(false)),
            expect_down: Arc::new(AtomicBool::new(false)),
            shifts: 0,
        })
        .collect();

    let started = Instant::now();
    let initial_cap = Duration::from_secs(args.initial_cap_secs);
    for client in &mut clients {
        connect(&args, shape, client, &lost, initial_cap).await?;
    }
    for client in &clients {
        announce_window(shape, client).await;
    }
    let (ok, result, _) = converge(shape, &clients, &lost, initial_cap).await;
    if !ok {
        fail(&format!(
            "initial convergence: receivers={} min_live={} max_live={} expected={} invalid={} parse_errors={}",
            result.receivers,
            result.min_live,
            result.max_live,
            shape.expected(),
            result.invalid,
            result.parse_errors
        ));
    }
    println!(
        "converged (initial) clients={} expected={} ms={}",
        args.clients,
        shape.expected(),
        started.elapsed().as_millis()
    );

    let epoch = Duration::from_secs(args.epoch_secs);
    let churn_window = Duration::from_secs(args.churn_secs);
    let converge_cap = Duration::from_secs(args.converge_cap_secs);
    let (mut flaps, mut reloads, mut converged_epochs) = (0u32, 0u32, 0u32);
    let schedule = Instant::now();
    for n in 1..=args.epochs {
        let t0 = (schedule + epoch * (n - 1)).max(Instant::now());
        tokio::time::sleep_until(t0.into()).await;
        let reload = (args.reload_every > 0 && n % args.reload_every == 0).then(|| {
            reloads += 1;
            reloads
        });
        let reload_before = match reload {
            Some(r) => Some(issue_reload(&args, r).await),
            None => None,
        };
        let flapped = if args.flap_every > 0 && n % args.flap_every == 0 {
            flaps += 1;
            // Client 0 is the management-plane query subject and never flaps.
            let target = 1 + (flaps - 1) % (args.clients - 1);
            flap(&args, shape, &mut clients[target as usize], flaps, &lost).await;
            Some(target)
        } else {
            None
        };
        let mut churned = 0;
        for (k, client) in clients.iter_mut().enumerate() {
            if Some(client.index) == flapped {
                continue;
            }
            let offset = churn_window * u32::try_from(k)? / args.clients;
            tokio::time::sleep_until((t0 + offset).into()).await;
            churned += churn(shape, client).await;
        }
        if let (Some(r), Some(before)) = (reload, reload_before) {
            settle_reload(&args, r, before).await;
        }
        let (ok, result, converge_ms) = converge(shape, &clients, &lost, converge_cap).await;
        converged_epochs += u32::from(ok);
        println!(
            "evpn_epoch n={n} receivers={} expected={} min_live={} max_live={} converged={} \
             converge_ms={converge_ms} churn_events={churned} flap_client={} reload={} \
             invalid={} parse_errors={} self_reflected={}",
            result.receivers,
            shape.expected(),
            result.min_live,
            result.max_live,
            u8::from(ok),
            flapped.map_or(-1, i64::from),
            reload.unwrap_or(0),
            result.invalid,
            result.parse_errors,
            result.self_reflected,
        );
    }
    // Hold the sessions to the end of the nominal window so the sampled
    // window covers the whole planned duration.
    tokio::time::sleep_until((schedule + epoch * args.epochs).into()).await;
    if lost.load(Ordering::SeqCst) {
        fail("a client session was lost unexpectedly");
    }
    let terminal = check(shape, &clients);
    println!(
        "evpn_receipt clients={} expected={} epochs={} converged_epochs={converged_epochs} \
         flaps={flaps} reloads={reloads} receivers={} min_live={} max_live={} invalid={} \
         parse_errors={} self_reflected={}",
        args.clients,
        shape.expected(),
        args.epochs,
        terminal.receivers,
        terminal.min_live,
        terminal.max_live,
        terminal.invalid,
        terminal.parse_errors,
        terminal.self_reflected,
    );
    finish(&args, &mut clients).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> Shape {
        Shape {
            clients: 450,
            type2: 300,
            type5: 200,
            shift2: 30,
            shift5: 7,
        }
    }

    #[test]
    fn originated_routes_classify_back_to_their_origin_and_slot() {
        let s = shape();
        for origin in [0, 199, 200, 449] {
            for idx in [0, 1, s.pool2() - 1] {
                assert_eq!(
                    classify(&type2_route(origin, idx), s),
                    Some((origin, idx as usize))
                );
            }
            for idx in [0, 255, s.pool5() - 1] {
                assert_eq!(
                    classify(&type5_route(origin, idx), s),
                    Some((origin, (s.pool2() + idx) as usize))
                );
            }
        }
    }

    #[test]
    fn foreign_and_out_of_pool_routes_are_invalid() {
        let s = shape();
        assert_eq!(classify(&type2_route(450, 0), s), None);
        assert_eq!(classify(&type2_route(0, s.pool2()), s), None);
        assert_eq!(classify(&type5_route(0, s.pool5()), s), None);
        let EvpnRoute::MacIp(mut wrong_ip) = type2_route(1, 5) else {
            unreachable!()
        };
        wrong_ip.ip = Some(IpAddr::V4(type2_ip(6)));
        assert_eq!(classify(&EvpnRoute::MacIp(wrong_ip), s), None);
    }

    #[test]
    fn windows_slide_through_the_pool_and_wrap() {
        let s = Shape {
            clients: 3,
            type2: 4,
            type5: 2,
            shift2: 3,
            shift5: 1,
        };
        assert_eq!(s.window2(0).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(s.window2(1).collect::<Vec<_>>(), [3, 4, 5, 6]);
        assert_eq!(s.window2(2).collect::<Vec<_>>(), [6, 7, 0, 1]);
        assert_eq!(s.window5(3).collect::<Vec<_>>(), [3, 0]);
    }

    #[test]
    fn view_tracks_set_semantics_and_rejects_self_and_foreign() {
        let s = shape();
        let mut view = View::new(s);
        view.apply(1, s, &type2_route(2, 7), true);
        view.apply(1, s, &type2_route(2, 7), true);
        assert_eq!(view.live, 1);
        view.apply(1, s, &type2_route(1, 7), true);
        assert_eq!((view.live, view.self_reflected), (1, 1));
        view.apply(1, s, &type5_route(450, 0), true);
        assert_eq!(view.invalid, 1);
        view.apply(1, s, &type2_route(2, 7), false);
        view.apply(1, s, &type2_route(2, 7), false);
        assert_eq!(view.live, 0);
    }

    #[test]
    fn full_batches_fit_the_standard_message_limit() {
        let routes: Vec<EvpnRoute> = (0..40u32).map(|i| type2_route(449, i)).collect();
        let encoded =
            rustbgpd_wire::encode_message(&build_update(449, routes.clone(), vec![])).unwrap();
        assert!(encoded.len() <= 4096);
        let encoded = rustbgpd_wire::encode_message(&build_update(449, vec![], routes)).unwrap();
        assert!(encoded.len() <= 4096);
    }

    #[test]
    fn reload_outcomes_require_every_series() {
        let body = RELOAD_OUTCOMES
            .iter()
            .map(|o| format!("bgp_sighup_reload_outcomes_total{{outcome=\"{o}\"}} 3"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(reload_outcomes(&body).unwrap(), [3; 5]);
        let missing = body.replace("task_failed", "other");
        assert!(reload_outcomes(&missing).is_err());
    }
}
