//! ADR-0113 outbound prefix-limit integration receipt harness.
//!
//! Four real BGP stub sessions dial a running rustbgpd over loopback TCP and
//! exchange real OPEN/KEEPALIVE/UPDATE messages encoded and decoded by
//! `crates/wire`. One stub is the route source; the other three are observers
//! whose received NLRI is the wire-side truth this receipt reports. The
//! observers are deliberately shaped so one limited peer rides the shared
//! update-group fanout and another takes the private per-peer path:
//!
//! | stub | role | limits | distribution path |
//! |---|---|---|---|
//! | 0 | route source | none | grouped |
//! | 1 | peer-group member, inherits both maxima | group | grouped |
//! | 2 | unlimited sibling in the same update group | none | grouped |
//! | 3 | per-client-best peer, neighbor-level maxima | neighbor | private |
//!
//! Phases: converge -> assert the caps hold on the wire -> SIGHUP a lowering
//! below current usage and assert it is rejected with wire state intact ->
//! SIGHUP a raise and assert the recovery resync fills the new capacity.
//!
//! Every assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line, and a
//! machine-readable summary is written to `<out_dir>/summary.json`. A failed
//! check exits 1; an operational failure (session, timeout, tooling) exits 2.
//!
//! Usage:
//!   outboundlimits <daemon_port> <daemon_pid> <rbgp_bin> <grpc_addr> \
//!       <metrics_addr> <config_live> <config_lower> <config_raise> <out_dir>
//!
//! Shape pinned in docs/perf/outbound-prefix-limits-2026-07.md.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustbgpd_wire::attribute::MpReachNlri;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::nlri::{NlriEntry, Prefix};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Pinned fleet shape. The receipt discloses these exact numbers; they are
// constants rather than arguments so a published row cannot describe a
// different run than the one the driver performed.
// ---------------------------------------------------------------------------

/// Stub sessions: source + limited grouped member + unlimited sibling +
/// limited private peer.
const PEERS: usize = 4;
const SOURCE: usize = 0;
const GROUPED_CAPPED: usize = 1;
const GROUPED_SIBLING: usize = 2;
const PRIVATE_CAPPED: usize = 3;

/// IPv4 and IPv6 unicast prefixes the source originates.
const V4_ROUTES: usize = 12;
const V6_ROUTES: usize = 6;

/// Configured maxima in the starting config (`config_live`).
const V4_LIMIT: usize = 8;
const V6_LIMIT: usize = 4;

const HOLD_TIME: u16 = 180;
/// Longest wait for a convergence predicate before the run fails.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(60);
/// Quiet window after a predicate holds, so a late UPDATE cannot be mistaken
/// for a settled state. Also the window a rejected reload gets to prove it
/// changed nothing.
const SETTLE: Duration = Duration::from_secs(5);

fn peer_addr(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 9, 0, u8::try_from(i + 1).expect("peer index fits"))
}

fn peer_asn(i: usize) -> u32 {
    64601 + u32::try_from(i).expect("peer index fits")
}

fn peer_role(i: usize) -> &'static str {
    match i {
        SOURCE => "route-source",
        GROUPED_CAPPED => "grouped-capped-member",
        GROUPED_SIBLING => "grouped-unlimited-sibling",
        _ => "private-capped-peer",
    }
}

fn v4_prefix(i: usize) -> Ipv4Prefix {
    Ipv4Prefix::new(
        Ipv4Addr::new(20, 0, u8::try_from(i).expect("route index fits"), 0),
        24,
    )
}

fn v6_prefix(i: usize) -> Ipv6Prefix {
    Ipv6Prefix::new(
        Ipv6Addr::new(
            0x2001,
            0x0db8,
            0,
            u16::try_from(i).expect("route index fits"),
            0,
            0,
            0,
            0,
        ),
        64,
    )
}

// ---------------------------------------------------------------------------
// Per-observer wire state.
// ---------------------------------------------------------------------------

/// What one stub has actually seen on the wire. `v4`/`v6` are the currently
/// advertised sets (announcements add, withdrawals remove), which is the
/// quantity ADR-0113's maxima bound. The cumulative counters exist so a phase
/// can assert *no* churn reached a peer, which a set snapshot cannot show.
#[derive(Default)]
struct Wire {
    v4: HashSet<Ipv4Prefix>,
    v6: HashSet<Ipv6Prefix>,
    announced_nlri: u64,
    withdrawn_nlri: u64,
    updates: u64,
}

struct Obs {
    wire: Mutex<Wire>,
    established: AtomicBool,
    decode_errors: AtomicU64,
}

impl Obs {
    fn new() -> Self {
        Self {
            wire: Mutex::new(Wire::default()),
            established: AtomicBool::new(false),
            decode_errors: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> (usize, usize, u64, u64, u64) {
        let wire = self.wire.lock().expect("wire state lock");
        (
            wire.v4.len(),
            wire.v6.len(),
            wire.announced_nlri,
            wire.withdrawn_nlri,
            wire.updates,
        )
    }
}

struct Ctx {
    daemon: SocketAddr,
    obs: Vec<Obs>,
}

// ---------------------------------------------------------------------------
// Session establishment.
// ---------------------------------------------------------------------------

fn source_attrs_v4() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(SOURCE)])],
        }),
        // A 127/8 NEXT_HOP is rejected with UPDATE error subcode 8, so the
        // source uses a synthetic off-loopback address. Observers never
        // resolve it.
        PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 1)),
    ]
}

fn mp_reach_v6(prefixes: &[Ipv6Prefix]) -> MpReachNlri {
    MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 1)),
        link_local_next_hop: None,
        announced: prefixes
            .iter()
            .map(|prefix| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(*prefix),
            })
            .collect(),
        flowspec_announced: Vec::new(),
        evpn_announced: Vec::new(),
        bgpls_announced: Vec::new(),
        vpn_announced: Vec::new(),
        labeled_announced: Vec::new(),
        rtc_announced: Vec::new(),
    }
}

/// The source's full table as two UPDATEs: one legacy-body IPv4 message and
/// one `MP_REACH_NLRI` IPv6 message.
fn source_table() -> Vec<Message> {
    let v4: Vec<Ipv4NlriEntry> = (0..V4_ROUTES)
        .map(|i| Ipv4NlriEntry {
            path_id: 0,
            prefix: v4_prefix(i),
        })
        .collect();
    let v6: Vec<Ipv6Prefix> = (0..V6_ROUTES).map(v6_prefix).collect();

    let mut v6_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(SOURCE)])],
        }),
    ];
    v6_attrs.push(PathAttribute::MpReachNlri(mp_reach_v6(&v6)));

    vec![
        Message::Update(UpdateMessage::build(
            &v4,
            &[],
            &source_attrs_v4(),
            true,
            false,
            Ipv4UnicastMode::Body,
        )),
        Message::Update(UpdateMessage::build(
            &[],
            &[],
            &v6_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        )),
    ]
}

async fn establish(ctx: Arc<Ctx>, i: usize) -> Result<mpsc::Sender<Message>, String> {
    let local = peer_addr(i);
    let sock = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    sock.bind(SocketAddr::new(local.into(), 0))
        .map_err(|e| format!("bind {local}: {e}"))?;
    let mut stream = sock
        .connect(ctx.daemon)
        .await
        .map_err(|e| format!("connect from {local}: {e}"))?;
    stream.set_nodelay(true).ok();

    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(peer_asn(i)).expect("stub ASN fits two octets"),
        hold_time: HOLD_TIME,
        // Higher than the daemon's router-id so RFC 6286 collision
        // resolution keeps this inbound connection.
        bgp_identifier: Ipv4Addr::new(240, 9, 0, u8::try_from(i + 1).expect("peer index fits")),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: peer_asn(i) },
            Capability::RouteRefresh,
        ],
    };
    let bytes = encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("open write: {e}"))?;

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN) {
            if buf.len() >= usize::from(total) {
                let mut body = buf.split_to(usize::from(total)).freeze();
                match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(Message::Open(_)) => break,
                    Ok(Message::Notification(n)) => {
                        return Err(format!(
                            "NOTIFICATION during open: {:?}/{}",
                            n.code, n.subcode
                        ))
                    }
                    Ok(_) => continue,
                    Err(e) => return Err(format!("decode during open: {e}")),
                }
            }
        }
        let mut tmp = [0u8; 4096];
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("closed before OPEN".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let keepalive = encode_message(&Message::Keepalive).expect("keepalive encodes");
    stream
        .write_all(&keepalive)
        .await
        .map_err(|e| format!("keepalive write: {e}"))?;
    ctx.obs[i].established.store(true, Ordering::Release);

    let (tx, mut tx_rx) = mpsc::channel::<Message>(64);
    let (mut reader, mut writer) = stream.into_split();

    let writer_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { break };
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                _ = tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).expect("keepalive encodes");
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                else => break,
            }
        }
        writer_ctx.obs[i]
            .established
            .store(false, Ordering::Release);
    });

    let reader_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut frame = BytesMut::with_capacity(1 << 16);
        let mut tmp = vec![0u8; 1 << 16];
        loop {
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    reader_ctx.obs[i]
                        .established
                        .store(false, Ordering::Release);
                    return;
                }
                Ok(n) => n,
            };
            frame.extend_from_slice(&tmp[..n]);
            loop {
                if frame.len() < HEADER_LEN {
                    break;
                }
                let total = match peek_message_length(&frame, MAX_MESSAGE_LEN) {
                    Ok(Some(len)) => usize::from(len),
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("stub {i} invalid daemon frame: {error}");
                        reader_ctx.obs[i]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        reader_ctx.obs[i]
                            .established
                            .store(false, Ordering::Release);
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut body = frame.split_to(total).freeze();
                let msg = match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(msg) => msg,
                    Err(error) => {
                        eprintln!("stub {i} failed to decode daemon message: {error}");
                        reader_ctx.obs[i]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        reader_ctx.obs[i]
                            .established
                            .store(false, Ordering::Release);
                        return;
                    }
                };
                if let Message::Update(update) = msg {
                    let parsed = match update.parse(true, false, &[]) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            // A daemon UPDATE this harness cannot decode is a
                            // daemon defect, and silently skipping it looks
                            // exactly like the under-delivery being measured.
                            eprintln!("stub {i} decode error on daemon UPDATE: {error}");
                            reader_ctx.obs[i]
                                .decode_errors
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    let mut wire = reader_ctx.obs[i].wire.lock().expect("wire state lock");
                    wire.updates += 1;
                    for entry in &parsed.withdrawn {
                        wire.v4.remove(&entry.prefix);
                        wire.withdrawn_nlri += 1;
                    }
                    for entry in &parsed.announced {
                        wire.v4.insert(entry.prefix);
                        wire.announced_nlri += 1;
                    }
                    for attribute in &parsed.attributes {
                        match attribute {
                            PathAttribute::MpReachNlri(mp) => {
                                for entry in &mp.announced {
                                    match entry.prefix {
                                        Prefix::V4(p) => {
                                            wire.v4.insert(p);
                                        }
                                        Prefix::V6(p) => {
                                            wire.v6.insert(p);
                                        }
                                    }
                                    wire.announced_nlri += 1;
                                }
                            }
                            PathAttribute::MpUnreachNlri(mp) => {
                                for entry in &mp.withdrawn {
                                    match entry.prefix {
                                        Prefix::V4(p) => {
                                            wire.v4.remove(&p);
                                        }
                                        Prefix::V6(p) => {
                                            wire.v6.remove(&p);
                                        }
                                    }
                                    wire.withdrawn_nlri += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    });

    Ok(tx)
}

// ---------------------------------------------------------------------------
// Daemon observation: Prometheus scrape and `rbgp`.
// ---------------------------------------------------------------------------

async fn scrape(addr: SocketAddr) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("metrics connect: {e}"))?;
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("metrics request: {e}"))?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .map_err(|e| format!("metrics read: {e}"))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Value of a Prometheus sample whose label set contains every `labels` pair.
/// Returns `None` when the series is absent — which ADR-0113 makes load
/// bearing: an unlimited family must drop its limit and headroom series
/// rather than export a stale finite value.
fn sample(scrape: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    scrape.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        if !rest.starts_with('{') && !rest.starts_with(' ') {
            return None;
        }
        if !labels
            .iter()
            .all(|(key, value)| rest.contains(&format!("{key}=\"{value}\"")))
        {
            return None;
        }
        rest.rsplit(' ').next()?.trim().parse::<f64>().ok()
    })
}

struct Rbgp {
    bin: PathBuf,
    addr: String,
}

impl Rbgp {
    async fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = tokio::process::Command::new(&self.bin)
            .arg("--addr")
            .arg(&self.addr)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("rbgp {args:?}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "rbgp {args:?} exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

// ---------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------

struct Checks {
    rows: Vec<(String, bool, String)>,
}

impl Checks {
    fn assert(&mut self, name: &str, pass: bool, detail: String) {
        println!(
            "CHECK {name} {} {detail}",
            if pass { "PASS" } else { "FAIL" }
        );
        self.rows.push((name.to_string(), pass, detail));
    }

    fn eq<T: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        let pass = got == want;
        self.assert(name, pass, format!("got={got:?} want={want:?}"));
    }

    fn failed(&self) -> usize {
        self.rows.iter().filter(|(_, pass, _)| !pass).count()
    }
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

struct Args {
    port: u16,
    pid: i32,
    rbgp: Rbgp,
    metrics: SocketAddr,
    config_live: PathBuf,
    config_lower: PathBuf,
    config_raise: PathBuf,
    out: PathBuf,
}

fn usage() -> ! {
    eprintln!(
        "usage: outboundlimits <daemon_port> <daemon_pid> <rbgp_bin> <grpc_addr> \
         <metrics_addr> <config_live> <config_lower> <config_raise> <out_dir>"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.len() != 9 {
        usage();
    }
    Args {
        port: argv[0].parse().unwrap_or_else(|_| usage()),
        pid: argv[1].parse().unwrap_or_else(|_| usage()),
        rbgp: Rbgp {
            bin: PathBuf::from(&argv[2]),
            addr: argv[3].clone(),
        },
        metrics: argv[4].parse().unwrap_or_else(|_| usage()),
        config_live: PathBuf::from(&argv[5]),
        config_lower: PathBuf::from(&argv[6]),
        config_raise: PathBuf::from(&argv[7]),
        out: PathBuf::from(&argv[8]),
    }
}

/// Poll `predicate` up to [`CONVERGE_TIMEOUT`]. `None` means it never held.
/// A timeout is a normal, reportable outcome for a phase gate — the run keeps
/// collecting evidence so one failure does not hide the rest of the picture.
async fn wait_for<F>(mut predicate: F) -> Option<Duration>
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < CONVERGE_TIMEOUT {
        if predicate() {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Everything the daemon reports at one phase boundary, written to the
/// artifact directory and returned for assertions.
struct Evidence {
    metrics: String,
    neighbor_json: Vec<String>,
    /// `rbgp neighbor <capped> --compare <peer>` for the sibling and the
    /// private peer, in that order.
    compares: Vec<String>,
    advertised_v4: usize,
    advertised_v6: usize,
}

async fn collect(args: &Args, label: &str) -> Result<Evidence, String> {
    let metrics = scrape(args.metrics).await?;
    std::fs::write(args.out.join(format!("metrics-{label}.prom")), &metrics)
        .map_err(|e| format!("write metrics: {e}"))?;

    let mut neighbor_json = Vec::new();
    for i in 0..PEERS {
        let addr = peer_addr(i).to_string();
        let json = args.rbgp.run(&["-j", "neighbor", &addr]).await?;
        std::fs::write(
            args.out.join(format!("neighbor-{addr}-{label}.json")),
            &json,
        )
        .map_err(|e| format!("write neighbor json: {e}"))?;
        neighbor_json.push(json);
    }
    // The human surface is retained too: ADR-0113 requires the operator-facing
    // rows, not only the machine ones.
    let human = args
        .rbgp
        .run(&["neighbor", &peer_addr(GROUPED_CAPPED).to_string()])
        .await?;
    std::fs::write(
        args.out.join(format!("neighbor-capped-{label}.txt")),
        &human,
    )
    .map_err(|e| format!("write neighbor text: {e}"))?;

    // Two operator-visible membership comparisons: the capped member against
    // its unlimited sibling (must be one shared group) and against the
    // private peer (must be separate, for the documented reason).
    let mut compares = Vec::new();
    for (name, other) in [("sibling", GROUPED_SIBLING), ("private", PRIVATE_CAPPED)] {
        let json = args
            .rbgp
            .run(&[
                "-j",
                "neighbor",
                &peer_addr(GROUPED_CAPPED).to_string(),
                "--compare",
                &peer_addr(other).to_string(),
            ])
            .await?;
        std::fs::write(
            args.out
                .join(format!("update-group-compare-{name}-{label}.json")),
            &json,
        )
        .map_err(|e| format!("write group compare: {e}"))?;
        compares.push(json);
    }

    let capped = peer_addr(GROUPED_CAPPED).to_string();
    let mut advertised = Vec::new();
    for family in ["ipv4-unicast", "ipv6-unicast"] {
        let json = args
            .rbgp
            .run(&["-j", "rib", "advertised", &capped, "-a", family])
            .await?;
        std::fs::write(
            args.out
                .join(format!("advertised-capped-{family}-{label}.json")),
            &json,
        )
        .map_err(|e| format!("write advertised: {e}"))?;
        // `JsonRoute` has exactly one top-level `"prefix"` key per route and
        // no nested one, so occurrences are the route count.
        advertised.push(json.matches("\"prefix\"").count());
    }

    Ok(Evidence {
        metrics,
        neighbor_json,
        compares,
        advertised_v4: advertised[0],
        advertised_v6: advertised[1],
    })
}

/// Collapse a pretty-printed JSON document onto one line for a check detail.
fn one_line(json: &str) -> String {
    json.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sighup(pid: i32) {
    // SAFETY: `kill` with a valid signal number is safe; the driver owns the
    // pid and reaps the daemon itself.
    unsafe {
        libc::kill(pid, libc::SIGHUP);
    }
}

/// Assert one peer/family capacity row across all four gauges. `expect` is
/// `(usage, limit, blocking)`; a `None` limit asserts the limit and headroom
/// series are *absent*, which is ADR-0113's unlimited-family contract.
fn capacity_row(
    checks: &mut Checks,
    metrics: &str,
    phase: &str,
    peer: &str,
    family: &str,
    expect: (f64, Option<f64>, f64),
) {
    let (usage, limit, blocking) = expect;
    checks.eq(
        &format!("{phase}.metric.usage.{peer}.{family}"),
        sample(
            metrics,
            "bgp_outbound_prefix_usage",
            &[("peer", peer), ("family", family)],
        ),
        Some(usage),
    );
    checks.eq(
        &format!("{phase}.metric.limit.{peer}.{family}"),
        sample(
            metrics,
            "bgp_outbound_prefix_limit",
            &[("peer", peer), ("family", family)],
        ),
        limit,
    );
    checks.eq(
        &format!("{phase}.metric.headroom.{peer}.{family}"),
        sample(
            metrics,
            "bgp_outbound_prefix_headroom",
            &[("peer", peer), ("family", family)],
        ),
        limit.map(|limit| (limit - usage).max(0.0)),
    );
    checks.eq(
        &format!("{phase}.metric.blocking.{peer}.{family}"),
        sample(
            metrics,
            "bgp_outbound_prefix_blocking",
            &[("peer", peer), ("family", family)],
        ),
        Some(blocking),
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();
    match run(&args).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("outboundlimits: {error}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_lines, reason = "one linear receipt script")]
async fn run(args: &Args) -> Result<ExitCode, String> {
    let ctx = Arc::new(Ctx {
        daemon: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), args.port),
        obs: (0..PEERS).map(|_| Obs::new()).collect(),
    });
    let mut checks = Checks { rows: Vec::new() };

    let mut senders = Vec::new();
    for i in 0..PEERS {
        senders.push(establish(Arc::clone(&ctx), i).await?);
    }
    if wait_for(|| {
        ctx.obs
            .iter()
            .all(|o| o.established.load(Ordering::Acquire))
    })
    .await
    .is_none()
    {
        return Err("not every stub session reached Established".into());
    }

    // Phase 1 — the source announces its full table.
    for msg in source_table() {
        senders[SOURCE]
            .send(msg)
            .await
            .map_err(|_| "source session closed before announce".to_string())?;
    }

    // The unlimited sibling is the non-vacuity sentinel: until it holds the
    // whole table, "the capped peer only got 8" would be indistinguishable
    // from "only 8 were ever distributed".
    let Some(converge) = wait_for(|| {
        let (v4, v6, ..) = ctx.obs[GROUPED_SIBLING].snapshot();
        v4 == V4_ROUTES && v6 == V6_ROUTES
    })
    .await
    else {
        // Nothing downstream means anything if the table was never
        // distributed, so this one wait stays fatal.
        return Err("the unlimited sibling never received the full table".into());
    };
    tokio::time::sleep(SETTLE).await;

    // -- Phase: blocked -----------------------------------------------------
    let blocked = collect(args, "blocked").await?;
    let capped = peer_addr(GROUPED_CAPPED).to_string();
    let sibling = peer_addr(GROUPED_SIBLING).to_string();
    let private = peer_addr(PRIVATE_CAPPED).to_string();

    let (cap_v4, cap_v6, ..) = ctx.obs[GROUPED_CAPPED].snapshot();
    let (sib_v4, sib_v6, sib_ann, sib_wd, _) = ctx.obs[GROUPED_SIBLING].snapshot();
    let (pri_v4, pri_v6, ..) = ctx.obs[PRIVATE_CAPPED].snapshot();

    checks.eq("blocked.wire.capped.ipv4", cap_v4, V4_LIMIT);
    checks.eq("blocked.wire.capped.ipv6", cap_v6, V6_LIMIT);
    checks.eq("blocked.wire.sibling.ipv4", sib_v4, V4_ROUTES);
    checks.eq("blocked.wire.sibling.ipv6", sib_v6, V6_ROUTES);
    checks.eq("blocked.wire.private.ipv4", pri_v4, V4_LIMIT);
    checks.eq("blocked.wire.private.ipv6", pri_v6, V6_LIMIT);
    checks.eq(
        "blocked.wire.capped.withdrawn",
        {
            let (.., wd, _) = ctx.obs[GROUPED_CAPPED].snapshot();
            wd
        },
        0,
    );

    // The grouped assertion. `bgp_peer_update_group` is >= 0 for a shared
    // update group and the sentinel -1 for the private path, so this is the
    // difference ADR-0113 asks the receipt to prove: the limited member is
    // riding the same shared fanout as an unlimited sibling, not a per-peer
    // private path that happens to also enforce a cap.
    let capped_group = sample(
        &blocked.metrics,
        "bgp_peer_update_group",
        &[("peer", &capped)],
    );
    let sibling_group = sample(
        &blocked.metrics,
        "bgp_peer_update_group",
        &[("peer", &sibling)],
    );
    let private_group = sample(
        &blocked.metrics,
        "bgp_peer_update_group",
        &[("peer", &private)],
    );
    checks.assert(
        "blocked.grouped.capped_is_grouped",
        capped_group.is_some_and(|group| group >= 0.0),
        format!("bgp_peer_update_group{{peer={capped}}}={capped_group:?}"),
    );
    checks.assert(
        "blocked.grouped.shares_group_with_sibling",
        capped_group.is_some() && capped_group == sibling_group,
        format!("capped={capped_group:?} sibling={sibling_group:?}"),
    );
    checks.assert(
        "blocked.grouped.private_peer_is_private",
        private_group == Some(-1.0),
        format!("bgp_peer_update_group{{peer={private}}}={private_group:?}"),
    );
    // The same fact through the operator-visible surface, which does not
    // expose internal group ids: `shared` between the two grouped peers, and
    // `separate` with the documented `per_client_best` reason for the private
    // one. This is the check that would still fail if the limit were quietly
    // implemented by pushing the capped member onto a private path.
    checks.assert(
        "blocked.grouped.cli_verdict_shared_with_sibling",
        blocked.compares[0].contains("\"verdict\": \"shared\"")
            && blocked.compares[0].contains("\"primary_membership\": \"grouped\"")
            && blocked.compares[0].contains("\"comparison_membership\": \"grouped\""),
        format!(
            "rbgp neighbor --compare(sibling): {}",
            one_line(&blocked.compares[0])
        ),
    );
    checks.assert(
        "blocked.grouped.cli_verdict_separate_from_private",
        blocked.compares[1].contains("\"verdict\": \"private\"")
            && blocked.compares[1].contains("\"comparison_membership\": \"per_client_best\""),
        format!(
            "rbgp neighbor --compare(private): {}",
            one_line(&blocked.compares[1])
        ),
    );
    // One member blocking must not filter the shared payload or split the
    // group: exactly one peer (the per-client-best one) is on the private path.
    checks.eq(
        "blocked.grouped.fallback_peers",
        sample(&blocked.metrics, "bgp_update_group_fallback_peers", &[]),
        Some(1.0),
    );

    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &capped,
        "ipv4_unicast",
        (8.0, Some(8.0), 1.0),
    );
    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &capped,
        "ipv6_unicast",
        (4.0, Some(4.0), 1.0),
    );
    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &private,
        "ipv4_unicast",
        (8.0, Some(8.0), 1.0),
    );
    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &private,
        "ipv6_unicast",
        (4.0, Some(4.0), 1.0),
    );
    // The unlimited sibling reports usage without inventing a numeric maximum.
    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &sibling,
        "ipv4_unicast",
        (12.0, None, 0.0),
    );
    capacity_row(
        &mut checks,
        &blocked.metrics,
        "blocked",
        &sibling,
        "ipv6_unicast",
        (6.0, None, 0.0),
    );

    checks.eq(
        "blocked.metric.blocked_total.capped.ipv4",
        sample(
            &blocked.metrics,
            "bgp_outbound_prefix_blocked_total",
            &[("peer", &capped), ("family", "ipv4_unicast")],
        ),
        Some((V4_ROUTES - V4_LIMIT) as f64),
    );
    checks.eq(
        "blocked.metric.blocked_total.capped.ipv6",
        sample(
            &blocked.metrics,
            "bgp_outbound_prefix_blocked_total",
            &[("peer", &capped), ("family", "ipv6_unicast")],
        ),
        Some((V6_ROUTES - V6_LIMIT) as f64),
    );

    checks.assert(
        "blocked.cli.capped_reports_blocking_reason",
        blocked.neighbor_json[GROUPED_CAPPED].contains("outbound_prefix_limit_reached"),
        "rbgp neighbor -j carries the stable blocking reason".to_string(),
    );
    checks.assert(
        "blocked.cli.sibling_reports_no_reason",
        !blocked.neighbor_json[GROUPED_SIBLING].contains("outbound_prefix_limit_reached"),
        "the unlimited sibling reports no blocking reason".to_string(),
    );
    // ADR-0113: usage must agree with advertised-route queries.
    checks.eq(
        "blocked.advertised.capped.ipv4",
        blocked.advertised_v4,
        V4_LIMIT,
    );
    checks.eq(
        "blocked.advertised.capped.ipv6",
        blocked.advertised_v6,
        V6_LIMIT,
    );

    // -- Phase: a lowering below current usage is rejected atomically -------
    std::fs::copy(&args.config_lower, &args.config_live)
        .map_err(|e| format!("stage lowering config: {e}"))?;
    sighup(args.pid);
    tokio::time::sleep(SETTLE).await;
    let lowered = collect(args, "lower-rejected").await?;

    let (cap_v4_l, cap_v6_l, _, cap_wd_l, _) = ctx.obs[GROUPED_CAPPED].snapshot();
    let (sib_v4_l, sib_v6_l, sib_ann_l, sib_wd_l, _) = ctx.obs[GROUPED_SIBLING].snapshot();
    checks.eq("lower.wire.capped.ipv4_unchanged", cap_v4_l, V4_LIMIT);
    checks.eq("lower.wire.capped.ipv6_unchanged", cap_v6_l, V6_LIMIT);
    checks.eq("lower.wire.capped.no_withdrawals", cap_wd_l, 0);
    checks.eq("lower.wire.sibling.ipv4_unchanged", sib_v4_l, V4_ROUTES);
    checks.eq("lower.wire.sibling.ipv6_unchanged", sib_v6_l, V6_ROUTES);
    checks.eq(
        "lower.wire.sibling.no_new_announcements",
        sib_ann_l,
        sib_ann,
    );
    checks.eq("lower.wire.sibling.no_new_withdrawals", sib_wd_l, sib_wd);
    checks.assert(
        "lower.sessions_still_established",
        ctx.obs
            .iter()
            .all(|o| o.established.load(Ordering::Acquire)),
        "no session was reset by the rejected edit".to_string(),
    );
    // The running maxima survive the rejected candidate untouched.
    capacity_row(
        &mut checks,
        &lowered.metrics,
        "lower",
        &capped,
        "ipv4_unicast",
        (8.0, Some(8.0), 1.0),
    );
    capacity_row(
        &mut checks,
        &lowered.metrics,
        "lower",
        &capped,
        "ipv6_unicast",
        (4.0, Some(4.0), 1.0),
    );
    capacity_row(
        &mut checks,
        &lowered.metrics,
        "lower",
        &private,
        "ipv4_unicast",
        (8.0, Some(8.0), 1.0),
    );
    checks.eq(
        "lower.advertised.capped.ipv4",
        lowered.advertised_v4,
        V4_LIMIT,
    );
    checks.eq(
        "lower.advertised.capped.ipv6",
        lowered.advertised_v6,
        V6_LIMIT,
    );

    // -- Phase: a raise recovers the withheld intent ------------------------
    std::fs::copy(&args.config_raise, &args.config_live)
        .map_err(|e| format!("stage raise config: {e}"))?;
    sighup(args.pid);
    let recovery = wait_for(|| {
        let (v4, v6, ..) = ctx.obs[GROUPED_CAPPED].snapshot();
        v4 == V4_ROUTES && v6 == V6_ROUTES
    })
    .await;
    checks.assert(
        "recovered.capped_reached_the_raised_maximum",
        recovery.is_some(),
        recovery.map_or_else(
            || format!("no recovery within {CONVERGE_TIMEOUT:?}"),
            |elapsed| format!("{:.3}s after SIGHUP", elapsed.as_secs_f64()),
        ),
    );
    tokio::time::sleep(SETTLE).await;
    let raised = collect(args, "recovered").await?;

    let (cap_v4_r, cap_v6_r, _, cap_wd_r, _) = ctx.obs[GROUPED_CAPPED].snapshot();
    let (sib_v4_r, sib_v6_r, sib_ann_r, sib_wd_r, _) = ctx.obs[GROUPED_SIBLING].snapshot();
    let (pri_v4_r, pri_v6_r, ..) = ctx.obs[PRIVATE_CAPPED].snapshot();
    checks.eq("recovered.wire.capped.ipv4", cap_v4_r, V4_ROUTES);
    checks.eq("recovered.wire.capped.ipv6", cap_v6_r, V6_ROUTES);
    checks.eq("recovered.wire.capped.no_withdrawals", cap_wd_r, 0);
    checks.eq("recovered.wire.private.ipv4", pri_v4_r, V4_ROUTES);
    checks.eq("recovered.wire.private.ipv6", pri_v6_r, V6_ROUTES);
    // The recovery resync is target-peer and target-family scoped: the
    // sibling sharing the update group must see no churn from it.
    checks.eq("recovered.wire.sibling.ipv4_unchanged", sib_v4_r, V4_ROUTES);
    checks.eq("recovered.wire.sibling.ipv6_unchanged", sib_v6_r, V6_ROUTES);
    checks.eq(
        "recovered.wire.sibling.no_new_announcements",
        sib_ann_r,
        sib_ann_l,
    );
    checks.eq(
        "recovered.wire.sibling.no_new_withdrawals",
        sib_wd_r,
        sib_wd_l,
    );
    checks.assert(
        "recovered.sessions_still_established",
        ctx.obs
            .iter()
            .all(|o| o.established.load(Ordering::Acquire)),
        "the whole block/recovery arc kept every session established".to_string(),
    );

    capacity_row(
        &mut checks,
        &raised.metrics,
        "recovered",
        &capped,
        "ipv4_unicast",
        (12.0, Some(12.0), 0.0),
    );
    capacity_row(
        &mut checks,
        &raised.metrics,
        "recovered",
        &capped,
        "ipv6_unicast",
        (6.0, Some(6.0), 0.0),
    );
    checks.assert(
        "recovered.cli.blocking_reason_cleared",
        !raised.neighbor_json[GROUPED_CAPPED].contains("outbound_prefix_limit_reached"),
        "rbgp neighbor -j no longer reports a blocking reason".to_string(),
    );
    checks.assert(
        "recovered.grouped.still_same_group",
        raised.compares[0].contains("\"verdict\": \"shared\""),
        "recovery did not split the update group".to_string(),
    );
    checks.eq(
        "recovered.grouped.fallback_peers",
        sample(&raised.metrics, "bgp_update_group_fallback_peers", &[]),
        Some(1.0),
    );
    checks.eq(
        "recovered.advertised.capped.ipv4",
        raised.advertised_v4,
        V4_ROUTES,
    );
    checks.eq(
        "recovered.advertised.capped.ipv6",
        raised.advertised_v6,
        V6_ROUTES,
    );
    checks.eq(
        "recovered.metric.no_regroup",
        sample(&raised.metrics, "bgp_update_group_regroups_total", &[]),
        sample(&blocked.metrics, "bgp_update_group_regroups_total", &[]),
    );

    let decode_errors: u64 = ctx
        .obs
        .iter()
        .map(|o| o.decode_errors.load(Ordering::Relaxed))
        .sum();
    checks.eq("run.decode_errors", decode_errors, 0);

    // -- Summary ------------------------------------------------------------
    let mut wire_rows = BTreeMap::new();
    for i in 0..PEERS {
        let (v4, v6, ann, wd, updates) = ctx.obs[i].snapshot();
        wire_rows.insert(
            peer_addr(i).to_string(),
            format!(
                "{{\"role\":\"{}\",\"asn\":{},\"final_ipv4\":{v4},\"final_ipv6\":{v6},\
                 \"announced_nlri\":{ann},\"withdrawn_nlri\":{wd},\"updates\":{updates}}}",
                peer_role(i),
                peer_asn(i)
            ),
        );
    }
    let failed = checks.failed();
    let summary = format!(
        "{{\n  \"shape\": {{\n    \"peers\": {PEERS},\n    \"families\": \
         [\"ipv4_unicast\", \"ipv6_unicast\"],\n    \"add_path\": \"not negotiated on any \
         session\",\n    \"ipv4_routes\": {V4_ROUTES},\n    \"ipv6_routes\": {V6_ROUTES},\n    \
         \"initial_max_prefixes_out_ipv4\": {V4_LIMIT},\n    \
         \"initial_max_prefixes_out_ipv6\": {V6_LIMIT},\n    \
         \"raised_max_prefixes_out_ipv4\": {V4_ROUTES},\n    \
         \"raised_max_prefixes_out_ipv6\": {V6_ROUTES}\n  }},\n  \
         \"cold_convergence_seconds\": {:.3},\n  \"recovery_seconds\": {},\n  \
         \"wire\": {{\n{}\n  }},\n  \"checks_total\": {},\n  \"checks_failed\": {failed}\n}}\n",
        converge.as_secs_f64(),
        recovery.map_or_else(
            || "null".to_string(),
            |elapsed| format!("{:.3}", elapsed.as_secs_f64())
        ),
        wire_rows
            .iter()
            .map(|(peer, row)| format!("    \"{peer}\": {row}"))
            .collect::<Vec<_>>()
            .join(",\n"),
        checks.rows.len(),
    );
    std::fs::write(args.out.join("summary.json"), &summary)
        .map_err(|e| format!("write summary: {e}"))?;
    print!("{summary}");

    if failed == 0 {
        println!("RESULT PASS {} checks", checks.rows.len());
        Ok(ExitCode::SUCCESS)
    } else {
        println!("RESULT FAIL {failed}/{} checks", checks.rows.len());
        Ok(ExitCode::FAILURE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_reads_labelled_series_and_reports_absence() {
        let scrape =
            "# HELP x\nbgp_outbound_prefix_usage{peer=\"127.9.0.2\",family=\"ipv4_unicast\"} 8\n\
                      bgp_outbound_prefix_usage{peer=\"127.9.0.3\",family=\"ipv4_unicast\"} 12\n\
                      bgp_update_group_fallback_peers 1\n";
        assert_eq!(
            sample(
                scrape,
                "bgp_outbound_prefix_usage",
                &[("peer", "127.9.0.2"), ("family", "ipv4_unicast")]
            ),
            Some(8.0)
        );
        assert_eq!(
            sample(scrape, "bgp_update_group_fallback_peers", &[]),
            Some(1.0)
        );
        // An unlimited family drops its limit series entirely; the receipt
        // asserts that absence, so a silent Some(0.0) would be a false pass.
        assert_eq!(
            sample(
                scrape,
                "bgp_outbound_prefix_limit",
                &[("peer", "127.9.0.2"), ("family", "ipv4_unicast")]
            ),
            None
        );
    }

    #[test]
    fn sample_does_not_match_a_longer_metric_name() {
        let scrape = "bgp_outbound_prefix_blocked_total{peer=\"127.9.0.2\"} 4\n";
        assert_eq!(
            sample(
                scrape,
                "bgp_outbound_prefix_blocked",
                &[("peer", "127.9.0.2")]
            ),
            None
        );
    }

    #[test]
    fn fleet_addresses_and_asns_are_distinct() {
        let addrs: HashSet<_> = (0..PEERS).map(peer_addr).collect();
        let asns: HashSet<_> = (0..PEERS).map(peer_asn).collect();
        assert_eq!(addrs.len(), PEERS);
        assert_eq!(asns.len(), PEERS);
        const {
            assert!(
                V4_LIMIT < V4_ROUTES && V6_LIMIT < V6_ROUTES,
                "caps must actually block"
            )
        };
    }

    #[test]
    fn source_table_encodes_both_families_on_the_wire() {
        let msgs = source_table();
        assert_eq!(msgs.len(), 2);
        let mut v4 = 0;
        let mut v6 = 0;
        for msg in &msgs {
            let Message::Update(update) = msg else {
                panic!("expected UPDATE")
            };
            let bytes = encode_message(msg).expect("source UPDATE encodes");
            assert!(bytes.len() <= usize::from(MAX_MESSAGE_LEN));
            let parsed = update
                .parse(true, false, &[])
                .expect("source UPDATE parses");
            v4 += parsed.announced.len();
            for attribute in &parsed.attributes {
                if let PathAttribute::MpReachNlri(mp) = attribute {
                    v6 += mp.announced.len();
                }
            }
        }
        assert_eq!(v4, V4_ROUTES);
        assert_eq!(v6, V6_ROUTES);
    }
}
