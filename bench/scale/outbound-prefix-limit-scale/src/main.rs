//! Real-daemon scale receipt for ADR-0113 grouped outbound prefix limits.
//!
//! One private route-server-client source originates 400,000 IPv4 /32s to
//! N homogeneous grouped route-server-client members. The immutable driver
//! runs this same finite-limit workload against its own immediate parent and
//! current candidate commit. Both install a cap equal to the converged table,
//! withhold a 64-prefix tail, then remove the cap and must recover the whole
//! tail to every member.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::nlri::Prefix;
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Origin, PathAttribute};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

const TABLE_ROUTES: usize = 400_000;
const WITHHELD_ROUTES: usize = 64;
const TOTAL_ROUTES: usize = TABLE_ROUTES + WITHHELD_ROUTES;
const UPDATE_BATCH: usize = 700;
const HOLD_TIME: u16 = 180;
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SETTLE: Duration = Duration::from_secs(2);
const ALLOWED_MEMBERS: [usize; 3] = [1, 10, 100];
const PREFIX_BASE: u32 = 0x0a00_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variant {
    Parent,
    Candidate,
}

impl Variant {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "parent" => Some(Self::Parent),
            "candidate" => Some(Self::Candidate),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Candidate => "candidate",
        }
    }
}

fn peer_addr(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(
        u32::from(Ipv4Addr::new(127, 10, 0, 1))
            + u32::try_from(index).expect("fixed fleet index fits u32"),
    )
}

fn peer_asn(index: usize) -> u32 {
    64_512 + u32::try_from(index).expect("fixed fleet index fits u32")
}

fn prefix(index: usize) -> Ipv4Prefix {
    Ipv4Prefix::new(
        Ipv4Addr::from(
            PREFIX_BASE + u32::try_from(index).expect("fixed route index fits IPv4 space"),
        ),
        32,
    )
}

fn prefix_index(prefix: Ipv4Prefix) -> Option<usize> {
    if prefix.len != 32 {
        return None;
    }
    let raw = u32::from(prefix.addr).checked_sub(PREFIX_BASE)?;
    let index = usize::try_from(raw).ok()?;
    (index < TOTAL_ROUTES).then_some(index)
}

#[derive(Debug)]
struct PrefixBitmap {
    words: Vec<u64>,
    unique: usize,
    announcements: u64,
    withdrawals: u64,
    updates: u64,
    unexpected: u64,
}

impl PrefixBitmap {
    fn new() -> Self {
        Self {
            words: vec![0; TOTAL_ROUTES.div_ceil(64)],
            unique: 0,
            announcements: 0,
            withdrawals: 0,
            updates: 0,
            unexpected: 0,
        }
    }

    fn announce(&mut self, prefix: Ipv4Prefix) {
        self.announcements = self.announcements.saturating_add(1);
        let Some(index) = prefix_index(prefix) else {
            self.unexpected = self.unexpected.saturating_add(1);
            return;
        };
        let mask = 1u64 << (index % 64);
        let word = &mut self.words[index / 64];
        if *word & mask == 0 {
            *word |= mask;
            self.unique += 1;
        }
    }

    fn withdraw(&mut self, prefix: Ipv4Prefix) {
        self.withdrawals = self.withdrawals.saturating_add(1);
        let Some(index) = prefix_index(prefix) else {
            self.unexpected = self.unexpected.saturating_add(1);
            return;
        };
        let mask = 1u64 << (index % 64);
        let word = &mut self.words[index / 64];
        if *word & mask != 0 {
            *word &= !mask;
            self.unique -= 1;
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct WireSnapshot {
    unique: usize,
    announcements: u64,
    withdrawals: u64,
    updates: u64,
    unexpected: u64,
}

struct Observer {
    wire: Mutex<PrefixBitmap>,
    established: AtomicBool,
    flaps: AtomicU64,
    decode_errors: AtomicU64,
}

impl Observer {
    fn new() -> Self {
        Self {
            wire: Mutex::new(PrefixBitmap::new()),
            established: AtomicBool::new(false),
            flaps: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
        }
    }

    fn mark_down(&self) {
        if self.established.swap(false, Ordering::AcqRel) {
            self.flaps.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> WireSnapshot {
        let wire = self.wire.lock().expect("wire bitmap lock");
        WireSnapshot {
            unique: wire.unique,
            announcements: wire.announcements,
            withdrawals: wire.withdrawals,
            updates: wire.updates,
            unexpected: wire.unexpected,
        }
    }
}

struct Context {
    daemon: SocketAddr,
    observers: Vec<Observer>,
}

fn source_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![peer_asn(0)])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 255, 0, 1)),
    ]
}

fn source_update(range: Range<usize>) -> Message {
    let announced = range
        .map(|index| Ipv4NlriEntry {
            path_id: 0,
            prefix: prefix(index),
        })
        .collect::<Vec<_>>();
    Message::Update(UpdateMessage::build(
        &announced,
        &[],
        &source_attributes(),
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

async fn establish(context: Arc<Context>, index: usize) -> Result<mpsc::Sender<Message>, String> {
    let local = peer_addr(index);
    let socket = TcpSocket::new_v4().map_err(|error| format!("socket: {error}"))?;
    socket
        .bind(SocketAddr::new(local.into(), 0))
        .map_err(|error| format!("bind {local}: {error}"))?;
    let mut stream = socket
        .connect(context.daemon)
        .await
        .map_err(|error| format!("connect from {local}: {error}"))?;
    stream.set_nodelay(true).ok();

    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(peer_asn(index)).expect("fixed ASN fits two octets"),
        hold_time: HOLD_TIME,
        bgp_identifier: Ipv4Addr::from(
            u32::from(Ipv4Addr::new(240, 10, 0, 1))
                + u32::try_from(index).expect("fixed fleet index fits"),
        ),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs {
                asn: peer_asn(index),
            },
            Capability::RouteRefresh,
        ],
    };
    let bytes =
        encode_message(&Message::Open(open)).map_err(|error| format!("open encode: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("open write: {error}"))?;

    let mut buffer = BytesMut::with_capacity(4096);
    loop {
        if let Ok(Some(total)) = peek_message_length(&buffer, MAX_MESSAGE_LEN) {
            if buffer.len() >= usize::from(total) {
                let mut body = buffer.split_to(usize::from(total)).freeze();
                match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(Message::Open(_)) => break,
                    Ok(Message::Notification(notification)) => {
                        return Err(format!(
                            "NOTIFICATION during open: {:?}/{}",
                            notification.code, notification.subcode
                        ));
                    }
                    Ok(_) => continue,
                    Err(error) => return Err(format!("decode during open: {error}")),
                }
            }
        }
        let mut scratch = [0u8; 4096];
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|error| format!("open read: {error}"))?;
        if read == 0 {
            return Err("connection closed before OPEN".to_string());
        }
        buffer.extend_from_slice(&scratch[..read]);
    }

    stream
        .write_all(&encode_message(&Message::Keepalive).expect("KEEPALIVE encodes"))
        .await
        .map_err(|error| format!("KEEPALIVE write: {error}"))?;
    context.observers[index]
        .established
        .store(true, Ordering::Release);

    let (sender, mut outbound) = mpsc::channel::<Message>(64);
    let (mut reader, mut writer) = stream.into_split();

    let writer_context = Arc::clone(&context);
    tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;
        loop {
            tokio::select! {
                Some(message) = outbound.recv() => {
                    let Ok(bytes) = encode_message(&message) else { break };
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                _ = keepalive.tick() => {
                    let bytes = encode_message(&Message::Keepalive).expect("KEEPALIVE encodes");
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                else => break,
            }
        }
        writer_context.observers[index].mark_down();
    });

    let reader_context = Arc::clone(&context);
    tokio::spawn(async move {
        let mut frame = buffer;
        let mut scratch = vec![0u8; 1 << 16];
        loop {
            let read = match reader.read(&mut scratch).await {
                Ok(0) | Err(_) => {
                    reader_context.observers[index].mark_down();
                    return;
                }
                Ok(read) => read,
            };
            frame.extend_from_slice(&scratch[..read]);
            loop {
                if frame.len() < HEADER_LEN {
                    break;
                }
                let total = match peek_message_length(&frame, MAX_MESSAGE_LEN) {
                    Ok(Some(total)) => usize::from(total),
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("stub {index} invalid daemon frame: {error}");
                        reader_context.observers[index]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut body = frame.split_to(total).freeze();
                let message = match decode_message(&mut body, MAX_MESSAGE_LEN) {
                    Ok(message) => message,
                    Err(error) => {
                        eprintln!("stub {index} failed to decode daemon message: {error}");
                        reader_context.observers[index]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                let Message::Update(update) = message else {
                    continue;
                };
                let parsed = match update.parse(true, false, &[]) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        eprintln!("stub {index} failed to parse daemon UPDATE: {error}");
                        reader_context.observers[index]
                            .decode_errors
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let mut wire = reader_context.observers[index]
                    .wire
                    .lock()
                    .expect("wire bitmap lock");
                wire.updates = wire.updates.saturating_add(1);
                for entry in parsed.withdrawn {
                    wire.withdraw(entry.prefix);
                }
                for entry in parsed.announced {
                    wire.announce(entry.prefix);
                }
                for attribute in parsed.attributes {
                    match attribute {
                        PathAttribute::MpReachNlri(reach) => {
                            for entry in reach.announced {
                                match entry.prefix {
                                    Prefix::V4(prefix) => wire.announce(prefix),
                                    Prefix::V6(_) => {
                                        wire.unexpected = wire.unexpected.saturating_add(1);
                                    }
                                }
                            }
                        }
                        PathAttribute::MpUnreachNlri(unreach) => {
                            for entry in unreach.withdrawn {
                                match entry.prefix {
                                    Prefix::V4(prefix) => wire.withdraw(prefix),
                                    Prefix::V6(_) => {
                                        wire.unexpected = wire.unexpected.saturating_add(1);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(sender)
}

async fn scrape(address: SocketAddr) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|error| format!("metrics connect: {error}"))?;
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| format!("metrics request: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| format!("metrics read: {error}"))?;
    let response = String::from_utf8_lossy(&response);
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "metrics response has no HTTP header terminator".to_string())?;
    Ok(body.to_string())
}

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
        rest.rsplit_once(' ')?.1.parse().ok()
    })
}

fn labelled_samples(scrape: &str, name: &str) -> Vec<(BTreeMap<String, String>, f64)> {
    scrape
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix(name)?;
            let labels = rest.strip_prefix('{')?;
            let (labels, value) = labels.rsplit_once("} ")?;
            let labels = labels
                .split(',')
                .filter_map(|field| {
                    let (key, value) = field.split_once('=')?;
                    Some((
                        key.to_string(),
                        value.trim_matches('"').replace("\\\"", "\""),
                    ))
                })
                .collect();
            Some((labels, value.parse().ok()?))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcStatus {
    vm_rss_kib: u64,
    vm_size_kib: u64,
    vm_hwm_kib: u64,
}

fn parse_proc_status(status: &str) -> Result<ProcStatus, String> {
    fn value(status: &str, key: &str) -> Result<u64, String> {
        let line = status
            .lines()
            .find(|line| line.starts_with(key))
            .ok_or_else(|| format!("/proc status is missing {key}"))?;
        let mut fields = line[key.len()..].split_whitespace();
        let value = fields
            .next()
            .ok_or_else(|| format!("/proc status {key} is missing a value"))?
            .parse()
            .map_err(|error| format!("invalid /proc status {key}: {error}"))?;
        if fields.next() != Some("kB") || fields.next().is_some() {
            return Err(format!(
                "/proc status {key} does not use the expected kB unit"
            ));
        }
        Ok(value)
    }
    Ok(ProcStatus {
        vm_rss_kib: value(status, "VmRSS:")?,
        vm_size_kib: value(status, "VmSize:")?,
        vm_hwm_kib: value(status, "VmHWM:")?,
    })
}

#[derive(Clone, Copy, Debug)]
struct Metrics {
    allocated: u64,
    active: u64,
    resident: u64,
    mapped: u64,
    apply_count: f64,
    apply_sum: f64,
    recovery_count: f64,
    recovery_sum: f64,
}

#[derive(Debug)]
struct Evidence {
    scrape: String,
    proc: ProcStatus,
    metrics: Metrics,
}

struct Args {
    variant: Variant,
    members: usize,
    port: u16,
    pid: i32,
    metrics: SocketAddr,
    config_live: PathBuf,
    config_apply: PathBuf,
    config_recover: PathBuf,
    out: PathBuf,
}

fn usage() -> ! {
    eprintln!(
        "usage: outbound-prefix-limit-scale <parent|candidate> <members> <daemon-port> \
         <daemon-pid> <metrics-addr> <config-live> <config-apply> <config-recover> <out-dir>"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 9 {
        usage();
    }
    let variant = Variant::parse(&args[0]).unwrap_or_else(|| usage());
    let members = args[1].parse().unwrap_or_else(|_| usage());
    if !ALLOWED_MEMBERS.contains(&members) {
        usage();
    }
    Args {
        variant,
        members,
        port: args[2].parse().unwrap_or_else(|_| usage()),
        pid: args[3].parse().unwrap_or_else(|_| usage()),
        metrics: args[4].parse().unwrap_or_else(|_| usage()),
        config_live: PathBuf::from(&args[5]),
        config_apply: PathBuf::from(&args[6]),
        config_recover: PathBuf::from(&args[7]),
        out: PathBuf::from(&args[8]),
    }
}

async fn collect(args: &Args, phase: &str) -> Result<Evidence, String> {
    let scrape = scrape(args.metrics).await?;
    fs::write(args.out.join(format!("metrics-{phase}.prom")), &scrape)
        .map_err(|error| format!("write metrics: {error}"))?;
    let proc_text = fs::read_to_string(format!("/proc/{}/status", args.pid))
        .map_err(|error| format!("read daemon proc status: {error}"))?;
    fs::write(
        args.out.join(format!("proc-status-{phase}.txt")),
        &proc_text,
    )
    .map_err(|error| format!("write proc status: {error}"))?;
    let required = |name: &str, labels: &[(&str, &str)]| {
        sample(&scrape, name, labels).ok_or_else(|| format!("missing metric {name}{labels:?}"))
    };
    let integer = |name: &str| -> Result<u64, String> {
        let value = required(name, &[])?;
        if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
            return Err(format!(
                "metric {name} is not a non-negative integer: {value}"
            ));
        }
        Ok(value as u64)
    };
    let metrics = Metrics {
        allocated: integer("jemalloc_allocated_bytes")?,
        active: integer("jemalloc_active_bytes")?,
        resident: integer("jemalloc_resident_bytes")?,
        mapped: integer("jemalloc_mapped_bytes")?,
        apply_count: required(
            "bgp_rib_outbound_prefix_limit_actor_duration_seconds_count",
            &[("operation", "apply")],
        )?,
        apply_sum: required(
            "bgp_rib_outbound_prefix_limit_actor_duration_seconds_sum",
            &[("operation", "apply")],
        )?,
        recovery_count: required(
            "bgp_rib_outbound_prefix_limit_actor_duration_seconds_count",
            &[("operation", "recovery")],
        )?,
        recovery_sum: required(
            "bgp_rib_outbound_prefix_limit_actor_duration_seconds_sum",
            &[("operation", "recovery")],
        )?,
    };
    Ok(Evidence {
        scrape,
        proc: parse_proc_status(&proc_text)?,
        metrics,
    })
}

struct Checks {
    rows: Vec<(String, bool, String)>,
}

impl Checks {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }

    fn assert(&mut self, name: impl Into<String>, pass: bool, detail: impl Into<String>) {
        let name = name.into();
        let detail = detail.into();
        println!(
            "CHECK {name} {} {detail}",
            if pass { "PASS" } else { "FAIL" }
        );
        self.rows.push((name, pass, detail));
    }

    fn eq<T: PartialEq + std::fmt::Debug>(&mut self, name: impl Into<String>, got: T, want: T) {
        self.assert(name, got == want, format!("got={got:?} want={want:?}"));
    }

    fn failed(&self) -> usize {
        self.rows.iter().filter(|(_, pass, _)| !pass).count()
    }
}

fn sighup(pid: i32) -> Result<(), String> {
    // SAFETY: the driver passes the child daemon pid and this uses a valid
    // signal constant. A non-zero return is surfaced as a hard receipt error.
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    (result == 0)
        .then_some(())
        .ok_or_else(|| format!("SIGHUP failed: {}", std::io::Error::last_os_error()))
}

async fn wait_for<F>(mut predicate: F) -> Option<Duration>
where
    F: FnMut() -> bool,
{
    let started = Instant::now();
    while started.elapsed() < CONVERGE_TIMEOUT {
        if predicate() {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn wait_for_metric(
    args: &Args,
    baseline: Metrics,
    operation: &str,
) -> Result<Evidence, String> {
    let started = Instant::now();
    loop {
        let evidence = collect(args, &format!("{operation}-poll")).await?;
        let (before, after) = match operation {
            "apply" => (baseline.apply_count, evidence.metrics.apply_count),
            "recovery" => (baseline.recovery_count, evidence.metrics.recovery_count),
            _ => return Err(format!("unknown operation {operation}")),
        };
        if after >= before + 1.0 {
            return Ok(evidence);
        }
        if started.elapsed() >= CONVERGE_TIMEOUT {
            return Err(format!(
                "{operation} histogram did not advance within {CONVERGE_TIMEOUT:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn assert_group_inventory(checks: &mut Checks, args: &Args, evidence: &Evidence, phase: &str) {
    checks.eq(
        format!("{phase}.group.count"),
        sample(&evidence.scrape, "bgp_update_groups", &[]),
        Some(1.0),
    );
    let group_rows = labelled_samples(&evidence.scrape, "bgp_update_group_members");
    checks.eq(format!("{phase}.group.series"), group_rows.len(), 1);
    let Some((labels, count)) = group_rows.first() else {
        return;
    };
    let Some(group) = labels.get("group") else {
        checks.assert(
            format!("{phase}.group.label"),
            false,
            "sole member series has no group label",
        );
        return;
    };
    checks.eq(
        format!("{phase}.group.members"),
        *count,
        args.members as f64,
    );
    let parsed_group = group.parse::<f64>().ok();
    for member in 1..=args.members {
        let peer = peer_addr(member).to_string();
        checks.eq(
            format!("{phase}.group.peer.{peer}"),
            sample(
                &evidence.scrape,
                "bgp_peer_update_group",
                &[("peer", &peer)],
            ),
            parsed_group,
        );
    }
    let source = peer_addr(0).to_string();
    checks.eq(
        format!("{phase}.group.source_private"),
        sample(
            &evidence.scrape,
            "bgp_peer_update_group",
            &[("peer", &source)],
        ),
        Some(-1.0),
    );
    checks.eq(
        format!("{phase}.group.fallback_only_source"),
        sample(&evidence.scrape, "bgp_update_group_fallback_peers", &[]),
        Some(1.0),
    );
}

#[derive(Clone, Copy)]
struct CapacityExpectation {
    usage: usize,
    limit: Option<usize>,
    blocking: usize,
    blocked_total: Option<usize>,
}

fn assert_member_capacity(
    checks: &mut Checks,
    args: &Args,
    evidence: &Evidence,
    phase: &str,
    expected: CapacityExpectation,
) {
    for member in 1..=args.members {
        let peer = peer_addr(member).to_string();
        let labels = [("peer", peer.as_str()), ("family", "ipv4_unicast")];
        checks.eq(
            format!("{phase}.capacity.usage.{peer}"),
            sample(&evidence.scrape, "bgp_outbound_prefix_usage", &labels),
            Some(expected.usage as f64),
        );
        checks.eq(
            format!("{phase}.capacity.limit.{peer}"),
            sample(&evidence.scrape, "bgp_outbound_prefix_limit", &labels),
            expected.limit.map(|value| value as f64),
        );
        checks.eq(
            format!("{phase}.capacity.blocking.{peer}"),
            sample(&evidence.scrape, "bgp_outbound_prefix_blocking", &labels),
            Some(expected.blocking as f64),
        );
        checks.eq(
            format!("{phase}.capacity.blocked_total.{peer}"),
            sample(
                &evidence.scrape,
                "bgp_outbound_prefix_blocked_total",
                &labels,
            ),
            expected.blocked_total.map(|value| value as f64),
        );
    }
}

async fn wait_for_blocked(args: &Args) -> Result<Evidence, String> {
    let started = Instant::now();
    loop {
        let evidence = collect(args, "blocked-poll").await?;
        let complete = (1..=args.members).all(|member| {
            let peer = peer_addr(member).to_string();
            let labels = [("peer", peer.as_str()), ("family", "ipv4_unicast")];
            sample(&evidence.scrape, "bgp_outbound_prefix_usage", &labels)
                == Some(TABLE_ROUTES as f64)
                && sample(&evidence.scrape, "bgp_outbound_prefix_blocking", &labels) == Some(1.0)
                && sample(
                    &evidence.scrape,
                    "bgp_outbound_prefix_blocked_total",
                    &labels,
                ) == Some(WITHHELD_ROUTES as f64)
        });
        if complete {
            return Ok(evidence);
        }
        if started.elapsed() >= CONVERGE_TIMEOUT {
            return Err(format!(
                "not every {} member reported the complete blocked tail within {CONVERGE_TIMEOUT:?}",
                args.variant.as_str()
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn all_member_counts(context: &Context, members: usize, expected: usize) -> bool {
    (1..=members).all(|member| context.observers[member].snapshot().unique == expected)
}

fn assert_member_wire(
    checks: &mut Checks,
    context: &Context,
    members: usize,
    phase: &str,
    expected: usize,
) {
    for member in 1..=members {
        let peer = peer_addr(member);
        let snapshot = context.observers[member].snapshot();
        checks.eq(
            format!("{phase}.wire.unique.{peer}"),
            snapshot.unique,
            expected,
        );
        checks.eq(
            format!("{phase}.wire.withdrawals.{peer}"),
            snapshot.withdrawals,
            0,
        );
        checks.eq(
            format!("{phase}.wire.unexpected.{peer}"),
            snapshot.unexpected,
            0,
        );
        checks.assert(
            format!("{phase}.wire.announcements_non_vacuous.{peer}"),
            snapshot.announcements >= expected as u64,
            format!(
                "announcements={} expected_at_least={expected}",
                snapshot.announcements
            ),
        );
        checks.assert(
            format!("{phase}.wire.updates_non_vacuous.{peer}"),
            snapshot.updates > 0,
            format!("updates={}", snapshot.updates),
        );
    }
}

fn assert_samples(
    checks: &mut Checks,
    phase: &str,
    operation: &str,
    before: Metrics,
    after: Metrics,
    expected_count: f64,
) -> f64 {
    let (before_count, after_count, before_sum, after_sum) = match operation {
        "apply" => (
            before.apply_count,
            after.apply_count,
            before.apply_sum,
            after.apply_sum,
        ),
        "recovery" => (
            before.recovery_count,
            after.recovery_count,
            before.recovery_sum,
            after.recovery_sum,
        ),
        _ => unreachable!("closed operation set"),
    };
    checks.eq(
        format!("{phase}.histogram.{operation}.count_delta"),
        after_count - before_count,
        expected_count,
    );
    after_sum - before_sum
}

fn histogram_max_bucket_bounds(
    before: &str,
    after: &str,
    operation: &str,
    expected_count: f64,
) -> (f64, Option<f64>) {
    fn finite_buckets(scrape: &str, operation: &str) -> Vec<(f64, f64)> {
        let mut buckets = labelled_samples(
            scrape,
            "bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket",
        )
        .into_iter()
        .filter_map(|(labels, count)| {
            (labels.get("operation").map(String::as_str) == Some(operation))
                .then(|| labels.get("le")?.parse::<f64>().ok().map(|le| (le, count)))
                .flatten()
        })
        .filter(|(le, _)| le.is_finite())
        .collect::<Vec<_>>();
        buckets.sort_by(|(left, _), (right, _)| left.total_cmp(right));
        buckets
    }

    let before = finite_buckets(before, operation);
    let after = finite_buckets(after, operation);
    let mut lower = 0.0;
    for (upper, after_count) in after {
        let before_count = before
            .iter()
            .find_map(|(candidate, count)| (*candidate == upper).then_some(*count))
            .unwrap_or(0.0);
        if after_count - before_count >= expected_count {
            return (lower, Some(upper));
        }
        lower = upper;
    }
    // Histogram timing is diagnostic only. An exact `_count` delta above
    // proves the samples exist; `None` here records that at least one sample
    // landed in the +Inf bucket above the largest finite boundary.
    (lower, None)
}

fn json_f64_or_null(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.9}")
    } else {
        "null".to_string()
    }
}

fn snapshot_json(label: &str, evidence: &Evidence) -> String {
    format!(
        "\"{label}\":{{\"jemalloc_allocated_bytes\":{},\"jemalloc_active_bytes\":{},\
         \"jemalloc_resident_bytes\":{},\"jemalloc_mapped_bytes\":{},\"vm_rss_kib\":{},\
         \"vm_size_kib\":{},\"vm_hwm_kib\":{},\"apply_count\":{:.0},\
         \"apply_sum_seconds\":{:.9},\"recovery_count\":{:.0},\
         \"recovery_sum_seconds\":{:.9}}}",
        evidence.metrics.allocated,
        evidence.metrics.active,
        evidence.metrics.resident,
        evidence.metrics.mapped,
        evidence.proc.vm_rss_kib,
        evidence.proc.vm_size_kib,
        evidence.proc.vm_hwm_kib,
        evidence.metrics.apply_count,
        evidence.metrics.apply_sum,
        evidence.metrics.recovery_count,
        evidence.metrics.recovery_sum,
    )
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();
    match run(&args).await {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("outbound-prefix-limit-scale: {error}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_lines, reason = "linear real-daemon receipt")]
async fn run(args: &Args) -> Result<ExitCode, String> {
    fs::create_dir_all(&args.out).map_err(|error| format!("create output: {error}"))?;
    let context = Arc::new(Context {
        daemon: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), args.port),
        observers: (0..=args.members).map(|_| Observer::new()).collect(),
    });
    let mut checks = Checks::new();
    let mut senders = Vec::with_capacity(args.members + 1);
    for index in 0..=args.members {
        senders.push(establish(Arc::clone(&context), index).await?);
    }
    let established = wait_for(|| {
        context
            .observers
            .iter()
            .all(|observer| observer.established.load(Ordering::Acquire))
    })
    .await;
    if established.is_none() {
        return Err("not every real BGP stub reached Established".to_string());
    }

    for start in (0..TABLE_ROUTES).step_by(UPDATE_BATCH) {
        senders[0]
            .send(source_update(
                start..(start + UPDATE_BATCH).min(TABLE_ROUTES),
            ))
            .await
            .map_err(|_| "source session closed during table announce".to_string())?;
    }
    let cold = wait_for(|| all_member_counts(&context, args.members, TABLE_ROUTES)).await;
    if cold.is_none() {
        return Err(format!(
            "members did not converge {TABLE_ROUTES} routes within {CONVERGE_TIMEOUT:?}; shape was not reduced"
        ));
    }
    tokio::time::sleep(SETTLE).await;
    let baseline = collect(args, "baseline").await?;
    assert_group_inventory(&mut checks, args, &baseline, "baseline");
    assert_member_wire(
        &mut checks,
        &context,
        args.members,
        "baseline",
        TABLE_ROUTES,
    );
    assert_member_capacity(
        &mut checks,
        args,
        &baseline,
        "baseline",
        CapacityExpectation {
            usage: TABLE_ROUTES,
            limit: None,
            blocking: 0,
            blocked_total: None,
        },
    );

    fs::copy(&args.config_apply, &args.config_live)
        .map_err(|error| format!("stage apply config: {error}"))?;
    sighup(args.pid)?;
    let _ = wait_for_metric(args, baseline.metrics, "apply").await?;
    tokio::time::sleep(SETTLE).await;
    let applied = collect(args, "applied").await?;
    let apply_seconds = assert_samples(
        &mut checks,
        "applied",
        "apply",
        baseline.metrics,
        applied.metrics,
        1.0,
    );
    assert_group_inventory(&mut checks, args, &applied, "applied");
    assert_member_wire(&mut checks, &context, args.members, "applied", TABLE_ROUTES);
    assert_member_capacity(
        &mut checks,
        args,
        &applied,
        "applied",
        CapacityExpectation {
            usage: TABLE_ROUTES,
            limit: Some(TABLE_ROUTES),
            blocking: 0,
            blocked_total: None,
        },
    );

    senders[0]
        .send(source_update(TABLE_ROUTES..TOTAL_ROUTES))
        .await
        .map_err(|_| "source session closed during tail announce".to_string())?;
    let tail_expected = TABLE_ROUTES;
    wait_for_blocked(args).await?;
    tokio::time::sleep(SETTLE).await;
    let blocked = collect(args, "blocked").await?;
    assert_group_inventory(&mut checks, args, &blocked, "blocked");
    assert_member_wire(
        &mut checks,
        &context,
        args.members,
        "blocked",
        tail_expected,
    );
    assert_member_capacity(
        &mut checks,
        args,
        &blocked,
        "blocked",
        CapacityExpectation {
            usage: tail_expected,
            limit: Some(TABLE_ROUTES),
            blocking: 1,
            blocked_total: Some(WITHHELD_ROUTES),
        },
    );

    fs::copy(&args.config_recover, &args.config_live)
        .map_err(|error| format!("stage recovery config: {error}"))?;
    let recovery_wall_started = Instant::now();
    sighup(args.pid)?;
    let _ = wait_for_metric(args, blocked.metrics, "apply").await?;
    let _ = wait_for_metric(args, blocked.metrics, "recovery").await?;
    let recovered_wire = wait_for(|| all_member_counts(&context, args.members, TOTAL_ROUTES)).await;
    let recovery_wall_seconds =
        recovered_wire.map(|_| recovery_wall_started.elapsed().as_secs_f64());
    checks.assert(
        "recovered.every_member_received_withheld_tail",
        recovered_wire.is_some(),
        format!("expected={TOTAL_ROUTES} elapsed={recovered_wire:?}"),
    );
    tokio::time::sleep(SETTLE).await;
    let recovered = collect(args, "recovered").await?;
    let recover_apply_seconds = assert_samples(
        &mut checks,
        "recovered",
        "apply",
        blocked.metrics,
        recovered.metrics,
        1.0,
    );
    let expected_count = args.members as f64;
    let recovery_seconds = assert_samples(
        &mut checks,
        "recovered",
        "recovery",
        blocked.metrics,
        recovered.metrics,
        expected_count,
    );
    let recovery_max_slice_bucket = histogram_max_bucket_bounds(
        &blocked.scrape,
        &recovered.scrape,
        "recovery",
        expected_count,
    );
    assert_group_inventory(&mut checks, args, &recovered, "recovered");
    assert_member_wire(
        &mut checks,
        &context,
        args.members,
        "recovered",
        TOTAL_ROUTES,
    );
    assert_member_capacity(
        &mut checks,
        args,
        &recovered,
        "recovered",
        CapacityExpectation {
            usage: TOTAL_ROUTES,
            limit: None,
            blocking: 0,
            blocked_total: Some(WITHHELD_ROUTES),
        },
    );

    let flaps = context
        .observers
        .iter()
        .map(|observer| observer.flaps.load(Ordering::Relaxed))
        .sum::<u64>();
    checks.eq("run.session_flaps", flaps, 0);
    let decode_errors = context
        .observers
        .iter()
        .map(|observer| observer.decode_errors.load(Ordering::Relaxed))
        .sum::<u64>();
    checks.eq("run.decode_errors", decode_errors, 0);
    checks.assert(
        "run.sessions_established",
        context
            .observers
            .iter()
            .all(|observer| observer.established.load(Ordering::Acquire)),
        "every source/member session remained Established",
    );

    let failed = checks.failed();
    let summary = format!(
        "{{\n  \"variant\":\"{}\",\n  \"members\":{},\n  \"table_routes\":{},\n  \
         \"withheld_routes\":{},\n  \"cold_convergence_seconds\":{:.6},\n  \
         \"apply_seconds\":{},\n  \"recovery_apply_seconds\":{},\n  \
         \"recovery_seconds\":{},\n  \"recovery_wall_seconds\":{},\n  \
         \"recovery_max_slice_bucket_lower_seconds\":{},\n  \
         \"recovery_max_slice_bucket_upper_seconds\":{},\n  \
         \"snapshots\":{{\n    {},\n    {},\n    {},\n    {}\n  }},\n  \
         \"checks_total\":{},\n  \"checks_failed\":{}\n}}\n",
        args.variant.as_str(),
        args.members,
        TABLE_ROUTES,
        WITHHELD_ROUTES,
        cold.expect("cold convergence was checked").as_secs_f64(),
        json_f64_or_null(apply_seconds),
        json_f64_or_null(recover_apply_seconds),
        json_f64_or_null(recovery_seconds),
        recovery_wall_seconds.map_or_else(|| "null".to_string(), |value| format!("{value:.9}")),
        json_f64_or_null(recovery_max_slice_bucket.0),
        recovery_max_slice_bucket
            .1
            .map_or_else(|| "null".to_string(), json_f64_or_null),
        snapshot_json("baseline", &baseline),
        snapshot_json("applied", &applied),
        snapshot_json("blocked", &blocked),
        snapshot_json("recovered", &recovered),
        checks.rows.len(),
        failed,
    );
    fs::write(args.out.join("summary.json"), &summary)
        .map_err(|error| format!("write summary: {error}"))?;
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
    fn fixed_shape_is_not_silently_shrinkable() {
        assert_eq!(ALLOWED_MEMBERS, [1, 10, 100]);
        assert_eq!(TABLE_ROUTES, 400_000);
        assert_eq!(WITHHELD_ROUTES, 64);
        assert_eq!(UPDATE_BATCH, 700);
        assert_eq!(Variant::parse("parent"), Some(Variant::Parent));
        assert_eq!(Variant::parse("candidate"), Some(Variant::Candidate));
        assert_eq!(Variant::parse("control"), None);
    }

    #[test]
    fn observer_counts_a_session_drop_once() {
        let observer = Observer::new();
        observer.established.store(true, Ordering::Release);
        observer.mark_down();
        observer.mark_down();
        assert!(!observer.established.load(Ordering::Acquire));
        assert_eq!(observer.flaps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn source_batches_cover_the_first_and_last_prefix_with_real_encoding() {
        let first = source_update(0..UPDATE_BATCH);
        let last = source_update(TABLE_ROUTES..TOTAL_ROUTES);
        for message in [&first, &last] {
            let bytes = encode_message(message).expect("real source UPDATE encodes");
            assert!(bytes.len() <= usize::from(MAX_MESSAGE_LEN));
            let Message::Update(update) = message else {
                panic!("source batch must be UPDATE");
            };
            let parsed = update
                .parse(true, false, &[])
                .expect("real source UPDATE parses");
            assert!(!parsed.announced.is_empty());
        }
        let Message::Update(last) = last else {
            unreachable!()
        };
        let parsed = last.parse(true, false, &[]).expect("tail parses");
        assert_eq!(
            parsed.announced.first().unwrap().prefix,
            prefix(TABLE_ROUTES)
        );
        assert_eq!(
            parsed.announced.last().unwrap().prefix,
            prefix(TOTAL_ROUTES - 1)
        );
    }

    #[test]
    fn bitmap_counts_unique_routes_without_retaining_prefix_objects() {
        let mut bitmap = PrefixBitmap::new();
        bitmap.announce(prefix(0));
        bitmap.announce(prefix(0));
        bitmap.announce(prefix(TOTAL_ROUTES - 1));
        assert_eq!(bitmap.unique, 2);
        assert_eq!(bitmap.announcements, 3);
        bitmap.withdraw(prefix(0));
        assert_eq!(bitmap.unique, 1);
        assert_eq!(bitmap.withdrawals, 1);
        assert_eq!(bitmap.unexpected, 0);
    }

    #[test]
    fn proc_status_keeps_point_rss_and_high_water_distinct() {
        let parsed = parse_proc_status(
            "Name:\trustbgpd\nVmSize:\t1000 kB\nVmHWM:\t900 kB\nVmRSS:\t700 kB\n",
        )
        .expect("fixture parses");
        assert_eq!(
            parsed,
            ProcStatus {
                vm_rss_kib: 700,
                vm_size_kib: 1000,
                vm_hwm_kib: 900,
            }
        );
        assert!(parse_proc_status("VmRSS: 1 MB\nVmSize: 2 kB\nVmHWM: 3 kB\n").is_err());
    }

    #[test]
    fn metric_parser_requires_exact_name_and_group_label() {
        let scrape = "bgp_update_groups 1\n\
                       bgp_update_group_members{group=\"7\"} 10\n\
                       bgp_rib_outbound_prefix_limit_actor_duration_seconds_count{operation=\"apply\"} 2\n\
                       bgp_rib_outbound_prefix_limit_actor_duration_seconds_count_extra{operation=\"apply\"} 99\n";
        assert_eq!(sample(scrape, "bgp_update_groups", &[]), Some(1.0));
        let groups = labelled_samples(scrape, "bgp_update_group_members");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0.get("group").map(String::as_str), Some("7"));
        assert_eq!(groups[0].1, 10.0);
        assert_eq!(
            sample(
                scrape,
                "bgp_rib_outbound_prefix_limit_actor_duration_seconds_count",
                &[("operation", "apply")]
            ),
            Some(2.0)
        );
    }

    /// Timing is report-only: select the finite bucket containing every
    /// expected sample when possible, otherwise report the `+Inf` overflow
    /// without rejecting the exact sample-count gate.
    #[test]
    fn recovery_max_bucket_reports_finite_and_inf_slices() {
        let before = "bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.1\"} 7\n\
                      bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.2\"} 8\n\
                      bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.5\"} 9\n\
                      bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"+Inf\"} 9\n";
        let after = "bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.1\"} 97\n\
                     bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.2\"} 107\n\
                     bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"0.5\"} 109\n\
                     bgp_rib_outbound_prefix_limit_actor_duration_seconds_bucket{operation=\"recovery\",le=\"+Inf\"} 109\n";
        assert_eq!(
            histogram_max_bucket_bounds(before, after, "recovery", 100.0),
            (0.2, Some(0.5))
        );
        assert_eq!(
            histogram_max_bucket_bounds(before, after, "recovery", 101.0),
            (0.5, None),
            "samples above the largest finite bucket remain reportable"
        );
        assert_eq!(json_f64_or_null(0.0), "0.000000000");
        assert_eq!(json_f64_or_null(f64::INFINITY), "null");
        assert_eq!(json_f64_or_null(f64::NAN), "null");
    }
}
