//! LAN-333 reload-stall harness: N real BGP stub clients dial into a
//! running rustbgpd route server over loopback TCP, announce a full
//! table, run steady churn, then drive changed-policy SIGHUP reloads
//! and measure UPDATE-delivery gaps at every receiving client.
//!
//! Shape pinned in docs/perf/reload-stall-2026-07.md.
//!
//! Usage:
//!   reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
//!       <policy_live> <policy_a> <policy_b> <reloads> <control_secs>
//!
//! Stubs bind distinct 127.1.x.y source addresses (matching the
//! generated [[neighbors]] blocks) and connect to 127.0.0.1:<port>.
//! The last CHURNERS stubs each flap a dedicated 16-prefix block every
//! CHURN_MS milliseconds throughout. On ROUTE_REFRESH a stub re-sends
//! its base slice (plus its churn block if currently announced).

// Event.other and Ctx.n_peers are recorded for the observation/context
// model but not read by the percentile analysis; keep them so the
// recorded data shape matches what produced the receipt.
#![allow(dead_code)]

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use rustbgpd_wire::header::peek_message_length;
use rustbgpd_wire::message::{decode_message, encode_message, Message};
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::{Ipv4UnicastMode, UpdateMessage};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Origin, PathAttribute};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

const CHURNERS: u32 = 8;
const CHURN_BLOCK: u32 = 16;
const CHURN_MS: u64 = 125;
const NLRI_PER_MSG: usize = 900;
const HOLD_TIME: u16 = 180;
const COMMUNITY_GEN_A: u32 = (65_500 << 16) | 1_000;
const COMMUNITY_GEN_B: u32 = (65_500 << 16) | 2_000;
const STUB_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(120);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(120);
const HEALTH_POLL: Duration = Duration::from_millis(100);

/// One received-UPDATE observation.
#[derive(Clone, Copy)]
struct Event {
    t_us: u64,
    /// announced NLRI in the base table space (20.0.0.0â€“26.x)
    base_ann: u32,
    /// everything else delivered in this UPDATE (churn announces + withdraws)
    other: u32,
}

struct Obs {
    events: Mutex<Vec<Event>>,
    /// cumulative base-space announced NLRI
    base_ann_total: AtomicU64,
    established: AtomicBool,
    /// communities seen on the most recently sampled fully-parsed UPDATE
    last_comms: Mutex<Vec<u32>>,
    /// Community marker required for the active reload generation.
    expected_community: AtomicU32,
    /// Unique base prefixes observed with `expected_community`.
    generation: Mutex<GenerationProgress>,
    /// One outstanding ROUTE-REFRESH reply at a time (see the reader).
    refresh_pending: AtomicBool,
}

#[derive(Default)]
struct GenerationProgress {
    current: Vec<MarkerState>,
    active: u64,
    target: u64,
    excluded_start: usize,
    excluded_end: usize,
    completed_at_us: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MarkerState {
    #[default]
    Missing,
    Active,
    Inactive,
    Markerless,
    Excluded,
}

impl GenerationProgress {
    fn reset(&mut self, total_prefixes: u32, target: u64, excluded_start: u32, excluded_len: u32) {
        self.current.clear();
        self.current.resize(
            usize::try_from(total_prefixes).unwrap(),
            MarkerState::Missing,
        );
        self.active = 0;
        self.target = target;
        self.excluded_start = usize::try_from(excluded_start).unwrap();
        self.excluded_end = usize::try_from(excluded_start + excluded_len).unwrap();
        self.current[self.excluded_start..self.excluded_end].fill(MarkerState::Excluded);
        self.completed_at_us = None;
    }

    fn replace(
        &mut self,
        prefix_index: usize,
        state: MarkerState,
        t_us: u64,
    ) -> Result<(), &'static str> {
        let Some(slot) = self.current.get_mut(prefix_index) else {
            return Err("out-of-range base prefix identity");
        };
        if *slot == MarkerState::Excluded {
            return Err("observer received its own base prefix");
        }
        if *slot == MarkerState::Active && state != MarkerState::Active {
            self.active -= 1;
        } else if *slot != MarkerState::Active && state == MarkerState::Active {
            self.active += 1;
        }
        *slot = state;
        if self.active == self.target && self.completed_at_us.is_none() {
            self.completed_at_us = Some(t_us);
        } else if self.active != self.target {
            // Completion describes current receiver state, not cumulative
            // history. An inactive or markerless replacement revokes it.
            self.completed_at_us = None;
        }
        Ok(())
    }

    fn complete(&self) -> bool {
        self.active == self.target && self.completed_at_us.is_some()
    }
}

struct Ctx {
    t0: Instant,
    n_peers: u32,
    per_peer: u32,
    daemon: SocketAddr,
    obs: Vec<Obs>,
    /// Daemon messages the stub failed to frame or decode — a daemon defect that
    /// invalidates the run (see the reader and the exit check in `main`).
    parse_errors: AtomicU64,
    /// Base-table withdrawals are forbidden during this announce-only scenario.
    base_withdrawals: AtomicU64,
    /// UPDATEs carrying both the active and inactive generation markers.
    marker_conflicts: AtomicU64,
    /// Duplicate, malformed, out-of-range, or self base-prefix identities.
    route_identity_defects: AtomicU64,
}

fn now_us(ctx: &Ctx) -> u64 {
    u64::try_from(ctx.t0.elapsed().as_micros()).unwrap()
}

fn live_sessions(ctx: &Ctx) -> usize {
    ctx.obs
        .iter()
        .filter(|observer| observer.established.load(Ordering::Relaxed))
        .count()
}

fn require_healthy(ctx: &Ctx, phase: &str) {
    let sessions = live_sessions(ctx);
    let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
    let base_withdrawals = ctx.base_withdrawals.load(Ordering::Relaxed);
    let marker_conflicts = ctx.marker_conflicts.load(Ordering::Relaxed);
    let route_identity_defects = ctx.route_identity_defects.load(Ordering::Relaxed);
    if sessions != ctx.n_peers as usize
        || parse_errors != 0
        || base_withdrawals != 0
        || marker_conflicts != 0
        || route_identity_defects != 0
    {
        eprintln!(
            "FAIL: {phase} health defect: sessions_up={sessions}/{} parse_errors={parse_errors} \
             base_withdrawals={base_withdrawals} marker_conflicts={marker_conflicts} \
             route_identity_defects={route_identity_defects}",
            ctx.n_peers
        );
        std::process::exit(1);
    }
}

async fn guarded_sleep(ctx: &Ctx, duration: Duration, phase: &str) {
    let deadline = Instant::now() + duration;
    loop {
        require_healthy(ctx, phase);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(remaining.min(HEALTH_POLL)).await;
    }
    require_healthy(ctx, phase);
}

fn wall_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

fn stub_addr(i: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        127,
        1,
        u8::try_from(i / 200).unwrap(),
        u8::try_from(i % 200 + 1).unwrap(),
    )
}

fn stub_asn(i: u32) -> u32 {
    64512 + i
}

/// Base-table /24 for global route index (same scheme as rrharness).
fn base_prefix(idx: u32) -> Ipv4Prefix {
    let a = 20 + u8::try_from(idx >> 16).expect("prefix space exhausted");
    let b = u8::try_from((idx >> 8) & 0xff).unwrap();
    let c = u8::try_from(idx & 0xff).unwrap();
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, 0), 24)
}

fn base_prefix_index(prefix: Ipv4Prefix, total_prefixes: u32) -> Option<usize> {
    if prefix.len != 24 {
        return None;
    }
    let [a, b, c, d] = prefix.addr.octets();
    if d != 0 || !(20..30).contains(&a) {
        return None;
    }
    let index = (u32::from(a - 20) << 16) | (u32::from(b) << 8) | u32::from(c);
    (index < total_prefixes).then(|| usize::try_from(index).unwrap())
}

fn marker_state(expected: u32, communities: &[u32]) -> MarkerState {
    let inactive = match expected {
        COMMUNITY_GEN_A => COMMUNITY_GEN_B,
        COMMUNITY_GEN_B => COMMUNITY_GEN_A,
        _ => return MarkerState::Markerless,
    };
    if communities.contains(&expected) {
        MarkerState::Active
    } else if communities.contains(&inactive) {
        MarkerState::Inactive
    } else {
        MarkerState::Markerless
    }
}

fn validated_base_indices(
    announced: &[Ipv4Prefix],
    total_prefixes: u32,
    excluded_start: usize,
    excluded_end: usize,
) -> Result<Vec<usize>, &'static str> {
    let mut indices = Vec::new();
    let mut unique = HashSet::new();
    for prefix in announced {
        let first = prefix.addr.octets()[0];
        if !(20..30).contains(&first) {
            continue;
        }
        let Some(index) = base_prefix_index(*prefix, total_prefixes) else {
            return Err("malformed or out-of-range base prefix identity");
        };
        if (excluded_start..excluded_end).contains(&index) {
            return Err("observer received its own base prefix");
        }
        if !unique.insert(index) {
            return Err("duplicate base prefix identity in one UPDATE");
        }
        indices.push(index);
    }
    Ok(indices)
}

fn generation_marker_conflict(expected: u32, communities: &[u32]) -> bool {
    let inactive = match expected {
        COMMUNITY_GEN_A => COMMUNITY_GEN_B,
        COMMUNITY_GEN_B => COMMUNITY_GEN_A,
        _ => return false,
    };
    communities.contains(&expected) && communities.contains(&inactive)
}

fn churn_prefix(churner: u32, j: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(
        Ipv4Addr::new(
            172,
            16 + u8::try_from(churner).unwrap(),
            u8::try_from(j).unwrap(),
            0,
        ),
        24,
    )
}

fn base_attrs(i: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![stub_asn(i)])],
        }),
        // Non-loopback synthetic next-hop: the daemon rejects 127/8
        // NEXT_HOP with UPDATE error subcode 8. Route-server mode passes
        // it through untouched; observers never resolve it.
        PathAttribute::NextHop(Ipv4Addr::new(
            10,
            9,
            u8::try_from(i / 200).unwrap(),
            u8::try_from(i % 200 + 1).unwrap(),
        )),
    ]
}

fn announce_msgs(i: u32, prefixes: &[Ipv4Prefix]) -> Vec<Message> {
    let attrs = base_attrs(i);
    prefixes
        .chunks(NLRI_PER_MSG)
        .map(|chunk| {
            let entries: Vec<Ipv4NlriEntry> = chunk
                .iter()
                .map(|p| Ipv4NlriEntry {
                    path_id: 0,
                    prefix: *p,
                })
                .collect();
            Message::Update(UpdateMessage::build(
                &entries,
                &[],
                &attrs,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
        })
        .collect()
}

fn withdraw_msg(prefixes: &[Ipv4Prefix]) -> Message {
    let entries: Vec<Ipv4NlriEntry> = prefixes
        .iter()
        .map(|p| Ipv4NlriEntry {
            path_id: 0,
            prefix: *p,
        })
        .collect();
    Message::Update(UpdateMessage::build(
        &[],
        &entries,
        &[],
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
}

/// Slice of the base table owned by stub `i`.
fn own_slice(ctx: &Ctx, i: u32) -> Vec<Ipv4Prefix> {
    let lo = i * ctx.per_peer;
    (lo..lo + ctx.per_peer).map(base_prefix).collect()
}

async fn establish_stub(ctx: Arc<Ctx>, i: u32) -> Result<mpsc::Sender<Message>, String> {
    let local = stub_addr(i);
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
        my_as: u16::try_from(stub_asn(i)).unwrap(),
        hold_time: HOLD_TIME,
        bgp_identifier: Ipv4Addr::new(
            240,
            1,
            u8::try_from(i / 200).unwrap(),
            u8::try_from(i % 200 + 1).unwrap(),
        ),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: stub_asn(i) },
            Capability::RouteRefresh,
        ],
    };
    let bytes = encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("open write: {e}"))?;

    // Read the daemon's OPEN.
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        if let Ok(Some(total)) = peek_message_length(&buf, MAX_MESSAGE_LEN) {
            if buf.len() >= usize::from(total) {
                let mut b = buf.split_to(usize::from(total)).freeze();
                match decode_message(&mut b, MAX_MESSAGE_LEN) {
                    Ok(Message::Open(_)) => break,
                    Ok(Message::Notification(n)) => {
                        return Err(format!(
                            "NOTIFICATION during open: {:?}/{}",
                            n.code, n.subcode
                        ))
                    }
                    Ok(_) => continue, // tolerate keepalives etc.
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
    let ka = encode_message(&Message::Keepalive).unwrap();
    stream
        .write_all(&ka)
        .await
        .map_err(|e| format!("ka write: {e}"))?;

    ctx.obs[i as usize]
        .established
        .store(true, Ordering::Relaxed);

    let (tx, mut tx_rx) = mpsc::channel::<Message>(256);
    let (mut reader, mut writer) = stream.into_split();

    // Writer task: outbound messages + periodic keepalive.
    let wctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut ka_tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ka_tick.tick().await;
        loop {
            let live = tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { break };
                    writer.write_all(&bytes).await.is_ok()
                }
                _ = ka_tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).unwrap();
                    writer.write_all(&bytes).await.is_ok()
                }
                else => break,
            };
            if !live {
                break;
            }
        }
        wctx.obs[i as usize]
            .established
            .store(false, Ordering::Relaxed);
    });

    // Reader task: frame, decode, record UPDATE arrivals, answer
    // ROUTE_REFRESH by re-sending the base slice.
    let tx_for_reader = tx.clone();
    let rctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut frame = BytesMut::with_capacity(1 << 16);
        let mut tmp = vec![0u8; 1 << 16];
        loop {
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    rctx.obs[i as usize]
                        .established
                        .store(false, Ordering::Relaxed);
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
                    Err(_) => {
                        rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                        rctx.obs[i as usize]
                            .established
                            .store(false, Ordering::Relaxed);
                        return;
                    }
                };
                if frame.len() < total {
                    break;
                }
                let mut mb = frame.split_to(total).freeze();
                let msg = match decode_message(&mut mb, MAX_MESSAGE_LEN) {
                    Ok(m) => m,
                    Err(_) => {
                        rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                        rctx.obs[i as usize]
                            .established
                            .store(false, Ordering::Relaxed);
                        return;
                    }
                };
                match msg {
                    Message::Update(u) => {
                        // Parse the wire UPDATE once: NLRI, withdrawals, and
                        // attributes all come from the same decode (the earlier
                        // code decoded the NLRI twice, then re-parsed the whole
                        // UPDATE). A decode failure is a daemon defect, so count
                        // it and fail the run rather than silently skipping the
                        // UPDATE — a silent skip looks exactly like the daemon
                        // under-delivery this harness measures.
                        let parsed = match u.parse(true, false, &[]) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("stub {i} decode error on daemon UPDATE: {e}");
                                rctx.parse_errors.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        let total_prefixes = rctx.n_peers * rctx.per_peer;
                        let own_start = usize::try_from(i * rctx.per_peer).unwrap();
                        let own_end = own_start + usize::try_from(rctx.per_peer).unwrap();
                        let announced_prefixes: Vec<Ipv4Prefix> =
                            parsed.announced.iter().map(|entry| entry.prefix).collect();
                        let base_indices = match validated_base_indices(
                            &announced_prefixes,
                            total_prefixes,
                            own_start,
                            own_end,
                        ) {
                            Ok(indices) => indices,
                            Err(error) => {
                                eprintln!("stub {i} invalid base announcement: {error}");
                                rctx.route_identity_defects.fetch_add(1, Ordering::Relaxed);
                                Vec::new()
                            }
                        };
                        let base = u32::try_from(base_indices.len()).unwrap();
                        let mut other = u32::try_from(parsed.withdrawn.len()).unwrap_or(0);
                        let withdrawn_prefixes: Vec<Ipv4Prefix> =
                            parsed.withdrawn.iter().map(|entry| entry.prefix).collect();
                        let withdrawn_base = match validated_base_indices(
                            &withdrawn_prefixes,
                            total_prefixes,
                            own_start,
                            own_end,
                        ) {
                            Ok(indices) => indices.len(),
                            Err(error) => {
                                eprintln!("stub {i} invalid base withdrawal: {error}");
                                rctx.route_identity_defects.fetch_add(1, Ordering::Relaxed);
                                0
                            }
                        };
                        if withdrawn_base != 0 {
                            rctx.base_withdrawals.fetch_add(
                                u64::try_from(withdrawn_base).unwrap(),
                                Ordering::Relaxed,
                            );
                        }
                        other += u32::try_from(parsed.announced.len()).unwrap_or(0) - base;
                        let ob = &rctx.obs[i as usize];
                        let t_us = now_us(&rctx);
                        if base > 0 {
                            // Borrow the communities out of the single parse;
                            // clone once only to store the last-seen sample.
                            let communities: &[u32] = parsed
                                .attributes
                                .iter()
                                .find_map(|attribute| match attribute {
                                    PathAttribute::Communities(c) => Some(c.as_slice()),
                                    _ => None,
                                })
                                .unwrap_or(&[]);
                            *ob.last_comms.lock().unwrap() = communities.to_vec();

                            let expected = ob.expected_community.load(Ordering::Acquire);
                            if generation_marker_conflict(expected, communities) {
                                rctx.marker_conflicts.fetch_add(1, Ordering::Relaxed);
                            }
                            if expected != 0 {
                                let state = marker_state(expected, communities);
                                let mut generation = ob.generation.lock().unwrap();
                                if ob.expected_community.load(Ordering::Acquire) == expected {
                                    for &index in &base_indices {
                                        if let Err(error) = generation.replace(index, state, t_us) {
                                            eprintln!(
                                                "stub {i} invalid generation replacement: {error}"
                                            );
                                            rctx.route_identity_defects
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                        ob.base_ann_total
                            .fetch_add(u64::from(base), Ordering::Relaxed);
                        ob.events.lock().unwrap().push(Event {
                            t_us,
                            base_ann: base,
                            other,
                        });
                    }
                    Message::RouteRefresh(_) => {
                        // Answer off-thread so the reader never blocks on a full
                        // writer channel while the daemon floods us. Bound it to
                        // one outstanding response per peer: a refresh storm must
                        // not spawn overlapping full-slice floods that duplicate
                        // announcements and skew the measurement.
                        if rctx.obs[i as usize]
                            .refresh_pending
                            .swap(true, Ordering::AcqRel)
                        {
                            continue;
                        }
                        let tx = tx_for_reader.clone();
                        let rc = Arc::clone(&rctx);
                        tokio::spawn(async move {
                            let slice = own_slice(&rc, i);
                            for m in announce_msgs(i, &slice) {
                                if tx.send(m).await.is_err() {
                                    break;
                                }
                            }
                            rc.obs[i as usize]
                                .refresh_pending
                                .store(false, Ordering::Release);
                        });
                    }
                    Message::Notification(_) => {
                        rctx.obs[i as usize]
                            .established
                            .store(false, Ordering::Relaxed);
                        return;
                    }
                    _ => {}
                }
            }
        }
    });

    Ok(tx)
}

/// Percentile over a sorted slice.
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

/// Max inter-UPDATE gap (ms) for one observer over [s_us, e_us].
/// Includes the leading gap from s_us to the first event; includes the
/// trailing gap to e_us only when `trailing` is set (control windows).
fn max_gap_ms(ctx: &Ctx, i: usize, s_us: u64, e_us: u64, trailing: bool) -> f64 {
    let ev = ctx.obs[i].events.lock().unwrap();
    let mut last = s_us;
    let mut max_gap = 0u64;
    for e in ev.iter() {
        if e.t_us < s_us {
            continue;
        }
        if e.t_us > e_us {
            break;
        }
        max_gap = max_gap.max(e.t_us - last);
        last = e.t_us;
    }
    if trailing {
        max_gap = max_gap.max(e_us.saturating_sub(last));
    }
    max_gap as f64 / 1000.0
}

/// First event time at which every expected unique base prefix was observed
/// with the active policy-generation community marker.
fn completion_us(ctx: &Ctx, i: usize) -> Option<u64> {
    ctx.obs[i].generation.lock().unwrap().completed_at_us
}

fn rss_mib(pid: i32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .unwrap_or(0)
                / 1024;
        }
    }
    0
}

fn stats_line(label: &str, mut vals: Vec<f64>) {
    vals.sort_by(f64::total_cmp);
    println!(
        "{label}: p50={:.2} p95={:.2} max={:.2} (n={})",
        pct(&vals, 0.5),
        pct(&vals, 0.95),
        pct(&vals, 1.0),
        vals.len()
    );
}

#[allow(clippy::too_many_lines)]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 10 {
        eprintln!(
            "usage: reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
             <policy_live> <policy_a> <policy_b> <reloads> <control_secs>"
        );
        std::process::exit(2);
    }
    let n_peers: u32 = a[1].parse().unwrap();
    let total: u32 = a[2].parse().unwrap();
    let port: u16 = a[3].parse().unwrap();
    let pid: i32 = a[4].parse().unwrap();
    let policy_live = a[5].clone();
    let policy_a = a[6].clone();
    let policy_b = a[7].clone();
    let reloads: u32 = a[8].parse().unwrap();
    let control_secs: u64 = a[9].parse().unwrap();
    let per_peer = total / n_peers;
    assert_eq!(total % n_peers, 0, "total must divide evenly");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(24)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let ctx = Arc::new(Ctx {
            t0: Instant::now(),
            n_peers,
            per_peer,
            daemon: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port),
            obs: (0..n_peers)
                .map(|_| Obs {
                    events: Mutex::new(Vec::with_capacity(1 << 14)),
                    base_ann_total: AtomicU64::new(0),
                    established: AtomicBool::new(false),
                    last_comms: Mutex::new(Vec::new()),
                    expected_community: AtomicU32::new(0),
                    generation: Mutex::new(GenerationProgress::default()),
                    refresh_pending: AtomicBool::new(false),
                })
                .collect(),
            parse_errors: AtomicU64::new(0),
            base_withdrawals: AtomicU64::new(0),
            marker_conflicts: AtomicU64::new(0),
            route_identity_defects: AtomicU64::new(0),
        });
        println!("# reloadstall peers={n_peers} prefixes={total} per_peer={per_peer} pid={pid}");

        // --- Establish all sessions (waves of 64). ---
        let establishment = tokio::time::timeout(ESTABLISHMENT_TIMEOUT, async {
            let mut txs: Vec<mpsc::Sender<Message>> = Vec::with_capacity(n_peers as usize);
            for wave in (0..n_peers).collect::<Vec<_>>().chunks(64) {
                let mut handles = Vec::new();
                for &i in wave {
                    let c = Arc::clone(&ctx);
                    handles.push((
                        i,
                        tokio::spawn(async move {
                            tokio::time::timeout(STUB_OPEN_TIMEOUT, establish_stub(c, i)).await
                        }),
                    ));
                }
                for (i, handle) in handles {
                    match handle.await {
                        Ok(Ok(Ok(tx))) => txs.push(tx),
                        Ok(Ok(Err(error))) => return Err(format!("stub {i} failed: {error}")),
                        Ok(Err(_)) => {
                            return Err(format!("stub {i} connect/OPEN exceeded 15 seconds"));
                        }
                        Err(error) => return Err(format!("stub {i} task failed: {error}")),
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, String>(txs)
        })
        .await;
        let txs = match establishment {
            Ok(Ok(txs)) => txs,
            Ok(Err(error)) => {
                eprintln!("FAIL: {error}");
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("FAIL: overall establishment exceeded 120 seconds");
                std::process::exit(1);
            }
        };
        require_healthy(&ctx, "post-establishment");
        println!(
            "established {} at {:.1}s",
            txs.len(),
            ctx.t0.elapsed().as_secs_f64()
        );

        // --- Announce base table. ---
        for i in 0..n_peers {
            let slice = own_slice(&ctx, i);
            for m in announce_msgs(i, &slice) {
                txs[i as usize].send(m).await.unwrap();
            }
        }
        // Converged: every observer holds the table minus its own slice.
        let expected = u64::from(total - per_peer);
        let convergence_deadline = Instant::now() + CONVERGENCE_TIMEOUT;
        loop {
            tokio::time::sleep(HEALTH_POLL).await;
            require_healthy(&ctx, "initial convergence");
            let min = ctx
                .obs
                .iter()
                .map(|o| o.base_ann_total.load(Ordering::Relaxed))
                .min()
                .unwrap();
            if min >= expected {
                break;
            }
            if Instant::now() >= convergence_deadline {
                eprintln!(
                    "FAIL: initial convergence exceeded 120 seconds: min={min} target={expected}"
                );
                std::process::exit(1);
            }
        }
        require_healthy(&ctx, "post-convergence");
        println!(
            "converged (>= {expected}/observer) at {:.1}s rss_mib={}",
            ctx.t0.elapsed().as_secs_f64(),
            rss_mib(pid)
        );

        // --- Start churn: last CHURNERS stubs flap a dedicated block. ---
        for c in 0..CHURNERS {
            let i = n_peers - CHURNERS + c;
            let tx = txs[i as usize].clone();
            let block: Vec<Ipv4Prefix> = (0..CHURN_BLOCK).map(|j| churn_prefix(c, j)).collect();
            tokio::spawn(async move {
                // Stagger churners across the interval.
                tokio::time::sleep(Duration::from_millis(
                    u64::from(c) * CHURN_MS / u64::from(CHURNERS),
                ))
                .await;
                let mut announced = false;
                loop {
                    let msg = if announced {
                        withdraw_msg(&block)
                    } else {
                        announce_msgs(i, &block).pop().unwrap()
                    };
                    announced = !announced;
                    if tx.send(msg).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(CHURN_MS)).await;
                }
            });
        }
        // Let churn reach steady state.
        guarded_sleep(&ctx, Duration::from_secs(3), "churn warmup").await;

        // --- Control window. ---
        let cs = now_us(&ctx);
        guarded_sleep(&ctx, Duration::from_secs(control_secs), "control window").await;
        let ce = now_us(&ctx);
        let gaps: Vec<f64> = (0..n_peers as usize)
            .map(|i| max_gap_ms(&ctx, i, cs, ce, true))
            .collect();
        stats_line("control_maxgap_ms", gaps);
        println!("control_rss_mib {}", rss_mib(pid));

        // --- Reload loop. ---
        for r in 1..=reloads {
            let next = if r % 2 == 1 { &policy_b } else { &policy_a };
            let expected_community = if r % 2 == 1 {
                COMMUNITY_GEN_B
            } else {
                COMMUNITY_GEN_A
            };
            std::fs::copy(next, &policy_live).unwrap();
            let rss_before = rss_mib(pid);
            for (i, observer) in ctx.obs.iter().enumerate() {
                observer.expected_community.store(0, Ordering::Release);
                observer.generation.lock().unwrap().reset(
                    total,
                    expected,
                    u32::try_from(i).unwrap() * per_peer,
                    per_peer,
                );
                observer
                    .expected_community
                    .store(expected_community, Ordering::Release);
            }
            let t_hup = now_us(&ctx);
            println!("reload {r} SIGHUP wall_us={} policy={next}", wall_us());
            let kill_rc = unsafe { libc::kill(pid, libc::SIGHUP) };
            if kill_rc != 0 {
                eprintln!(
                    "reload {r} failed to deliver SIGHUP: {}",
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }
            // Wait for every observer to receive the full re-advertisement.
            let deadline = Instant::now() + Duration::from_secs(900);
            let mut ticks = 0u32;
            loop {
                tokio::time::sleep(HEALTH_POLL).await;
                require_healthy(&ctx, &format!("reload {r}"));
                let done = (0..n_peers as usize).all(|i| completion_us(&ctx, i).is_some());
                if done {
                    break;
                }
                ticks += 1;
                if ticks.is_multiple_of(20) {
                    let sat = (0..n_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} progress: complete={sat}/{n_peers}");
                }
                if Instant::now() > deadline {
                    println!("reload {r} TIMEOUT waiting for re-advertisement");
                    let sat = (0..n_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} observers_complete {sat}/{n_peers}");
                    std::process::exit(1);
                }
            }
            let (active_min, active_max, completed_observers) = ctx
                .obs
                .iter()
                .map(|observer| {
                    let generation = observer.generation.lock().unwrap();
                    (generation.active, generation.complete())
                })
                .fold((u64::MAX, 0, 0usize), |(min, max, completed), row| {
                    (
                        min.min(row.0),
                        max.max(row.0),
                        completed + usize::from(row.1),
                    )
                });
            if active_min != expected
                || active_max != expected
                || completed_observers != n_peers as usize
            {
                eprintln!(
                    "FAIL: reload {r} current-generation completion mismatch: \
                     min={active_min} max={active_max} target={expected} \
                     observers={completed_observers}/{n_peers}"
                );
                std::process::exit(1);
            }
            let community = format!(
                "{}:{}",
                expected_community >> 16,
                expected_community & 0xffff
            );
            println!(
                "reload {r} current_generation_complete \
                 contract=current-state-generation-community-v2 \
                 community={community} observers={completed_observers}/{n_peers} \
                 active_prefixes_per_observer={active_min} target={expected}"
            );
            // Per-observer completion + max gap over the reload window.
            let mut comp_s: Vec<f64> = Vec::new();
            let mut gaps: Vec<f64> = Vec::new();
            let mut firsts: Vec<f64> = Vec::new();
            for i in 0..n_peers as usize {
                if let Some(tc) = completion_us(&ctx, i) {
                    comp_s.push((tc - t_hup) as f64 / 1e6);
                    gaps.push(max_gap_ms(&ctx, i, t_hup, tc, false));
                    // Leading stall: SIGHUP -> first UPDATE of any kind.
                    let ev = ctx.obs[i].events.lock().unwrap();
                    if let Some(e) = ev.iter().find(|e| e.t_us >= t_hup) {
                        firsts.push((e.t_us - t_hup) as f64 / 1000.0);
                    }
                }
            }
            stats_line(&format!("reload {r} completion_s"), comp_s);
            stats_line(&format!("reload {r} maxgap_ms"), gaps);
            stats_line(&format!("reload {r} first_update_ms"), firsts);
            println!(
                "reload {r} rss_mib before={rss_before} after={} comms_sample={:?}",
                rss_mib(pid),
                ctx.obs[0].last_comms.lock().unwrap().clone()
            );
            // Keep observing the session through the quiesce interval. In
            // particular, the final cycle must not report a stale `true` just
            // before a reader or writer notices a closed transport.
            guarded_sleep(
                &ctx,
                Duration::from_secs(20),
                &format!("reload {r} quiesce"),
            )
            .await;
            let (verified_min, verified_observers) =
                ctx.obs
                    .iter()
                    .fold((u64::MAX, 0usize), |(minimum, complete), observer| {
                        let generation = observer.generation.lock().unwrap();
                        (
                            minimum.min(generation.active),
                            complete + usize::from(generation.complete()),
                        )
                    });
            if verified_min != expected || verified_observers != n_peers as usize {
                eprintln!(
                    "FAIL: reload {r} post-quiesce current-generation mismatch: \
                     active_min={verified_min} target={expected} \
                     observers={verified_observers}/{n_peers}"
                );
                std::process::exit(1);
            }
            println!(
                "reload {r} current_generation_verified \
                 contract=current-state-generation-community-v2 \
                 community={community} observers={verified_observers}/{n_peers} \
                 active_prefixes_per_observer={verified_min} target={expected}"
            );
            let up = live_sessions(&ctx);
            println!("reload {r} sessions_up {up}/{n_peers}");
        }

        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        let base_withdrawals = ctx.base_withdrawals.load(Ordering::Relaxed);
        let marker_conflicts = ctx.marker_conflicts.load(Ordering::Relaxed);
        let route_identity_defects = ctx.route_identity_defects.load(Ordering::Relaxed);
        require_healthy(&ctx, "final");
        println!(
            "defects parse_errors={parse_errors} base_withdrawals={base_withdrawals} \
             marker_conflicts={marker_conflicts} route_identity_defects={route_identity_defects}"
        );
        println!("done rss_mib={}", rss_mib(pid));
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_progress_tracks_current_receiver_state() {
        let mut progress = GenerationProgress::default();
        progress.reset(128, 2, 100, 26);

        progress.replace(7, MarkerState::Active, 10).unwrap();
        progress.replace(7, MarkerState::Active, 20).unwrap();
        assert_eq!(progress.active, 1, "replacement does not double count");
        assert_eq!(progress.completed_at_us, None);

        progress.replace(63, MarkerState::Active, 30).unwrap();
        assert_eq!(progress.active, 2);
        assert_eq!(progress.completed_at_us, Some(30));
        assert!(progress.complete());
    }

    #[test]
    fn late_inactive_only_replacement_revokes_completion() {
        let mut progress = GenerationProgress::default();
        progress.reset(2, 2, 2, 0);
        progress.replace(0, MarkerState::Active, 10).unwrap();
        progress.replace(1, MarkerState::Active, 20).unwrap();
        assert!(progress.complete());

        progress.replace(1, MarkerState::Inactive, 30).unwrap();
        assert_eq!(progress.active, 1);
        assert_eq!(progress.completed_at_us, None);
        assert!(!progress.complete());
    }

    #[test]
    fn late_markerless_replacement_revokes_completion() {
        let mut progress = GenerationProgress::default();
        progress.reset(1, 1, 1, 0);
        progress.replace(0, MarkerState::Active, 10).unwrap();
        assert!(progress.complete());

        progress.replace(0, MarkerState::Markerless, 20).unwrap();
        assert_eq!(progress.active, 0);
        assert_eq!(progress.completed_at_us, None);
        assert!(!progress.complete());
    }

    #[test]
    fn generation_marker_conflict_requires_active_and_inactive_markers() {
        assert!(generation_marker_conflict(
            COMMUNITY_GEN_A,
            &[COMMUNITY_GEN_A, COMMUNITY_GEN_B]
        ));
        assert!(generation_marker_conflict(
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_B, COMMUNITY_GEN_A]
        ));
        assert!(!generation_marker_conflict(
            COMMUNITY_GEN_A,
            &[COMMUNITY_GEN_A]
        ));
        assert!(!generation_marker_conflict(
            0,
            &[COMMUNITY_GEN_A, COMMUNITY_GEN_B]
        ));
    }

    #[test]
    fn generation_progress_rejects_observers_own_slice() {
        let mut progress = GenerationProgress::default();
        progress.reset(4, 3, 2, 1);
        assert_eq!(
            progress.replace(2, MarkerState::Active, 10),
            Err("observer received its own base prefix")
        );
        assert_eq!(progress.active, 0);
    }

    #[test]
    fn base_identity_validation_rejects_duplicates_wrong_lengths_and_range() {
        let duplicate = [base_prefix(7), base_prefix(7)];
        assert_eq!(
            validated_base_indices(&duplicate, 128, 100, 128),
            Err("duplicate base prefix identity in one UPDATE")
        );
        let wrong_length = [Ipv4Prefix::new(Ipv4Addr::new(20, 0, 7, 0), 25)];
        assert_eq!(
            validated_base_indices(&wrong_length, 128, 100, 128),
            Err("malformed or out-of-range base prefix identity")
        );
        let out_of_range = [base_prefix(128)];
        assert_eq!(
            validated_base_indices(&out_of_range, 128, 100, 128),
            Err("malformed or out-of-range base prefix identity")
        );
        let own = [base_prefix(100)];
        assert_eq!(
            validated_base_indices(&own, 128, 100, 128),
            Err("observer received its own base prefix")
        );
    }

    #[test]
    fn marker_state_distinguishes_active_inactive_and_markerless() {
        assert_eq!(
            marker_state(COMMUNITY_GEN_B, &[COMMUNITY_GEN_B]),
            MarkerState::Active
        );
        assert_eq!(
            marker_state(COMMUNITY_GEN_B, &[COMMUNITY_GEN_A]),
            MarkerState::Inactive
        );
        assert_eq!(marker_state(COMMUNITY_GEN_B, &[]), MarkerState::Markerless);
    }

    #[test]
    fn base_prefix_index_round_trips_and_rejects_non_base_routes() {
        for index in [0, 1, 65_535, 65_536, 400_399] {
            assert_eq!(
                base_prefix_index(base_prefix(index), 400_400),
                Some(index as usize)
            );
        }
        assert_eq!(base_prefix_index(base_prefix(400_400), 400_400), None);
        assert_eq!(
            base_prefix_index(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 24), 400_400),
            None
        );
    }
}
