//! LAN-333 reload-stall harness: N real BGP stub clients dial into a
//! running rustbgpd route server over loopback TCP, announce a full
//! table, run steady churn, then drive changed-policy SIGHUP reloads
//! and measure UPDATE-delivery gaps at every receiving client.
//!
//! Shape pinned in docs/perf/reload-stall-2026-07.md.
//!
//! Usage:
//!   reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
//!       <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
//!       [changed_peers] [reload_cmd] [--flapstorm K]
//!
//! Stubs bind distinct 127.1.x.y source addresses (matching the
//! generated [[neighbors]] blocks) and connect to 127.0.0.1:<port>.
//! The last CHURNERS stubs each flap a dedicated 16-prefix block every
//! CHURN_MS milliseconds throughout. On ROUTE_REFRESH a stub re-sends
//! its base slice (plus its churn block if currently announced).
//!
//! IXP-matrix extensions (LAN-334) — the 9/10-positional-arg SIGHUP
//! invocation above is a frozen contract and behaves identically:
//! - `reload_cmd` (11th positional): each reload runs `sh -c <reload_cmd>`
//!   (e.g. `docker exec <c> birdc configure`) instead of SIGHUP-ing
//!   <daemon_pid>; a nonzero exit fails the run like a failed SIGHUP.
//! - `daemon_pid` 0: skip in-harness RSS sampling (an outer sampler owns
//!   it; RSS columns report 0). Requires `reload_cmd` or `--flapstorm`.
//! - `--flapstorm K` (anywhere in argv): alternative mode replacing the
//!   reload loop. After convergence + the control window, close the first
//!   K stub sockets simultaneously, timestamp every survivor's receipt of
//!   all K slices' withdrawals, reconnect the K after 10 s, re-announce
//!   their slices, and timestamp survivors' re-announce completion.
//!   3 rounds, per-round percentiles + `flapstorm_csv` lines.

// Event.other and Ctx.n_peers are recorded for the observation/context
// model but not read by the percentile analysis; keep them so the
// recorded data shape matches what produced the receipt.
#![allow(dead_code)]

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
const COMMUNITY_STABLE: u32 = (65_500 << 16) | 9_000;
const STALL_WINDOW: Duration = Duration::from_secs(120);
const FLAP_ROUNDS: u32 = 3;
const FLAP_RECONNECT_SECS: u64 = 10;

/// What the shared per-observer bitmap is armed to track (flapstorm mode).
const FLAP_OFF: u32 = 0;
const FLAP_TRACK_WITHDRAWS: u32 = 1;
const FLAP_TRACK_ANNOUNCES: u32 = 2;

/// One received-UPDATE observation.
#[derive(Clone, Copy)]
struct Event {
    t_us: u64,
    /// announced NLRI in the base table space (20.0.0.0 onward, one first-octet per 65536 prefixes)
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
    /// Most recent announced UPDATE carrying the content-stable export marker.
    stable_marker_seen_at_us: AtomicU64,
    /// Community marker required for the active reload generation.
    expected_community: AtomicU32,
    /// Unique base prefixes observed with `expected_community`.
    generation: Mutex<GenerationProgress>,
    /// One outstanding ROUTE-REFRESH reply at a time (see the reader).
    refresh_pending: AtomicBool,
    /// Flapstorm arming: FLAP_OFF, or feed withdrawn/announced base
    /// prefixes into `generation` (which the reload path leaves idle in
    /// flapstorm mode — `expected_community` stays 0).
    flap_mode: AtomicU32,
}

/// A live stub session: its outbound channel plus the reader/writer task
/// handles, so flapstorm can hard-close the socket by aborting both tasks
/// (dropping both split halves closes the fd).
struct Stub {
    tx: mpsc::Sender<Message>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct GenerationProgress {
    seen: Vec<u64>,
    unique: u64,
    target: u64,
    excluded_start: usize,
    excluded_end: usize,
    completed_at_us: Option<u64>,
}

impl GenerationProgress {
    fn reset(&mut self, total_prefixes: u32, target: u64, excluded_start: u32, excluded_len: u32) {
        self.seen.clear();
        self.seen
            .resize(usize::try_from(total_prefixes).unwrap().div_ceil(64), 0);
        self.unique = 0;
        self.target = target;
        self.excluded_start = usize::try_from(excluded_start).unwrap();
        self.excluded_end = usize::try_from(excluded_start + excluded_len).unwrap();
        self.completed_at_us = None;
    }

    fn observe(&mut self, prefix_index: usize, t_us: u64) {
        if (self.excluded_start..self.excluded_end).contains(&prefix_index) {
            return;
        }
        let word = prefix_index / 64;
        let bit = 1u64 << (prefix_index % 64);
        let Some(slot) = self.seen.get_mut(word) else {
            return;
        };
        if *slot & bit != 0 {
            return;
        }
        *slot |= bit;
        self.unique += 1;
        if self.unique >= self.target && self.completed_at_us.is_none() {
            self.completed_at_us = Some(t_us);
        }
    }
}

struct Ctx {
    t0: Instant,
    n_peers: u32,
    per_peer: u32,
    daemon: SocketAddr,
    obs: Vec<Obs>,
    /// Daemon UPDATEs the stub failed to decode — a daemon defect that
    /// invalidates the run (see the reader and the exit check in `main`).
    parse_errors: AtomicU64,
}

fn now_us(ctx: &Ctx) -> u64 {
    u64::try_from(ctx.t0.elapsed().as_micros()).unwrap()
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
    // Lower bound only: the base space starts at 20.0.0.0 and grows one
    // first-octet per 65536 prefixes; the `index < total_prefixes` gate below
    // is the real upper bound (churn 172.16+.x maps to index >= 9.9M and is
    // rejected there). A hardcoded 20..30 octet cap here silently dropped
    // every prefix past index 655359 and wedged the 1M-route shape (LAN-449).
    if d != 0 || a < 20 {
        return None;
    }
    let index = (u32::from(a - 20) << 16) | (u32::from(b) << 8) | u32::from(c);
    (index < total_prefixes).then(|| usize::try_from(index).unwrap())
}

fn observe_generation(
    progress: &mut GenerationProgress,
    expected_community: u32,
    communities: &[u32],
    announced: &[Ipv4Prefix],
    total_prefixes: u32,
    t_us: u64,
) {
    if expected_community == 0 || !communities.contains(&expected_community) {
        return;
    }
    for prefix in announced {
        if let Some(index) = base_prefix_index(*prefix, total_prefixes) {
            progress.observe(index, t_us);
        }
    }
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

async fn establish_stub(ctx: Arc<Ctx>, i: u32) -> Result<Stub, String> {
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
    let writer_ctx = Arc::clone(&ctx);
    let writer_handle = tokio::spawn(async move {
        let mut ka_tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ka_tick.tick().await;
        loop {
            tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { break };
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                _ = ka_tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).unwrap();
                    if writer.write_all(&bytes).await.is_err() { break; }
                }
                else => break,
            }
        }
        writer_ctx.obs[i as usize]
            .established
            .store(false, Ordering::Relaxed);
    });

    // Reader task: frame, decode, record UPDATE arrivals, answer
    // ROUTE_REFRESH by re-sending the base slice.
    let tx_for_reader = tx.clone();
    let rctx = Arc::clone(&ctx);
    let reader_handle = tokio::spawn(async move {
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
                    Err(error) => {
                        eprintln!("stub {i} invalid daemon frame: {error}");
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
                    Err(error) => {
                        eprintln!("stub {i} failed to decode daemon message: {error}");
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
                        let mut base = 0u32;
                        let mut other = u32::try_from(parsed.withdrawn.len()).unwrap_or(0);
                        for e in &parsed.announced {
                            // Same predicate as generation tracking: a second,
                            // divergent octet-range check here is what capped
                            // base_ann_total at 655360 and hung convergence.
                            if base_prefix_index(e.prefix, total_prefixes).is_some() {
                                base += 1;
                            } else {
                                other += 1;
                            }
                        }
                        let ob = &rctx.obs[i as usize];
                        let t_us = now_us(&rctx);
                        if !parsed.announced.is_empty() {
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
                            if communities.contains(&COMMUNITY_STABLE) {
                                ob.stable_marker_seen_at_us.store(t_us, Ordering::Release);
                            }

                            let expected = ob.expected_community.load(Ordering::Acquire);
                            if base > 0 && expected != 0 && communities.contains(&expected) {
                                let mut generation = ob.generation.lock().unwrap();
                                if ob.expected_community.load(Ordering::Acquire) == expected {
                                    for e in &parsed.announced {
                                        if let Some(index) =
                                            base_prefix_index(e.prefix, total_prefixes)
                                        {
                                            generation.observe(index, t_us);
                                        }
                                    }
                                }
                            }
                        }
                        // Flapstorm arming: feed the tracked direction into the
                        // same per-observer bitmap the reload path uses. Runs
                        // for withdraw-only UPDATEs too (the reload-generation
                        // block above is announce-gated).
                        let flap_mode = ob.flap_mode.load(Ordering::Acquire);
                        if flap_mode != FLAP_OFF {
                            let tracked = if flap_mode == FLAP_TRACK_WITHDRAWS {
                                &parsed.withdrawn
                            } else {
                                &parsed.announced
                            };
                            let mut generation = ob.generation.lock().unwrap();
                            for e in tracked {
                                if let Some(index) = base_prefix_index(e.prefix, total_prefixes) {
                                    generation.observe(index, t_us);
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
                    _ => {}
                }
            }
        }
    });

    Ok(Stub {
        tx,
        reader: reader_handle,
        writer: writer_handle,
    })
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
/// trailing gap to e_us when `trailing` is set (control windows and the
/// full-fleet reload window, whose stable observers have no completion event).
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

fn stable_marker_is_fresh(seen_at_us: u64, since_us: u64) -> bool {
    seen_at_us != 0 && seen_at_us >= since_us
}

fn stable_marker_peers_since(ctx: &Ctx, changed_peers: u32, since_us: u64) -> usize {
    ctx.obs
        .iter()
        .skip(changed_peers as usize)
        .filter(|observer| {
            stable_marker_is_fresh(
                observer.stable_marker_seen_at_us.load(Ordering::Acquire),
                since_us,
            )
        })
        .count()
}

fn rss_mib(pid: i32) -> u64 {
    if pid <= 0 {
        // daemon_pid 0: an outer sampler owns RSS; report 0 everywhere.
        return 0;
    }
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

#[derive(Clone, Copy)]
struct Stats {
    p50: f64,
    p95: f64,
    max: f64,
    n: usize,
}

fn stats_line(label: &str, mut vals: Vec<f64>) -> Stats {
    vals.sort_by(f64::total_cmp);
    let stats = Stats {
        p50: pct(&vals, 0.5),
        p95: pct(&vals, 0.95),
        max: pct(&vals, 1.0),
        n: vals.len(),
    };
    println!(
        "{label}: p50={:.2} p95={:.2} max={:.2} (n={})",
        stats.p50, stats.p95, stats.max, stats.n
    );
    stats
}

/// Progress watchdog for one flapstorm phase: every survivor (observers
/// `first..n_peers`) must complete its armed bitmap; fail loudly when no
/// survivor makes unique-prefix progress for STALL_WINDOW (same discipline
/// as the reload loop — no absolute deadline).
async fn wait_flap_completion(ctx: &Ctx, first: usize, round: u32, phase: &str) {
    let mut last_unique = 0u64;
    let mut last_progress = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if (first..ctx.obs.len()).all(|i| completion_us(ctx, i).is_some()) {
            return;
        }
        let sum: u64 = (first..ctx.obs.len())
            .map(|i| ctx.obs[i].generation.lock().unwrap().unique)
            .sum();
        if sum > last_unique {
            last_unique = sum;
            last_progress = Instant::now();
        } else if last_progress.elapsed() > STALL_WINDOW {
            let done = (first..ctx.obs.len())
                .filter(|&i| completion_us(ctx, i).is_some())
                .count();
            eprintln!(
                "flap {round} {phase} STALLED: no progress for {}s; \
                 survivors complete {done}/{}",
                STALL_WINDOW.as_secs(),
                ctx.obs.len() - first
            );
            for i in (first..ctx.obs.len())
                .filter(|&i| completion_us(ctx, i).is_none())
                .take(10)
            {
                let g = ctx.obs[i].generation.lock().unwrap();
                eprintln!(
                    "flap {round} {phase} observer {i} incomplete: unique={}/{}",
                    g.unique, g.target
                );
            }
            std::process::exit(1);
        }
    }
}

/// Arm every survivor's shared bitmap to track `mode` over the flapped
/// window (base indices `[0, flap_prefixes)`; everything else excluded).
fn arm_survivors(ctx: &Ctx, k: u32, flap_prefixes: u32, total: u32, mode: u32) {
    for observer in ctx.obs.iter().skip(k as usize) {
        observer.flap_mode.store(FLAP_OFF, Ordering::Release);
        observer.generation.lock().unwrap().reset(
            total,
            u64::from(flap_prefixes),
            flap_prefixes,
            total - flap_prefixes,
        );
        observer.flap_mode.store(mode, Ordering::Release);
    }
}

/// `--flapstorm K` mode: the alternative to the reload loop (see the crate
/// doc). The flapped cohort is the first K stubs — never the churners,
/// which are the last CHURNERS.
async fn run_flapstorm(ctx: &Arc<Ctx>, stubs: &mut [Stub], k: u32, pid: i32) {
    let n_peers = ctx.n_peers;
    let total = n_peers * ctx.per_peer;
    let flap_prefixes = k * ctx.per_peer;
    let survivors = k as usize..n_peers as usize;
    println!(
        "flapstorm_csv_header,round,peers_total,peers_flapped,prefixes,flap_prefixes,\
         withdraw_p50_s,withdraw_p95_s,withdraw_max_s,\
         reannounce_p50_s,reannounce_p95_s,reannounce_max_s,\
         rss_mib,sessions_up,parse_errors"
    );
    for round in 1..=FLAP_ROUNDS {
        // Arm before closing so no withdrawal is missed.
        arm_survivors(ctx, k, flap_prefixes, total, FLAP_TRACK_WITHDRAWS);
        println!("flap {round} close wall_us={}", wall_us());
        let t_close = now_us(ctx);
        // Simultaneous close: abort both split-half tasks per flapped stub.
        for stub in stubs.iter().take(k as usize) {
            stub.reader.abort();
            stub.writer.abort();
        }
        for observer in ctx.obs.iter().take(k as usize) {
            observer.established.store(false, Ordering::Relaxed);
        }
        wait_flap_completion(ctx, k as usize, round, "withdraw").await;
        let withdraw_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| completion_us(ctx, i))
            .map(|tc| tc.saturating_sub(t_close) as f64 / 1e6)
            .collect();
        let withdraw = stats_line(&format!("flap {round} withdraw_s"), withdraw_s);

        // Hold the sessions down until FLAP_RECONNECT_SECS past the close.
        let since_close_ms = now_us(ctx).saturating_sub(t_close) / 1000;
        let hold_ms = (FLAP_RECONNECT_SECS * 1000).saturating_sub(since_close_ms);
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;

        // Re-arm before any flapped session returns, so no announce is missed.
        arm_survivors(ctx, k, flap_prefixes, total, FLAP_TRACK_ANNOUNCES);
        for i in 0..k {
            match establish_stub(Arc::clone(ctx), i).await {
                Ok(stub) => stubs[i as usize] = stub,
                Err(e) => {
                    eprintln!("flap {round} reconnect stub {i} failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        let t_reann = now_us(ctx);
        println!("flap {round} reannounce wall_us={}", wall_us());
        for i in 0..k {
            let slice = own_slice(ctx, i);
            for m in announce_msgs(i, &slice) {
                if stubs[i as usize].tx.send(m).await.is_err() {
                    eprintln!("flap {round} re-announce send failed for stub {i}");
                    std::process::exit(1);
                }
            }
        }
        wait_flap_completion(ctx, k as usize, round, "reannounce").await;
        let reann_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| completion_us(ctx, i))
            .map(|tc| tc.saturating_sub(t_reann) as f64 / 1e6)
            .collect();
        let reannounce = stats_line(&format!("flap {round} reannounce_s"), reann_s);
        // First re-announce arrival per survivor: distinguishes a steady
        // drain (first ≪ completion: fan-out throughput) from an
        // idle-then-burst gate (first ≈ completion: a daemon-side timer).
        let first_s: Vec<f64> = survivors
            .clone()
            .filter_map(|i| {
                let events = ctx.obs[i].events.lock().unwrap();
                events
                    .iter()
                    .find(|e| e.t_us >= t_reann && e.base_ann > 0)
                    .map(|e| e.t_us.saturating_sub(t_reann) as f64 / 1e6)
            })
            .collect();
        stats_line(&format!("flap {round} first_reann_s"), first_s);
        for observer in ctx.obs.iter().skip(k as usize) {
            observer.flap_mode.store(FLAP_OFF, Ordering::Release);
        }
        let rss = rss_mib(pid);
        let up = ctx
            .obs
            .iter()
            .filter(|o| o.established.load(Ordering::Relaxed))
            .count();
        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        println!("flap {round} sessions_up {up}/{n_peers} rss_mib={rss}");
        if up != n_peers as usize || parse_errors != 0 {
            eprintln!(
                "FAIL: flap {round} integrity check failed: \
                 sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
            );
            std::process::exit(1);
        }
        println!(
            "flapstorm_csv,{round},{n_peers},{k},{total},{flap_prefixes},\
             {:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{rss},{up},{parse_errors}",
            withdraw.p50,
            withdraw.p95,
            withdraw.max,
            reannounce.p50,
            reannounce.p95,
            reannounce.max,
        );
        // Quiesce between rounds.
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    // --flapstorm K may appear anywhere; strip it before positional parsing.
    let mut flapstorm: Option<u32> = None;
    if let Some(pos) = a.iter().position(|s| s == "--flapstorm") {
        flapstorm = Some(
            a.get(pos + 1)
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| {
                    eprintln!("--flapstorm requires a stub count K");
                    std::process::exit(2);
                }),
        );
        a.drain(pos..=pos + 1);
    }
    if a.len() < 10 {
        eprintln!(
            "usage: reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
             <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
             [changed_peers] [reload_cmd] [--flapstorm K]\n\
             reload_cmd: run `sh -c <reload_cmd>` per reload instead of SIGHUP-ing <daemon_pid>\n\
             daemon_pid 0: skip in-harness RSS sampling (outer sampler owns it); \
             requires reload_cmd or --flapstorm\n\
             --flapstorm K: flap the first K stubs for {FLAP_ROUNDS} rounds instead of reloading"
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
    let changed_peers: u32 = a.get(10).map_or(n_peers, |value| value.parse().unwrap());
    let reload_cmd: Option<String> = a.get(11).cloned();
    assert!(n_peers >= CHURNERS, "n_peers must be at least {CHURNERS}");
    assert!(
        (1..=n_peers).contains(&changed_peers),
        "changed_peers must be in 1..={n_peers}"
    );
    assert!(
        pid != 0 || reload_cmd.is_some() || flapstorm.is_some(),
        "daemon_pid 0 (outer RSS sampler) requires reload_cmd or --flapstorm"
    );
    if let Some(k) = flapstorm {
        assert!(
            (1..=n_peers - CHURNERS).contains(&k),
            "--flapstorm K must be in 1..={} (the last {CHURNERS} stubs are churners)",
            n_peers - CHURNERS
        );
    }
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
                    stable_marker_seen_at_us: AtomicU64::new(0),
                    expected_community: AtomicU32::new(0),
                    generation: Mutex::new(GenerationProgress::default()),
                    refresh_pending: AtomicBool::new(false),
                    flap_mode: AtomicU32::new(FLAP_OFF),
                })
                .collect(),
            parse_errors: AtomicU64::new(0),
        });
        println!(
            "# reloadstall peers={n_peers} changed_peers={changed_peers} \
             stable_peers={} prefixes={total} per_peer={per_peer} pid={pid}",
            n_peers - changed_peers
        );

        // --- Establish all sessions (waves of 64). ---
        let mut stubs: Vec<Stub> = Vec::with_capacity(n_peers as usize);
        for wave in (0..n_peers).collect::<Vec<_>>().chunks(64) {
            let mut handles = Vec::new();
            for &i in wave {
                let c = Arc::clone(&ctx);
                handles.push((i, tokio::spawn(establish_stub(c, i))));
            }
            for (i, h) in handles {
                match h.await.unwrap() {
                    Ok(stub) => stubs.push(stub),
                    Err(e) => {
                        eprintln!("stub {i} failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!(
            "established {} at {:.1}s",
            stubs.len(),
            ctx.t0.elapsed().as_secs_f64()
        );

        // --- Announce base table. ---
        for i in 0..n_peers {
            let slice = own_slice(&ctx, i);
            for m in announce_msgs(i, &slice) {
                stubs[i as usize].tx.send(m).await.unwrap();
            }
        }
        // Converged: every observer holds the table minus its own slice.
        // Watchdog: if no observer makes progress for a generous window,
        // abort with expected-vs-observed counts instead of parking forever
        // (the pre-LAN-449 failure mode: a wrong predicate here is silent).
        let expected = u64::from(total - per_peer);
        let mut last_sum = 0u64;
        let mut last_progress = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let counts: Vec<u64> = ctx
                .obs
                .iter()
                .map(|o| o.base_ann_total.load(Ordering::Relaxed))
                .collect();
            if *counts.iter().min().unwrap() >= expected {
                break;
            }
            let sum: u64 = counts.iter().sum();
            if sum > last_sum {
                last_sum = sum;
                last_progress = Instant::now();
            } else if last_progress.elapsed() > STALL_WINDOW {
                let below: Vec<(usize, u64)> = counts
                    .iter()
                    .enumerate()
                    .filter(|&(_, &c)| c < expected)
                    .map(|(i, &c)| (i, c))
                    .collect();
                eprintln!(
                    "FAIL: base-table convergence stalled for {}s: expected >= {expected} \
                     base prefixes per observer, {} of {n_peers} observers below; \
                     first stalled (observer, observed): {:?}",
                    STALL_WINDOW.as_secs(),
                    below.len(),
                    &below[..below.len().min(10)]
                );
                std::process::exit(1);
            }
        }
        println!(
            "converged (>= {expected}/observer) at {:.1}s rss_mib={}",
            ctx.t0.elapsed().as_secs_f64(),
            rss_mib(pid)
        );

        // --- Start churn: last CHURNERS stubs flap a dedicated block. ---
        for c in 0..CHURNERS {
            let i = n_peers - CHURNERS + c;
            let tx = stubs[i as usize].tx.clone();
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
        tokio::time::sleep(Duration::from_secs(3)).await;

        // --- Control window. ---
        let cs = now_us(&ctx);
        tokio::time::sleep(Duration::from_secs(control_secs)).await;
        let ce = now_us(&ctx);
        let gaps: Vec<f64> = (0..n_peers as usize)
            .map(|i| max_gap_ms(&ctx, i, cs, ce, true))
            .collect();
        stats_line("control_maxgap_ms", gaps);
        println!("control_rss_mib {}", rss_mib(pid));

        // --- Flapstorm mode: an alternative to the reload loop. ---
        if let Some(k) = flapstorm {
            run_flapstorm(&ctx, &mut stubs, k, pid).await;
            println!("done rss_mib={}", rss_mib(pid));
            let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
            if parse_errors > 0 {
                eprintln!(
                    "FAIL: {parse_errors} daemon UPDATE decode error(s) — a wire defect; measurement is invalid"
                );
                std::process::exit(1);
            }
            std::process::exit(0);
        }

        println!(
            "reloadstall_csv_header,reload,peers_total,peers_changed,peers_stable,prefixes,\
             completion_p50_s,completion_p95_s,completion_max_s,\
             changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,\
             all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,\
             all_observer_maxgap_max_ms,changed_first_update_p50_ms,\
             changed_first_update_p95_ms,changed_first_update_max_ms,\
             rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
        );

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
            for (i, observer) in ctx
                .obs
                .iter()
                .take(changed_peers as usize)
                .enumerate()
            {
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
            let expected_stable = usize::try_from(n_peers - changed_peers).unwrap();
            if let Some(cmd) = &reload_cmd {
                // Matrix cells (BIRD/OpenBGPD) reload via a command, e.g.
                // `docker exec <c> birdc configure`; nonzero exit = reload
                // failure, same handling as a failed SIGHUP.
                println!("reload {r} reload_cmd wall_us={} policy={next}", wall_us());
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .status();
                if !matches!(&status, Ok(s) if s.success()) {
                    eprintln!("reload {r} reload_cmd failed: {status:?}");
                    std::process::exit(1);
                }
            } else {
                println!("reload {r} SIGHUP wall_us={} policy={next}", wall_us());
                let kill_rc = unsafe { libc::kill(pid, libc::SIGHUP) };
                if kill_rc != 0 {
                    eprintln!(
                        "reload {r} failed to deliver SIGHUP: {}",
                        std::io::Error::last_os_error()
                    );
                    std::process::exit(1);
                }
            }
            // Completion is intentionally scoped to observers whose effective
            // export chain changed. Stable proof starts only after every
            // changed observer has the new generation, below.
            // Progress watchdog, not an absolute deadline: full-fleet
            // re-advertisement time scales with peers x prefixes, so any
            // fixed deadline falsely fails some larger shape while the wire
            // is still delivering. Fail loudly only when no changed observer
            // makes generation progress for STALL_WINDOW.
            let unique_sum = |ctx: &Ctx| -> u64 {
                (0..changed_peers as usize)
                    .map(|i| ctx.obs[i].generation.lock().unwrap().unique)
                    .sum()
            };
            let mut last_unique = 0u64;
            let mut last_progress = Instant::now();
            let mut ticks = 0u32;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let done =
                    (0..changed_peers as usize).all(|i| completion_us(&ctx, i).is_some());
                if done {
                    break;
                }
                ticks += 1;
                if ticks.is_multiple_of(100) {
                    let sat = (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} progress: complete={sat}/{changed_peers}");
                }
                let sum = unique_sum(&ctx);
                if sum > last_unique {
                    last_unique = sum;
                    last_progress = Instant::now();
                } else if last_progress.elapsed() > STALL_WINDOW {
                    println!(
                        "reload {r} STALLED: no re-advertisement progress for {}s",
                        STALL_WINDOW.as_secs()
                    );
                    let sat = (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_some())
                        .count();
                    eprintln!("reload {r} observers_complete {sat}/{changed_peers}");
                    // Per-observer expected-vs-observed for the first few
                    // incomplete observers, so a wedge here is diagnosable.
                    for i in (0..changed_peers as usize)
                        .filter(|&i| completion_us(&ctx, i).is_none())
                        .take(10)
                    {
                        let g = ctx.obs[i].generation.lock().unwrap();
                        eprintln!(
                            "reload {r} observer {i} incomplete: unique={}/{}",
                            g.unique, g.target
                        );
                    }
                    std::process::exit(1);
                }
            }
            let reload_end_us = (0..changed_peers as usize)
                .filter_map(|i| completion_us(&ctx, i))
                .max()
                .expect("changed_peers is non-zero and every observer completed");
            // Reset the evidence threshold only after the changed cohort has
            // fully received the target generation. Fresh stable-marker churn
            // after this point proves stable observers retained stable-out
            // through the completed transition, rather than merely sampling
            // an UPDATE queued before or during it.
            let marker_since_us = now_us(&ctx);
            let mut stable_ticks = 0u32;
            let mut last_stable = 0usize;
            let mut stable_progress = Instant::now();
            loop {
                let stable_marker_peers =
                    stable_marker_peers_since(&ctx, changed_peers, marker_since_us);
                if stable_marker_peers == expected_stable {
                    break;
                }
                if stable_marker_peers > last_stable {
                    last_stable = stable_marker_peers;
                    stable_progress = Instant::now();
                } else if stable_progress.elapsed() > STALL_WINDOW {
                    eprintln!(
                        "reload {r} STALLED: no post-completion stable-marker progress for {}s: {stable_marker_peers}/{expected_stable}",
                        STALL_WINDOW.as_secs()
                    );
                    std::process::exit(1);
                }
                stable_ticks += 1;
                if stable_ticks.is_multiple_of(20) {
                    eprintln!(
                        "reload {r} post-completion stable markers: {stable_marker_peers}/{expected_stable}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Changed-observer completion and gap metrics preserve the
            // historical measurement. The all-observer gap extends through
            // the slowest changed observer so stable sessions cannot disappear
            // from the receipt just because they have no completion marker.
            let mut comp_s: Vec<f64> = Vec::new();
            let mut gaps: Vec<f64> = Vec::new();
            let mut firsts: Vec<f64> = Vec::new();
            for i in 0..changed_peers as usize {
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
            let all_observer_gaps: Vec<f64> = (0..n_peers as usize)
                .map(|i| max_gap_ms(&ctx, i, t_hup, reload_end_us, true))
                .collect();
            let completion = stats_line(&format!("reload {r} completion_s"), comp_s);
            let changed_gap = stats_line(&format!("reload {r} maxgap_ms"), gaps);
            let all_gap = stats_line(
                &format!("reload {r} all_observer_maxgap_ms"),
                all_observer_gaps,
            );
            let first_update = stats_line(&format!("reload {r} first_update_ms"), firsts);
            let rss_after = rss_mib(pid);
            println!(
                "reload {r} rss_mib before={rss_before} after={} comms_sample={:?}",
                rss_after,
                ctx.obs[0].last_comms.lock().unwrap().clone()
            );
            let up = ctx
                .obs
                .iter()
                .filter(|o| o.established.load(Ordering::Relaxed))
                .count();
            println!("reload {r} sessions_up {up}/{n_peers}");
            let stable_marker_peers =
                stable_marker_peers_since(&ctx, changed_peers, marker_since_us);
            println!(
                "reload {r} stable_marker_peers {stable_marker_peers}/{expected_stable}"
            );
            let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
            if stable_marker_peers != expected_stable
                || up != n_peers as usize
                || parse_errors != 0
            {
                eprintln!(
                    "FAIL: reload {r} integrity check failed: stable_marker_peers={stable_marker_peers}/{expected_stable}, sessions_up={up}/{n_peers}, parse_errors={parse_errors}"
                );
                std::process::exit(1);
            }
            println!(
                "reloadstall_csv,{r},{n_peers},{changed_peers},{},{total},\
                 {:.6},{:.6},{:.6},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},\
                 {:.3},{:.3},{:.3},{rss_before},{rss_after},{stable_marker_peers},{up},{parse_errors}",
                n_peers - changed_peers,
                completion.p50,
                completion.p95,
                completion.max,
                changed_gap.p50,
                changed_gap.p95,
                changed_gap.max,
                all_gap.p50,
                all_gap.p95,
                all_gap.max,
                first_update.p50,
                first_update.p95,
                first_update.max,
            );
            // Quiesce between reloads.
            tokio::time::sleep(Duration::from_secs(20)).await;
        }

        println!("done rss_mib={}", rss_mib(pid));
        let parse_errors = ctx.parse_errors.load(Ordering::Relaxed);
        if parse_errors > 0 {
            eprintln!(
                "FAIL: {parse_errors} daemon UPDATE decode error(s) — a wire defect; measurement is invalid"
            );
            std::process::exit(1);
        }
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_progress_counts_unique_prefixes_only() {
        let mut progress = GenerationProgress::default();
        progress.reset(128, 2, 100, 26);

        progress.observe(7, 10);
        progress.observe(7, 20);
        assert_eq!(
            progress.unique, 1,
            "a duplicate announce is not completion progress"
        );
        assert_eq!(progress.completed_at_us, None);

        progress.observe(63, 30);
        assert_eq!(progress.unique, 2);
        assert_eq!(progress.completed_at_us, Some(30));
        progress.observe(64, 40);
        assert_eq!(
            progress.completed_at_us,
            Some(30),
            "completion time is stable"
        );
    }

    #[test]
    fn generation_progress_rejects_stale_policy_markers() {
        let mut progress = GenerationProgress::default();
        progress.reset(128, 1, 100, 27);
        let announced = [base_prefix(7)];

        observe_generation(
            &mut progress,
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_A],
            &announced,
            128,
            10,
        );
        assert_eq!(progress.unique, 0);
        assert_eq!(progress.completed_at_us, None);

        observe_generation(
            &mut progress,
            COMMUNITY_GEN_B,
            &[COMMUNITY_GEN_B],
            &announced,
            128,
            20,
        );
        assert_eq!(progress.unique, 1);
        assert_eq!(progress.completed_at_us, Some(20));
    }

    #[test]
    fn generation_progress_rejects_observers_own_slice() {
        let mut progress = GenerationProgress::default();
        progress.reset(4, 3, 2, 1);

        progress.observe(0, 10);
        progress.observe(1, 20);
        progress.observe(2, 30);
        assert_eq!(progress.unique, 2, "own prefix must not advance completion");
        assert_eq!(progress.completed_at_us, None);

        progress.observe(3, 40);
        assert_eq!(progress.unique, 3);
        assert_eq!(progress.completed_at_us, Some(40));
    }

    #[test]
    fn flap_window_tracks_only_flapped_slices() {
        // 4 peers x 2 prefixes each, K=2 flapped: window = indices [0, 4),
        // exclusion covers [4, 8) — the arm_survivors reset shape.
        let mut progress = GenerationProgress::default();
        progress.reset(8, 4, 4, 4);

        progress.observe(4, 10); // survivor's own slice: excluded
        progress.observe(7, 20); // another survivor slice: excluded
        assert_eq!(progress.unique, 0, "non-flapped indices must not count");

        for idx in 0..4u64 {
            progress.observe(usize::try_from(idx).unwrap(), 30 + idx);
        }
        assert_eq!(progress.unique, 4);
        assert_eq!(progress.completed_at_us, Some(33));
    }

    #[test]
    fn stable_marker_freshness_rejects_missing_and_pre_threshold_evidence() {
        assert!(!stable_marker_is_fresh(0, 100));
        assert!(!stable_marker_is_fresh(99, 100));
        assert!(stable_marker_is_fresh(100, 100));
        assert!(stable_marker_is_fresh(101, 100));
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
        // 1M-route shape (LAN-449): indexes past 655359 use first octets >= 30
        // and must still round-trip; the total gate stays the upper bound.
        for index in [655_359, 655_360, 999_999] {
            assert_eq!(
                base_prefix_index(base_prefix(index), 1_000_000),
                Some(index as usize)
            );
        }
        assert_eq!(base_prefix_index(base_prefix(1_000_000), 1_000_000), None);
        assert_eq!(
            base_prefix_index(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 24), 1_000_000),
            None
        );
    }
}
