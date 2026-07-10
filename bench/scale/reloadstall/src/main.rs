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

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
}

struct Ctx {
    t0: Instant,
    n_peers: u32,
    per_peer: u32,
    daemon: SocketAddr,
    obs: Vec<Obs>,
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
    tokio::spawn(async move {
        let mut ka_tick = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
        ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ka_tick.tick().await;
        loop {
            tokio::select! {
                Some(msg) = tx_rx.recv() => {
                    let Ok(bytes) = encode_message(&msg) else { return };
                    if writer.write_all(&bytes).await.is_err() { return; }
                }
                _ = ka_tick.tick() => {
                    let bytes = encode_message(&Message::Keepalive).unwrap();
                    if writer.write_all(&bytes).await.is_err() { return; }
                }
                else => return,
            }
        }
    });

    // Reader task: frame, decode, record UPDATE arrivals, answer
    // ROUTE_REFRESH by re-sending the base slice.
    let tx_for_reader = tx.clone();
    let rctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut frame = BytesMut::with_capacity(1 << 16);
        let mut tmp = vec![0u8; 1 << 16];
        let mut msg_n: u64 = 0;
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
                    Err(_) => return,
                };
                if frame.len() < total {
                    break;
                }
                let mut mb = frame.split_to(total).freeze();
                let msg = match decode_message(&mut mb, MAX_MESSAGE_LEN) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                match msg {
                    Message::Update(u) => {
                        msg_n += 1;
                        let ann = rustbgpd_wire::nlri::decode_nlri(&u.nlri).unwrap_or_default();
                        let wd_n = rustbgpd_wire::nlri::decode_nlri(&u.withdrawn_routes)
                            .map(|v| v.len())
                            .unwrap_or(0);
                        let mut base = 0u32;
                        let mut other = u32::try_from(wd_n).unwrap_or(0);
                        for p in &ann {
                            let first = p.addr.octets()[0];
                            if (20..30).contains(&first) {
                                base += 1;
                            } else {
                                other += 1;
                            }
                        }
                        // Sample full attribute parse occasionally so the
                        // driver can verify which policy generation the
                        // delivered routes carry (community marker).
                        if msg_n.is_multiple_of(31) && base > 0 {
                            if let Ok(parsed) = u.parse(true, false, &[]) {
                                for a in parsed.attributes {
                                    if let PathAttribute::Communities(cs) = a {
                                        *rctx.obs[i as usize].last_comms.lock().unwrap() = cs;
                                    }
                                }
                            }
                        }
                        let ob = &rctx.obs[i as usize];
                        ob.base_ann_total
                            .fetch_add(u64::from(base), Ordering::Relaxed);
                        ob.events.lock().unwrap().push(Event {
                            t_us: now_us(&rctx),
                            base_ann: base,
                            other,
                        });
                    }
                    Message::RouteRefresh(_) => {
                        let slice = own_slice(&rctx, i);
                        for m in announce_msgs(i, &slice) {
                            if tx_for_reader.send(m).await.is_err() {
                                return;
                            }
                        }
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

/// First event time (us) at which the observer's cumulative base-space
/// announce delta since `s_us` reaches `target`. None if not reached.
fn completion_us(ctx: &Ctx, i: usize, s_us: u64, target: u64) -> Option<u64> {
    let ev = ctx.obs[i].events.lock().unwrap();
    let mut acc = 0u64;
    for e in ev.iter() {
        if e.t_us < s_us {
            continue;
        }
        acc += u64::from(e.base_ann);
        if acc >= target {
            return Some(e.t_us);
        }
    }
    None
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
                })
                .collect(),
        });
        println!("# reloadstall peers={n_peers} prefixes={total} per_peer={per_peer} pid={pid}");

        // --- Establish all sessions (waves of 64). ---
        let mut txs: Vec<mpsc::Sender<Message>> = Vec::with_capacity(n_peers as usize);
        for wave in (0..n_peers).collect::<Vec<_>>().chunks(64) {
            let mut handles = Vec::new();
            for &i in wave {
                let c = Arc::clone(&ctx);
                handles.push((i, tokio::spawn(establish_stub(c, i))));
            }
            for (i, h) in handles {
                match h.await.unwrap() {
                    Ok(tx) => txs.push(tx),
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
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let min = ctx
                .obs
                .iter()
                .map(|o| o.base_ann_total.load(Ordering::Relaxed))
                .min()
                .unwrap();
            if min >= expected {
                break;
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

        // --- Reload loop. ---
        for r in 1..=reloads {
            let next = if r % 2 == 1 { &policy_b } else { &policy_a };
            std::fs::copy(next, &policy_live).unwrap();
            let rss_before = rss_mib(pid);
            let base_before: Vec<u64> = ctx
                .obs
                .iter()
                .map(|o| o.base_ann_total.load(Ordering::Relaxed))
                .collect();
            let t_hup = now_us(&ctx);
            println!("reload {r} SIGHUP wall_us={} policy={next}", wall_us());
            unsafe {
                libc::kill(pid, libc::SIGHUP);
            }
            // Wait for every observer to receive the full re-advertisement.
            let deadline = Instant::now() + Duration::from_secs(900);
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let done = (0..n_peers as usize).all(|i| {
                    ctx.obs[i].base_ann_total.load(Ordering::Relaxed) - base_before[i] >= expected
                });
                if done {
                    break;
                }
                if Instant::now() > deadline {
                    println!("reload {r} TIMEOUT waiting for re-advertisement");
                    let sat = (0..n_peers as usize)
                        .filter(|&i| {
                            ctx.obs[i].base_ann_total.load(Ordering::Relaxed) - base_before[i]
                                >= expected
                        })
                        .count();
                    println!("reload {r} observers_complete {sat}/{n_peers}");
                    break;
                }
            }
            // Per-observer completion + max gap over the reload window.
            let mut comp_s: Vec<f64> = Vec::new();
            let mut gaps: Vec<f64> = Vec::new();
            let mut firsts: Vec<f64> = Vec::new();
            for i in 0..n_peers as usize {
                if let Some(tc) = completion_us(&ctx, i, t_hup, expected) {
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
            let up = ctx
                .obs
                .iter()
                .filter(|o| o.established.load(Ordering::Relaxed))
                .count();
            println!("reload {r} sessions_up {up}/{n_peers}");
            // Quiesce between reloads.
            tokio::time::sleep(Duration::from_secs(20)).await;
        }

        println!("done rss_mib={}", rss_mib(pid));
        std::process::exit(0);
    });
}
