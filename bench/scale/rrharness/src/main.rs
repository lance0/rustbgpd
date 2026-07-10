//! rrharness reconstruction (LAN-250 / ADR-0100 slice 0), manager-direct
//! variant: the real `RibManager` run loop on a dedicated named OS thread
//! ("ribmgr", current_thread runtime), N registered RR-client outbound peers
//! whose bounded channels are drained by trivial consumer tasks, route
//! injection via `RibUpdate::RoutesReceived`, staged gauge via
//! `QueryAdjRibOutCounts`, drained gauge via per-message NLRI counting.
//!
//! Differences from the 2026-07-03 rrharness (documented in the receipt):
//! transport sessions/TCP stubs are replaced by channel drains, so
//! prepare/encode/writer costs do not exist in this process — slice 0 only
//! attributes the manager task, which is unchanged by that substitution.
//!
//! Modes:
//!   rrharness flood <n_clients> <n_prefixes> <secs> <out_prefix>
//!   rrharness churn <n_clients> <n_cand> <n_prefixes> <secs> <out_prefix>

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_rib::RibManager;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, AspaValidationContext, Ipv4Prefix, Origin, PathAttribute, Prefix,
    RpkiValidation, Safi,
};
use tokio::sync::{mpsc, oneshot};

const BATCH: usize = 1000;
const CHANNEL_CAP: usize = 8192;
const INGRESS_FLOOD: u32 = 4;

fn route(prefix: Ipv4Prefix, src: Ipv4Addr, local_pref: u32) -> Route {
    let attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(src),
        PathAttribute::LocalPref(local_pref),
    ];
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(src),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(src),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: src,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: AspaValidationContext::default(),
    }
}

/// Distinct /24 for a global route index (block-offset aware).
fn flood_prefix(offset: u64) -> Ipv4Prefix {
    let a = 20 + u8::try_from(offset >> 16).expect("prefix space exhausted");
    let b = u8::try_from((offset >> 8) & 0xff).unwrap();
    let c = u8::try_from(offset & 0xff).unwrap();
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, 0), 24)
}

fn churn_prefix(i: u64) -> Ipv4Prefix {
    let b = 16 + u8::try_from(i >> 8).expect("churn prefix space exhausted");
    let c = u8::try_from(i & 0xff).unwrap();
    Ipv4Prefix::new(Ipv4Addr::new(172, b, c, 0), 24)
}

fn client_addr(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 64, 0, 0)) + i))
}

fn source_addr(i: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 0, 0, 1)) + i)
}

fn rss_mib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .unwrap_or(0);
            return kb / 1024;
        }
    }
    0
}

/// utime+stime (seconds) of a thread from /proc/self/task/<tid>/stat.
fn thread_cpu_secs(tid: i32) -> f64 {
    let stat = fs::read_to_string(format!("/proc/self/task/{tid}/stat")).unwrap_or_default();
    // fields 14/15 (1-based) after the comm field; comm may contain spaces but
    // never does for our named thread — split after the closing paren.
    let after = stat.rsplit(") ").next().unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let utime: f64 = f.get(11).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = f.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let hz = 100.0; // CONFIG_HZ user-visible clock ticks
    (utime + stime) / hz
}

fn empty_routes_received(peer: IpAddr, announced: Vec<Route>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer,
        session_id: 0,
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    }
}

struct Harness {
    tx: mpsc::Sender<RibUpdate>,
    qtx: mpsc::Sender<RibUpdate>,
    drained: Arc<AtomicU64>,
    clients: Vec<IpAddr>,
    mgr_tid: i32,
}

async fn setup(n_clients: u32) -> Harness {
    let (tx, rx) = mpsc::channel::<RibUpdate>(1024);
    let (qtx, qrx) = mpsc::channel::<RibUpdate>(64);
    let (tid_tx, tid_rx) = std::sync::mpsc::channel::<i32>();
    std::thread::Builder::new()
        .name("ribmgr".into())
        .spawn(move || {
            tid_tx.send(unsafe { libc::gettid() }).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mgr = RibManager::new(
                rx,
                qrx,
                None,
                Some(Ipv4Addr::new(10, 255, 255, 255)),
                BgpMetrics::new(),
            );
            rt.block_on(mgr.run());
        })
        .unwrap();
    let mgr_tid = tid_rx.recv().unwrap();

    let drained = Arc::new(AtomicU64::new(0));
    let mut clients = Vec::with_capacity(n_clients as usize);
    for i in 0..n_clients {
        let peer = client_addr(i);
        clients.push(peer);
        let (otx, mut orx) = mpsc::channel::<OutboundRouteUpdate>(CHANNEL_CAP);
        let drained = Arc::clone(&drained);
        tokio::spawn(async move {
            while let Some(update) = orx.recv().await {
                let n = update.announce.len() + update.withdraw.len();
                if n > 0 {
                    drained.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        });
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 1,
            peer_asn: 64512,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            outbound_tx: otx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
    }
    Harness {
        tx,
        qtx,
        drained,
        clients,
        mgr_tid,
    }
}

impl Harness {
    async fn staged_counts(&self) -> HashMap<IpAddr, u64> {
        let (reply, rx) = oneshot::channel();
        self.qtx
            .send(RibUpdate::QueryAdjRibOutCounts { reply })
            .await
            .unwrap();
        let counts = rx.await.unwrap();
        counts
            .into_iter()
            .map(|(peer, families)| {
                let v4 = families
                    .iter()
                    .find(|((afi, safi), _)| *afi == Afi::Ipv4 && *safi == Safi::Unicast)
                    .map_or(0, |(_, c)| *c);
                (peer, v4)
            })
            .collect()
    }

    async fn wait_staged(&self, expected: u64) {
        let mut polls = 0u64;
        loop {
            let counts = self.staged_counts().await;
            if self
                .clients
                .iter()
                .all(|c| counts.get(c).copied().unwrap_or(0) >= expected)
            {
                return;
            }
            polls += 1;
            if polls.is_multiple_of(250) {
                let min = self
                    .clients
                    .iter()
                    .map(|c| counts.get(c).copied().unwrap_or(0))
                    .min()
                    .unwrap_or(0);
                let max = self
                    .clients
                    .iter()
                    .map(|c| counts.get(c).copied().unwrap_or(0))
                    .max()
                    .unwrap_or(0);
                eprintln!(
                    "wait_staged: expected={expected} min={min} max={max} drained={} counts_len={}",
                    self.drained.load(Ordering::Relaxed),
                    counts.len()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_drained(&self, target: u64) {
        while self.drained.load(Ordering::Relaxed) < target {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Inject `n` flood routes at global offset `base`, split over the ingress
    /// sources, in BATCH-sized RoutesReceived messages.
    async fn inject_flood_block(&self, base: u64, n: u64) {
        let per_src = n / u64::from(INGRESS_FLOOD);
        for s in 0..INGRESS_FLOOD {
            let src = source_addr(s);
            let lo = base + u64::from(s) * per_src;
            let hi = if s == INGRESS_FLOOD - 1 {
                base + n
            } else {
                lo + per_src
            };
            let mut batch = Vec::with_capacity(BATCH);
            for off in lo..hi {
                batch.push(route(flood_prefix(off), src, 100));
                if batch.len() == BATCH {
                    self.tx
                        .send(empty_routes_received(
                            IpAddr::V4(src),
                            std::mem::replace(&mut batch, Vec::with_capacity(BATCH)),
                        ))
                        .await
                        .unwrap();
                }
            }
            if !batch.is_empty() {
                self.tx
                    .send(empty_routes_received(IpAddr::V4(src), batch))
                    .await
                    .unwrap();
            }
        }
    }
}

fn write_folded(report: &pprof::Report, path: &str) {
    let mut out = String::new();
    for (frames, count) in &report.data {
        let stack: Vec<String> = frames
            .frames
            .iter()
            .flat_map(|fs| fs.iter().map(|sym| format!("{sym}")))
            .collect();
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            frames.thread_name,
            stack.join(";"),
            count
        ));
    }
    fs::write(path, out).unwrap();
}

#[allow(clippy::too_many_lines)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).expect("mode").clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(12)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        match mode.as_str() {
            "flood" => {
                let n_clients: u32 = args[2].parse().unwrap();
                let n_prefixes: u64 = args[3].parse().unwrap();
                let secs: u64 = args[4].parse().unwrap();
                let out = args[5].clone();
                let h = setup(n_clients).await;
                println!("# flood clients={n_clients} prefixes={n_prefixes} secs={secs}");
                println!("rss_established_mib {}", rss_mib());

                let t0 = Instant::now();
                h.inject_flood_block(0, n_prefixes).await;
                h.wait_staged(n_prefixes).await;
                let staged = t0.elapsed();
                h.wait_drained(n_prefixes * u64::from(n_clients)).await;
                let drained_t = t0.elapsed();
                println!("cold_staged_s {:.3}", staged.as_secs_f64());
                println!("cold_drained_s {:.3}", drained_t.as_secs_f64());
                println!("rss_converged_mib {}", rss_mib());

                // Sustained fresh-block window under the profiler.
                let cpu0 = thread_cpu_secs(h.mgr_tid);
                let guard = pprof::ProfilerGuardBuilder::default()
                    .frequency(997)
                    .build()
                    .unwrap();
                let w0 = Instant::now();
                let mut blocks: u64 = 0;
                while w0.elapsed() < Duration::from_secs(secs) {
                    blocks += 1;
                    let base = blocks * n_prefixes;
                    let before = h.drained.load(Ordering::Relaxed);
                    h.inject_flood_block(base, n_prefixes).await;
                    h.wait_drained(before + n_prefixes * u64::from(n_clients))
                        .await;
                }
                let window = w0.elapsed().as_secs_f64();
                let cpu1 = thread_cpu_secs(h.mgr_tid);
                let report = guard.report().build().unwrap();
                drop(guard);
                write_folded(&report, &format!("{out}.folded"));
                println!("sustained_blocks {blocks}");
                println!("sustained_window_s {window:.3}");
                println!("mgr_cpu_s {:.3}", cpu1 - cpu0);
                println!("mgr_busy_frac {:.3}", (cpu1 - cpu0) / window);
                println!("rss_end_mib {}", rss_mib());
            }
            "churn" => {
                let n_clients: u32 = args[2].parse().unwrap();
                let n_cand: u32 = args[3].parse().unwrap();
                let n_prefixes: u64 = args[4].parse().unwrap();
                let secs: u64 = args[5].parse().unwrap();
                let out = args[6].clone();
                let h = setup(n_clients).await;
                println!(
                    "# churn clients={n_clients} candidates={n_cand} prefixes={n_prefixes} secs={secs}"
                );
                println!("rss_established_mib {}", rss_mib());

                // Prime: every candidate source announces the full prefix set.
                let t0 = Instant::now();
                for s in 0..n_cand {
                    let src = source_addr(s);
                    let mut batch = Vec::with_capacity(BATCH);
                    for i in 0..n_prefixes {
                        batch.push(route(churn_prefix(i), src, 100));
                        if batch.len() == BATCH {
                            h.tx.send(empty_routes_received(
                                IpAddr::V4(src),
                                std::mem::replace(&mut batch, Vec::with_capacity(BATCH)),
                            ))
                            .await
                            .unwrap();
                        }
                    }
                    if !batch.is_empty() {
                        h.tx.send(empty_routes_received(IpAddr::V4(src), batch))
                            .await
                            .unwrap();
                    }
                }
                h.wait_staged(n_prefixes).await;
                // Let mid-prime best-flip deliveries settle.
                let mut last = h.drained.load(Ordering::Relaxed);
                loop {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let now = h.drained.load(Ordering::Relaxed);
                    if now == last {
                        break;
                    }
                    last = now;
                }
                println!("prime_s {:.3}", t0.elapsed().as_secs_f64());
                println!("rss_primed_mib {}", rss_mib());

                // Flap waves under the profiler: rotate the winning source
                // with escalating LOCAL_PREF; every wave = n_prefixes flips
                // fanned to all clients.
                let cpu0 = thread_cpu_secs(h.mgr_tid);
                let guard = pprof::ProfilerGuardBuilder::default()
                    .frequency(997)
                    .build()
                    .unwrap();
                let w0 = Instant::now();
                let mut waves: u64 = 0;
                while w0.elapsed() < Duration::from_secs(secs) {
                    let src = source_addr(u32::try_from(waves).unwrap() % n_cand);
                    let lp = 1000 + u32::try_from(waves).unwrap();
                    let before = h.drained.load(Ordering::Relaxed);
                    let mut batch = Vec::with_capacity(BATCH);
                    for i in 0..n_prefixes {
                        batch.push(route(churn_prefix(i), src, lp));
                        if batch.len() == BATCH {
                            h.tx.send(empty_routes_received(
                                IpAddr::V4(src),
                                std::mem::replace(&mut batch, Vec::with_capacity(BATCH)),
                            ))
                            .await
                            .unwrap();
                        }
                    }
                    if !batch.is_empty() {
                        h.tx.send(empty_routes_received(IpAddr::V4(src), batch))
                            .await
                            .unwrap();
                    }
                    h.wait_drained(before + n_prefixes * u64::from(n_clients))
                        .await;
                    waves += 1;
                }
                let window = w0.elapsed().as_secs_f64();
                let cpu1 = thread_cpu_secs(h.mgr_tid);
                let report = guard.report().build().unwrap();
                drop(guard);
                write_folded(&report, &format!("{out}.folded"));
                println!("waves {waves}");
                println!("waves_per_s {:.2}", waves as f64 / window);
                println!("window_s {window:.3}");
                println!("mgr_cpu_s {:.3}", cpu1 - cpu0);
                println!("mgr_busy_frac {:.3}", (cpu1 - cpu0) / window);
                println!("rss_end_mib {}", rss_mib());
            }
            other => panic!("unknown mode {other}"),
        }
    });
    std::process::exit(0);
}
