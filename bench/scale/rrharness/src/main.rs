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

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
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

fn invalid_stat(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Parse `utime+stime` clock ticks from a Linux `/proc/<pid>/stat` record.
///
/// The parenthesized `comm` field may contain spaces and right parentheses, so
/// field-number parsing must start after the *last* `") "` delimiter rather
/// than by splitting the complete record on whitespace.
fn parse_thread_cpu_ticks(stat: &str) -> io::Result<u64> {
    let open = stat
        .find('(')
        .ok_or_else(|| invalid_stat("/proc stat is missing the comm opening parenthesis"))?;
    let close = stat
        .rfind(") ")
        .ok_or_else(|| invalid_stat("/proc stat is missing the comm closing delimiter"))?;
    if close <= open {
        return Err(invalid_stat("/proc stat has an invalid comm field"));
    }

    // The suffix starts with field 3 (`state`), making zero-based positions
    // 11 and 12 fields 14 (`utime`) and 15 (`stime`) respectively.
    let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    let parse_tick = |index: usize, name: &str| -> io::Result<u64> {
        fields
            .get(index)
            .ok_or_else(|| invalid_stat(format!("/proc stat is missing {name}")))?
            .parse::<u64>()
            .map_err(|error| invalid_stat(format!("invalid /proc stat {name}: {error}")))
    };
    let utime = parse_tick(11, "utime")?;
    let stime = parse_tick(12, "stime")?;
    utime
        .checked_add(stime)
        .ok_or_else(|| invalid_stat("/proc stat utime+stime overflowed u64"))
}

fn validate_clock_ticks(ticks: libc::c_long) -> io::Result<u64> {
    if ticks <= 0 {
        return Err(io::Error::other(format!(
            "sysconf(_SC_CLK_TCK) returned invalid value {ticks}"
        )));
    }
    u64::try_from(ticks).map_err(|_| {
        io::Error::other(format!(
            "sysconf(_SC_CLK_TCK) value {ticks} does not fit in u64"
        ))
    })
}

fn clock_ticks_per_second() -> io::Result<u64> {
    // SAFETY: sysconf has no pointer arguments and `_SC_CLK_TCK` is a valid
    // process-wide query on every Linux target supported by this harness.
    validate_clock_ticks(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
}

/// `utime+stime` (seconds) of a thread from `/proc/self/task/<tid>/stat`.
fn thread_cpu_secs(tid: i32, ticks_per_second: u64) -> io::Result<f64> {
    if ticks_per_second == 0 {
        return Err(io::Error::other("_SC_CLK_TCK must be greater than zero"));
    }
    let stat = fs::read_to_string(format!("/proc/self/task/{tid}/stat"))?;
    Ok(parse_thread_cpu_ticks(&stat)? as f64 / ticks_per_second as f64)
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
    ticks_per_second: u64,
}

async fn setup(n_clients: u32) -> Harness {
    let ticks_per_second = clock_ticks_per_second().expect("failed to query sysconf(_SC_CLK_TCK)");
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
        ticks_per_second,
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

fn escape_folded_field(value: &str) -> io::Result<String> {
    if value.contains(['\t', '\n', '\r']) {
        return Err(invalid_stat("profile field contains a tab or newline"));
    }
    Ok(value.replace('%', "%25").replace(';', "%3B"))
}

fn render_folded(
    samples: impl IntoIterator<Item = (String, Vec<String>, u64)>,
) -> io::Result<String> {
    let mut aggregated: BTreeMap<(String, Vec<String>), u64> = BTreeMap::new();
    let mut input_total = 0u64;
    for (thread, stack, count) in samples {
        let thread = escape_folded_field(&thread)?;
        let stack = stack
            .into_iter()
            .map(|frame| escape_folded_field(&frame))
            .collect::<io::Result<Vec<_>>>()?;
        input_total = input_total
            .checked_add(count)
            .ok_or_else(|| invalid_stat("profile sample total overflowed u64"))?;
        let entry = aggregated.entry((thread, stack)).or_default();
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| invalid_stat("profile stack sample count overflowed u64"))?;
    }

    let mut output_total = 0u64;
    let mut out = String::new();
    for ((thread, stack), count) in aggregated {
        output_total = output_total
            .checked_add(count)
            .ok_or_else(|| invalid_stat("aggregated profile sample total overflowed u64"))?;
        out.push_str(&format!("{thread}\t{}\t{count}\n", stack.join(";")));
    }
    if output_total != input_total {
        return Err(invalid_stat("profile aggregation changed the sample total"));
    }
    Ok(out)
}

fn write_folded(report: &pprof::Report, path: &str) -> io::Result<()> {
    let mut samples = Vec::with_capacity(report.data.len());
    for (frames, &count) in &report.data {
        let count = u64::try_from(count)
            .map_err(|_| invalid_stat(format!("profiler returned invalid sample count {count}")))?;
        let stack = frames
            .frames
            .iter()
            .rev()
            .flat_map(|frame| frame.iter().rev().map(|symbol| format!("{symbol}")))
            .collect();
        samples.push((frames.thread_name.clone(), stack, count));
    }
    fs::write(path, render_folded(samples)?)
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
                let cpu0 = thread_cpu_secs(h.mgr_tid, h.ticks_per_second)
                    .expect("failed to read initial ribmgr CPU time");
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
                let cpu1 = thread_cpu_secs(h.mgr_tid, h.ticks_per_second)
                    .expect("failed to read final ribmgr CPU time");
                let report = guard.report().build().unwrap();
                drop(guard);
                write_folded(&report, &format!("{out}.folded"))
                    .expect("failed to write folded profile");
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
                let cpu0 = thread_cpu_secs(h.mgr_tid, h.ticks_per_second)
                    .expect("failed to read initial ribmgr CPU time");
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
                let cpu1 = thread_cpu_secs(h.mgr_tid, h.ticks_per_second)
                    .expect("failed to read final ribmgr CPU time");
                let report = guard.report().build().unwrap();
                drop(guard);
                write_folded(&report, &format!("{out}.folded"))
                    .expect("failed to write folded profile");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(comm: &str, utime: &str, stime: &str) -> String {
        format!("42 ({comm}) S 1 2 3 4 5 6 7 8 9 10 {utime} {stime} 16 17 18 19 20 21")
    }

    #[test]
    fn parses_cpu_ticks_with_spaces_and_parentheses_in_comm() {
        assert_eq!(
            parse_thread_cpu_ticks(&stat("rib mgr ) worker", "120", "23")).unwrap(),
            143
        );
    }

    #[test]
    fn rejects_truncated_stat_record() {
        let error = parse_thread_cpu_ticks("42 (ribmgr) S 1 2").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("utime"));
    }

    #[test]
    fn rejects_invalid_tick_field() {
        let error = parse_thread_cpu_ticks(&stat("ribmgr", "not-a-number", "23")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("utime"));
    }

    #[test]
    fn rejects_tick_sum_overflow() {
        let error =
            parse_thread_cpu_ticks(&stat("ribmgr", &u64::MAX.to_string(), "1")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn host_clock_tick_query_is_positive() {
        assert!(clock_ticks_per_second().unwrap() > 0);
    }

    #[test]
    fn clock_tick_validator_rejects_non_positive_values() {
        assert!(validate_clock_ticks(-1).is_err());
        assert!(validate_clock_ticks(0).is_err());
        assert_eq!(validate_clock_ticks(250).unwrap(), 250);
    }

    #[test]
    fn folded_render_aggregates_duplicates_sorts_and_preserves_samples() {
        let output = render_folded([
            ("ribmgr".to_string(), vec!["root".into(), "z".into()], 2),
            ("ribmgr".to_string(), vec!["root".into(), "a".into()], 3),
            ("ribmgr".to_string(), vec!["root".into(), "z".into()], 5),
        ])
        .unwrap();
        assert_eq!(output, "ribmgr\troot;a\t3\nribmgr\troot;z\t7\n");
        let total: u64 = output
            .lines()
            .map(|line| line.rsplit_once('\t').unwrap().1.parse::<u64>().unwrap())
            .sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn folded_render_rejects_overflow_and_escapes_delimiters() {
        assert!(render_folded([
            ("ribmgr".to_string(), vec!["root".into()], u64::MAX),
            ("ribmgr".to_string(), vec!["root".into()], 1),
        ])
        .is_err());
        assert_eq!(
            render_folded([(
                "ribmgr".to_string(),
                vec!["array::<[u8; 32]>::percent%owner".into()],
                1,
            )])
            .unwrap(),
            "ribmgr\tarray::<[u8%3B 32]>::percent%25owner\t1\n"
        );
        assert!(render_folded([("ribmgr".to_string(), vec!["bad\tframe".into()], 1,)]).is_err());
    }
}
