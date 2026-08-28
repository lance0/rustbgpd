//! Large-table receipt harness for bounded internal dataplane prefix pages.

use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::{RibManager, Route, RouteOrigin, RouteQueryScope};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug)]
enum IndexMode {
    Eager,
    LazyBaseline,
}

impl IndexMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::LazyBaseline => "lazy_indexed_baseline",
        }
    }
}

#[derive(Debug)]
struct Args {
    prefixes: usize,
    announcers: usize,
    max_paths: u32,
    repetition: usize,
    mode: IndexMode,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            prefixes: 100_000,
            announcers: 1,
            max_paths: 1,
            repetition: 1,
            mode: IndexMode::Eager,
        }
    }
}

fn parse_positive(value: String, flag: &str) -> usize {
    let value = value
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{flag} expects a positive integer"));
    assert!(value > 0, "{flag} must be positive");
    value
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--bench" => {}
            "--prefixes" => {
                args.prefixes = parse_positive(
                    raw.next().expect("--prefixes requires a value"),
                    "--prefixes",
                );
            }
            "--announcers" => {
                args.announcers = parse_positive(
                    raw.next().expect("--announcers requires a value"),
                    "--announcers",
                );
            }
            "--max-paths" => {
                args.max_paths = u32::try_from(parse_positive(
                    raw.next().expect("--max-paths requires a value"),
                    "--max-paths",
                ))
                .expect("--max-paths fits u32");
            }
            "--repetition" => {
                args.repetition = parse_positive(
                    raw.next().expect("--repetition requires a value"),
                    "--repetition",
                );
            }
            "--mode" => {
                args.mode = match raw.next().expect("--mode requires a value").as_str() {
                    "eager" => IndexMode::Eager,
                    "lazy" | "lazy-baseline" => IndexMode::LazyBaseline,
                    other => panic!("--mode expects eager or lazy-baseline, got {other}"),
                };
            }
            "--help" | "-h" => {
                println!(
                    "dataplane_prefix_paging [--prefixes 100000] [--announcers 1] \
                     [--max-paths 1] [--repetition 1] [--mode eager|lazy-baseline]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    assert!(
        args.announcers >= usize::try_from(args.max_paths.min(256)).unwrap(),
        "announcers must cover the normalized max-paths fixture"
    );
    args
}

fn peer(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(
        0xc633_6401u32
            .checked_add(u32::try_from(index).expect("announcer index fits IPv4"))
            .expect("announcer fixture stays in IPv4 space"),
    )
}

fn prefix(index: usize) -> Prefix {
    let host = 0x0a00_0000u32
        .checked_add(u32::try_from(index).expect("prefix count fits IPv4"))
        .expect("prefix fixture stays in IPv4 space");
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(host), 32))
}

fn make_routes(prefixes: usize, announcers: usize) -> Vec<Route> {
    let attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001])],
        }),
        PathAttribute::LocalPref(100),
    ]);
    let mut routes = Vec::with_capacity(prefixes.saturating_mul(announcers));
    for announcer in 0..announcers {
        let peer = peer(announcer);
        for index in 0..prefixes {
            routes.push(Route {
                prefix: prefix(index),
                next_hop: IpAddr::V4(peer),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: IpAddr::V4(peer),
                attributes: Arc::clone(&attributes),
                received_at: Instant::now(),
                origin_type: RouteOrigin::Ebgp,
                peer_router_id: peer,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                aspa_context: rustbgpd_wire::AspaValidationContext::default(),
            });
        }
    }
    routes
}

fn resident_bytes() -> io::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| {
            let kib = line.strip_prefix("VmRSS:")?.split_whitespace().next()?;
            kib.parse::<u64>().ok()?.checked_mul(1_024)
        })
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| io::Error::other("/proc/self/status has no positive VmRSS"))
}

fn percentile(sorted: &[Duration], numerator: usize, denominator: usize) -> Duration {
    let rank = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[rank]
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn checksum_bytes(checksum: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *checksum ^= u64::from(*byte);
        *checksum = checksum.wrapping_mul(FNV_PRIME);
    }
}

#[derive(Debug)]
struct Traversal {
    pages: usize,
    rows: usize,
    next_hops: usize,
    checksum: u64,
    complete: Duration,
    page_p50: Duration,
    page_p99: Duration,
    page_max: Duration,
}

fn traverse(manager: &mut RibManager, prefixes: usize, max_paths: u32) -> Traversal {
    let started = Instant::now();
    let mut timings = Vec::new();
    let mut cursor = None;
    let mut previous = None;
    let mut rows = 0usize;
    let mut next_hops = 0usize;
    let mut checksum = FNV_OFFSET_BASIS;
    loop {
        let page_started = Instant::now();
        let page = manager
            .bench_query_fib_install_candidates_page(cursor, max_paths)
            .expect("eager dataplane index enabled");
        timings.push(page_started.elapsed());
        for candidate in &page.candidates {
            assert!(previous.is_none_or(|prior| prior < candidate.best.prefix));
            previous = Some(candidate.best.prefix);
            match candidate.best.prefix {
                Prefix::V4(prefix) => {
                    checksum_bytes(&mut checksum, &[4, prefix.len]);
                    checksum_bytes(&mut checksum, &prefix.addr.octets());
                }
                Prefix::V6(prefix) => {
                    checksum_bytes(&mut checksum, &[6, prefix.len]);
                    checksum_bytes(&mut checksum, &prefix.addr.octets());
                }
            }
            for next_hop in &candidate.next_hops {
                match next_hop.next_hop {
                    IpAddr::V4(address) => checksum_bytes(&mut checksum, &address.octets()),
                    IpAddr::V6(address) => checksum_bytes(&mut checksum, &address.octets()),
                }
            }
            next_hops = next_hops.saturating_add(candidate.next_hops.len());
        }
        rows = rows.saturating_add(page.candidates.len());
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(rows, prefixes);
    timings.sort_unstable();
    let page_max = *timings.last().expect("one or more pages");
    assert!(
        page_max < Duration::from_secs(2),
        "page exceeded the two-second stop threshold: {page_max:?}"
    );
    Traversal {
        pages: timings.len(),
        rows,
        next_hops,
        checksum,
        complete: started.elapsed(),
        page_p50: percentile(&timings, 50, 100),
        page_p99: percentile(&timings, 99, 100),
        page_max,
    }
}

fn main() -> io::Result<()> {
    let args = parse_args();
    let (_update_tx, update_rx) = mpsc::channel(1);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let manager = RibManager::new(update_rx, query_rx, None, None, BgpMetrics::new());
    let mut manager = match args.mode {
        IndexMode::Eager => manager.with_eager_dataplane_prefix_index(),
        IndexMode::LazyBaseline => manager,
    };
    let routes = make_routes(args.prefixes, args.announcers);
    let churn_rows = make_routes(args.prefixes.min(1_000), 1);

    let ingest_started = Instant::now();
    manager.bench_seed_loc_rib(routes);
    let ingest = ingest_started.elapsed();
    let churn_started = Instant::now();
    manager.bench_churn_loc_rib(churn_rows);
    let churn = churn_started.elapsed();

    let index_started = Instant::now();
    if matches!(args.mode, IndexMode::LazyBaseline) {
        let page = manager.bench_query_route_page(RouteQueryScope::Best, None, 1);
        assert_eq!(page.routes.len(), 1);
    }
    let index_ready = index_started.elapsed();
    let index = manager.bench_dataplane_prefix_index_receipt();
    assert_eq!(index.prefixes, args.prefixes);
    let rss = resident_bytes()?;

    let traversal = matches!(args.mode, IndexMode::Eager)
        .then(|| traverse(&mut manager, args.prefixes, args.max_paths));
    let mut output = BufWriter::new(io::stdout().lock());
    writeln!(
        output,
        "mode,prefixes,announcers,max_paths,repetition,ingest_ns,churn_rows,churn_ns,index_ready_ns,index_prefixes,index_bytes,resident_bytes,pages,rows,next_hops,checksum,complete_ns,page_p50_ns,page_p99_ns,page_max_ns"
    )?;
    if let Some(sample) = traversal {
        writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:016x},{},{},{},{}",
            args.mode.label(),
            args.prefixes,
            args.announcers,
            args.max_paths,
            args.repetition,
            ingest.as_nanos(),
            args.prefixes.min(1_000),
            churn.as_nanos(),
            index_ready.as_nanos(),
            index.prefixes,
            index.index_bytes,
            rss,
            sample.pages,
            sample.rows,
            sample.next_hops,
            sample.checksum,
            sample.complete.as_nanos(),
            sample.page_p50.as_nanos(),
            sample.page_p99.as_nanos(),
            sample.page_max.as_nanos(),
        )?;
    } else {
        writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{},{},{},0,0,0,0000000000000000,0,0,0,0",
            args.mode.label(),
            args.prefixes,
            args.announcers,
            args.max_paths,
            args.repetition,
            ingest.as_nanos(),
            args.prefixes.min(1_000),
            churn.as_nanos(),
            index_ready.as_nanos(),
            index.prefixes,
            index.index_bytes,
            rss,
        )?;
    }
    output.flush()
}
