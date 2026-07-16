//! Manager-level complete-traversal benchmark for LAN-391.
//!
//! This is a custom benchmark harness rather than Criterion: the
//! repeated-scan baseline can take long enough at 400k routes/page-size 100
//! that Criterion's minimum sample count is counterproductive. Each process
//! runs exactly one complete traversal. Its page samples are summarized as
//! p50/p99/max synchronous handler-boundary timings in machine-readable CSV;
//! they include oneshot setup and retrieval but no actor scheduling. The same
//! row records seed ingest, a bounded withdraw/reannounce control, and
//! post-setup resident bytes so persistent indices carry explicit write-side
//! and memory gates.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, RibManager, RouteQueryKey, RouteQueryScope, route_query_key,
};
use rustbgpd_rib::{Route, RouteOrigin};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};
use tokio::sync::mpsc;

#[derive(Debug)]
struct Args {
    route_count: usize,
    page_size: usize,
    scope: BenchScope,
    repetition: usize,
    output: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            route_count: 100_000,
            page_size: 100,
            scope: BenchScope::Best,
            repetition: 1,
            output: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BenchScope {
    Best,
    GroupedAdvertised,
}

impl BenchScope {
    const fn label(self) -> &'static str {
        match self {
            Self::Best => "best",
            Self::GroupedAdvertised => "grouped_advertised",
        }
    }

    fn query(self) -> RouteQueryScope {
        match self {
            Self::Best => RouteQueryScope::Best,
            Self::GroupedAdvertised => RouteQueryScope::Advertised {
                peer: RibManager::bench_peer_address(0),
            },
        }
    }

    fn expected_rows(self, route_count: usize) -> usize {
        match self {
            Self::Best => route_count,
            Self::GroupedAdvertised => {
                route_count - route_count.div_ceil(GROUP_SPLIT_HORIZON_STRIDE)
            }
        }
    }
}

fn parse_positive(value: String, flag: &str) -> usize {
    let parsed = value
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{flag} expects a positive integer"));
    assert!(parsed > 0, "{flag} must be positive");
    parsed
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            // Cargo passes this libtest-compatible marker to bench targets
            // even when `harness = false`.
            "--bench" => {}
            "--routes" => {
                args.route_count =
                    parse_positive(raw.next().expect("--routes requires a value"), "--routes");
            }
            "--page-size" => {
                args.page_size = parse_positive(
                    raw.next().expect("--page-size requires a value"),
                    "--page-size",
                );
            }
            "--scope" => {
                args.scope = match raw.next().expect("--scope requires a value").as_str() {
                    "best" => BenchScope::Best,
                    "grouped-advertised" | "grouped_advertised" => BenchScope::GroupedAdvertised,
                    other => panic!("--scope expects best or grouped-advertised, got {other}"),
                };
            }
            "--repetition" => {
                args.repetition = parse_positive(
                    raw.next().expect("--repetition requires a value"),
                    "--repetition",
                );
            }
            "--output" => {
                args.output = Some(PathBuf::from(raw.next().expect("--output requires a path")));
            }
            "--help" | "-h" => {
                println!(
                    "route_paging [--routes 100000] [--page-size 100] \
                     [--scope best|grouped-advertised] [--repetition 1] [--output FILE]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    args
}

/// Every sixteenth route is sourced by the queried update-group member. The
/// grouped view therefore exercises member-specific split horizon and has a
/// distinct row count/checksum from the Loc-RIB best control.
const GROUP_SPLIT_HORIZON_STRIDE: usize = 16;
/// A bounded remove/re-announce subset exposes write-side ordered-index cost
/// in every fresh process without materially extending the 64-cell campaign.
const CHURN_ROUTE_COUNT: usize = 1_000;

#[derive(Debug)]
struct PermissiveExactExport;

impl ExactExportSnapshot for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        Ok(ExactExportResult {
            encoded_len: 0,
            max_len: usize::MAX,
            generation: 0,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl ExactExportEncoder for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(Self)
    }
}

fn make_routes(count: usize) -> Vec<Route> {
    let external_peer = Ipv4Addr::new(198, 51, 100, 1);
    let grouped_member = RibManager::bench_peer_address(0);
    let attributes = Arc::new(Vec::new());
    (0..count)
        .map(|index| {
            let host = 0x0a00_0000u32
                .checked_add(u32::try_from(index).expect("route count fits in IPv4 space"))
                .expect("route fixture stays within IPv4 space");
            let peer = if index % GROUP_SPLIT_HORIZON_STRIDE == 0 {
                grouped_member
            } else {
                IpAddr::V4(external_peer)
            };
            let own_grouped_route = peer == grouped_member;
            Route {
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(host), 32)),
                next_hop: IpAddr::V4(external_peer),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer,
                attributes: Arc::clone(&attributes),
                received_at: Instant::now(),
                origin_type: if own_grouped_route {
                    RouteOrigin::Ibgp
                } else {
                    RouteOrigin::Ebgp
                },
                peer_router_id: external_peer,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                aspa_context: rustbgpd_wire::AspaValidationContext::default(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct SetupMetrics {
    ingest: Duration,
    churn_routes: usize,
    churn: Duration,
    resident_bytes: u64,
}

fn resident_bytes() -> io::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let bytes = status
        .lines()
        .find_map(|line| {
            let kib = line.strip_prefix("VmRSS:")?.split_whitespace().next()?;
            kib.parse::<u64>().ok()?.checked_mul(1_024)
        })
        .ok_or_else(|| io::Error::other("/proc/self/status has no valid positive VmRSS"))?;
    if bytes == 0 {
        return Err(io::Error::other("/proc/self/status reported zero VmRSS"));
    }
    Ok(bytes)
}

fn seeded_manager(
    count: usize,
) -> io::Result<(
    RibManager,
    Vec<mpsc::Receiver<rustbgpd_rib::OutboundRouteUpdate>>,
    SetupMetrics,
)> {
    let (_update_tx, update_rx) = mpsc::channel(1);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let mut manager = RibManager::new(update_rx, query_rx, None, None, BgpMetrics::new());
    let routes = make_routes(count);
    let churn_fixture = routes
        .iter()
        .take(CHURN_ROUTE_COUNT.min(routes.len()))
        .cloned()
        .collect::<Vec<_>>();
    let ingest_started = Instant::now();
    manager.bench_seed_loc_rib(routes);
    let ingest = ingest_started.elapsed();
    let churn_started = Instant::now();
    manager.bench_churn_loc_rib(churn_fixture);
    let churn = churn_started.elapsed();
    // Register after the timed writes. Initial-table staging builds the same
    // two-member grouped advertised view while keeping transport fanout out of
    // the ingest/churn controls. The helper drains the initial updates.
    let receivers =
        manager.bench_register_peers(2, None, true, 4, || Arc::new(PermissiveExactExport));
    let resident_bytes = resident_bytes()?;
    Ok((
        manager,
        receivers,
        SetupMetrics {
            ingest,
            churn_routes: CHURN_ROUTE_COUNT.min(count),
            churn,
            resident_bytes,
        },
    ))
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

struct Traversal {
    pages: usize,
    rows: usize,
    elapsed: Duration,
    page_p50: Duration,
    page_p99: Duration,
    page_max: Duration,
    ordered_key_checksum: u64,
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn checksum_bytes(checksum: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *checksum ^= u64::from(*byte);
        *checksum = checksum.wrapping_mul(FNV_PRIME);
    }
}

fn checksum_route_key(checksum: &mut u64, key: &RouteQueryKey) {
    let (prefix, peer, path_id) = key;
    match prefix {
        Prefix::V4(prefix) => {
            checksum_bytes(checksum, &[4, prefix.len]);
            checksum_bytes(checksum, &prefix.addr.octets());
        }
        Prefix::V6(prefix) => {
            checksum_bytes(checksum, &[6, prefix.len]);
            checksum_bytes(checksum, &prefix.addr.octets());
        }
    }
    match peer {
        IpAddr::V4(address) => {
            checksum_bytes(checksum, &[4]);
            checksum_bytes(checksum, &address.octets());
        }
        IpAddr::V6(address) => {
            checksum_bytes(checksum, &[6]);
            checksum_bytes(checksum, &address.octets());
        }
    }
    checksum_bytes(checksum, &path_id.to_be_bytes());
}

fn traverse(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    expected_rows: usize,
    page_size: usize,
) -> Traversal {
    let started = Instant::now();
    let mut page_durations = Vec::new();
    let mut after = None;
    let mut rows = 0usize;
    let mut previous = None;
    let mut ordered_key_checksum = FNV_OFFSET_BASIS;
    loop {
        let page_started = Instant::now();
        let page = manager.bench_query_route_page(scope, after, page_size);
        page_durations.push(page_started.elapsed());
        assert_eq!(
            page.total,
            u64::try_from(expected_rows).expect("benchmark count fits u64")
        );
        assert!(page.routes.len() <= page_size.min(1_000));
        for route in &page.routes {
            let key = route_query_key(route);
            assert!(previous.is_none_or(|prior| prior < key));
            checksum_route_key(&mut ordered_key_checksum, &key);
            previous = Some(key);
        }
        rows += page.routes.len();
        after = page.routes.last().map(route_query_key);
        if !page.has_more {
            break;
        }
        assert!(after.is_some(), "non-terminal page must advance the cursor");
    }
    let elapsed = started.elapsed();
    assert_eq!(rows, expected_rows);
    page_durations.sort_unstable();
    Traversal {
        pages: page_durations.len(),
        rows,
        elapsed,
        page_p50: percentile(&page_durations, 50, 100),
        page_p99: percentile(&page_durations, 99, 100),
        page_max: *page_durations.last().expect("one or more route pages"),
        ordered_key_checksum,
    }
}

fn main() -> io::Result<()> {
    let args = parse_args();
    let variant = std::env::var("RUSTBGPD_ROUTE_PAGING_VARIANT")
        .unwrap_or_else(|_| "unspecified".to_string());
    let commit =
        std::env::var("RUSTBGPD_ROUTE_PAGING_COMMIT").unwrap_or_else(|_| "unspecified".to_string());
    let harness_sha256 = std::env::var("RUSTBGPD_ROUTE_PAGING_HARNESS_SHA256")
        .unwrap_or_else(|_| "unspecified".to_string());
    let pair_order = std::env::var("RUSTBGPD_ROUTE_PAGING_PAIR_ORDER")
        .unwrap_or_else(|_| "unspecified".to_string());
    let run_position = std::env::var("RUSTBGPD_ROUTE_PAGING_RUN_POSITION")
        .unwrap_or_else(|_| "unspecified".to_string());
    let mut output: Box<dyn Write> = match args.output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    writeln!(
        output,
        "variant,commit,harness_sha256,scope,routes,page_size,repetition,pair_order,run_position,pages,rows,ordered_key_checksum,complete_ns,page_p50_ns,page_p99_ns,page_max_ns,rows_per_second,ingest_ns,churn_routes,churn_ns,resident_bytes"
    )?;

    let expected_rows = args.scope.expected_rows(args.route_count);
    let (mut manager, _receivers, setup) = seeded_manager(args.route_count)?;
    let sample = traverse(
        &mut manager,
        args.scope.query(),
        expected_rows,
        args.page_size,
    );
    if matches!(args.scope, BenchScope::GroupedAdvertised) {
        assert!(
            sample.rows < args.route_count,
            "grouped fixture must differ from the best-route control"
        );
    }
    let rows_per_second = sample.rows as f64 / sample.elapsed.as_secs_f64();
    writeln!(
        output,
        "{variant},{commit},{harness_sha256},{},{},{},{},{pair_order},{run_position},{},{},{:016x},{},{},{},{},{rows_per_second:.3},{},{},{},{}",
        args.scope.label(),
        args.route_count,
        args.page_size,
        args.repetition,
        sample.pages,
        sample.rows,
        sample.ordered_key_checksum,
        sample.elapsed.as_nanos(),
        sample.page_p50.as_nanos(),
        sample.page_p99.as_nanos(),
        sample.page_max.as_nanos(),
        setup.ingest.as_nanos(),
        setup.churn_routes,
        setup.churn.as_nanos(),
        setup.resident_bytes,
    )?;
    output.flush()?;
    Ok(())
}
