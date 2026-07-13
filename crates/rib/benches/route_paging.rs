//! Manager-level complete-traversal benchmark for LAN-391.
//!
//! This is a custom optimized benchmark harness rather than Criterion: the
//! repeated-scan baseline can take long enough at 400k routes/page-size 100
//! that Criterion's minimum sample count is counterproductive. One traversal
//! already yields hundreds or thousands of per-page occupancy samples, which
//! are summarized as p50/p99/max in machine-readable CSV.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, RibManager, RouteQueryScope, route_query_key,
};
use rustbgpd_rib::{Route, RouteOrigin};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};
use tokio::sync::mpsc;

#[derive(Debug)]
struct Args {
    route_counts: Vec<usize>,
    page_sizes: Vec<usize>,
    repetitions: usize,
    output: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            route_counts: vec![100_000, 400_000],
            page_sizes: vec![100, 1_000],
            repetitions: 1,
            output: None,
        }
    }
}

fn parse_usize_list(value: &str, flag: &str) -> Vec<usize> {
    let values: Vec<_> = value
        .split(',')
        .map(|part| {
            part.parse::<usize>()
                .unwrap_or_else(|_| panic!("{flag} expects comma-separated positive integers"))
        })
        .collect();
    assert!(
        values.iter().all(|value| *value > 0),
        "{flag} values must be positive"
    );
    values
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
                args.route_counts =
                    parse_usize_list(&raw.next().expect("--routes requires a value"), "--routes");
            }
            "--page-sizes" => {
                args.page_sizes = parse_usize_list(
                    &raw.next().expect("--page-sizes requires a value"),
                    "--page-sizes",
                );
            }
            "--repetitions" => {
                args.repetitions = raw
                    .next()
                    .expect("--repetitions requires a value")
                    .parse()
                    .expect("--repetitions expects a positive integer");
                assert!(args.repetitions > 0, "--repetitions must be positive");
            }
            "--output" => {
                args.output = Some(PathBuf::from(raw.next().expect("--output requires a path")));
            }
            "--help" | "-h" => {
                println!(
                    "route_paging [--routes 100000,400000] [--page-sizes 100,1000] \
                     [--repetitions 1] [--output FILE]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    args
}

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
    let peer = Ipv4Addr::new(198, 51, 100, 1);
    let attributes = Arc::new(Vec::new());
    (0..count)
        .map(|index| {
            let host = 0x0a00_0000u32
                .checked_add(u32::try_from(index).expect("route count fits in IPv4 space"))
                .expect("route fixture stays within IPv4 space");
            Route {
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(host), 32)),
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
            }
        })
        .collect()
}

fn seeded_manager(
    count: usize,
) -> (
    RibManager,
    Vec<mpsc::Receiver<rustbgpd_rib::OutboundRouteUpdate>>,
) {
    let (_update_tx, update_rx) = mpsc::channel(1);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let mut manager = RibManager::new(update_rx, query_rx, None, None, BgpMetrics::new());
    let receivers =
        manager.bench_register_peers(2, None, false, 4, || Arc::new(PermissiveExactExport));
    let routes = make_routes(count);
    let changed: HashSet<_> = routes.iter().map(|route| route.prefix).collect();
    manager.bench_seed_loc_rib(routes);
    manager.bench_distribute(&changed);
    (manager, receivers)
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
    }
}

fn main() -> io::Result<()> {
    let args = parse_args();
    let variant = std::env::var("RUSTBGPD_ROUTE_PAGING_VARIANT")
        .unwrap_or_else(|_| "unspecified".to_string());
    let commit =
        std::env::var("RUSTBGPD_ROUTE_PAGING_COMMIT").unwrap_or_else(|_| "unspecified".to_string());
    let mut output: Box<dyn Write> = match args.output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    writeln!(
        output,
        "variant,commit,scope,routes,page_size,repetition,pages,rows,complete_ns,page_p50_ns,page_p99_ns,page_max_ns,rows_per_second"
    )?;

    for route_count in args.route_counts {
        let (mut manager, _receivers) = seeded_manager(route_count);
        let scopes = [
            ("best", RouteQueryScope::Best),
            (
                "grouped_advertised",
                RouteQueryScope::Advertised {
                    peer: RibManager::bench_peer_address(0),
                },
            ),
        ];
        for page_size in &args.page_sizes {
            for (scope_name, scope) in scopes {
                for repetition in 1..=args.repetitions {
                    let sample = traverse(&mut manager, scope, route_count, *page_size);
                    let rows_per_second = sample.rows as f64 / sample.elapsed.as_secs_f64();
                    writeln!(
                        output,
                        "{variant},{commit},{scope_name},{route_count},{page_size},{repetition},{},{},{},{},{},{},{rows_per_second:.3}",
                        sample.pages,
                        sample.rows,
                        sample.elapsed.as_nanos(),
                        sample.page_p50.as_nanos(),
                        sample.page_p99.as_nanos(),
                        sample.page_max.as_nanos(),
                    )?;
                    output.flush()?;
                }
            }
        }
    }
    Ok(())
}
