//! One-shot LAN-1188 selection-deferral release measurement.
//!
//! Fixture construction is outside the timed interval. One ordinary Loc-RIB
//! count query is queued before the exact production expiry call, then served
//! through the manager's existing general-query drain. Each invocation emits
//! one JSON receipt; no statistical campaign policy lives in this binary.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, OutboundRouteUpdate, RibManager, RibUpdate, Route, RouteOrigin,
    SelectionDeferralConfig, SelectionDeferralWaiterConfig,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, RpkiValidation, Safi};
use tokio::sync::mpsc;

const FLEET_PEERS: usize = 700;
const FLEET_ROUTES: usize = 400_400;
const SELF_TEST_PEERS: usize = 4;
const SELF_TEST_ROUTES: usize = 64;
const LEDGER_IDENTITY_LIMIT: usize = 1_000_000;

const IPV4_UNICAST: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const IPV6_UNICAST: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const SEVEN_GATES: [(Afi, Safi); 7] = [
    IPV4_UNICAST,
    IPV6_UNICAST,
    (Afi::Ipv4, Safi::FlowSpec),
    (Afi::L2Vpn, Safi::Evpn),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::BgpLs, Safi::BgpLs),
];

// `bench_selection_deferral_inventory` layout.
const LOC_V4_ROUTES: usize = 0;
const LOC_V4_CHECKSUM: usize = 1;
const LOC_V6_ROUTES: usize = 2;
const LOC_V6_CHECKSUM: usize = 3;
const ADJ_V4_ROUTES: usize = 4;
const ADJ_V4_CHECKSUM: usize = 5;
const ADJ_V6_ROUTES: usize = 6;
const ADJ_V6_CHECKSUM: usize = 7;
const SOURCE_STORES: usize = 8;
const NONEMPTY_SOURCE_STORES: usize = 9;
const MIN_SOURCE_ROUTES: usize = 10;
const MAX_SOURCE_ROUTES: usize = 11;

// `bench_selection_deferral_release_with_sentinel` layout.
const RELEASE_NS: usize = 0;
const SENTINEL_NS: usize = 1;
const SENTINEL_COUNT: usize = 2;
const PRIMARY_DEPTH: usize = 3;
const QUERY_DEPTH_BEFORE: usize = 4;
const QUERY_DEPTH_AFTER: usize = 5;
const RELEASE_DELTA: usize = 6;
const TIMEOUT_DELTA: usize = 7;
const ACTIVE_GATES: usize = 8;
const RELEASED_GATES: usize = 9;
const TIMER_GATES: usize = 10;
const LEDGER_CLEARED: usize = 11;
const OBSERVED_GATES: usize = 12;
const OVERFLOWS_BEFORE: usize = 13;

type Families = Vec<(Afi, Safi)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Control,
    Ipv4,
    Dual,
    Seven,
    Overflow,
}

impl Mode {
    const fn label(self) -> &'static str {
        match self {
            Self::Control => "control_no_release",
            Self::Ipv4 => "ipv4_normal",
            Self::Dual => "dual_normal",
            Self::Seven => "seven_gate_normal",
            Self::Overflow => "dual_overflow_withdrawal",
        }
    }

    const fn expires(self) -> bool {
        !matches!(self, Self::Control)
    }

    const fn is_overflow(self) -> bool {
        matches!(self, Self::Overflow)
    }
}

#[derive(Debug)]
enum Command {
    Run(Mode),
    SelfTest,
    Help,
}

#[derive(Debug, Clone)]
struct Receipt {
    mode: String,
    peers: usize,
    expected_v4: usize,
    expected_v6: usize,
    expected_v4_checksum: u64,
    expected_v6_checksum: u64,
    gated_families: usize,
    sendable_families: usize,
    before: [u64; 12],
    after: [u64; 12],
    release: [u64; 14],
    eor_markers: usize,
    eor_complete_peers: usize,
    peers_with_route_payload: usize,
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

fn parse_args() -> Result<Command, String> {
    let mut raw = std::env::args().skip(1);
    let mut command = None;
    while let Some(argument) = raw.next() {
        match argument.as_str() {
            // Cargo passes this libtest-compatible marker to custom benches.
            "--bench" => {}
            "--mode" => {
                if command.is_some() {
                    return Err("choose exactly one of --mode or --self-test".into());
                }
                let value = raw.next().ok_or("--mode requires a value")?;
                let mode = match value.as_str() {
                    "control" | "control-no-release" => Mode::Control,
                    "ipv4" | "ipv4-normal" => Mode::Ipv4,
                    "dual" | "dual-normal" => Mode::Dual,
                    "seven" | "seven-gate-normal" => Mode::Seven,
                    "overflow" | "dual-overflow-withdrawal" => Mode::Overflow,
                    _ => {
                        return Err(format!(
                            "unknown mode {value:?}; expected control, ipv4, dual, seven, or overflow"
                        ));
                    }
                };
                command = Some(Command::Run(mode));
            }
            "--self-test" => {
                if command.is_some() {
                    return Err("choose exactly one of --mode or --self-test".into());
                }
                command = Some(Command::SelfTest);
            }
            "--help" | "-h" => {
                if command.is_some() {
                    return Err("--help cannot be combined with another command".into());
                }
                command = Some(Command::Help);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    command.ok_or_else(|| "one of --mode, --self-test, or --help is required".into())
}

fn help() {
    println!(
        "selection_deferral_release --mode control|ipv4|dual|seven|overflow\n\
         selection_deferral_release --self-test\n\n\
         Fleet modes are fixed at 700 route-server peers and 400,400 total routes.\n\
         --self-test is fixed at 4 peers and 64 routes and runs no fleet campaign."
    );
}

fn mode_families(mode: Mode) -> (Families, Families) {
    match mode {
        Mode::Control | Mode::Ipv4 => (vec![IPV4_UNICAST], vec![IPV4_UNICAST]),
        Mode::Dual | Mode::Overflow => (
            vec![IPV4_UNICAST, IPV6_UNICAST],
            vec![IPV4_UNICAST, IPV6_UNICAST],
        ),
        Mode::Seven => (SEVEN_GATES.to_vec(), vec![IPV4_UNICAST, IPV6_UNICAST]),
    }
}

fn expected_counts(mode: Mode, total: usize) -> (usize, usize) {
    match mode {
        Mode::Control | Mode::Ipv4 => (total, 0),
        Mode::Dual | Mode::Seven | Mode::Overflow => {
            assert_eq!(total % 2, 0, "dual fixture requires an even route count");
            (total / 2, total / 2)
        }
    }
}

fn prefix_v4(index: usize, filler: bool) -> Prefix {
    let base = if filler { 0x3000_0000 } else { 0x0b00_0000 };
    let host = base + u32::try_from(index).expect("IPv4 fixture index fits the address space");
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(host), 32))
}

fn prefix_v6(index: usize, filler: bool) -> Prefix {
    let base = if filler {
        0x2001_0db8_0001_0000_0000_0000_0000_0000u128
    } else {
        0x2001_0db8_0000_0000_0000_0000_0000_0000u128
    };
    Prefix::V6(Ipv6Prefix::new(
        Ipv6Addr::from(
            base + u128::try_from(index).expect("IPv6 fixture index fits the address space"),
        ),
        128,
    ))
}

fn make_route(
    prefix: Prefix,
    index: usize,
    peers: usize,
    attributes: &Arc<Vec<rustbgpd_wire::PathAttribute>>,
) -> Route {
    let peer = RibManager::bench_peer_address(index % peers);
    let next_hop = match prefix {
        Prefix::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        Prefix::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1)),
    };
    Route {
        prefix,
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer,
        attributes: Arc::clone(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn routes(v4: usize, v6: usize, peers: usize, filler: bool) -> Vec<Route> {
    let attributes = Arc::new(Vec::new());
    let mut routes = Vec::with_capacity(v4.saturating_add(v6));
    for index in 0..v4 {
        routes.push(make_route(
            prefix_v4(index, filler),
            index,
            peers,
            &attributes,
        ));
    }
    for index in 0..v6 {
        routes.push(make_route(
            prefix_v6(index, filler),
            v4.saturating_add(index),
            peers,
            &attributes,
        ));
    }
    routes
}

fn expected_checksum(count: usize, ipv6: bool) -> u64 {
    (0..count).fold(0, |checksum, index| {
        let prefix = if ipv6 {
            prefix_v6(index, false)
        } else {
            prefix_v4(index, false)
        };
        checksum.wrapping_add(RibManager::bench_selection_deferral_prefix_checksum(prefix))
    })
}

fn withdraw_inventory(manager: &mut RibManager, v4: usize, v6: usize, peers: usize, filler: bool) {
    let mut by_peer: BTreeMap<IpAddr, Vec<(Prefix, u32)>> = BTreeMap::new();
    for index in 0..v4 {
        by_peer
            .entry(RibManager::bench_peer_address(index % peers))
            .or_default()
            .push((prefix_v4(index, filler), 0));
    }
    for index in 0..v6 {
        by_peer
            .entry(RibManager::bench_peer_address(
                v4.saturating_add(index) % peers,
            ))
            .or_default()
            .push((prefix_v6(index, filler), 0));
    }
    for (peer, withdrawn) in by_peer {
        manager.bench_withdraw_loc_rib(peer, withdrawn);
    }
}

fn selection_config(peers: usize, families: &[(Afi, Safi)]) -> SelectionDeferralConfig {
    SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: (0..peers)
            .map(|index| SelectionDeferralWaiterConfig {
                peer: RibManager::bench_peer_address(index),
                families: families.to_vec(),
            })
            .collect(),
    }
}

fn manager() -> (RibManager, mpsc::Sender<RibUpdate>, mpsc::Sender<RibUpdate>) {
    let (update_tx, update_rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    (
        RibManager::new(update_rx, query_rx, None, None, BgpMetrics::new()),
        update_tx,
        query_tx,
    )
}

fn drain_eor(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected_families: &[(Afi, Safi)],
) -> (usize, usize, usize) {
    let expected = expected_families.iter().copied().collect::<HashSet<_>>();
    let mut markers = 0usize;
    let mut complete_peers = 0usize;
    let mut peers_with_routes = 0usize;
    for receiver in receivers {
        let mut seen = HashSet::new();
        let mut route_payload = false;
        while let Ok(update) = receiver.try_recv() {
            route_payload |= !update.announce.is_empty();
            for family in update.end_of_rib {
                assert!(
                    seen.insert(family),
                    "one release delivered duplicate EoR for {family:?}"
                );
                markers = markers.saturating_add(1);
            }
        }
        complete_peers = complete_peers.saturating_add(usize::from(seen == expected));
        peers_with_routes = peers_with_routes.saturating_add(usize::from(route_payload));
    }
    (markers, complete_peers, peers_with_routes)
}

fn run(mode: Mode, peers: usize, total_routes: usize) -> Receipt {
    let (gated_families, sendable_families) = mode_families(mode);
    let (expected_v4, expected_v6) = expected_counts(mode, total_routes);
    let expected_v4_checksum = expected_checksum(expected_v4, false);
    let expected_v6_checksum = expected_checksum(expected_v6, true);
    let (mut manager, _update_tx, query_tx) = manager();

    if mode.is_overflow() {
        manager.bench_seed_loc_rib(routes(expected_v4, expected_v6, peers, false));
        manager = manager.with_selection_deferral(selection_config(peers, &gated_families));
    } else {
        // The control is intentionally the exact gated setup with only the
        // expiry call omitted; its sentinel observes the still-frozen table.
        manager = manager.with_selection_deferral(selection_config(peers, &gated_families));
    }

    let mut receivers = manager.bench_register_selection_deferral_route_server_peers(
        peers,
        &gated_families,
        &sendable_families,
        gated_families.len().saturating_add(4),
        |_| Arc::new(PermissiveExactExport),
    );

    if mode.is_overflow() {
        withdraw_inventory(&mut manager, expected_v4, expected_v6, peers, false);
        let accepted_filler = LEDGER_IDENTITY_LIMIT
            .checked_sub(total_routes)
            .expect("overflow fixture total stays below the production identity limit");
        let filler_v4 = accepted_filler / 2 + peers;
        let filler_v6 = accepted_filler - accepted_filler / 2 + peers;
        manager.bench_seed_loc_rib(routes(filler_v4, filler_v6, peers, true));
        withdraw_inventory(&mut manager, filler_v4, filler_v6, peers, true);
    } else {
        manager.bench_seed_loc_rib(routes(expected_v4, expected_v6, peers, false));
        // Setup fanout belongs outside both the release timer and its control.
        for receiver in &mut receivers {
            while receiver.try_recv().is_ok() {}
        }
    }

    let before = manager.bench_selection_deferral_inventory();
    let release = manager.bench_selection_deferral_release_with_sentinel(
        &query_tx,
        &gated_families,
        RibManager::bench_peer_address(0),
        mode.expires(),
    );
    let after = manager.bench_selection_deferral_inventory();
    let expected_eor = if mode.expires() {
        sendable_families.as_slice()
    } else {
        &[]
    };
    let (eor_markers, eor_complete_peers, peers_with_route_payload) =
        drain_eor(&mut receivers, expected_eor);

    Receipt {
        mode: mode.label().into(),
        peers,
        expected_v4,
        expected_v6,
        expected_v4_checksum,
        expected_v6_checksum,
        gated_families: gated_families.len(),
        sendable_families: sendable_families.len(),
        before,
        after,
        release,
        eor_markers,
        eor_complete_peers,
        peers_with_route_payload,
    }
}

fn validate(receipt: &Receipt) -> Result<(), String> {
    let mode = match receipt.mode.as_str() {
        "control_no_release" => Mode::Control,
        "ipv4_normal" => Mode::Ipv4,
        "dual_normal" => Mode::Dual,
        "seven_gate_normal" => Mode::Seven,
        "dual_overflow_withdrawal" => Mode::Overflow,
        other => return Err(format!("unknown receipt mode {other:?}")),
    };
    let expected_total = receipt.expected_v4.saturating_add(receipt.expected_v6);
    let expect_source_rows = |inventory: &[u64; 12], populated: bool| -> Result<(), String> {
        if inventory[SOURCE_STORES] != receipt.peers as u64 {
            return Err("source-store count mismatch".into());
        }
        let expected_nonempty = if populated { receipt.peers as u64 } else { 0 };
        if inventory[NONEMPTY_SOURCE_STORES] != expected_nonempty {
            return Err("nonempty source-store count mismatch".into());
        }
        let expected_min = if populated {
            (expected_total / receipt.peers) as u64
        } else {
            0
        };
        let expected_max = if populated {
            expected_total.div_ceil(receipt.peers) as u64
        } else {
            0
        };
        if inventory[MIN_SOURCE_ROUTES] != expected_min
            || inventory[MAX_SOURCE_ROUTES] != expected_max
        {
            return Err("per-source distribution mismatch".into());
        }
        Ok(())
    };

    let expected_adj_populated = !mode.is_overflow();
    expect_source_rows(&receipt.before, expected_adj_populated)?;
    expect_source_rows(&receipt.after, expected_adj_populated)?;
    let (adj_v4, adj_v4_checksum, adj_v6, adj_v6_checksum) = if expected_adj_populated {
        (
            receipt.expected_v4 as u64,
            receipt.expected_v4_checksum,
            receipt.expected_v6 as u64,
            receipt.expected_v6_checksum,
        )
    } else {
        (0, 0, 0, 0)
    };
    for inventory in [&receipt.before, &receipt.after] {
        if inventory[ADJ_V4_ROUTES] != adj_v4
            || inventory[ADJ_V4_CHECKSUM] != adj_v4_checksum
            || inventory[ADJ_V6_ROUTES] != adj_v6
            || inventory[ADJ_V6_CHECKSUM] != adj_v6_checksum
        {
            return Err("Adj-RIB-In count/checksum mismatch".into());
        }
    }

    let before_loc_populated = mode.is_overflow();
    let before_expected = if before_loc_populated {
        (
            receipt.expected_v4 as u64,
            receipt.expected_v4_checksum,
            receipt.expected_v6 as u64,
            receipt.expected_v6_checksum,
        )
    } else {
        (0, 0, 0, 0)
    };
    if (
        receipt.before[LOC_V4_ROUTES],
        receipt.before[LOC_V4_CHECKSUM],
        receipt.before[LOC_V6_ROUTES],
        receipt.before[LOC_V6_CHECKSUM],
    ) != before_expected
    {
        return Err("pre-release Loc-RIB count/checksum mismatch".into());
    }
    let after_expected = if mode.is_overflow() || matches!(mode, Mode::Control) {
        (0, 0, 0, 0)
    } else {
        (
            receipt.expected_v4 as u64,
            receipt.expected_v4_checksum,
            receipt.expected_v6 as u64,
            receipt.expected_v6_checksum,
        )
    };
    if (
        receipt.after[LOC_V4_ROUTES],
        receipt.after[LOC_V4_CHECKSUM],
        receipt.after[LOC_V6_ROUTES],
        receipt.after[LOC_V6_CHECKSUM],
    ) != after_expected
    {
        return Err("post-release Loc-RIB count/checksum mismatch".into());
    }
    let expected_sentinel = after_expected.0.saturating_add(after_expected.2);
    if receipt.release[SENTINEL_COUNT] != expected_sentinel {
        return Err("sentinel Loc-RIB count mismatch".into());
    }
    if receipt.release[PRIMARY_DEPTH] != 0
        || receipt.release[QUERY_DEPTH_BEFORE] != 1
        || receipt.release[QUERY_DEPTH_AFTER] != 0
    {
        return Err("actor/query depth contract mismatch".into());
    }
    if receipt.release[SENTINEL_NS] < receipt.release[RELEASE_NS] {
        return Err("sentinel latency is shorter than release duration".into());
    }
    let expected_gates = receipt.gated_families as u64;
    if mode.expires() {
        if receipt.release[RELEASE_DELTA] != expected_gates
            || receipt.release[TIMEOUT_DELTA] != expected_gates
            || receipt.release[ACTIVE_GATES] != 0
            || receipt.release[RELEASED_GATES] != expected_gates
            || receipt.release[TIMER_GATES] != expected_gates
            || receipt.release[OBSERVED_GATES] != expected_gates
        {
            return Err("release/timeout/gate state mismatch".into());
        }
        if receipt.release[LEDGER_CLEARED] != 1 {
            return Err("selection-deferral ledger was not cleared".into());
        }
    } else if receipt.release[RELEASE_DELTA] != 0
        || receipt.release[TIMEOUT_DELTA] != 0
        || receipt.release[ACTIVE_GATES] != expected_gates
        || receipt.release[RELEASED_GATES] != 0
        || receipt.release[TIMER_GATES] != 0
        || receipt.release[OBSERVED_GATES] != expected_gates
        || receipt.release[LEDGER_CLEARED] != 0
    {
        return Err("no-release control state mismatch".into());
    }
    let expected_overflows = if mode.is_overflow() { 2 } else { 0 };
    if receipt.release[OVERFLOWS_BEFORE] != expected_overflows {
        return Err("overflow mode/counter mismatch".into());
    }
    let expected_eor_markers = if mode.expires() {
        receipt.peers.saturating_mul(receipt.sendable_families)
    } else {
        0
    };
    if receipt.eor_markers != expected_eor_markers || receipt.eor_complete_peers != receipt.peers {
        return Err("EoR delivery mismatch".into());
    }
    let expected_route_peers = if mode.expires() && !mode.is_overflow() && expected_total > 1 {
        receipt.peers
    } else {
        0
    };
    if receipt.peers_with_route_payload != expected_route_peers {
        return Err("released route payload delivery mismatch".into());
    }
    Ok(())
}

fn assert_rejected(label: &str, receipt: &Receipt, mutate: impl FnOnce(&mut Receipt)) {
    let mut corrupted = receipt.clone();
    mutate(&mut corrupted);
    assert!(
        validate(&corrupted).is_err(),
        "self-test corruption {label:?} was not rejected"
    );
}

fn self_test() {
    let receipt = run(Mode::Seven, SELF_TEST_PEERS, SELF_TEST_ROUTES);
    validate(&receipt).expect("uncorrupted self-test receipt validates");
    assert_rejected("query_depth", &receipt, |row| {
        row.release[QUERY_DEPTH_BEFORE] = 2;
    });
    assert_rejected("count", &receipt, |row| {
        row.after[LOC_V4_ROUTES] = row.after[LOC_V4_ROUTES].saturating_add(1);
    });
    assert_rejected("checksum", &receipt, |row| {
        row.after[LOC_V6_CHECKSUM] ^= 1;
    });
    assert_rejected("mode", &receipt, |row| {
        row.mode = "unknown".into();
    });
    assert_rejected("missing_eor", &receipt, |row| {
        row.eor_markers = row.eor_markers.saturating_sub(1);
    });
    assert_rejected("uncleared_state", &receipt, |row| {
        row.release[LEDGER_CLEARED] = 0;
    });
    assert_rejected("release_counter", &receipt, |row| {
        row.release[RELEASE_DELTA] = row.release[RELEASE_DELTA].saturating_sub(1);
    });

    let control = run(Mode::Control, SELF_TEST_PEERS, SELF_TEST_ROUTES);
    validate(&control).expect("same-setup no-release control validates");
    println!(
        "{{\"self_test\":\"pass\",\"peers\":{SELF_TEST_PEERS},\"routes\":{SELF_TEST_ROUTES},\"corruptions_rejected\":7}}"
    );
}

fn print_receipt(receipt: &Receipt) {
    println!(
        "{{\"mode\":\"{}\",\"peers\":{},\"expected_v4\":{},\"expected_v6\":{},\"expected_v4_checksum\":{},\"expected_v6_checksum\":{},\"gated_families\":{},\"sendable_families\":{},\"before\":{:?},\"after\":{:?},\"release\":{:?},\"eor_markers\":{},\"eor_complete_peers\":{},\"peers_with_route_payload\":{}}}",
        receipt.mode,
        receipt.peers,
        receipt.expected_v4,
        receipt.expected_v6,
        receipt.expected_v4_checksum,
        receipt.expected_v6_checksum,
        receipt.gated_families,
        receipt.sendable_families,
        receipt.before,
        receipt.after,
        receipt.release,
        receipt.eor_markers,
        receipt.eor_complete_peers,
        receipt.peers_with_route_payload,
    );
}

fn main() {
    match parse_args() {
        Ok(Command::Help) => help(),
        Ok(Command::SelfTest) => self_test(),
        Ok(Command::Run(mode)) => {
            let receipt = run(mode, FLEET_PEERS, FLEET_ROUTES);
            if let Err(error) = validate(&receipt) {
                eprintln!("selection-deferral receipt rejected: {error}");
                std::process::exit(1);
            }
            print_receipt(&receipt);
        }
        Err(error) => {
            eprintln!("selection_deferral_release: {error}");
            eprintln!("use --help for usage");
            std::process::exit(2);
        }
    }
}
