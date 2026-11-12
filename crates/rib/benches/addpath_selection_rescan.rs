//! RIB actor time for one UPDATE against the Add-Path paths stored for the
//! key or keys it touches.
//!
//! Every message goes through the production RIB dispatcher (`handle_update`)
//! and its route chunks, the way transport delivers one decoded UPDATE:
//! `VpnRoutesReceived`, `LabeledRoutesReceived`, and `WireRoutesReceived` for
//! unicast. One iBGP source holds the stored paths; no receiver is registered,
//! so the time is receive, Adj-RIB-In, selection and an empty distribution.
//! Fixture construction, state checks and restores stay outside the timed
//! region (`RibManager::bench_timed_update`).
//!
//! Cells:
//! - `one_key`: one key holding N stored paths, one path per UPDATE:
//!   `replace_non_best`, `replace_best_worse`, `withdraw_best`,
//!   `withdraw_non_best`. A key with one stored path has no non-best path,
//!   so the two non-best kinds of the N = 1 baseline run with two stored
//!   paths and say so in `stored_paths`.
//! - `many_key`: one UPDATE carrying as many Add-Path NLRI as fit in 4,096
//!   bytes, each NLRI a different key that holds 1,024 stored paths. The
//!   count comes from encoding the UPDATE with the wire crate (`wire_fit` in
//!   the `meta` line). `announce` replaces one non-best path per key and
//!   `withdraw` removes one. `announce_best_worse` and `withdraw_best` are
//!   report-only extras.
//! - `many_key_interleaved`: the `many_key` cells, report-only, over keys
//!   filled path by path (path 2 for every key, then path 3, and so on)
//!   instead of key by key. Storage that places a key's paths in arrival
//!   order keeps them adjacent in `many_key` and spreads them across the
//!   table here.
//! - `llgr`: sessions of 1,024 fresh path IDs for one key, each ended by
//!   Graceful Restart and the LLGR promotion, then one UPDATE that replaces
//!   the best path with an identical route.
//!
//! Output is one JSON object per line: `meta`, one `sample` per repetition
//! (warm-up repetitions flagged), one `summary` per cell with the median and
//! p95, and a final `done`.
//!
//!   cargo bench -p rustbgpd-rib --features bench-internals \
//!     --bench addpath_selection_rescan -- --reps 50
//!
//! `--perf-ctl CTL,ACK --perf-cells PATTERN` drives the control FIFOs of
//! `perf stat --control fifo:CTL,ACK --delay -1`, so hardware counters cover
//! only the timed UPDATEs of the non-warm-up repetitions of cells whose name
//! contains `PATTERN`. Timings are unchanged; the counters are attribution.

use std::io::{BufRead as _, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use rustbgpd_rib::route::{AspaContextId, ReceivedAt};
use rustbgpd_rib::update::WireRoutesReceived;
use rustbgpd_rib::{
    AttrSet, LabeledRibRoute, LabeledRibRouteKey, PeerId, RibManager, RibUpdate, Route,
    RouteOrigin, VpnRibRoute, VpnRibRouteKey,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode, LabeledNlri,
    LabeledNlriEntry, LlgrFamily, MAX_MESSAGE_LEN, MpReachNlri, MpUnreachNlri, MplsLabelEntry,
    Origin, PathAttribute, Prefix, RouteDistinguisher, RpkiValidation, Safi, UpdateMessage,
    VpnNlri, VpnNlriEntry, VpnPrefix, VpnRouteKey,
};
use tokio::sync::mpsc;

/// Benches link the allocator the daemon ships with.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
/// Default per-key Add-Path receive cap for one session.
const DEFAULT_CAP: u32 = 1024;
/// Routes per UPDATE while a session fills its key in the LLGR cells.
const LLGR_UPDATE_ROUTES: usize = 205;

// LOCAL_PREF decides every selection here: path 1 is the best, the rest tie
// and fall to the lowest path ID.
const BEST: u32 = 200;
const BASE: u32 = 100;
const ALTERNATE: [u32; 2] = [90, 80];
const WORSE: u32 = 50;

const DEFAULT_CAP_LIMIT_NS: u64 = 10_000_000;
const OPT_IN_LIMIT_NS: u64 = 50_000_000;
const OPT_IN_STORED: usize = 65_536;

/// Control FIFOs of a `perf stat --control` run, and whether the repetition
/// now running is one it counts.
struct PerfControl {
    ctl: std::fs::File,
    ack: std::io::BufReader<std::fs::File>,
    cells: String,
    armed: bool,
}

static PERF: Mutex<Option<PerfControl>> = Mutex::new(None);

/// Send `enable` or `disable` to perf and wait for its acknowledgement, when
/// the running repetition is counted.
fn perf_command(command: &str) {
    let mut perf = PERF.lock().expect("perf control lock");
    let Some(perf) = perf.as_mut().filter(|perf| perf.armed) else {
        return;
    };
    writeln!(perf.ctl, "{command}").expect("write perf control");
    let mut ack = String::new();
    perf.ack.read_line(&mut ack).expect("read perf ack");
    assert_eq!(ack.trim_matches(['\n', '\0']), "ack", "perf ack");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Vpn,
    Labeled,
    Unicast,
}

impl Family {
    const ALL: [Self; 3] = [Self::Vpn, Self::Labeled, Self::Unicast];

    const fn name(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Labeled => "labeled",
            Self::Unicast => "unicast",
        }
    }

    const fn afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::Vpn => (Afi::Ipv4, Safi::MplsVpn),
            Self::Labeled => (Afi::Ipv4, Safi::LabeledUnicast),
            Self::Unicast => (Afi::Ipv4, Safi::Unicast),
        }
    }
}

/// One route identity. `rd` is used by VPN only.
#[derive(Clone, Copy, Debug)]
struct Key {
    rd: u32,
    prefix: Ipv4Prefix,
}

impl Key {
    fn route_distinguisher(self) -> RouteDistinguisher {
        let [a, b, c, d] = self.rd.to_be_bytes();
        RouteDistinguisher([0, 0, 0xFD, 0xE8, a, b, c, d])
    }

    fn vpn(self) -> VpnRouteKey {
        VpnRouteKey {
            route_distinguisher: self.route_distinguisher(),
            prefix: VpnPrefix::v4(self.prefix.addr, self.prefix.len).expect("IPv4 length"),
        }
    }
}

fn single_key() -> Key {
    Key {
        rd: 1,
        prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24),
    }
}

/// `count` distinct keys in their cheapest wire encodings. VPN keys differ
/// by Route Distinguisher and share `0.0.0.0/0`. Unicast and labeled keys
/// are every prefix of length 0 through 8 (one address octet at most), then
/// /16 prefixes (two octets).
fn dense_keys(family: Family, count: usize) -> Vec<Key> {
    fn prefix(index: u32, len: u8) -> Ipv4Prefix {
        let addr = index.checked_shl(32 - u32::from(len)).unwrap_or(0);
        Ipv4Prefix::new(Ipv4Addr::from(addr), len)
    }
    if family == Family::Vpn {
        return (0..count)
            .map(|index| Key {
                rd: u32::try_from(index).expect("key index fits u32"),
                prefix: prefix(0, 0),
            })
            .collect();
    }
    (0u8..=8)
        .flat_map(|len| (0u32..1 << len).map(move |index| prefix(index, len)))
        .chain((0u32..1 << 16).map(|index| prefix(index, 16)))
        .take(count)
        .map(|prefix| Key { rd: 0, prefix })
        .collect()
}

fn label() -> Vec<MplsLabelEntry> {
    vec![MplsLabelEntry::try_new(100, 0, true).expect("valid label")]
}

fn attributes(local_pref: u32) -> Arc<AttrSet> {
    AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(local_pref),
    ])
}

fn unicast_route(key: Key, path_id: u32, attributes: &Arc<AttrSet>) -> Route {
    Route {
        prefix: Prefix::V4(key.prefix),
        next_hop: IpAddr::V4(SOURCE),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_addr(IpAddr::V4(SOURCE)),
        attributes: Arc::clone(attributes),
        received_at: ReceivedAt::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: ROUTER_ID,
        is_stale: false,
        is_llgr_stale: false,
        path_id,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: AspaContextId::DEFAULT,
    }
}

fn labeled_route(key: Key, path_id: u32, attributes: &Arc<AttrSet>) -> LabeledRibRoute {
    LabeledRibRoute {
        nlri: LabeledNlri {
            labels: label(),
            prefix: Prefix::V4(key.prefix),
        },
        next_hop: IpAddr::V4(SOURCE),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_addr(IpAddr::V4(SOURCE)),
        attributes: Arc::clone(attributes),
        received_at: std::time::Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: ROUTER_ID,
        is_stale: false,
        is_llgr_stale: false,
        path_id,
    }
}

fn vpn_route(key: Key, path_id: u32, attributes: &Arc<AttrSet>) -> VpnRibRoute {
    let VpnRouteKey {
        route_distinguisher,
        prefix,
    } = key.vpn();
    VpnRibRoute {
        nlri: VpnNlri {
            labels: label(),
            route_distinguisher,
            prefix,
        },
        next_hop: IpAddr::V4(SOURCE),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_addr(IpAddr::V4(SOURCE)),
        attributes: Arc::clone(attributes),
        received_at: std::time::Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: ROUTER_ID,
        is_stale: false,
        is_llgr_stale: false,
        path_id,
    }
}

/// The message transport sends the RIB for one decoded UPDATE that announces
/// `paths` with one attribute set (`announce`) or withdraws them.
fn update(
    family: Family,
    session_id: u64,
    paths: &[(Key, u32)],
    announce: Option<u32>,
) -> RibUpdate {
    let peer = PeerId::from_addr(IpAddr::V4(SOURCE));
    let attributes = announce.map(attributes);
    match family {
        Family::Vpn => RibUpdate::VpnRoutesReceived {
            peer,
            session_id,
            announced: attributes.as_ref().map_or_else(Vec::new, |attributes| {
                paths
                    .iter()
                    .map(|&(key, path_id)| vpn_route(key, path_id, attributes))
                    .collect()
            }),
            withdrawn: if attributes.is_some() {
                Vec::new()
            } else {
                paths
                    .iter()
                    .map(|&(key, path_id)| VpnRibRouteKey {
                        nlri_key: key.vpn(),
                        path_id,
                    })
                    .collect()
            },
        },
        Family::Labeled => RibUpdate::LabeledRoutesReceived {
            peer,
            session_id,
            announced: attributes.as_ref().map_or_else(Vec::new, |attributes| {
                paths
                    .iter()
                    .map(|&(key, path_id)| labeled_route(key, path_id, attributes))
                    .collect()
            }),
            withdrawn: if attributes.is_some() {
                Vec::new()
            } else {
                paths
                    .iter()
                    .map(|&(key, path_id)| LabeledRibRouteKey {
                        prefix: Prefix::V4(key.prefix),
                        path_id,
                    })
                    .collect()
            },
        },
        Family::Unicast => {
            let withdrawn: Vec<(Prefix, u32)> = if attributes.is_some() {
                Vec::new()
            } else {
                paths
                    .iter()
                    .map(|&(key, path_id)| (Prefix::V4(key.prefix), path_id))
                    .collect()
            };
            let wire_withdrawals = withdrawn.len();
            RibUpdate::WireRoutesReceived(WireRoutesReceived::new(
                RibUpdate::RoutesReceived {
                    peer,
                    session_id,
                    announced: attributes.as_ref().map_or_else(Vec::new, |attributes| {
                        paths
                            .iter()
                            .map(|&(key, path_id)| unicast_route(key, path_id, attributes))
                            .collect()
                    }),
                    withdrawn,
                    flowspec_announced: Vec::new(),
                    flowspec_withdrawn: Vec::new(),
                    evpn_announced: Vec::new(),
                    evpn_withdrawn: Vec::new(),
                    validated_with: None,
                },
                wire_withdrawals,
            ))
        }
    }
}

/// Encoded length of the smallest UPDATE that carries one Add-Path NLRI per
/// key: ORIGIN, an empty `AS_PATH`, `LOCAL_PREF` and the next hop for an
/// announcement, nothing but the NLRI for a withdrawal.
fn wire_len(family: Family, keys: &[Key], announce: bool) -> usize {
    let (afi, safi) = family.afi_safi();
    let unicast: Vec<Ipv4NlriEntry> = keys
        .iter()
        .map(|key| Ipv4NlriEntry {
            path_id: 1,
            prefix: key.prefix,
        })
        .collect();
    let (mut labeled, mut vpn) = (Vec::new(), Vec::new());
    match family {
        Family::Unicast => {}
        Family::Labeled => {
            labeled = keys
                .iter()
                .map(|key| LabeledNlriEntry {
                    path_id: 1,
                    nlri: LabeledNlri {
                        labels: label(),
                        prefix: Prefix::V4(key.prefix),
                    },
                })
                .collect();
        }
        Family::Vpn => {
            vpn = keys
                .iter()
                .map(|key| {
                    let VpnRouteKey {
                        route_distinguisher,
                        prefix,
                    } = key.vpn();
                    VpnNlriEntry {
                        path_id: 1,
                        nlri: VpnNlri {
                            labels: label(),
                            route_distinguisher,
                            prefix,
                        },
                    }
                })
                .collect();
        }
    }
    let mut path_attributes = if announce {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(BASE),
        ]
    } else {
        Vec::new()
    };
    let message = match (family, announce) {
        (Family::Unicast, true) => {
            path_attributes.push(PathAttribute::NextHop(SOURCE));
            UpdateMessage::build(
                &unicast,
                &[],
                &path_attributes,
                true,
                true,
                Ipv4UnicastMode::Body,
            )
        }
        (Family::Unicast, false) => UpdateMessage::build(
            &[],
            &unicast,
            &path_attributes,
            true,
            true,
            Ipv4UnicastMode::Body,
        ),
        (_, true) => {
            path_attributes.push(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                afi,
                safi,
                next_hop: IpAddr::V4(SOURCE),
                link_local_next_hop: None,
                announced: Vec::new(),
                flowspec_announced: Vec::new(),
                evpn_announced: Vec::new(),
                bgpls_announced: Vec::new(),
                vpn_announced: vpn,
                labeled_announced: labeled,
                rtc_announced: Vec::new(),
                vpn_flowspec_announced: Vec::new(),
            })));
            UpdateMessage::build(
                &[],
                &[],
                &path_attributes,
                true,
                true,
                Ipv4UnicastMode::Body,
            )
        }
        (_, false) => {
            path_attributes.push(PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
                afi,
                safi,
                withdrawn: Vec::new(),
                flowspec_withdrawn: Vec::new(),
                evpn_withdrawn: Vec::new(),
                bgpls_withdrawn: Vec::new(),
                vpn_withdrawn: vpn,
                labeled_withdrawn: labeled,
                rtc_withdrawn: Vec::new(),
                vpn_flowspec_withdrawn: Vec::new(),
            })));
            UpdateMessage::build(
                &[],
                &[],
                &path_attributes,
                true,
                true,
                Ipv4UnicastMode::Body,
            )
        }
    };
    message.encoded_len()
}

/// The most keys one 4,096-byte UPDATE can carry, and its encoded length.
fn wire_fit(family: Family, announce: bool) -> (usize, usize) {
    let limit = usize::from(MAX_MESSAGE_LEN);
    let keys = dense_keys(family, 1024);
    let (mut fits, mut over) = (1, keys.len());
    assert!(wire_len(family, &keys[..fits], announce) <= limit);
    assert!(wire_len(family, &keys, announce) > limit);
    while over - fits > 1 {
        let middle = fits + (over - fits) / 2;
        if wire_len(family, &keys[..middle], announce) <= limit {
            fits = middle;
        } else {
            over = middle;
        }
    }
    (fits, wire_len(family, &keys[..fits], announce))
}

struct Fixture {
    manager: RibManager,
    _tx: mpsc::Sender<RibUpdate>,
    _query_tx: mpsc::Sender<RibUpdate>,
}

impl Fixture {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(8);
        let (query_tx, query_rx) = mpsc::channel(1);
        Self {
            manager: RibManager::new(rx, query_rx, None, None, BgpMetrics::new()),
            _tx: tx,
            _query_tx: query_tx,
        }
    }

    /// Register `session_id` for the source, as transport does when the
    /// session reaches Established. Nothing is exported to it.
    fn register(&mut self, session_id: u64, llgr_families: Vec<(Afi, Safi)>) {
        let (outbound_tx, _outbound_rx) = mpsc::channel(8);
        let _ = self.manager.bench_timed_update(RibUpdate::PeerUp {
            supersedes: None,
            peer: PeerId::from_addr(IpAddr::V4(SOURCE)),
            session_id,
            peer_asn: 65_001,
            peer_router_id: ROUTER_ID,
            outbound_tx,
            export_policy: None,
            sendable_families: Vec::new(),
            is_ebgp: false,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: llgr_families,
        });
    }

    /// Time one UPDATE (`RibManager::bench_timed_update`).
    fn timed(&mut self, update: RibUpdate) -> u64 {
        perf_command("enable");
        let ns = self.manager.bench_timed_update(update);
        perf_command("disable");
        ns
    }

    /// Apply one message outside any timed cell.
    fn apply(&mut self, update: RibUpdate) {
        let _ = self.manager.bench_timed_update(update);
    }

    /// Paths the source has stored in `family`.
    fn stored(&self, family: Family) -> usize {
        let [unicast, labeled, vpn] = self
            .manager
            .bench_stored_paths(PeerId::from_addr(IpAddr::V4(SOURCE)));
        match family {
            Family::Unicast => unicast,
            Family::Labeled => labeled,
            Family::Vpn => vpn,
        }
    }

    fn best(&self, family: Family, key: Key) -> Option<u32> {
        match family {
            Family::Unicast => self
                .manager
                .bench_best_unicast_path_id(Prefix::V4(key.prefix)),
            Family::Labeled => self
                .manager
                .bench_best_labeled_path_id(Prefix::V4(key.prefix)),
            Family::Vpn => self.manager.bench_best_vpn_path_id(&key.vpn()),
        }
    }

    fn check(&self, family: Family, stored: usize, key: Key, best: Option<u32>) {
        assert_eq!(
            self.stored(family),
            stored,
            "{} stored paths",
            family.name()
        );
        assert_eq!(self.best(family, key), best, "{} best path", family.name());
    }
}

struct Cell {
    group: &'static str,
    family: Family,
    kind: &'static str,
    /// Stored paths of each touched key when the timed UPDATE arrives.
    stored_paths: usize,
    /// Keys the timed UPDATE touches, one NLRI each.
    keys: usize,
    /// LLGR sessions completed, zero outside the `llgr` group.
    cycles: u64,
    /// A cell the ticket fixed, as opposed to a report-only extra.
    ticket_cell: bool,
}

impl Cell {
    fn name(&self) -> String {
        let mut name = format!("{}/{}/{}", self.group, self.family.name(), self.kind);
        if self.cycles > 0 {
            name.push_str(&format!("/cycles={}", self.cycles));
        }
        if self.keys > 1 {
            name.push_str(&format!("/keys={}", self.keys));
        }
        name.push_str(&format!("/stored={}", self.stored_paths));
        name
    }

    /// The decision threshold on the median, when the cell has one.
    fn limit(&self) -> Option<(&'static str, u64)> {
        if self.stored_paths <= DEFAULT_CAP as usize {
            Some(("default_cap_10ms", DEFAULT_CAP_LIMIT_NS))
        } else if self.stored_paths >= OPT_IN_STORED && self.keys == 1 {
            Some(("opt_in_50ms", OPT_IN_LIMIT_NS))
        } else {
            None
        }
    }
}

struct Run {
    reps: usize,
    warmup: usize,
    out: std::io::BufWriter<std::io::Stdout>,
    cells: usize,
    ticket_cells: usize,
}

impl Run {
    /// Run `repetition` for the warm-up and the timed repetitions of `cell`.
    /// It returns the timed nanoseconds of one UPDATE and leaves the fixture
    /// as it found it.
    fn cell(&mut self, cell: &Cell, mut repetition: impl FnMut(usize) -> u64) {
        let name = cell.name();
        let mut samples = Vec::with_capacity(self.reps);
        for rep in 0..self.warmup + self.reps {
            let warmup = rep < self.warmup;
            if let Some(perf) = PERF.lock().expect("perf control lock").as_mut() {
                perf.armed = !warmup && name.contains(perf.cells.as_str());
            }
            let ns = repetition(rep);
            writeln!(
                self.out,
                r#"{{"type":"sample","cell":"{name}","rep":{rep},"warmup":{warmup},"ns":{ns}}}"#
            )
            .expect("write sample");
            if !warmup {
                samples.push(ns);
            }
        }
        samples.sort_unstable();
        let count = samples.len();
        let median = if count % 2 == 0 {
            u64::midpoint(samples[count / 2 - 1], samples[count / 2])
        } else {
            samples[count / 2]
        };
        // Nearest rank: the smallest sample with at least 95% at or below it.
        let p95 = samples[(count * 95).div_ceil(100) - 1];
        let (rule, limit, over) = cell.limit().map_or_else(
            || ("none".to_string(), "null".to_string(), false),
            |(rule, limit)| (rule.to_string(), limit.to_string(), median > limit),
        );
        writeln!(
            self.out,
            r#"{{"type":"summary","cell":"{name}","group":"{}","family":"{}","kind":"{}","stored_paths":{},"keys":{},"cycles":{},"ticket_cell":{},"reps":{count},"median_ns":{median},"p95_ns":{p95},"min_ns":{},"max_ns":{},"invalid_p95_over_3x_median":{},"rule":"{rule}","limit_ns":{limit},"over_limit":{over}}}"#,
            cell.group,
            cell.family.name(),
            cell.kind,
            cell.stored_paths,
            cell.keys,
            cell.cycles,
            cell.ticket_cell,
            samples[0],
            samples[count - 1],
            p95 > median.saturating_mul(3),
        )
        .expect("write summary");
        self.out.flush().expect("flush");
        self.cells += 1;
        self.ticket_cells += usize::from(cell.ticket_cell);
    }
}

/// One key with `stored` paths (IDs `1..=stored`, ID 1 the best), one path
/// per timed UPDATE.
fn one_key(run: &mut Run, family: Family, stored: u32) {
    let key = single_key();
    let mut fixture = Fixture::new();
    fixture.register(1, Vec::new());
    fixture.apply(update(family, 1, &[(key, 1)], Some(BEST)));
    if stored > 1 {
        let rest: Vec<(Key, u32)> = (2..=stored).map(|path_id| (key, path_id)).collect();
        fixture.apply(update(family, 1, &rest, Some(BASE)));
    }
    let count = stored as usize;
    fixture.check(family, count, key, Some(1));
    let cell = |kind, stored_paths| Cell {
        group: "one_key",
        family,
        kind,
        stored_paths,
        keys: 1,
        cycles: 0,
        ticket_cell: true,
    };
    let next_best = (stored > 1).then_some(2);

    run.cell(&cell("replace_best_worse", count), |_| {
        let ns = fixture.timed(update(family, 1, &[(key, 1)], Some(WORSE)));
        fixture.check(family, count, key, next_best.or(Some(1)));
        fixture.apply(update(family, 1, &[(key, 1)], Some(BEST)));
        ns
    });
    run.cell(&cell("withdraw_best", count), |_| {
        let ns = fixture.timed(update(family, 1, &[(key, 1)], None));
        fixture.check(family, count - 1, key, next_best);
        fixture.apply(update(family, 1, &[(key, 1)], Some(BEST)));
        ns
    });

    // A key with one stored path has no non-best path: add one.
    let (target, count) = if stored == 1 {
        fixture.apply(update(family, 1, &[(key, 2)], Some(BASE)));
        (2, 2)
    } else {
        (stored / 2 + 1, count)
    };
    fixture.check(family, count, key, Some(1));
    run.cell(&cell("replace_non_best", count), |rep| {
        let ns = fixture.timed(update(
            family,
            1,
            &[(key, target)],
            Some(ALTERNATE[rep % 2]),
        ));
        fixture.check(family, count, key, Some(1));
        ns
    });
    run.cell(&cell("withdraw_non_best", count), |_| {
        let ns = fixture.timed(update(family, 1, &[(key, target)], None));
        fixture.check(family, count - 1, key, Some(1));
        fixture.apply(update(family, 1, &[(key, target)], Some(BASE)));
        ns
    });
}

/// One UPDATE filling 4,096 bytes, every key at the default cap. The keys
/// are filled one key at a time, or path by path across all keys when
/// `interleaved` (report-only cells).
fn many_key(run: &mut Run, family: Family, interleaved: bool) {
    let (announce_fit, _) = wire_fit(family, true);
    let (withdraw_fit, _) = wire_fit(family, false);
    assert!(announce_fit <= withdraw_fit);
    let keys = dense_keys(family, withdraw_fit);
    let mut fixture = Fixture::new();
    fixture.register(1, Vec::new());
    let paths = |count: usize, path_id: u32| -> Vec<(Key, u32)> {
        keys[..count].iter().map(|&key| (key, path_id)).collect()
    };
    if interleaved {
        for path_id in 2..=DEFAULT_CAP {
            fixture.apply(update(family, 1, &paths(withdraw_fit, path_id), Some(BASE)));
        }
    } else {
        for &key in &keys {
            let rest: Vec<(Key, u32)> = (2..=DEFAULT_CAP).map(|path_id| (key, path_id)).collect();
            fixture.apply(update(family, 1, &rest, Some(BASE)));
        }
    }
    fixture.apply(update(family, 1, &paths(withdraw_fit, 1), Some(BEST)));
    let total = withdraw_fit * DEFAULT_CAP as usize;
    let (first, last) = (keys[0], keys[announce_fit - 1]);
    fixture.check(family, total, first, Some(1));
    fixture.check(family, total, last, Some(1));
    let target = DEFAULT_CAP / 2 + 1;
    let cell = |kind, keys, ticket_cell: bool| Cell {
        group: if interleaved {
            "many_key_interleaved"
        } else {
            "many_key"
        },
        family,
        kind,
        stored_paths: DEFAULT_CAP as usize,
        keys,
        cycles: 0,
        ticket_cell: ticket_cell && !interleaved,
    };

    run.cell(&cell("announce", announce_fit, true), |rep| {
        let ns = fixture.timed(update(
            family,
            1,
            &paths(announce_fit, target),
            Some(ALTERNATE[rep % 2]),
        ));
        fixture.check(family, total, last, Some(1));
        ns
    });
    run.cell(&cell("withdraw", withdraw_fit, true), |_| {
        let ns = fixture.timed(update(family, 1, &paths(withdraw_fit, target), None));
        fixture.check(family, total - withdraw_fit, last, Some(1));
        fixture.apply(update(family, 1, &paths(withdraw_fit, target), Some(BASE)));
        ns
    });
    run.cell(&cell("announce_best_worse", announce_fit, false), |_| {
        let ns = fixture.timed(update(family, 1, &paths(announce_fit, 1), Some(WORSE)));
        fixture.check(family, total, last, Some(2));
        fixture.apply(update(family, 1, &paths(announce_fit, 1), Some(BEST)));
        ns
    });
    run.cell(&cell("withdraw_best", withdraw_fit, false), |_| {
        let ns = fixture.timed(update(family, 1, &paths(withdraw_fit, 1), None));
        fixture.check(family, total - withdraw_fit, first, Some(2));
        fixture.apply(update(family, 1, &paths(withdraw_fit, 1), Some(BEST)));
        ns
    });
}

/// Sessions of 1,024 fresh path IDs for one key. Each session ends in
/// Graceful Restart and the LLGR promotion, so its paths stay stored. After
/// each session count in `cycles`, time one UPDATE that replaces the best
/// path with an identical route.
fn llgr(run: &mut Run, family: Family, cycles: &[u64]) {
    let Some(&last) = cycles.iter().max() else {
        return;
    };
    let key = single_key();
    let peer = PeerId::from_addr(IpAddr::V4(SOURCE));
    let (afi, safi) = family.afi_safi();
    let llgr_families = vec![LlgrFamily {
        afi,
        safi,
        forwarding_preserved: true,
        stale_time: 3600,
    }];
    let mut fixture = Fixture::new();
    for session_id in 1..=last {
        fixture.apply(RibUpdate::SetPeerGracefulRestartContext {
            peer,
            session_id,
            peer_restart_state: true,
            peer_gr_helper: true,
            peer_gr_families: vec![(afi, safi)],
            peer_enhanced_refresh: false,
            peer_llgr_families: llgr_families.clone(),
            local_llgr_stale_time: 3600,
        });
        fixture.register(session_id, vec![(afi, safi)]);
        let first = u32::try_from(session_id).expect("session fits u32") * DEFAULT_CAP;
        let fresh: Vec<(Key, u32)> = (first..first + DEFAULT_CAP)
            .map(|path_id| (key, path_id))
            .collect();
        for paths in fresh.chunks(LLGR_UPDATE_ROUTES) {
            fixture.apply(update(family, session_id, paths, Some(BASE)));
        }
        let stored =
            usize::try_from(session_id).expect("session fits usize") * DEFAULT_CAP as usize;
        fixture.check(family, stored, key, Some(first));
        if cycles.contains(&session_id) {
            let cell = Cell {
                group: "llgr",
                family,
                kind: "replace_one_path",
                stored_paths: stored,
                keys: 1,
                cycles: session_id,
                ticket_cell: true,
            };
            run.cell(&cell, |_| {
                let ns = fixture.timed(update(family, session_id, &[(key, first)], Some(BASE)));
                fixture.check(family, stored, key, Some(first));
                ns
            });
        }
        fixture.apply(RibUpdate::PeerGracefulRestart {
            peer,
            session_id,
            restart_time: 1,
            stale_routes_time: 1,
            gr_families: vec![(afi, safi)],
            peer_llgr_capable: true,
            peer_llgr_families: llgr_families.clone(),
            llgr_stale_time: 3600,
        });
        fixture.manager.bench_expire_gr_timer(peer);
    }
}

fn list<T: std::str::FromStr>(value: &str) -> Vec<T> {
    value
        .split(',')
        .map(|item| {
            item.parse()
                .unwrap_or_else(|_| panic!("invalid list item {item:?}"))
        })
        .collect()
}

fn join<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Peak resident set of this process in KiB, zero when unreadable.
fn vm_hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

fn main() {
    let (mut reps, mut warmup) = (50usize, 5usize);
    let mut stored: Vec<u32> = vec![1, 1024, 8192, 65_536];
    let mut cycles: Vec<u64> = vec![1, 8, 64];
    let mut label = String::from("unlabelled");
    let (mut perf_ctl, mut perf_cells) = (None::<String>, None::<String>);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value"));
        match arg.as_str() {
            "--reps" => reps = value().parse().expect("--reps"),
            "--warmup" => warmup = value().parse().expect("--warmup"),
            "--stored" => stored = list(&value()),
            "--llgr-cycles" => cycles = list(&value()),
            "--label" => label = value(),
            "--perf-ctl" => perf_ctl = Some(value()),
            "--perf-cells" => perf_cells = Some(value()),
            // Cargo passes `--bench` to every bench target.
            "--bench" => {}
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(reps >= 1, "--reps must be at least 1");
    assert!(
        label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "--label takes letters, digits, '-' and '_'"
    );
    if let Some(fifos) = perf_ctl {
        let (ctl, ack) = fifos.split_once(',').expect("--perf-ctl takes CTL,ACK");
        *PERF.lock().expect("perf control lock") = Some(PerfControl {
            ctl: std::fs::OpenOptions::new()
                .write(true)
                .open(ctl)
                .expect("open perf control FIFO"),
            ack: std::io::BufReader::new(std::fs::File::open(ack).expect("open perf ack FIFO")),
            cells: perf_cells.expect("--perf-ctl needs --perf-cells"),
            armed: false,
        });
    }
    let started = std::time::Instant::now();
    let mut run = Run {
        reps,
        warmup,
        out: std::io::BufWriter::new(std::io::stdout()),
        cells: 0,
        ticket_cells: 0,
    };
    let fits = Family::ALL
        .map(|family| {
            let (announce, announce_len) = wire_fit(family, true);
            let (withdraw, withdraw_len) = wire_fit(family, false);
            format!(
                r#""{}":{{"announce_nlri":{announce},"announce_bytes":{announce_len},"withdraw_nlri":{withdraw},"withdraw_bytes":{withdraw_len}}}"#,
                family.name()
            )
        })
        .join(",");
    writeln!(
        run.out,
        r#"{{"type":"meta","target":"addpath_selection_rescan","label":"{label}","reps":{reps},"warmup":{warmup},"stored":[{}],"llgr_cycles":[{}],"many_key_stored":{DEFAULT_CAP},"max_message_len":{MAX_MESSAGE_LEN},"wire_fit":{{{fits}}}}}"#,
        join(&stored),
        join(&cycles),
    )
    .expect("write meta");
    run.out.flush().expect("flush");

    // The RIB reads Tokio's clock for its LLGR deadlines.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        for family in Family::ALL {
            for &count in &stored {
                one_key(&mut run, family, count);
            }
        }
        for family in Family::ALL {
            many_key(&mut run, family, false);
        }
        for family in Family::ALL {
            llgr(&mut run, family, &cycles);
        }
        for family in Family::ALL {
            many_key(&mut run, family, true);
        }
    });

    let expected = stored.len() * 3 * 4 + 3 * 2 + cycles.len() * 3;
    writeln!(
        run.out,
        r#"{{"type":"done","cells":{},"ticket_cells":{},"expected_ticket_cells":{expected},"vm_hwm_kb":{},"elapsed_s":{:.1}}}"#,
        run.cells,
        run.ticket_cells,
        vm_hwm_kb(),
        started.elapsed().as_secs_f64(),
    )
    .expect("write done");
    run.out.flush().expect("flush");
    assert_eq!(run.ticket_cells, expected, "every ticket cell ran");
}
