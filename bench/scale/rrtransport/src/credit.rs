//! Outbound-credit qualification cells over real transport sessions.
//!
//! A production `RibManager` and production transport sessions reach
//! synthetic receivers over TCP loopback. Sources inject through
//! `RibUpdate`. Nothing here reads or sets the per-peer credit: every cell
//! runs at the default credit of the tree it was built from, and reads
//! only metrics that exist on every tree it compares (`bgp_rib_outbound_credit_bytes`
//! is recorded when present and never required by the harness).
//!
//! - `exhaust`: ordinary announce burst. The burst receivers and one
//!   healthy receiver establish, receive their End-of-RIB and pause their
//!   socket reads; a source that is not restarting then sends `rows` fresh
//!   routes, which every burst receiver's ordinary passes stage against its
//!   outbound credit until it is spent. Readers resume after a fixed pause.
//!   The healthy receiver gets a separate source's single-route churn and
//!   nothing of the burst.
//! - `restart`: the same cell behind an RFC 4724 restart. The RIB starts
//!   with selection deferred and the restarting source's End-of-RIB releases
//!   every route to every burst receiver behind its held End-of-RIB. The
//!   release owes each private receiver its family whole and delivers it as
//!   one uncharged whole-table operation, so this trigger never spends
//!   ordinary credit: it is a wire and recovery check, not an exhaustion one.
//! - `paused`: every EVPN receiver paused while one source re-announces
//!   its table with alternating `LOCAL_PREF` every round.
//! - `fill`: every receiver paused while one source sends fresh routes of
//!   one family; bytes per queued row is the slope of allocated bytes over
//!   the credit-rows gauge before the first refusal.
//! - `source_burst`: an unpaced burst and a healthy source's steady
//!   updates, both through real sessions; see the module.

pub mod release;
pub mod source_burst;

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use rustbgpd_evpn_load::{establish_on_with_read_hold, PeerConfig as StubConfig, PeerIoControl};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_rib::{
    AttrSet, EvpnRibRoute, FlowSpecRoute, LabeledRibRoute, PeerId, RibManager,
    SelectionDeferralConfig, SelectionDeferralWaiterConfig, VpnRibRoute,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, AspaValidation, EthernetTagId, EvpnImet, EvpnRoute, Ipv4Prefix,
    Ipv6Prefix, LabeledNlri, Message, MplsLabelEntry, Origin, PathAttribute, Prefix,
    RouteDistinguisher, RpkiValidation, Safi, VpnNlri, VpnPrefix,
};
use serde_json::{json, Value};
use tokio::net::TcpSocket;
use tokio::sync::{mpsc, oneshot, watch};

use crate::credit_wire::{
    delivery, unicast_prefix, ChurnState, Reference, WireFamily, WireState, BURST_RANGE,
    CHURN_PREFIX, EVPN_ORIGINATOR, EVPN_RD,
};
use crate::rr1000_support::rss_kib;

const SOURCE: Ipv4Addr = EVPN_ORIGINATOR;
const CHURN_SOURCE: Ipv4Addr = Ipv4Addr::new(127, 254, 0, 2);
const CLUSTER: Ipv4Addr = Ipv4Addr::new(127, 255, 0, 1);
const LOCAL_AS: u32 = 64_512;
/// Routes per source UPDATE, as a session hands them to the RIB.
const CHUNK: usize = 1_024;
/// Harness receive buffer: keeps the kernel from absorbing a paused
/// receiver's backlog, so it stays in the daemon's queues.
const RECEIVER_RCVBUF: u32 = 16 * 1024;
/// Burst routes carry this MED; MED 0 marks an absent route.
const BURST_VERSION: u32 = 7;
/// Sampling periods of the in-process instruments: sparse while a cell is
/// timed, dense where a fit needs points.
const SAMPLE: Duration = Duration::from_millis(250);
const FIT_SAMPLE: Duration = Duration::from_millis(50);
/// Churn period of the healthy receiver's single route.
const CHURN_EVERY: Duration = Duration::from_millis(20);
/// The churn-free window ends the pause: the healthy receiver's churn stops
/// this long before the burst readers resume. Short against cell 3's 1 s
/// delivery-gap bar, which the hold's own gap counts toward.
const QUIET_LEAD: Duration = Duration::from_millis(300);
/// After the held churn row arrives, time for its transport to drop the
/// written envelope and return its credit.
const QUIET_SETTLE: Duration = Duration::from_millis(20);
/// Gauge readings inside the churn-free window.
const QUIET_READ_EVERY: Duration = Duration::from_millis(10);
/// The longest the churn-free window's RIB waits may run past its end: the
/// churn task's stop (its last send can wait on the RIB's channel) and the
/// queries that republish the gauges. A RIB that stops serving its update
/// channel would otherwise hold the window, and the readers' resume behind
/// it, forever; a window at the cap is recorded as unavailable (bar 3 and
/// the exhaustion plateau INVALID).
const QUIET_CAP: Duration = Duration::from_secs(5);
/// Hold time of every receiver session, both ends.
const HOLD_SECS: u16 = 90;
/// The receiver stubs' own read timeout. A stub's deadline runs from its
/// last read and keeps running across a read pause, so it is longer than
/// the negotiated hold time; the daemon's sessions still use `HOLD_SECS`.
const READ_HOLD_SECS: u16 = 240;
/// Quiet period after every burst receiver is exact.
const QUIET: Duration = Duration::from_secs(2);
/// The release-under-churn variant withdraws every this-many-th burst
/// route during the drain and re-announces every other one of those at
/// `CHURN_VERSION`.
const CHURN_NTH: usize = 100;
const CHURN_VERSION: u32 = 9;
/// Period of the getter reads of the live-operation and credit-rows
/// gauges from the release on. The RIB publishes both once per run-loop
/// iteration; a getter read costs one atomic load.
const GAUGE_WATCH: Duration = Duration::from_millis(1);
/// Period of the inbox round-trip probe from the release until the burst
/// receivers settle: one `QueryLocRibCount` (a length read) through the
/// RIB's update channel, so a drain that yields without serving that
/// channel shows as a long round trip.
const ROUND_TRIP_EVERY: Duration = Duration::from_millis(10);
/// The longest one inbox round-trip probe (send and reply) may wait. A
/// RIB that stops serving its update channel would otherwise hold the
/// probe, and the cell's join on it, forever; a probe at the cap is
/// recorded as unfinished, far past the 250 ms turn bar.
const ROUND_TRIP_CAP: Duration = Duration::from_secs(30);
/// The RIB's row-credit constants, crate-private in
/// `crates/rib/src/outbound_credit.rs`: daemon-wide credit, per-peer floor
/// and ceiling, and one ordinary pass. Results record them so the analyzer
/// reads them from the run; a test fails when they drift from the RIB's.
const ROW_CREDIT: [(&str, usize); 4] = [
    ("DAEMON_ROW_CREDIT", 16_777_216),
    ("MIN_ROW_CREDIT", 8_192),
    ("MAX_ROW_CREDIT", 1_048_576),
    ("CHUNK_ROWS", 1_024),
];
/// The RIB's since-render slice maxima, in microseconds per stage.
const SLICE_MAX: &str = "bgp_rib_actor_slice_max_microseconds";
/// Histograms whose longest observation in the run the result brackets:
/// message turns, work outside them, owed-drain steps and eviction recoveries.
const TURN_HISTOGRAMS: [(&str, &str); 4] = [
    ("bgp_rib_actor_turn_duration_seconds", "kind"),
    ("bgp_rib_actor_work_duration_seconds", "work_unit"),
    ("bgp_rib_outbound_owed_drain_step_seconds", "scope"),
    ("bgp_rib_outbound_eviction_recovery_seconds", "outcome"),
];

/// Families a cell can inject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Unicast,
    Evpn,
    Vpn,
    Vpn6,
    Labeled4,
    Labeled6,
    FlowSpec,
}

impl Family {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "unicast" => Self::Unicast,
            "evpn" => Self::Evpn,
            "vpn" => Self::Vpn,
            "flowspec" => Self::FlowSpec,
            _ => bail!("unknown family {name}: unicast, evpn, vpn or flowspec"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::Evpn => "evpn",
            Self::Vpn => "vpn",
            Self::Vpn6 => "vpn6",
            Self::Labeled4 => "labeled4",
            Self::Labeled6 => "labeled6",
            Self::FlowSpec => "flowspec",
        }
    }

    fn afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::Unicast => (Afi::Ipv4, Safi::Unicast),
            Self::Evpn => (Afi::L2Vpn, Safi::Evpn),
            Self::Vpn => (Afi::Ipv4, Safi::MplsVpn),
            Self::Vpn6 => (Afi::Ipv6, Safi::MplsVpn),
            Self::Labeled4 => (Afi::Ipv4, Safi::LabeledUnicast),
            Self::Labeled6 => (Afi::Ipv6, Safi::LabeledUnicast),
            Self::FlowSpec => (Afi::Ipv4, Safi::FlowSpec),
        }
    }

    fn wire(self) -> Result<WireFamily> {
        Ok(match self {
            Self::Unicast => WireFamily::Unicast,
            Self::Evpn => WireFamily::Evpn,
            Self::Vpn => WireFamily::Vpn4,
            Self::Vpn6 => WireFamily::Vpn6,
            Self::Labeled4 => WireFamily::Labeled4,
            Self::Labeled6 => WireFamily::Labeled6,
            Self::FlowSpec => bail!("wire checks do not cover flowspec"),
        })
    }

    /// The row type the credit stages for this family.
    fn row_size_of(self) -> usize {
        match self {
            Self::Unicast => std::mem::size_of::<Route>(),
            Self::Evpn => std::mem::size_of::<EvpnRibRoute>(),
            Self::Vpn | Self::Vpn6 => std::mem::size_of::<VpnRibRoute>(),
            Self::Labeled4 | Self::Labeled6 => std::mem::size_of::<LabeledRibRoute>(),
            Self::FlowSpec => std::mem::size_of::<FlowSpecRoute>(),
        }
    }
}

/// How the burst of the exhaustion cell reaches the RIB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// Fresh routes from an established source: ordinary passes, charged
    /// to each receiver's credit.
    Ordinary,
    /// An RFC 4724 selection release: owed whole, uncharged.
    Restart,
}

impl Trigger {
    fn name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary_announce_burst",
            Self::Restart => "rfc4724_selection_release",
        }
    }

    /// The result's `cell` and file-name prefix.
    fn cell(self) -> &'static str {
        match self {
            Self::Ordinary => "exhaust",
            Self::Restart => "restart",
        }
    }

    /// The End-of-RIB order a burst receiver must see: after every route
    /// of a restart burst; once, before every route of an ordinary one.
    fn eor_check(self) -> &'static str {
        match self {
            Self::Ordinary => "one_eor_before_burst",
            Self::Restart => "eor_after_every_route",
        }
    }

    /// The fixed pause of the burst receivers' reads, from the first burst
    /// UPDATE: past the end of a paced ordinary burst (73.5 s) and inside
    /// the receivers' hold time.
    fn pause(self) -> Duration {
        match self {
            Self::Ordinary => Duration::from_secs(80),
            Self::Restart => Duration::from_secs(30),
        }
    }

    /// Time between source UPDATEs. An ordinary burst is paced at about
    /// half the rate the RIB stages it toward 150 private receivers, so
    /// the RIB's queue stays short and the healthy receiver's delivery
    /// shows what spent credit costs it, not how long the backlog is. A
    /// restart burst is held by the selection gate and needs no pacing.
    fn interval(self, reduced: bool) -> Duration {
        match (self, reduced) {
            (Self::Ordinary, false) => Duration::from_millis(500),
            (Self::Ordinary, true) => Duration::from_millis(10),
            (Self::Restart, _) => Duration::ZERO,
        }
    }

    fn eor_ordered(self, state: &WireState) -> bool {
        match self {
            Self::Ordinary => state.eors == 1 && state.routes_before_eor == 0,
            Self::Restart => state.eors == 1 && !state.eor_premature && state.routes_after_eor == 0,
        }
    }
}

/// Command-line options shared by the cells.
#[derive(Clone, Debug)]
pub struct Options {
    pub reduced: bool,
    pub correctness_only: bool,
    pub pause: Option<Duration>,
    pub seconds: Option<u64>,
    /// The runtime the RIB and the transport sessions run on. The harness
    /// (receivers, collectors, sampler, churn) runs on its own, so a long
    /// RIB turn can delay the daemon but never the observer's clock.
    pub daemon: Option<tokio::runtime::Handle>,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut options = Self {
            reduced: false,
            correctness_only: false,
            pause: None,
            seconds: None,
            daemon: None,
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--reduced" => options.reduced = true,
                "--correctness-only" => options.correctness_only = true,
                "--pause-ms" => {
                    let value = args.next().context("--pause-ms needs a value")?;
                    options.pause = Some(Duration::from_millis(value.parse()?));
                }
                "--seconds" => {
                    let value = args.next().context("--seconds needs a value")?;
                    options.seconds = Some(value.parse()?);
                }
                _ => bail!("unknown option {arg}"),
            }
        }
        // Only the fixed shape is a measurement: a reduced shape or any
        // pause or duration override marks the result correctness-only.
        options.correctness_only |=
            options.reduced || options.pause.is_some() || options.seconds.is_some();
        Ok(options)
    }
}

fn attributes(index: usize, med: u32, local_pref: u32) -> Arc<AttrSet> {
    let index = u32::try_from(index).expect("index fits u32");
    // Distinct attributes per route: one UPDATE a route, 202 bytes on the
    // wire for unicast, so a paused receiver's socket and writer budget
    // absorb only a small part of the burst and the rest stays charged to
    // the credit. The high half carries `index >> 16`, so routes 65,536
    // apart never share attributes (and an UPDATE) at the full shape; the
    // release witness divides queued bytes by one row's size (README).
    let path = (0..8).map(|hop| 64_496 + hop).collect();
    let communities = (0..24)
        .map(|tag| ((65_000 + (index >> 16)) << 16) | ((index + tag) & 0xffff))
        .collect();
    AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(path)],
        }),
        PathAttribute::NextHop(SOURCE),
        PathAttribute::LocalPref(local_pref),
        PathAttribute::Med(med),
        PathAttribute::Communities(communities),
    ])
}

fn unicast_route(index: usize, attrs: Arc<AttrSet>, source: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(Ipv4Prefix::new(unicast_prefix(index), 24)),
        next_hop: IpAddr::V4(source),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_ipv4(source),
        attributes: attrs,
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: source,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn evpn_route(index: usize, attrs: Arc<AttrSet>) -> EvpnRibRoute {
    EvpnRibRoute {
        route: EvpnRoute::Imet(EvpnImet {
            rd: EVPN_RD,
            ethernet_tag: EthernetTagId(u32::try_from(index + 1).expect("tag fits u32")),
            originator_ip: IpAddr::V4(EVPN_ORIGINATOR),
        }),
        next_hop: IpAddr::V4(SOURCE),
        link_local_next_hop: None,
        peer: PeerId::from_ipv4(SOURCE),
        attributes: attrs,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: SOURCE,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn mpls_destination(afi: Afi, index: usize) -> (Prefix, IpAddr) {
    if afi == Afi::Ipv6 {
        let subnet = u16::try_from(index).expect("IPv6 fixture subnet fits u16");
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, subnet, 0, 0, 0, 0, 0);
        let next_hop = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        (Prefix::V6(Ipv6Prefix::new(prefix, 48)), next_hop.into())
    } else {
        (
            Prefix::V4(Ipv4Prefix::new(unicast_prefix(index), 24)),
            SOURCE.into(),
        )
    }
}

fn route_label(index: usize) -> MplsLabelEntry {
    MplsLabelEntry {
        label: 16 + u32::try_from(index % 1_000).expect("label fits"),
        traffic_class: 0,
        bottom_of_stack: true,
    }
}

fn vpn_route(
    index: usize,
    attrs: Arc<AttrSet>,
    rd: RouteDistinguisher,
    (prefix, next_hop): (Prefix, IpAddr),
) -> VpnRibRoute {
    let prefix = match prefix {
        Prefix::V4(p) => VpnPrefix::V4 {
            addr: p.addr,
            len: p.len,
        },
        Prefix::V6(p) => VpnPrefix::V6 {
            addr: p.addr,
            len: p.len,
        },
    };
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![route_label(index)],
            route_distinguisher: rd,
            prefix,
        },
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_ipv4(SOURCE),
        attributes: attrs,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: SOURCE,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

/// VPN release rows come in pairs with the same prefix and different RDs.
fn release_source_update(family: Family, indices: std::ops::Range<usize>) -> RibUpdate {
    let afi = family.afi_safi().0;
    let peer = PeerId::from_ipv4(SOURCE);
    match family {
        Family::Vpn | Family::Vpn6 => RibUpdate::VpnRoutesReceived {
            peer,
            session_id: 1,
            announced: indices
                .map(|index| {
                    let rd =
                        RouteDistinguisher([0, 0, 0xfc, 0, 0, 0, 0, 1 + u8::from(index % 2 == 1)]);
                    vpn_route(
                        index,
                        attributes(index, BURST_VERSION, 100),
                        rd,
                        mpls_destination(afi, index / 2),
                    )
                })
                .collect(),
            withdrawn: Vec::new(),
        },
        Family::Labeled4 | Family::Labeled6 => RibUpdate::LabeledRoutesReceived {
            peer,
            session_id: 1,
            announced: indices
                .map(|index| {
                    let (prefix, next_hop) = mpls_destination(afi, index);
                    LabeledRibRoute {
                        nlri: LabeledNlri {
                            labels: vec![route_label(index)],
                            prefix,
                        },
                        next_hop,
                        link_local_next_hop: None,
                        next_hop_scope: None,
                        peer,
                        attributes: attributes(index, BURST_VERSION, 100),
                        received_at: Instant::now(),
                        origin_type: RouteOrigin::Ibgp,
                        peer_router_id: SOURCE,
                        is_stale: false,
                        is_llgr_stale: false,
                        path_id: 0,
                    }
                })
                .collect(),
            withdrawn: Vec::new(),
        },
        _ => source_update(family, indices, BURST_VERSION, 100),
    }
}

/// A large FlowSpec rule: destination prefix, 16 destination ports and 8
/// packet-length ranges, so its heap terms dominate the row element.
fn flowspec_route(index: usize, attrs: Arc<AttrSet>) -> FlowSpecRoute {
    use rustbgpd_wire::flowspec::{FlowSpecComponent, FlowSpecPrefix, FlowSpecRule, NumericMatch};
    let term = |value: u64, last: bool, lt: bool, gt: bool, eq: bool, and_bit: bool| NumericMatch {
        end_of_list: last,
        and_bit,
        lt,
        gt,
        eq,
        value,
    };
    let ports = (0..16)
        .map(|port| term(1_000 + port, port == 15, false, false, true, false))
        .collect();
    let lengths = (0..8)
        .flat_map(|range| {
            let low = 64 + range * 128;
            [
                term(low, false, false, true, true, false),
                term(low + 64, range == 7, true, false, false, true),
            ]
        })
        .collect();
    FlowSpecRoute {
        rule: FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    unicast_prefix(index),
                    24,
                ))),
                FlowSpecComponent::DestinationPort(ports),
                FlowSpecComponent::PacketLength(lengths),
            ],
        },
        afi: Afi::Ipv4,
        rd: None,
        peer: PeerId::from_ipv4(SOURCE),
        attributes: attrs,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: SOURCE,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

/// One source UPDATE of `family` announcing `indices` at `med`.
fn source_update(
    family: Family,
    indices: impl Iterator<Item = usize>,
    med: u32,
    local_pref: u32,
) -> RibUpdate {
    let peer = PeerId::from_ipv4(SOURCE);
    let session_id = 1;
    let attrs = |index| attributes(index, med, local_pref);
    let (mut announced, mut evpn, mut flowspec) = (Vec::new(), Vec::new(), Vec::new());
    match family {
        Family::Vpn => {
            return RibUpdate::VpnRoutesReceived {
                peer,
                session_id,
                announced: indices
                    .map(|index| {
                        vpn_route(
                            index,
                            attrs(index),
                            EVPN_RD,
                            mpls_destination(Afi::Ipv4, index),
                        )
                    })
                    .collect(),
                withdrawn: Vec::new(),
            };
        }
        Family::Vpn6 | Family::Labeled4 | Family::Labeled6 => {
            unreachable!("release-only family uses release_source_update")
        }
        Family::Unicast => {
            announced = indices
                .map(|index| unicast_route(index, attrs(index), SOURCE))
                .collect();
        }
        Family::Evpn => {
            evpn = indices
                .map(|index| evpn_route(index, attrs(index)))
                .collect()
        }
        Family::FlowSpec => {
            flowspec = indices
                .map(|index| flowspec_route(index, attrs(index)))
                .collect();
        }
    }
    RibUpdate::RoutesReceived {
        peer,
        session_id,
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: flowspec,
        flowspec_withdrawn: Vec::new(),
        evpn_announced: evpn,
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

/// One source UPDATE of `family` (unicast or EVPN) withdrawing `indices`.
fn source_withdrawal(family: Family, indices: &[usize]) -> RibUpdate {
    let (mut withdrawn, mut evpn_withdrawn) = (Vec::new(), Vec::new());
    for &index in indices {
        match family {
            Family::Evpn => {
                evpn_withdrawn.push(evpn_route(index, attributes(index, 1, 1)).route.key())
            }
            _ => withdrawn.push((Prefix::V4(Ipv4Prefix::new(unicast_prefix(index), 24)), 0)),
        }
    }
    RibUpdate::RoutesReceived {
        peer: PeerId::from_ipv4(SOURCE),
        session_id: 1,
        announced: Vec::new(),
        withdrawn,
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn,
        validated_with: None,
    }
}

/// The churn variant's subset of `0..rows`: every `CHURN_NTH`-th route is
/// withdrawn, and every other one of those re-announced at `CHURN_VERSION`.
fn churn_plan(rows: usize) -> (Vec<usize>, Vec<usize>) {
    let withdrawn: Vec<usize> = (0..rows).step_by(CHURN_NTH).collect();
    let reannounced = withdrawn.iter().copied().step_by(2).collect();
    (withdrawn, reannounced)
}

fn churn_update(sequence: u32) -> RibUpdate {
    let attrs = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(CHURN_SOURCE),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(sequence),
    ]);
    let mut route = unicast_route(0, attrs, CHURN_SOURCE);
    route.prefix = Prefix::V4(Ipv4Prefix::new(CHURN_PREFIX, 24));
    RibUpdate::RoutesReceived {
        peer: PeerId::from_ipv4(CHURN_SOURCE),
        session_id: 1,
        announced: vec![route],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

/// Register a synthetic source; `gr_families` makes it an RFC 4724 waiter.
async fn source_up(
    rib: &mpsc::Sender<RibUpdate>,
    source: Ipv4Addr,
    gr_families: Vec<(Afi, Safi)>,
) -> Result<mpsc::Receiver<rustbgpd_rib::update::OutboundRouteUpdate>> {
    let peer = PeerId::from_ipv4(source);
    if !gr_families.is_empty() {
        rib.send(RibUpdate::SetPeerGracefulRestartContext {
            peer,
            session_id: 1,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: gr_families,
            peer_enhanced_refresh: true,
            peer_llgr_families: Vec::new(),
            local_llgr_stale_time: 0,
        })
        .await?;
    }
    let (outbound_tx, outbound_rx) = mpsc::channel(16);
    rib.send(RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id: 1,
        peer_asn: LOCAL_AS,
        peer_router_id: source,
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
        negotiated_llgr_families: Vec::new(),
    })
    .await?;
    Ok(outbound_rx)
}

fn receiver_ip(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        127,
        10 + u8::try_from(index / 254).expect("receiver index"),
        1 + u8::try_from(index % 254).expect("receiver index"),
        1,
    )
}

fn statement(prefix: Option<Prefix>, neighbor: Option<NeighborSetMatch>) -> PolicyStatement {
    PolicyStatement {
        prefix,
        ge: None,
        le: prefix.map(|_| 32),
        action: PolicyAction::Deny,
        match_community: Vec::new(),
        match_as_path: None,
        match_neighbor_set: neighbor,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    }
}

fn permit_all_but(entry: PolicyStatement) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![entry],
        default_action: PolicyAction::Permit,
    }])
}

/// Permits everything but names a neighbor set, so unicast export is
/// evaluated per peer and every burst receiver keeps a private Adj-RIB-Out.
/// It also keeps the healthy receiver's churn route off the burst receivers.
fn private_unicast_policy() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![
            statement(
                None,
                Some(NeighborSetMatch {
                    addresses: Vec::new(),
                    remote_asns: vec![65_099],
                    peer_groups: Vec::new(),
                }),
            ),
            statement(Some(Prefix::V4(Ipv4Prefix::new(CHURN_PREFIX, 24))), None),
        ],
        default_action: PolicyAction::Permit,
    }])
}

/// Keeps every burst route away from the healthy receiver.
fn healthy_policy() -> PolicyChain {
    permit_all_but(statement(
        Some(Prefix::V4(Ipv4Prefix::new(BURST_RANGE.0, BURST_RANGE.1))),
        None,
    ))
}

fn transport_config(
    remote: SocketAddr,
    families: Vec<(Afi, Safi)>,
) -> rustbgpd_transport::TransportConfig {
    let mut config = crate::transport_config(remote);
    let mut peer = PeerConfig::new(LOCAL_AS, LOCAL_AS, CLUSTER);
    peer.connect_retry_secs = 1;
    peer.hold_time = HOLD_SECS;
    peer.families = families;
    config.peer = peer;
    config.cluster_id = Some(CLUSTER);
    config
}

/// A receiver's negotiated families and export policy.
type ReceiverSpec = (Vec<(Afi, Safi)>, Option<PolicyChain>);

/// One receiver: its daemon-side session and its harness-side stub.
struct Receiver {
    ip: Ipv4Addr,
    /// The stub's listening address: one end of its session's connection.
    listen: SocketAddr,
    session: PeerHandle,
    io: PeerIoControl,
    rx: Option<mpsc::Receiver<Message>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    stub_tx: mpsc::Sender<Message>,
}

/// The RIB, its metrics and every receiver of one run.
struct Fixture {
    metrics: BgpMetrics,
    rib: mpsc::Sender<RibUpdate>,
    _query: mpsc::Sender<RibUpdate>,
    manager: tokio::task::JoinHandle<()>,
    daemon: tokio::runtime::Handle,
    receivers: Vec<Receiver>,
    sources: Vec<mpsc::Receiver<rustbgpd_rib::update::OutboundRouteUpdate>>,
}

impl Fixture {
    fn start(options: &Options, deferral: Option<SelectionDeferralConfig>) -> Self {
        let daemon = options
            .daemon
            .clone()
            .unwrap_or_else(tokio::runtime::Handle::current);
        let metrics = BgpMetrics::new();
        let (rib, rib_rx) = mpsc::channel(4_096);
        let (query, query_rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rib_rx, query_rx, None, Some(CLUSTER), metrics.clone());
        if let Some(deferral) = deferral {
            manager = manager.with_selection_deferral(deferral);
        }
        Self {
            metrics,
            rib,
            _query: query,
            manager: daemon.spawn(manager.run()),
            daemon,
            receivers: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// Establish one receiver per `(families, export policy)`.
    async fn connect(&mut self, specs: Vec<ReceiverSpec>, deadline: Duration) -> Result<()> {
        self.connect_extended(specs, deadline, |_| false).await
    }

    /// [`Self::connect`], with the stubs at the indices `extended` picks
    /// (counted from the first of `specs`) advertising Extended Message.
    async fn connect_extended(
        &mut self,
        specs: Vec<ReceiverSpec>,
        deadline: Duration,
        extended: impl Fn(usize) -> bool,
    ) -> Result<()> {
        let mut pending = Vec::new();
        for (index, (families, policy)) in specs.into_iter().enumerate() {
            let ip = receiver_ip(self.receivers.len() + index);
            let socket = TcpSocket::new_v4()?;
            socket.set_recv_buffer_size(RECEIVER_RCVBUF)?;
            socket.bind(SocketAddr::new(IpAddr::V4(ip), 0))?;
            let listener = socket.listen(16)?;
            let address = listener.local_addr()?;
            let stub = StubConfig {
                listen: address,
                local_as: LOCAL_AS,
                router_id: ip,
                hold_time: HOLD_SECS,
                families: families.clone(),
                extended_message: extended(index),
            };
            let handshake =
                tokio::spawn(establish_on_with_read_hold(listener, stub, READ_HOLD_SECS));
            let guard = self.daemon.enter();
            let session = PeerHandle::spawn(
                transport_config(address, families),
                self.metrics.clone(),
                self.rib.clone(),
                None,
                policy,
                None,
                None,
                None,
                false,
            );
            drop(guard);
            session.start().await?;
            pending.push((ip, address, session, handshake));
        }
        let until = tokio::time::Instant::now() + deadline;
        for (ip, listen, session, handshake) in pending {
            let stub = tokio::time::timeout_at(until, handshake)
                .await
                .with_context(|| format!("receiver {ip}: handshake timed out"))???;
            loop {
                let state = session
                    .query_state_timeout(Duration::from_secs(5))
                    .await
                    .context("session state query failed")?;
                if state.fsm_state == SessionState::Established {
                    break;
                }
                ensure!(
                    tokio::time::Instant::now() < until,
                    "receiver {ip} did not establish: {:?}",
                    state.fsm_state
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            self.receivers.push(Receiver {
                ip,
                listen,
                session,
                io: stub.io_control,
                rx: Some(stub.rx),
                tasks: stub.tasks.into(),
                stub_tx: stub.tx,
            });
        }
        Ok(())
    }

    async fn set_paused(&mut self, range: std::ops::Range<usize>, paused: bool) -> Result<()> {
        for receiver in &mut self.receivers[range] {
            receiver.io.set_reads_paused(paused).await?;
        }
        Ok(())
    }

    /// Every receiver still Established; returns the ones that are not.
    async fn not_established(&self) -> Vec<String> {
        let mut down = Vec::new();
        for receiver in &self.receivers {
            match receiver
                .session
                .query_state_timeout(Duration::from_secs(5))
                .await
            {
                Some(state) if state.fsm_state == SessionState::Established => {}
                other => down.push(format!("{}: {other:?}", receiver.ip)),
            }
        }
        down
    }

    async fn close(self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut sessions = Vec::new();
        let mut tasks = vec![self.manager];
        for receiver in self.receivers {
            sessions.push(receiver.session);
            tasks.extend(receiver.tasks);
            drop(receiver.stub_tx);
        }
        drop(self.rib);
        let shutdown = crate::rr1000_support::shutdown(sessions, deadline).await;
        crate::rr1000_support::abort_and_join(tasks).await?;
        shutdown
    }
}

/// A metric's series, as `(labels, value)`.
type Series = Vec<(BTreeMap<String, String>, f64)>;

/// One gather of the registry, reduced to values: gathering is not free (it
/// merges allocator statistics), so every reading of one instant comes from
/// one snapshot.
struct Snapshot(Vec<(String, Series)>);

impl Snapshot {
    fn take(metrics: &BgpMetrics) -> Self {
        Self(
            metrics
                .registry()
                .gather()
                .iter()
                .map(|family| {
                    let series = family
                        .get_metric()
                        .iter()
                        .map(|metric| {
                            let labels = metric
                                .get_label()
                                .iter()
                                .map(|pair| (pair.name().to_string(), pair.value().to_string()))
                                .collect();
                            // Unset fields read as zero, so one sum covers both types.
                            let value =
                                metric.get_counter().get_value() + metric.get_gauge().get_value();
                            (labels, value)
                        })
                        .collect();
                    (family.name().to_string(), series)
                })
                .collect(),
        )
    }

    /// `None` when the arm has no such metric.
    fn series(&self, name: &str) -> Option<&Series> {
        self.0
            .iter()
            .find(|(family, _)| family == name)
            .map(|(_, series)| series)
    }

    fn total(&self, name: &str) -> Option<f64> {
        self.series(name)
            .map(|rows| rows.iter().map(|(_, value)| value).sum())
    }

    /// Credit refusals per peer label.
    fn credit_refusals(&self) -> BTreeMap<String, f64> {
        let mut refusals = BTreeMap::new();
        for (labels, value) in self
            .series("bgp_outbound_commit_refusals_total")
            .into_iter()
            .flatten()
        {
            if labels.get("reason").map(String::as_str) == Some("outbound_credit") {
                if let Some(peer) = labels.get("peer") {
                    *refusals.entry(peer.clone()).or_default() += value;
                }
            }
        }
        refusals
    }
}

fn peer_label(peer: Ipv4Addr) -> String {
    PeerId::from_ipv4(peer).label()
}

/// This process's cgroup v2 directory, when it is a scope with memory files.
fn cgroup() -> Option<PathBuf> {
    let line = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = line.lines().find_map(|line| line.strip_prefix("0::"))?;
    let directory = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    directory.join("memory.peak").exists().then_some(directory)
}

fn cgroup_value(name: &str) -> Option<String> {
    std::fs::read_to_string(cgroup()?.join(name))
        .ok()
        .map(|value| value.trim().to_string())
}

#[derive(Clone, Copy, Debug, Default)]
struct Jemalloc {
    allocated: Option<u64>,
    active: Option<u64>,
    resident: Option<u64>,
}

impl Jemalloc {
    /// The allocator gauges of one snapshot. The collector keeps a gauge at
    /// 0 until an epoch advance first succeeds, and a live jemalloc process
    /// never reads 0, so 0 is no reading.
    fn read(snapshot: &Snapshot) -> Self {
        let gauge = |name| {
            snapshot
                .total(name)
                .filter(|&bytes| bytes > 0.0)
                .map(|bytes| bytes as u64)
        };
        Self {
            allocated: gauge("jemalloc_allocated_bytes"),
            active: gauge("jemalloc_active_bytes"),
            resident: gauge("jemalloc_resident_bytes"),
        }
    }
}

/// One instrument sample.
#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    at_ms: f64,
    jemalloc: Jemalloc,
    credit_rows: f64,
    credit_bytes: Option<f64>,
    rss_kib: Option<u64>,
}

/// Peaks and samples of the instruments every arm has, plus the optional
/// credit-bytes gauge.
#[derive(Default)]
struct Instruments {
    samples: Vec<Sample>,
    peak_credit_rows: f64,
    peak_credit_bytes: Option<f64>,
    peak_operations_live: f64,
    peak_dirty_peers: f64,
    peak_jemalloc: Jemalloc,
    at_peak_rss: Option<Sample>,
    first_refusal_ms: Option<f64>,
    /// Whole-table operations live at the sample that first saw a refusal.
    operations_live_at_first_refusal: Option<f64>,
    all_refused_ms: Option<f64>,
    /// Whole-run maximum of each `bgp_rib_actor_slice_max_microseconds`
    /// stage over the sampler's reads, and how many reads it took.
    slice_max_us: BTreeMap<String, f64>,
    slice_reads: usize,
}

impl Instruments {
    fn observe_memory(&mut self, sample: Sample) {
        let peak = &mut self.peak_jemalloc;
        peak.allocated = peak.allocated.max(sample.jemalloc.allocated);
        peak.active = peak.active.max(sample.jemalloc.active);
        peak.resident = peak.resident.max(sample.jemalloc.resident);
        if sample.rss_kib > self.at_peak_rss.and_then(|previous| previous.rss_kib) {
            self.at_peak_rss = Some(sample);
        }
    }
}

/// Publish the RIB's since-render slice maxima, take one snapshot, and fold
/// the published maxima into `into`. Publishing resets the RIB's window, so
/// the harness publishes only here and keeps the whole-run maximum itself.
fn fold_slice_maxima(metrics: &BgpMetrics, into: &mut BTreeMap<String, f64>) -> Snapshot {
    metrics.publish_render_window_maxima();
    let snapshot = Snapshot::take(metrics);
    for (labels, value) in snapshot.series(SLICE_MAX).into_iter().flatten() {
        let stage = labels.get("stage").cloned().unwrap_or_default();
        let max = into.entry(stage).or_insert(0.0);
        *max = max.max(*value);
    }
    snapshot
}

/// Per label value: a histogram's sample count and cumulative buckets
/// `(upper bound in seconds, count)`.
type Buckets = BTreeMap<String, (u64, Vec<(f64, u64)>)>;

/// Keyed by `label`'s value, as `value/family` where the series also
/// carries a `family` label (a tree may label owed-drain steps by family).
fn buckets(metrics: &BgpMetrics, name: &str, label: &str) -> Buckets {
    let mut buckets = Buckets::new();
    for family in metrics.registry().gather() {
        if family.name() != name {
            continue;
        }
        for metric in family.get_metric() {
            let value = |name: &str| {
                metric
                    .get_label()
                    .iter()
                    .find(|pair| pair.name() == name)
                    .map(|pair| pair.value().to_string())
            };
            let mut key = value(label).unwrap_or_default();
            if let Some(family) = value("family").filter(|_| label != "family") {
                key = format!("{key}/{family}");
            }
            let histogram = metric.get_histogram();
            let edges = histogram
                .get_bucket()
                .iter()
                .map(|bucket| (bucket.upper_bound(), bucket.cumulative_count()))
                .collect();
            buckets.insert(key, (histogram.get_sample_count(), edges));
        }
    }
    buckets
}

/// Per label value observed between `before` and `after`: the count and
/// the bucket edges bracketing the longest observation, in ms. It is above
/// `above_ms` and at most `at_most_ms` (null past the top edge).
fn longest(before: &Buckets, after: &Buckets) -> Value {
    let mut out = serde_json::Map::new();
    for (key, (count, edges)) in after {
        let (base_count, base_edges) = before.get(key).cloned().unwrap_or_default();
        let observed = count - base_count;
        if observed == 0 {
            continue;
        }
        let within =
            |index: usize| edges[index].1 - base_edges.get(index).map_or(0, |&(_, count)| count);
        let first_full = (0..edges.len()).find(|&index| within(index) == observed);
        let above = first_full
            .unwrap_or(edges.len())
            .checked_sub(1)
            .map_or(0.0, |index| edges[index].0 * 1e3);
        out.insert(
            key.clone(),
            json!({
                "observations": observed,
                "above_ms": above,
                "at_most_ms": first_full.map(|index| edges[index].0 * 1e3),
            }),
        );
    }
    Value::Object(out)
}

/// Getter reads of the live-operation and credit-rows gauges, and reads of
/// the credit-bytes gauge where the tree exports it.
#[derive(Default)]
struct GaugeWatch {
    reads: usize,
    peak_operations_live: i64,
    peak_credit_rows: i64,
    operations_first_ms: Option<f64>,
    operations_last_ms: Option<f64>,
    credit_bytes_reads: usize,
    peak_credit_bytes: Option<f64>,
    /// `watched`, `not exported`, `exported after start` (the gauge was
    /// absent when the watch started, as a labeled family is until its
    /// first child, so nothing read it) or `failed` (the watch panicked).
    credit_bytes_watch: &'static str,
}

/// The credit-bytes gauge, where a tree exports it.
const CREDIT_BYTES: &str = "bgp_rib_outbound_credit_bytes";

/// Sets `stop` when dropped, so an early return or a canceled cell still
/// ends the blocking byte watch, which runtime shutdown would wait on.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Read both getters every `GAUGE_WATCH` until `stop`, and the credit-bytes
/// gauge beside them (`watch_credit_bytes`).
fn watch_gauges(
    metrics: BgpMetrics,
    t0: Instant,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<GaugeWatch> {
    tokio::spawn(async move {
        let mut watch = GaugeWatch::default();
        let mut tick = tokio::time::interval(GAUGE_WATCH);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let bytes = watch_credit_bytes(&metrics, &stop);
        while !stop.load(Ordering::Acquire) {
            tick.tick().await;
            let operations = metrics.rib_outbound_operations_live();
            watch.reads += 1;
            watch.peak_operations_live = watch.peak_operations_live.max(operations);
            watch.peak_credit_rows = watch
                .peak_credit_rows
                .max(metrics.rib_outbound_credit_rows());
            if operations > 0 {
                let at_ms = t0.elapsed().as_secs_f64() * 1e3;
                watch.operations_first_ms.get_or_insert(at_ms);
                watch.operations_last_ms = Some(at_ms);
            }
        }
        watch.credit_bytes_watch = match bytes {
            Some(bytes) => match bytes.await {
                Ok(read) => {
                    (watch.credit_bytes_reads, watch.peak_credit_bytes) = read;
                    "watched"
                }
                Err(_) => "failed",
            },
            None if Snapshot::take(&metrics).series(CREDIT_BYTES).is_some() => {
                "exported after start"
            }
            None => "not exported",
        };
        watch
    })
}

/// Read `bgp_rib_outbound_credit_bytes` every `GAUGE_WATCH` until `stop`,
/// where the tree exports it: `(reads, peak)`; `None` on a tree without it.
/// No tree this harness builds against has a getter for it on every arm,
/// so each read is a registry gather, over a millisecond on the reduced
/// shape; it runs on its own blocking thread so the getter reads keep
/// their period, back to back when a gather outlasts the period.
fn watch_credit_bytes(
    metrics: &BgpMetrics,
    stop: &Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<(usize, Option<f64>)>> {
    Snapshot::take(metrics).series(CREDIT_BYTES)?;
    let (metrics, stop) = (metrics.clone(), Arc::clone(stop));
    Some(tokio::task::spawn_blocking(move || {
        let (mut reads, mut peak) = (0, None::<f64>);
        while !stop.load(Ordering::Acquire) {
            let started = Instant::now();
            if let Some(value) = Snapshot::take(&metrics).total(CREDIT_BYTES) {
                peak = Some(peak.map_or(value, |peak| peak.max(value)));
            }
            reads += 1;
            std::thread::sleep(GAUGE_WATCH.saturating_sub(started.elapsed()));
        }
        (reads, peak)
    }))
}

/// The inbox round trips of one run.
#[derive(Default)]
struct RoundTrips {
    probes: usize,
    longest_ms: f64,
    /// When the longest one was sent, in ms from t0.
    longest_sent_ms: Option<f64>,
    /// The last probe got no reply within `cap`; `longest_ms` is its wait
    /// so far and probing stopped there.
    unfinished: bool,
}

/// Send one `QueryLocRibCount` every `ROUND_TRIP_EVERY` until `stop` and
/// keep the longest wait for its reply. Each probe waits at most `cap`, so
/// the task ends within `cap` of `stop` whether or not the RIB answers.
fn probe_round_trips(
    rib: mpsc::Sender<RibUpdate>,
    t0: Instant,
    stop: Arc<AtomicBool>,
    cap: Duration,
) -> tokio::task::JoinHandle<Result<RoundTrips>> {
    tokio::spawn(async move {
        let mut trips = RoundTrips::default();
        while !stop.load(Ordering::Acquire) {
            let sent = Instant::now();
            let (reply, count) = oneshot::channel();
            let probe = async {
                rib.send(RibUpdate::QueryLocRibCount { reply }).await?;
                count.await?;
                anyhow::Ok(())
            };
            let finished = tokio::time::timeout(cap, probe).await;
            let took = sent.elapsed().as_secs_f64() * 1e3;
            if took > trips.longest_ms {
                trips.longest_ms = took;
                trips.longest_sent_ms = Some(sent.duration_since(t0).as_secs_f64() * 1e3);
            }
            if finished.is_err() {
                trips.unfinished = true;
                break;
            }
            finished??;
            trips.probes += 1;
            tokio::time::sleep(ROUND_TRIP_EVERY).await;
        }
        Ok(trips)
    })
}

/// Sample the instruments until `stop`; watch `watched` peers' refusals.
fn sampler(
    metrics: BgpMetrics,
    start: Instant,
    watched: Vec<Ipv4Addr>,
    keep_samples: bool,
    period: Duration,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Instruments> {
    tokio::spawn(async move {
        let mut instruments = Instruments::default();
        let labels: Vec<_> = watched.iter().map(|&peer| peer_label(peer)).collect();
        let mut refused = vec![false; watched.len()];
        while !stop.load(Ordering::Acquire) {
            let at_ms = start.elapsed().as_secs_f64() * 1e3;
            let snapshot = fold_slice_maxima(&metrics, &mut instruments.slice_max_us);
            instruments.slice_reads += 1;
            let gauge = |name| snapshot.total(name).unwrap_or(0.0);
            let sample = Sample {
                at_ms,
                jemalloc: Jemalloc::read(&snapshot),
                credit_rows: gauge("bgp_rib_outbound_credit_rows"),
                credit_bytes: snapshot.total("bgp_rib_outbound_credit_bytes"),
                rss_kib: rss_kib().ok().map(|(rss, _)| rss),
            };
            instruments.peak_credit_rows = instruments.peak_credit_rows.max(sample.credit_rows);
            instruments.peak_credit_bytes =
                match (instruments.peak_credit_bytes, sample.credit_bytes) {
                    (Some(peak), Some(value)) => Some(peak.max(value)),
                    (peak, value) => peak.or(value),
                };
            instruments.peak_operations_live = instruments
                .peak_operations_live
                .max(gauge("bgp_rib_outbound_operations_live"));
            instruments.peak_dirty_peers = instruments
                .peak_dirty_peers
                .max(gauge("bgp_rib_outbound_dirty_peers"));
            instruments.observe_memory(sample);
            if instruments.all_refused_ms.is_none() && !watched.is_empty() {
                let refusals = snapshot.credit_refusals();
                for (index, label) in labels.iter().enumerate() {
                    if !refused[index] && refusals.get(label).copied().unwrap_or(0.0) > 0.0 {
                        refused[index] = true;
                        if instruments.first_refusal_ms.is_none() {
                            instruments.first_refusal_ms = Some(at_ms);
                            instruments.operations_live_at_first_refusal =
                                Some(gauge("bgp_rib_outbound_operations_live"));
                        }
                    }
                }
                if refused.iter().all(|&seen| seen) {
                    instruments.all_refused_ms = Some(at_ms);
                }
            }
            if keep_samples {
                instruments.samples.push(sample);
            }
            drop(snapshot);
            tokio::time::sleep(period).await;
        }
        instruments
    })
}

fn memory_json(instruments: &Instruments) -> Value {
    let (rss, hwm) = rss_kib().unwrap_or((0, 0));
    let peak = instruments.peak_jemalloc;
    let at = instruments.at_peak_rss.unwrap_or_default();
    json!({
        "cgroup": cgroup().map(|path| path.display().to_string()),
        "cgroup_memory_peak_bytes": cgroup_value("memory.peak").and_then(|value| value.parse::<u64>().ok()),
        "cgroup_memory_max": cgroup_value("memory.max"),
        "cgroup_swap_max": cgroup_value("memory.swap.max"),
        "cgroup_oom_kill": cgroup_value("memory.events").and_then(|events| {
            events.lines().find_map(|line| line.strip_prefix("oom_kill ").map(str::to_string))
        }),
        "vmrss_kib": rss,
        "vmhwm_kib": hwm,
        "peak_sampled_rss_kib": at.rss_kib,
        "peak_jemalloc_allocated_bytes": peak.allocated,
        "peak_jemalloc_active_bytes": peak.active,
        "peak_jemalloc_resident_bytes": peak.resident,
        "at_peak_sampled_rss": {
            "jemalloc_allocated_bytes": at.jemalloc.allocated,
            "jemalloc_active_bytes": at.jemalloc.active,
            "jemalloc_resident_bytes": at.jemalloc.resident,
        },
        "peak_credit_rows": instruments.peak_credit_rows,
        "peak_credit_bytes": instruments.peak_credit_bytes,
        "peak_operations_live": instruments.peak_operations_live,
        "peak_dirty_peers": instruments.peak_dirty_peers,
    })
}

/// Common sampler for cells that only need its memory report.
pub(super) struct MemorySampling {
    stop: StopOnDrop,
    task: tokio::task::JoinHandle<Instruments>,
}

impl MemorySampling {
    pub(super) fn start(metrics: BgpMetrics) -> Self {
        let stop = StopOnDrop(Arc::new(AtomicBool::new(false)));
        let task = sampler(
            metrics,
            Instant::now(),
            Vec::new(),
            false,
            SAMPLE,
            Arc::clone(&stop.0),
        );
        Self { stop, task }
    }

    pub(super) async fn finish(self) -> Result<Value> {
        drop(self.stop);
        Ok(memory_json(&self.task.await?))
    }
}

/// The summed credit gauge in its tree's unit: bytes where the byte gauge
/// exists, else rows.
fn credit_reading(sample: &Sample) -> f64 {
    sample.credit_bytes.unwrap_or(sample.credit_rows)
}

/// The healthy receiver's churn task and its stop flag.
type Churn = (Arc<AtomicBool>, tokio::task::JoinHandle<()>);

/// Churn-free readings of the summed credit gauge, in ms from `t0`.
struct Quiet {
    /// When the churn task had stopped.
    stopped: Instant,
    stopped_ms: f64,
    last_sequence: Option<u32>,
    /// When the last churn row before the stop had arrived.
    delivered: Option<Instant>,
    delivered_ms: Option<f64>,
    published_ms: Option<f64>,
    end_ms: f64,
    readings: Vec<f64>,
    /// Why the window has no evidence: a RIB wait reached `QUIET_CAP`.
    unavailable: Option<String>,
}

/// Stop the churn task by `deadline`. Past it, its send is waiting on a RIB
/// that stopped serving its channel: abort it and wait for the abort, so a
/// send that completes at the deadline cannot log a row after a restarted
/// task read its next sequence, and return false.
async fn stop_churn(churn: Churn, deadline: tokio::time::Instant) -> Result<bool> {
    let (stop, mut task) = churn;
    stop.store(true, Ordering::Release);
    if let Ok(joined) = tokio::time::timeout_at(deadline, &mut task).await {
        joined?;
        return Ok(true);
    }
    crate::rr1000_support::abort_and_join([task]).await?;
    Ok(false)
}

/// The healthy receiver's gap exclusion: from the later of the churn's stop
/// and its last row's delivery to the restart, so a slow delivery after the
/// stop stays in the gap; nothing when that row never arrived.
fn excluded_window(
    stopped: Instant,
    delivered: Option<Instant>,
    restarted: Instant,
) -> Option<(Instant, Instant)> {
    delivered.map(|delivered| (delivered.max(stopped), restarted))
}

/// `unaffected.quiet_excluded`, in ms from `t0`: null when the last churn
/// row before the window never arrived, and `unavailable`, never null, when
/// a RIB wait in the window reached its cap, so an unknown span cannot read
/// as nothing excluded.
fn quiet_excluded_json(quiet: &Quiet, excluded: Option<(Instant, Instant)>, t0: Instant) -> Value {
    let ms = |at: Instant| at.saturating_duration_since(t0).as_secs_f64() * 1e3;
    match (&quiet.unavailable, excluded) {
        (Some(why), _) => json!({"unavailable": why}),
        (None, Some((from, to))) => json!({
            "from_ms": ms(from),
            "to_ms": ms(to),
            "span_ms": to.saturating_duration_since(from).as_secs_f64() * 1e3,
        }),
        (None, None) => Value::Null,
    }
}

/// Stop the healthy receiver's churn, wait until its last row reached the
/// receiver, make the RIB republish its gauges, then read the summed credit
/// gauge until `until`. The RIB publishes the gauge once per turn and holds
/// it until its next turn, and the 20 ms churn is nearly every turn, so
/// outside this window nothing bounds how many samples carry the churn row
/// (README). The RIB waits end within `cap` of `until`, however late the
/// window starts; past it the window is unavailable and the cell goes on to
/// resume its readers.
#[expect(
    clippy::too_many_arguments,
    reason = "the window's churn, RIB, gauges, logs and time bounds are the caller's own state"
)]
async fn quiet_window(
    churn: Churn,
    rib: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    log: &Mutex<Vec<(u32, Instant)>>,
    received: &Mutex<ChurnState>,
    t0: Instant,
    until: Instant,
    cap: Duration,
) -> Result<Quiet> {
    let ms = |at: Instant| at.saturating_duration_since(t0).as_secs_f64() * 1e3;
    // Anchored to the window's end: a window that starts late, behind a
    // held read at its own cap, gets only what remains of `cap`.
    let cap_at = tokio::time::Instant::from_std(until) + cap;
    let unavailable = || {
        format!(
            "no RIB reply within {} ms of the window's end",
            cap.as_millis()
        )
    };
    let joined = stop_churn(churn, cap_at).await?;
    let stopped = Instant::now();
    let stopped_ms = ms(stopped);
    let last_sequence = log
        .lock()
        .expect("churn log")
        .last()
        .map(|&(sequence, _)| sequence);
    let delivered = loop {
        // A churn the cap stopped has no last row to wait for.
        if !joined {
            break None;
        }
        let arrived = last_sequence.is_none_or(|last| {
            received
                .lock()
                .expect("churn state")
                .arrivals
                .iter()
                .any(|&(sequence, _)| sequence >= last)
        });
        if arrived {
            break Some(Instant::now());
        }
        if Instant::now() >= until {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    let mut quiet = Quiet {
        stopped,
        stopped_ms,
        last_sequence,
        delivered,
        delivered_ms: delivered.map(ms),
        published_ms: None,
        end_ms: stopped_ms,
        readings: Vec::new(),
        unavailable: (!joined).then(unavailable),
    };
    if delivered.is_some() {
        let published = async {
            tokio::time::sleep(QUIET_SETTLE).await;
            published_credit_rows(rib, metrics).await
        };
        match tokio::time::timeout_at(cap_at, published).await {
            Ok(published) => {
                published?;
                quiet.published_ms = Some(ms(Instant::now()));
            }
            Err(_) => quiet.unavailable = Some(unavailable()),
        }
        while quiet.unavailable.is_none() && Instant::now() < until {
            let snapshot = Snapshot::take(metrics);
            let rows = snapshot
                .total("bgp_rib_outbound_credit_rows")
                .unwrap_or(0.0);
            quiet.readings.push(
                snapshot
                    .total("bgp_rib_outbound_credit_bytes")
                    .unwrap_or(rows),
            );
            tokio::time::sleep(QUIET_READ_EVERY).await;
        }
    }
    quiet.end_ms = ms(Instant::now());
    Ok(quiet)
}

/// Publish the RIB's gauges, then read the summed credit-rows gauge. Each
/// query is one RIB turn; the second is served only after the first turn
/// ended and the next began by publishing the gauges.
async fn published_credit_rows(rib: &mpsc::Sender<RibUpdate>, metrics: &BgpMetrics) -> Result<f64> {
    for _ in 0..2 {
        let (reply, count) = oneshot::channel();
        rib.send(RibUpdate::QueryLocRibCount { reply }).await?;
        count.await?;
    }
    Ok(Snapshot::take(metrics)
        .total("bgp_rib_outbound_credit_rows")
        .unwrap_or(0.0))
}

/// Bytes queued in the kernel on the established connections with an end
/// at one of `listeners` (the receiver stubs' listening addresses), from a
/// `/proc/net/tcp` table, and how many connection ends matched. The table
/// covers this process's whole network namespace, so connections are picked
/// by address and port, both ends: each end's send queue (written, not yet
/// acknowledged) plus receive queue (arrived, not yet read). On loopback
/// that is every written byte a paused reader has not read.
fn socket_queue_bytes(table: &str, listeners: &HashSet<SocketAddr>) -> Result<(u64, usize)> {
    let endpoint = |field: &str| -> Result<SocketAddr> {
        let (address, port) = field.split_once(':').context("tcp endpoint")?;
        let ip = Ipv4Addr::from(u32::from_str_radix(address, 16)?.to_le_bytes());
        Ok(SocketAddr::new(
            IpAddr::V4(ip),
            u16::from_str_radix(port, 16)?,
        ))
    };
    let (mut bytes, mut ends) = (0, 0);
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        ensure!(fields.len() > 4, "short /proc/net/tcp line: {line}");
        // State 01 is ESTABLISHED.
        let ours =
            listeners.contains(&endpoint(fields[1])?) || listeners.contains(&endpoint(fields[2])?);
        if fields[3] != "01" || !ours {
            continue;
        }
        let (tx, rx) = fields[4].split_once(':').context("tcp queues")?;
        bytes += u64::from_str_radix(tx, 16)? + u64::from_str_radix(rx, 16)?;
        ends += 1;
    }
    Ok((bytes, ends))
}

/// The longest the release cells' held read, its queries and their replies
/// included, may take. A RIB that stops serving its update channel would
/// otherwise hold the read, and the readers' resume behind it, forever; a
/// read at the cap is recorded as unavailable (bar 6 INVALID).
const HELD_READ_CAP: Duration = Duration::from_secs(5);

/// Rows the RIB has handed toward the paused burst receivers and they have
/// not read, read without the credit gauge: every receiver's Adj-RIB-Out
/// count of the burst family less the rows the receivers decoded. Unicast
/// asks `QueryAdvertisedCount` for every receiver at once (O(1) a private
/// peer: `AdjRibOut::len`); EVPN has no O(1) per-family count, so it reads
/// `QueryBmpPeerStats`, which walks every peer's Adj-RIB-Out in one turn.
/// Beside it, the credit gauge published before and after those queries,
/// the session writers' queued bytes and the kernel queues of the
/// receivers' connections (null when the table is unreadable or no
/// connection matches).
async fn held_snapshot(
    rib: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    receivers: &[(Ipv4Addr, SocketAddr)],
    family: Family,
    read: u64,
    t0: Instant,
) -> Result<Value> {
    let charged_before = published_credit_rows(rib, metrics).await?;
    let at = t0.elapsed();
    let mut advertised = 0;
    if family == Family::Unicast {
        let mut replies = Vec::with_capacity(receivers.len());
        for &(ip, _) in receivers {
            let (reply, count) = oneshot::channel();
            let peer = PeerId::from_ipv4(ip);
            rib.send(RibUpdate::QueryAdvertisedCount { peer, reply })
                .await?;
            replies.push(count);
        }
        for count in replies {
            advertised += u64::try_from(count.await?)?;
        }
    } else {
        let (reply, stats) = oneshot::channel();
        rib.send(RibUpdate::QueryBmpPeerStats { reply }).await?;
        let stats = stats.await?;
        for &(ip, _) in receivers {
            advertised += stats
                .adj_rib_out_post
                .get(&PeerId::from_ipv4(ip))
                .and_then(|counts| counts.iter().find(|(key, _)| *key == family.afi_safi()))
                .map_or(0, |&(_, count)| count);
        }
    }
    let charged_after = published_credit_rows(rib, metrics).await?;
    let writer = Snapshot::take(metrics)
        .total("bgp_outbound_writer_bytes")
        .unwrap_or(0.0);
    let listeners = receivers.iter().map(|&(_, listen)| listen).collect();
    let sockets = std::fs::read_to_string("/proc/self/net/tcp")
        .ok()
        .and_then(|table| socket_queue_bytes(&table, &listeners).ok())
        .filter(|&(_, ends)| ends > 0);
    Ok(json!({
        "at_ms": at.as_secs_f64() * 1e3,
        "advertised_rows": advertised,
        "read_rows": read,
        "charged_before": charged_before,
        "charged_after": charged_after,
        "writer_bytes": writer,
        "socket_bytes": sockets.map(|(bytes, _)| bytes),
        "socket_ends": sockets.map(|(_, ends)| ends),
    }))
}

/// `held_snapshot` within `cap`; past it, the read is unavailable and the
/// cell goes on to resume its readers.
async fn held_read(
    rib: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    receivers: &[(Ipv4Addr, SocketAddr)],
    family: Family,
    read: u64,
    t0: Instant,
    cap: Duration,
) -> Result<Value> {
    let snapshot = held_snapshot(rib, metrics, receivers, family, read, t0);
    match tokio::time::timeout(cap, snapshot).await {
        Ok(held) => held,
        Err(_) => Ok(json!({
            "unavailable": format!("no reply within {} ms", cap.as_millis()),
        })),
    }
}

/// The lowest and highest of `values`.
fn range(values: impl Iterator<Item = f64>) -> Option<(f64, f64)> {
    values.fold(None, |range, value| {
        Some(range.map_or((value, value), |(low, high): (f64, f64)| {
            (low.min(value), high.max(value))
        }))
    })
}

/// The exhaustion plateau: the sampler's samples from the first at or above
/// the churn-free minimum to the last taken before the readers' resume was
/// issued, together with the churn-free readings.
fn plateau_json(instruments: &Instruments, quiet: &Quiet, resume_issued_ms: f64) -> Value {
    let unit = if instruments.samples.iter().any(|s| s.credit_bytes.is_some()) {
        "bytes"
    } else {
        "rows"
    };
    let quiet_range = range(quiet.readings.iter().copied());
    let threshold = quiet_range.map(|(low, _)| low);
    let window: Vec<&Sample> = threshold.map_or_else(Vec::new, |threshold| {
        instruments
            .samples
            .iter()
            .filter(|s| s.at_ms < resume_issued_ms)
            .skip_while(|s| credit_reading(s) < threshold)
            .collect()
    });
    let range = range(
        window
            .iter()
            .map(|s| credit_reading(s))
            .chain(quiet.readings.iter().copied()),
    );
    json!({
        "unit": unit,
        "sample_interval_ms": SAMPLE.as_secs_f64() * 1e3,
        "threshold": threshold,
        "start_ms": window.first().map(|s| s.at_ms),
        "end_ms": window.last().map(|s| s.at_ms),
        "samples": window.len(),
        "samples_above_threshold": threshold.map(|threshold| {
            window.iter().filter(|s| credit_reading(s) > threshold).count()
        }),
        "min": range.map(|(low, _)| low),
        "max": range.map(|(_, high)| high),
        "resume_issued_ms": resume_issued_ms,
        "quiet": {
            "churn_stopped_ms": quiet.stopped_ms,
            "last_churn_sequence": quiet.last_sequence,
            "churn_delivered_ms": quiet.delivered_ms,
            "published_ms": quiet.published_ms,
            "end_ms": quiet.end_ms,
            "readings": quiet.readings.len(),
            "read_every_ms": QUIET_READ_EVERY.as_secs_f64() * 1e3,
            "min": threshold,
            "max": quiet_range.map(|(_, high)| high),
            "unavailable": quiet.unavailable,
        },
    })
}

/// A cell's outcome: every check its result records passed, so the exit
/// status never disagrees with the result file.
fn recorded_pass(result: &Value) -> bool {
    result["checks"].as_object().is_some_and(|checks| {
        !checks.is_empty() && checks.values().all(|v| v.as_bool() == Some(true))
    })
}

fn write_result(output: &Path, name: &str, value: &Value) -> Result<()> {
    std::fs::create_dir_all(output)?;
    let path = output.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(value)? + "\n")?;
    println!("{}", serde_json::to_string(value)?);
    eprintln!("wrote {}", path.display());
    Ok(())
}

/// A paused stub's read deadline runs from its last read before the pause,
/// which the daemon's KEEPALIVEs keep within `HOLD_SECS`, so the pause plus
/// that must stay inside the stub's `READ_HOLD_SECS`.
fn check_read_hold(pause: Duration) -> Result<()> {
    ensure!(
        pause + Duration::from_secs(HOLD_SECS.into()) < Duration::from_secs(READ_HOLD_SECS.into()),
        "a {pause:?} pause plus up to {HOLD_SECS} s since the last read must stay inside the \
         receivers' {READ_HOLD_SECS} s read hold"
    );
    Ok(())
}

/// Cells 2 and 3: the exhaustion cell and its unaffected peer, or the same
/// cell behind an RFC 4724 restart (cell 7). With `churn`, a restart run
/// also withdraws and re-announces a subset of the burst while the release
/// drains (`restart-churn`).
pub async fn exhaust(
    family: Family,
    trigger: Trigger,
    churn: bool,
    output: &Path,
    options: &Options,
) -> Result<bool> {
    ensure!(
        !churn || trigger == Trigger::Restart,
        "the churn variant follows a selection release"
    );
    let cell = if churn {
        "restart-churn"
    } else {
        trigger.cell()
    };
    ensure!(
        matches!(family, Family::Unicast | Family::Evpn),
        "exhaust and restart cover unicast and evpn only"
    );
    let wire_family = family.wire()?;
    let (receivers, rows, pause, deadline) = if options.reduced {
        (
            4,
            4_096,
            Duration::from_millis(500),
            Duration::from_secs(120),
        )
    } else {
        (150, 150_000, trigger.pause(), Duration::from_secs(900))
    };
    let pause = options.pause.unwrap_or(pause);
    check_read_hold(pause)?;
    let interval = trigger.interval(options.reduced);
    let burst_family = family.afi_safi();
    let restart = trigger == Trigger::Restart;
    let gr_families = if restart {
        vec![burst_family]
    } else {
        Vec::new()
    };
    let mut fixture = Fixture::start(
        options,
        restart.then(|| SelectionDeferralConfig {
            timeout: Duration::from_secs(3_600),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: PeerId::from_ipv4(SOURCE).into(),
                families: gr_families.clone(),
            }],
        }),
    );
    // A restarting source re-establishes first, so the gate is armed
    // before any receiver registers and every burst End-of-RIB is held.
    let source_rx = source_up(&fixture.rib, SOURCE, gr_families).await?;
    let churn_rx = source_up(&fixture.rib, CHURN_SOURCE, Vec::new()).await?;
    fixture.sources = vec![source_rx, churn_rx];
    let burst_policy = (family == Family::Unicast).then(private_unicast_policy);
    let mut specs: Vec<_> = (0..receivers)
        .map(|_| (vec![burst_family], burst_policy.clone()))
        .collect();
    specs.push((vec![(Afi::Ipv4, Safi::Unicast)], Some(healthy_policy())));
    fixture.connect(specs, Duration::from_secs(120)).await?;
    eprintln!(
        "{cell} {}: {} receivers established",
        family.name(),
        receivers + 1
    );
    let plan = churn.then(|| churn_plan(rows));
    let reference = Arc::new(match &plan {
        Some((withdrawn, reannounced)) => {
            Reference::churned(rows, BURST_VERSION, withdrawn, reannounced, CHURN_VERSION)
        }
        None => Reference::uniform(rows, BURST_VERSION),
    });
    let healthy = receivers;
    // Every outbound peer the RIB divides its credit among: the burst
    // receivers, the healthy one and the sources.
    let registered_peers = fixture.receivers.len() + fixture.sources.len();

    // Collectors: burst receivers check the table; the healthy one logs churn.
    let stop = watch::channel(false);
    let mut collectors = Vec::new();
    for receiver in &mut fixture.receivers[..receivers] {
        let mut rx = receiver.rx.take().expect("receiver stream");
        let mut stop_rx = stop.1.clone();
        let state = Arc::new(Mutex::new(WireState::with_reference(
            wire_family,
            Arc::clone(&reference),
        )));
        let shared = Arc::clone(&state);
        collectors.push((
            state,
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        message = rx.recv() => {
                            let now = Instant::now();
                            let mut state = shared.lock().expect("wire state");
                            match message {
                                Some(message) => state.apply(&message, now),
                                None => {
                                    state.closed();
                                    return;
                                }
                            }
                        }
                        _ = stop_rx.changed() => return,
                    }
                }
            }),
        ));
    }
    let churn_state = Arc::new(Mutex::new(ChurnState::default()));
    let churn_collector = {
        let mut rx = fixture.receivers[healthy]
            .rx
            .take()
            .expect("healthy stream");
        let mut stop_rx = stop.1.clone();
        let shared = Arc::clone(&churn_state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    message = rx.recv() => {
                        let now = Instant::now();
                        let mut state = shared.lock().expect("churn state");
                        match message {
                            Some(message) => state.apply(&message, now),
                            None => {
                                state.resets += 1;
                                return;
                            }
                        }
                    }
                    _ = stop_rx.changed() => return,
                }
            }
        })
    };

    // An ordinary burst follows each receiver's End-of-RIB, so nothing of
    // the session's start is left to deliver behind the paused reads.
    if !restart {
        let until = Instant::now() + Duration::from_secs(30);
        while !collectors
            .iter()
            .all(|(state, _)| state.lock().expect("wire state").eor_seen)
        {
            ensure!(Instant::now() < until, "a receiver got no End-of-RIB");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    // Burst receivers pause their socket reads, acknowledged, before the burst.
    fixture.set_paused(0..receivers, true).await?;
    // Setup's slice maxima and turn histograms, so the run's own start at t0.
    let mut setup_slices = BTreeMap::new();
    drop(fold_slice_maxima(&fixture.metrics, &mut setup_slices));
    let histograms_before: Vec<Buckets> = TURN_HISTOGRAMS
        .iter()
        .map(|(name, label)| buckets(&fixture.metrics, name, label))
        .collect();
    let t0 = Instant::now();
    let watched: Vec<_> = fixture.receivers[..receivers]
        .iter()
        .map(|r| r.ip)
        .collect();
    let sampling = Arc::new(AtomicBool::new(false));
    let instruments = sampler(
        fixture.metrics.clone(),
        t0,
        watched.clone(),
        true,
        SAMPLE,
        Arc::clone(&sampling),
    );
    // The healthy receiver's churn runs until the cell ends, apart from the
    // churn-free window; a restarted task continues the sequence.
    let churn_log = Arc::new(Mutex::new(Vec::<(u32, Instant)>::new()));
    let rib = fixture.rib.clone();
    let start_churn = || -> Churn {
        let rib = rib.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let log = Arc::clone(&churn_log);
        let task = tokio::spawn(async move {
            let last = log
                .lock()
                .expect("churn log")
                .last()
                .map(|&(sequence, _)| sequence);
            let mut sequence = last.map_or(1, |last| last + 1);
            let mut tick = tokio::time::interval(CHURN_EVERY);
            while !task_stop.load(Ordering::Acquire) {
                tick.tick().await;
                let sent = Instant::now();
                if rib.send(churn_update(sequence)).await.is_err() {
                    return;
                }
                log.lock().expect("churn log").push((sequence, sent));
                sequence += 1;
            }
        });
        (stop, task)
    };
    // An ordinary burst is paced, so the churn runs beside it from its
    // first UPDATE. A restart's churn starts behind the release in the
    // RIB's queue, so the gate never holds it.
    let mut churn = (!restart).then(start_churn);
    for start in (0..rows).step_by(CHUNK) {
        if start != 0 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
        fixture
            .rib
            .send(source_update(
                family,
                start..(start + CHUNK).min(rows),
                BURST_VERSION,
                100,
            ))
            .await?;
    }
    if restart {
        fixture
            .rib
            .send(RibUpdate::EndOfRib {
                peer: PeerId::from_ipv4(SOURCE),
                session_id: 1,
                afi: burst_family.0,
                safi: burst_family.1,
            })
            .await?;
    }
    // When the burst's last UPDATE (a restart's End-of-RIB) was sent.
    let release_sent = t0.elapsed();
    eprintln!("burst sent at {release_sent:?}");
    let watching = Arc::new(AtomicBool::new(false));
    let _stop_watching = StopOnDrop(Arc::clone(&watching));
    let gauges = watch_gauges(fixture.metrics.clone(), t0, Arc::clone(&watching));
    let probing = Arc::new(AtomicBool::new(false));
    let round_trips = probe_round_trips(
        fixture.rib.clone(),
        t0,
        Arc::clone(&probing),
        ROUND_TRIP_CAP,
    );
    let window_start = if restart { t0 + release_sent } else { t0 };
    let churn = churn.take().unwrap_or_else(start_churn);

    // The churn variant: halfway to the churn-free window, with the release
    // queued ahead of it and every burst reader still paused, withdraw the
    // planned subset and re-announce half of it at a new version.
    let burst_churn = match &plan {
        Some((withdrawn, reannounced)) => {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                t0 + pause.saturating_sub(QUIET_LEAD) / 2,
            ))
            .await;
            let started = t0.elapsed();
            for chunk in withdrawn.chunks(CHUNK) {
                fixture.rib.send(source_withdrawal(family, chunk)).await?;
            }
            for chunk in reannounced.chunks(CHUNK) {
                let indices = chunk.iter().copied();
                fixture
                    .rib
                    .send(source_update(family, indices, CHURN_VERSION, 100))
                    .await?;
            }
            Some((started, t0.elapsed()))
        }
        None => None,
    };

    tokio::time::sleep_until(tokio::time::Instant::from_std(
        t0 + pause.saturating_sub(QUIET_LEAD),
    ))
    .await;
    // A release cell's held payload, read with every burst reader paused.
    let held = if restart {
        let ends: Vec<_> = fixture.receivers[..receivers]
            .iter()
            .map(|r| (r.ip, r.listen))
            .collect();
        let read = collectors
            .iter()
            .map(|(state, _)| {
                let state = state.lock().expect("wire state");
                state.announced + state.withdrawals
            })
            .sum();
        let (metrics, cap) = (&fixture.metrics, HELD_READ_CAP);
        Some(held_read(&rib, metrics, &ends, family, read, t0, cap).await?)
    } else {
        None
    };
    let quiet = quiet_window(
        churn,
        &rib,
        &fixture.metrics,
        &churn_log,
        &churn_state,
        t0,
        t0 + pause,
        QUIET_CAP,
    )
    .await?;
    // The churn-free window ends where the churn restarts.
    let restarted = Instant::now();
    let churn = start_churn();
    let resume_issued = t0.elapsed();
    fixture.set_paused(0..receivers, false).await?;
    let resumed = t0.elapsed();
    eprintln!("readers resumed at {resumed:?}");

    // Settled: every burst receiver exact at once; then a quiet period.
    let until = t0 + deadline;
    let settled = loop {
        let all = collectors
            .iter()
            .all(|(state, _)| state.lock().expect("wire state").exact());
        if all {
            break Some(t0.elapsed());
        }
        if Instant::now() >= until {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    eprintln!("settled at {settled:?}");
    probing.store(true, Ordering::Release);
    let round_trips_to = t0.elapsed();
    let round_trips = round_trips.await??;
    tokio::time::sleep(QUIET).await;
    let end = Instant::now();
    if !stop_churn(churn, tokio::time::Instant::now() + QUIET_CAP).await? {
        eprintln!("churn stop unfinished within {QUIET_CAP:?}: the RIB is not serving its channel");
    }
    sampling.store(true, Ordering::Release);
    watching.store(true, Ordering::Release);
    let gauges_to = t0.elapsed();
    let mut instruments = instruments.await?;
    let gauges = gauges.await?;
    // The cell-end read: slices that completed after the sampler's last.
    drop(fold_slice_maxima(
        &fixture.metrics,
        &mut instruments.slice_max_us,
    ));
    instruments.slice_reads += 1;
    let turn_longest: Vec<Value> = TURN_HISTOGRAMS
        .iter()
        .zip(&histograms_before)
        .map(|((name, label), before)| {
            let after = buckets(&fixture.metrics, name, label);
            // A tree without the metric has no instrument: null, not `{}`.
            if after.is_empty() {
                Value::Null
            } else {
                longest(before, &after)
            }
        })
        .collect();
    let down = fixture.not_established().await;
    let _ = stop.0.send(true);
    for (_, collector) in &mut collectors {
        collector.await?;
    }
    churn_collector.await?;

    let snapshot = Snapshot::take(&fixture.metrics);
    let refusals = snapshot.credit_refusals();
    let refused_by = |ip: &Ipv4Addr| refusals.get(&peer_label(*ip)).copied().unwrap_or(0.0);
    // Recovery is the latest settle time of any receiver, so a receiver that
    // settled, lost a route and settled again counts its last settle.
    let mut rows_json = Vec::new();
    let (mut exact, mut ordered, mut missing, mut after_eor, mut resets) = (0, 0, 0, 0, 0);
    let (mut survivors, mut churned_after_eor, mut duplicates) = (0, 0, 0);
    let (mut row_bytes, mut rows_per_update): (Option<(u64, u64)>, u64) = (None, 0);
    let mut reflected = Vec::new();
    let mut latest = Duration::ZERO;
    // The first and last receiver's End-of-RIB, from t0.
    let mut eors: Option<(Duration, Duration)> = None;
    for ((state, _), ip) in collectors.iter().zip(&watched) {
        let state = state.lock().expect("wire state");
        exact += usize::from(state.exact());
        ordered += usize::from(trigger.eor_ordered(&state));
        missing += state.missing();
        after_eor += state.routes_after_eor;
        survivors += state.withdrawn_survivors();
        churned_after_eor += state.churned_after_eor;
        duplicates += state.duplicates_before_eor;
        if let Some((min, max)) = state.row_bytes {
            let (low, high) = row_bytes.unwrap_or((min, max));
            row_bytes = Some((low.min(min), high.max(max)));
        }
        rows_per_update = rows_per_update.max(state.max_rows_per_update);
        reflected.push(state.churn_reflected_before_eor);
        resets += state.resets;
        if let Some(at) = state.settled_at {
            latest = latest.max(at.saturating_duration_since(t0));
        }
        if let Some(at) = state.eor_at.map(|at| at.saturating_duration_since(t0)) {
            eors = Some(eors.map_or((at, at), |(first, last)| (first.min(at), last.max(at))));
        }
        rows_json.push(json!({
            "peer": ip.to_string(),
            "exact": state.exact(),
            "missing": state.missing(),
            "withdrawn_survivors": state.withdrawn_survivors(),
            "eor_seen": state.eor_seen,
            "eor_premature": state.eor_premature,
            "routes_after_eor": state.routes_after_eor,
            "churned_after_eor": state.churned_after_eor,
            "churn_reflected_before_eor": state.churn_reflected_before_eor,
            "duplicates_before_eor": state.duplicates_before_eor,
            "routes_before_eor": state.routes_before_eor,
            "eors": state.eors,
            "announced": state.announced,
            "withdrawals": state.withdrawals,
            "outside": state.outside,
            "decode_failures": state.decode_failures,
            "min_row_bytes": state.row_bytes.map(|(min, _)| min),
            "max_row_bytes": state.row_bytes.map(|(_, max)| max),
            "max_rows_per_update": state.max_rows_per_update,
            "resets": state.resets,
            "credit_refusals": refused_by(ip),
        }));
    }
    let (arrivals, churn_resets) = {
        let state = churn_state.lock().expect("churn state");
        (state.arrivals.clone(), state.resets)
    };
    let injected = churn_log.lock().expect("churn log").clone();
    let excluded = excluded_window(quiet.stopped, quiet.delivered, restarted);
    let unaffected = delivery(&injected, &arrivals, window_start, end, excluded);
    let refused_peers = watched.iter().filter(|ip| refused_by(ip) > 0.0).count();
    let healthy_ip = fixture.receivers[healthy].ip;
    let flaps = snapshot.total("bgp_session_flaps_total");
    let ms = |duration: Duration| duration.as_secs_f64() * 1e3;
    // The healthy receiver's session counts too.
    let resets = resets + churn_resets;
    let burst_churn = match (&plan, burst_churn) {
        (Some((withdrawn, reannounced)), Some((started, sent))) => json!({
            "rule": format!(
                "every {CHURN_NTH}th burst route withdrawn, every other one of those \
                 re-announced at MED {CHURN_VERSION}, sent at (pause - churn-free lead) / 2 \
                 while the burst readers are paused"
            ),
            "withdrawn": withdrawn.len(),
            "re_announced": reannounced.len(),
            "started_ms": ms(started),
            "sent_ms": ms(sent),
        }),
        _ => Value::Null,
    };
    let actor = json!({
        "read_every_ms": ms(SAMPLE),
        "reads": instruments.slice_reads,
        "window": "t0 (readers paused, before the burst) to the cell end",
        "slice_max_us": instruments.slice_max_us,
        "setup_slice_max_us": setup_slices,
        "turn_longest_ms": turn_longest[0],
        "work_longest_ms": turn_longest[1],
        "owed_drain_step_longest_ms": turn_longest[2],
        "eviction_recovery_longest_ms": turn_longest[3],
        "inbox_round_trip": {
            "from_ms": ms(release_sent),
            "to_ms": ms(round_trips_to),
            "every_ms": ms(ROUND_TRIP_EVERY),
            "probes": round_trips.probes,
            "longest_ms": round_trips.longest_ms,
            "longest_sent_ms": round_trips.longest_sent_ms,
            "unfinished": round_trips.unfinished,
            "cap_ms": ms(ROUND_TRIP_CAP),
        },
    });
    let drain_gauges = json!({
        "from_ms": ms(release_sent),
        "to_ms": ms(gauges_to),
        "read_every_ms": ms(GAUGE_WATCH),
        "reads": gauges.reads,
        "peak_operations_live": gauges.peak_operations_live,
        "operations_live_first_ms": gauges.operations_first_ms,
        "operations_live_last_ms": gauges.operations_last_ms,
        "peak_credit_rows": gauges.peak_credit_rows,
        // Null on a tree without `bgp_rib_outbound_credit_bytes`.
        "peak_credit_bytes": gauges.peak_credit_bytes,
        "credit_bytes_reads": gauges.credit_bytes_reads,
        "credit_bytes_watch": gauges.credit_bytes_watch,
    });
    let result = json!({
        "schema": "rrtransport-credit/1",
        "cell": cell,
        "family": family.name(),
        "mode": if options.correctness_only { "correctness" } else { "measured" },
        "shape": {
            "receivers": receivers,
            "rows_per_receiver": rows,
            "pause_ms": ms(pause),
            "chunk_rows": CHUNK,
            "burst_interval_ms": ms(interval),
            "trigger": trigger.name(),
            "registered_peers": registered_peers,
            "receiver_rcvbuf_bytes": RECEIVER_RCVBUF,
        },
        "row_size_of": family.row_size_of(),
        "row_credit": ROW_CREDIT.iter().copied().collect::<BTreeMap<_, _>>(),
        // The healthy receiver's churn row, which the summed credit gauge
        // may hold on top of the burst receivers'.
        "healthy_row_size_of": Family::Unicast.row_size_of(),
        "timing": {
            "release_sent_ms": ms(release_sent),
            "resumed_ms": ms(resumed),
            // From t0, when every burst reader had acknowledged its pause,
            // to every reader's acknowledged resume: longer than
            // `shape.pause_ms` when burst submission ran past the deadline.
            "actual_pause_ms": ms(resumed),
            "settled_ms": settled.map(ms),
            "recovery_ms": settled.map(|_| ms(latest)),
            "drain_after_resume_ms": settled.map(|_| ms(latest.saturating_sub(resumed))),
            "first_eor_ms": eors.map(|(first, _)| ms(first)),
            "last_eor_ms": eors.map(|(_, last)| ms(last)),
        },
        "churn": burst_churn,
        "actor": actor,
        "drain_gauges": drain_gauges,
        "checks": {
            "final_state_exact": exact == receivers,
            trigger.eor_check(): ordered == receivers,
            "no_session_resets": resets == 0 && down.is_empty(),
        },
        "wire": {
            "exact_receivers": exact,
            "missing_routes": missing,
            "routes_after_eor": after_eor,
            "withdrawn_survivors": survivors,
            "churned_after_eor": churned_after_eor,
            // Per burst receiver, at its End-of-RIB (null without one).
            "churn_reflected_before_eor": reflected,
            "duplicates_before_eor": duplicates,
            // The fewest and most wire bytes per announced burst row, and
            // the most announced rows in one UPDATE, on any receiver.
            "min_row_bytes": row_bytes.map(|(min, _)| min),
            "max_row_bytes": row_bytes.map(|(_, max)| max),
            "max_rows_per_update": rows_per_update,
            "stub_resets": resets,
            "not_established": down,
            "session_flaps_total": flaps,
        },
        "witness": {
            // What an analyzer may count as exhaustion. Owe-whole flips and
            // credit refusals are context only: a selection release flips
            // every private receiver with no credit spent, and a live
            // whole-table operation is refused for the same reason.
            "signals": [
                "plateau of bgp_rib_outbound_credit_bytes (bgp_rib_outbound_credit_rows on a \
                 tree without it), summed over peers, before the readers resume: its minimum, \
                 churn-free readings included, equal to receivers x ceil(per-peer credit at \
                 shape.registered_peers / row) x row, the churn-free minimum equal to it, and \
                 its maximum at most one healthy row above it",
            ],
            "plateau": plateau_json(&instruments, &quiet, ms(resume_issued)),
            "peak_credit_rows": instruments.peak_credit_rows,
            "peak_credit_bytes": instruments.peak_credit_bytes,
            "refused_receivers": refused_peers,
            "outbound_route_drops_total": snapshot.total("bgp_outbound_route_drops_total"),
            "receivers": receivers,
            "healthy_receiver_refusals": refused_by(&healthy_ip),
            "first_refusal_ms": instruments.first_refusal_ms,
            "operations_live_at_first_refusal": instruments.operations_live_at_first_refusal,
            "all_refused_ms": instruments.all_refused_ms,
            "owing_flips_total": snapshot.total("bgp_rib_outbound_owing_flips_total"),
            "owing_fallback_total": snapshot.total("bgp_rib_outbound_owing_fallback_total"),
            "held": held,
        },
        "unaffected": {
            "injected": unaffected.injected,
            "delivered": unaffected.delivered,
            // Less the harness's own churn-free window, counted in the raw one.
            "max_gap_ms": ms(unaffected.max_gap),
            "max_gap_raw_ms": ms(unaffected.max_gap_raw),
            "quiet_excluded": quiet_excluded_json(&quiet, excluded, t0),
            "quiet_lead_ms": ms(QUIET_LEAD),
            "p50_latency_ms": ms(unaffected.p50),
            "p99_latency_ms": ms(unaffected.p99),
            "max_latency_ms": ms(unaffected.max),
            "resets": churn_resets,
        },
        "memory": memory_json(&instruments),
        "receivers": rows_json,
    });
    write_result(output, &format!("{cell}-{}.json", family.name()), &result)?;
    fixture.close().await?;
    Ok(recorded_pass(&result))
}

/// Cell 1 (and its instruments): every private EVPN receiver paused while
/// one source re-announces its whole table each round, flipping
/// `LOCAL_PREF`.
pub async fn paused(output: &Path, options: &Options) -> Result<bool> {
    let (receivers, rows, seconds) = if options.reduced {
        (4, 2_000, 4)
    } else {
        (150, 37_500, 240)
    };
    let seconds = options.seconds.unwrap_or(seconds);
    let round = Duration::from_secs(2);
    let mut fixture = Fixture::start(options, None);
    fixture.sources = vec![source_up(&fixture.rib, SOURCE, Vec::new()).await?];
    let specs = (0..receivers)
        .map(|_| (vec![(Afi::L2Vpn, Safi::Evpn)], None))
        .collect();
    fixture.connect(specs, Duration::from_secs(120)).await?;
    // Drain initial EoRs, then keep each stream open but unread.
    let streams: Vec<_> = fixture
        .receivers
        .iter_mut()
        .map(|receiver| receiver.rx.take().expect("receiver stream"))
        .collect();
    fixture.set_paused(0..receivers, true).await?;
    let t0 = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let instruments = sampler(
        fixture.metrics.clone(),
        t0,
        Vec::new(),
        false,
        SAMPLE,
        Arc::clone(&stop),
    );
    let mut rounds = 0_u32;
    while t0.elapsed() < Duration::from_secs(seconds) {
        let started = Instant::now();
        let local_pref = 100 + rounds % 2;
        for start in (0..rows).step_by(CHUNK) {
            fixture
                .rib
                .send(source_update(
                    Family::Evpn,
                    start..(start + CHUNK).min(rows),
                    BURST_VERSION,
                    local_pref,
                ))
                .await?;
        }
        rounds += 1;
        tokio::time::sleep_until(tokio::time::Instant::from_std(started + round)).await;
    }
    stop.store(true, Ordering::Release);
    let instruments = instruments.await?;
    let down = fixture.not_established().await;
    let result = json!({
        "schema": "rrtransport-credit/1",
        "cell": "paused",
        "family": "evpn",
        "mode": if options.correctness_only { "correctness" } else { "measured" },
        "shape": {"receivers": receivers, "routes": rows, "rounds": rounds, "round_ms": 2_000, "seconds": seconds},
        "row_size_of": Family::Evpn.row_size_of(),
        "checks": {"no_session_resets": down.is_empty()},
        "not_established": down,
        "memory": memory_json(&instruments),
    });
    write_result(output, "paused-evpn.json", &result)?;
    drop(streams);
    fixture.close().await?;
    Ok(recorded_pass(&result))
}

/// Least-squares slope of `y` over `x`, with its standard error.
fn slope(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = points.len() as f64;
    if points.len() < 3 {
        return None;
    }
    let (mx, my) = (
        points.iter().map(|p| p.0).sum::<f64>() / n,
        points.iter().map(|p| p.1).sum::<f64>() / n,
    );
    let sxx: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx == 0.0 {
        return None;
    }
    let sxy: f64 = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    let b = sxy / sxx;
    let residual: f64 = points
        .iter()
        .map(|p| (p.1 - my - b * (p.0 - mx)).powi(2))
        .sum();
    Some((b, (residual / (n - 2.0) / sxx).sqrt()))
}

/// Cell 6: bytes per queued row of one family, report-only.
pub async fn fill(family: Family, output: &Path, options: &Options) -> Result<bool> {
    let (receivers, rows) = if options.reduced {
        (4, 8_192)
    } else {
        (150, 150_000)
    };
    let mut fixture = Fixture::start(options, None);
    fixture.sources = vec![source_up(&fixture.rib, SOURCE, Vec::new()).await?];
    // Unicast and VPN group by default; the peer-context policy keeps them private.
    let policy = matches!(family, Family::Unicast | Family::Vpn).then(private_unicast_policy);
    let specs = (0..receivers)
        .map(|_| (vec![family.afi_safi()], policy.clone()))
        .collect();
    fixture.connect(specs, Duration::from_secs(120)).await?;
    let streams: Vec<_> = fixture
        .receivers
        .iter_mut()
        .map(|receiver| receiver.rx.take().expect("receiver stream"))
        .collect();
    fixture.set_paused(0..receivers, true).await?;
    let watched: Vec<_> = fixture.receivers.iter().map(|r| r.ip).collect();
    let t0 = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let instruments = sampler(
        fixture.metrics.clone(),
        t0,
        watched,
        true,
        FIT_SAMPLE,
        Arc::clone(&stop),
    );
    for start in (0..rows).step_by(CHUNK) {
        fixture
            .rib
            .send(source_update(
                family,
                start..(start + CHUNK).min(rows),
                BURST_VERSION,
                100,
            ))
            .await?;
    }
    // Let the RIB stage what it will while every reader stays paused: until
    // neither the credit-rows gauge nor allocated bytes (which also move
    // inside one long RIB unit, when the gauge is not sampled) change for 5 s.
    let mut last = (-1.0, 0.0);
    let mut steady = 0;
    while steady < 50 && t0.elapsed() < Duration::from_secs(600) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let snapshot = Snapshot::take(&fixture.metrics);
        let now = (
            snapshot
                .total("bgp_rib_outbound_credit_rows")
                .unwrap_or(0.0),
            snapshot.total("jemalloc_allocated_bytes").unwrap_or(0.0),
        );
        let quiet = (now.0 - last.0).abs() < f64::EPSILON && (now.1 - last.1).abs() < 1_048_576.0;
        steady = if quiet { steady + 1 } else { 0 };
        if !quiet {
            last = now;
        }
    }
    stop.store(true, Ordering::Release);
    let instruments = instruments.await?;
    // The fit window: credit rows rising, before any refusal, between 10%
    // and 90% of the pre-refusal peak.
    let cutoff = instruments.first_refusal_ms.unwrap_or(f64::INFINITY);
    let before: Vec<_> = instruments
        .samples
        .iter()
        .filter(|sample| sample.at_ms < cutoff)
        .collect();
    let peak = before.iter().map(|s| s.credit_rows).fold(0.0, f64::max);
    let points: Vec<_> = before
        .iter()
        .filter(|s| s.credit_rows >= 0.1 * peak && s.credit_rows <= 0.9 * peak)
        .filter_map(|s| Some((s.credit_rows, s.jemalloc.allocated? as f64)))
        .collect();
    let fit = slope(&points);
    let result = json!({
        "schema": "rrtransport-credit/1",
        "cell": "fill",
        "family": family.name(),
        "mode": if options.correctness_only { "correctness" } else { "measured" },
        "shape": {"receivers": receivers, "rows_per_receiver": rows},
        "row_size_of": family.row_size_of(),
        "estimate": {
            "method": "least-squares slope of jemalloc allocated bytes over bgp_rib_outbound_credit_rows, \
                       sampled every 50 ms with every reader paused, before the first credit refusal, \
                       between 10% and 90% of the pre-refusal credit-rows peak",
            "points": points.len(),
            "bytes_per_queued_row": fit.map(|f| f.0),
            "stderr": fit.map(|f| f.1),
            "pre_refusal_peak_credit_rows": peak,
        },
        "witness": {"first_refusal_ms": instruments.first_refusal_ms},
        "memory": memory_json(&instruments),
    });
    write_result(output, &format!("fill-{}.json", family.name()), &result)?;
    drop(streams);
    fixture.close().await?;
    // A reduced shape may never queue enough rows to fit; it checks plumbing.
    Ok(fit.is_some() || options.reduced)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use std::time::Instant;

    use std::time::Duration;

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use rustbgpd_rib::update::RibUpdate;

    use std::sync::Mutex;

    use super::{
        attributes, buckets, check_read_hold, churn_plan, fold_slice_maxima, held_read, longest,
        quiet_excluded_json, quiet_window, recorded_pass, socket_queue_bytes, source_withdrawal,
        stop_churn, watch_credit_bytes, watch_gauges, Buckets, Churn, Family, Options, Snapshot,
        StopOnDrop, Trigger, CREDIT_BYTES, HELD_READ_CAP, QUIET_CAP, QUIET_LEAD, SLICE_MAX,
        TURN_HISTOGRAMS,
    };
    use crate::credit_wire::{Observed, WireFamily, WireState};

    fn parse(args: &[&str]) -> Options {
        Options::parse(&args.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn allocator_peaks_and_first_peak_rss_sample_are_independent() {
        let mut instruments = super::Instruments::default();
        for (rss_kib, allocated, active, resident) in [
            (Some(16), 600, 750, 900),
            (Some(20), 400, 725, 850),
            (Some(20), 425, 800, 880),
            (None, 450, 775, 950),
        ] {
            instruments.observe_memory(super::Sample {
                rss_kib,
                jemalloc: super::Jemalloc {
                    allocated: Some(allocated),
                    active: Some(active),
                    resident: Some(resident),
                },
                ..Default::default()
            });
        }
        let memory = super::memory_json(&instruments);
        assert_eq!(memory["peak_sampled_rss_kib"], 20);
        assert_eq!(memory["peak_jemalloc_allocated_bytes"], 600);
        assert_eq!(memory["peak_jemalloc_active_bytes"], 800);
        assert_eq!(memory["peak_jemalloc_resident_bytes"], 950);
        assert_eq!(
            memory["at_peak_sampled_rss"],
            json!({
                "jemalloc_allocated_bytes": 400,
                "jemalloc_active_bytes": 725,
                "jemalloc_resident_bytes": 850,
            })
        );
        let empty = super::memory_json(&super::Instruments::default());
        assert!(empty["peak_sampled_rss_kib"].is_null());
        assert!(empty["at_peak_sampled_rss"]["jemalloc_allocated_bytes"].is_null());
    }

    #[test]
    fn each_allocator_reading_comes_from_its_own_gauge_and_zero_is_no_reading() {
        let snapshot = |values: [f64; 4]| {
            let names = [
                "jemalloc_allocated_bytes",
                "jemalloc_active_bytes",
                "jemalloc_resident_bytes",
                "jemalloc_mapped_bytes",
            ];
            super::Snapshot(
                names
                    .iter()
                    .zip(values)
                    .map(|(name, value)| (name.to_string(), vec![(BTreeMap::new(), value)]))
                    .collect(),
            )
        };
        let read = super::Jemalloc::read(&snapshot([100.0, 200.0, 300.0, 400.0]));
        assert_eq!(
            (read.allocated, read.active, read.resident),
            (Some(100), Some(200), Some(300))
        );
        // The collector's gauges before any epoch advance succeeded.
        let never = super::Jemalloc::read(&snapshot([0.0; 4]));
        assert_eq!(
            (never.allocated, never.active, never.resident),
            (None, None, None)
        );
        let absent = super::Jemalloc::read(&super::Snapshot(Vec::new()));
        assert_eq!(absent.allocated, None);
    }

    #[test]
    fn socket_queues_sum_both_ends_of_the_receivers_connections_only() {
        // The stub listens on 127.10.1.1:179; its session runs to
        // 127.0.0.1:40000, both ends established (01). A listener (0A), the
        // same receiver address on another port (another process's
        // connection in the namespace) and an unrelated connection do not
        // count.
        let table = [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when",
            "   0: 01010A7F:00B3 0100007F:9C40 01 00000010:00000020 00:00000000",
            "   1: 0100007F:9C40 01010A7F:00B3 01 00000100:00000000 00:00000000",
            "   2: 01010A7F:00B3 00000000:0000 0A 00000005:00000005 00:00000000",
            "   3: 01010A7F:00B4 0100007F:9C41 01 00002000:00002000 00:00000000",
            "   4: 0100007F:1F90 0200007F:9C42 01 00001000:00001000 00:00000000",
        ]
        .join("\n");
        let listen = "127.10.1.1:179".parse().unwrap();
        let listeners = [listen].into_iter().collect();
        assert_eq!(
            socket_queue_bytes(&table, &listeners).unwrap(),
            (0x10 + 0x20 + 0x100, 2)
        );
        // No listener matched: zero ends, which the cell records as null.
        assert_eq!(
            socket_queue_bytes(&table, &Default::default()).unwrap(),
            (0, 0)
        );
        assert!(socket_queue_bytes("header\n  0: short", &listeners).is_err());
    }

    #[tokio::test]
    async fn held_read_is_unavailable_when_the_rib_never_replies() {
        // A RIB that never serves its channel: the read ends at its cap,
        // well inside the test's own.
        let (rib, _queue) = tokio::sync::mpsc::channel(4);
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        let cap = std::time::Duration::from_millis(50);
        let started = std::time::Instant::now();
        let read = held_read(&rib, &metrics, &[], Family::Unicast, 0, started, cap);
        let held = tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .expect("the held read ends at its cap")
            .unwrap();
        assert_eq!(
            held,
            serde_json::json!({"unavailable": "no reply within 50 ms"})
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_rib_still_reaches_the_readers_resume_within_the_caps() {
        // The cell's order before it resumes its readers: the held read,
        // then the churn-free window. The RIB never serves its channel, in
        // paused time: each wait ends at its cap, not the test's own. One
        // clock: `t0` and the window's end come from tokio's paused clock.
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        let (log, received) = (Mutex::default(), Mutex::default());
        let cap = QUIET_CAP;
        // Returns the window and when it started and ended, from its end.
        let window = |churn: Churn, rib: tokio::sync::mpsc::Sender<RibUpdate>, lead, late| {
            let (metrics, log, received) = (&metrics, &log, &received);
            async move {
                let t0 = tokio::time::Instant::now();
                let until = t0 + lead;
                if late {
                    let read = held_read(
                        &rib,
                        metrics,
                        &[],
                        Family::Unicast,
                        0,
                        t0.into(),
                        HELD_READ_CAP,
                    );
                    let held = read.await.unwrap();
                    assert!(held.get("unavailable").is_some(), "{held}");
                }
                let entered = tokio::time::Instant::now();
                let quiet = quiet_window(
                    churn,
                    &rib,
                    metrics,
                    log,
                    received,
                    t0.into(),
                    until.into(),
                    cap,
                );
                let quiet = tokio::time::timeout(4 * (HELD_READ_CAP + cap), quiet)
                    .await
                    .expect("the churn-free window ends at its cap")
                    .unwrap();
                let ended = tokio::time::Instant::now();
                (quiet, entered.checked_duration_since(until), ended - until)
            }
        };
        // The churn task's send waits on the RIB's full channel.
        let stuck = || {
            let (rib, queue) = tokio::sync::mpsc::channel(1);
            let sender = rib.clone();
            let task = tokio::spawn(async move {
                for _ in 0..2 {
                    let (reply, _count) = tokio::sync::oneshot::channel();
                    let _ = sender.send(RibUpdate::QueryLocRibCount { reply }).await;
                }
            });
            ((Arc::new(AtomicBool::new(false)), task), rib, queue)
        };
        // The churn stops; the queries that republish the gauges go
        // unanswered.
        let stopped = || {
            let (rib, queue) = tokio::sync::mpsc::channel(8);
            let churn = (Arc::new(AtomicBool::new(false)), tokio::spawn(async {}));
            (churn, rib, queue)
        };

        // On time, the window's waits get the full cap past its end. Late,
        // behind a held read at its cap, they get only what remains of it:
        // 0.3 s here, none when the read ended at the cap itself.
        let late = HELD_READ_CAP.checked_sub(QUIET_LEAD).unwrap();
        for (lead, held, entered) in [
            (QUIET_LEAD, true, Some(late)),
            (Duration::ZERO, true, Some(cap)),
            (QUIET_LEAD, false, None),
        ] {
            let (churn, rib, _queue) = stuck();
            let (quiet, at, ended) = window(churn, rib, lead, held).await;
            assert_eq!(
                (at, ended),
                (entered, cap),
                "lead {lead:?}, held read {held}"
            );
            assert!(quiet.unavailable.is_some() && quiet.delivered.is_none());
            assert!(quiet.readings.is_empty());
            let excluded = quiet_excluded_json(&quiet, None, Instant::now());
            assert!(excluded["unavailable"].is_string(), "{excluded}");

            let (churn, rib, _queue) = stopped();
            let (quiet, at, ended) = window(churn, rib, lead, held).await;
            assert_eq!(
                (at, ended),
                (entered, cap),
                "lead {lead:?}, held read {held}"
            );
            assert!(quiet.unavailable.is_some() && quiet.delivered.is_some());
            assert!(quiet.published_ms.is_none() && quiet.readings.is_empty());
            let excluded = super::excluded_window(quiet.stopped, quiet.delivered, Instant::now());
            let excluded = quiet_excluded_json(&quiet, excluded, Instant::now());
            assert!(excluded["unavailable"].is_string(), "{excluded}");
        }
    }

    #[test]
    fn a_churn_send_completing_at_the_stop_deadline_logs_before_the_restart() {
        // The old churn task has logged row 1; its send of row 2 completes
        // as the stop's deadline passes, and its poll is still running when
        // the stop aborts it. The poll is held by a handshake: a worker that
        // parks while the stop is pending releases it, so a stop that waits
        // for the aborted task lets it finish; a stop that returns at once
        // leaves it held until the restart has read its next sequence.
        let stop = Arc::new(AtomicBool::new(false));
        let returned = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release = Arc::new(Mutex::new(Some(release_tx)));
        let runtime = {
            let (stop, returned, release) = (stop.clone(), returned.clone(), release.clone());
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .on_thread_park(move || {
                    if stop.load(Ordering::Acquire) && !returned.load(Ordering::Acquire) {
                        if let Some(release) = release.lock().unwrap().take() {
                            release.send(()).unwrap();
                        }
                    }
                })
                .build()
                .unwrap()
        };
        let log = Arc::new(Mutex::new(Vec::<(u32, Instant)>::new()));
        runtime.block_on(async {
            let (sending_tx, sending_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let task_log = Arc::clone(&log);
            let task = tokio::spawn(async move {
                task_log.lock().unwrap().push((1, Instant::now()));
                sending_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                task_log.lock().unwrap().push((2, Instant::now()));
                done_tx.send(()).unwrap();
            });
            sending_rx.recv().unwrap();
            let churn: Churn = (Arc::clone(&stop), task);
            // Already passed, so the stop aborts on its first poll.
            let deadline = tokio::time::Instant::now() - Duration::from_secs(1);
            let returned = Arc::clone(&returned);
            let joined = tokio::spawn(async move {
                let joined = stop_churn(churn, deadline).await;
                returned.store(true, Ordering::Release);
                joined
            });
            assert!(!joined.await.unwrap().unwrap());
            // The restart reads its next sequence, as `start_churn` does.
            let next = log.lock().unwrap().last().map_or(1, |&(last, _)| last + 1);
            if let Some(release) = release.lock().unwrap().take() {
                release.send(()).unwrap();
            }
            done_rx.recv().unwrap();
            log.lock().unwrap().push((next, Instant::now()));
        });
        let sequences: Vec<u32> = log.lock().unwrap().iter().map(|&(s, _)| s).collect();
        assert_eq!(sequences, [1, 2, 3]);
    }

    #[test]
    fn burst_attributes_are_distinct_across_the_full_shape() {
        // Rows sharing attributes share an UPDATE, which shrinks the bytes
        // a row and inflates the release witness's slack.
        let distinct: std::collections::HashSet<_> = (0..150_000)
            .map(|index| attributes(index, 7, 100))
            .collect();
        assert_eq!(distinct.len(), 150_000);
    }

    #[test]
    fn only_the_fixed_shape_is_measured() {
        assert!(!parse(&[]).correctness_only);
        for args in [
            &["--reduced"][..],
            &["--correctness-only"],
            &["--seconds", "1"],
            &["--pause-ms", "500"],
        ] {
            assert!(
                parse(args).correctness_only,
                "{args:?} must not be measured"
            );
        }
    }

    #[test]
    fn each_trigger_checks_its_own_end_of_rib_order() {
        let now = Instant::now();
        let eor = Observed {
            end_of_rib: true,
            ..Observed::default()
        };
        let route = Observed {
            announced: vec![(0, Some(7))],
            ..Observed::default()
        };
        let run = |messages: &[&Observed]| {
            let mut state = WireState::new(WireFamily::Unicast, 1, 7);
            for message in messages {
                state.apply_observed(message, now);
            }
            (
                Trigger::Ordinary.eor_ordered(&state),
                Trigger::Restart.eor_ordered(&state),
            )
        };
        // (ordinary, restart): the marker before the burst, or after it.
        assert_eq!(run(&[&eor, &route]), (true, false));
        assert_eq!(run(&[&route, &eor]), (false, true));
        // Seeded: a second End-of-RIB behind an ordinary burst.
        assert_eq!(run(&[&eor, &route, &eor]), (false, false));
        // Seeded: a route ahead of an ordinary burst's End-of-RIB.
        assert_eq!(run(&[&route, &eor, &route]), (false, false));
        // Seeded: a restart burst's End-of-RIB twice.
        assert_eq!(run(&[&route, &eor, &eor]), (false, false));
        assert_ne!(Trigger::Ordinary.eor_check(), Trigger::Restart.eor_check());
        assert_ne!(Trigger::Ordinary.cell(), Trigger::Restart.cell());
    }

    #[test]
    fn read_hold_covers_the_pause_and_the_time_since_the_last_read() {
        // Fixed pauses: 80 s ordinary, 30 s restart.
        for trigger in [Trigger::Ordinary, Trigger::Restart] {
            check_read_hold(trigger.pause()).unwrap();
        }
        // 240 s read hold - 90 s since the last read.
        check_read_hold(Duration::from_millis(149_999)).unwrap();
        assert!(check_read_hold(Duration::from_secs(150)).is_err());
    }

    #[test]
    fn burst_intervals_match_the_measured_shape() {
        // `credit_bars.py` fixes `burst_interval_ms` at 500 for a measured run.
        assert_eq!(
            Trigger::Ordinary.interval(false),
            Duration::from_millis(500)
        );
        assert_eq!(Trigger::Ordinary.interval(true), Duration::from_millis(10));
        assert_eq!(Trigger::Restart.interval(false), Duration::ZERO);
        assert_eq!(Trigger::Restart.interval(true), Duration::ZERO);
    }

    #[test]
    fn seeded_session_reset_fails_the_recorded_outcome() {
        // The paused-reader result records a disconnected receiver.
        let result = json!({"checks": {"no_session_resets": false}, "not_established": ["x"]});
        assert!(!recorded_pass(&result));
        assert!(recorded_pass(
            &json!({"checks": {"no_session_resets": true}})
        ));
        let wire = json!({"checks": {"final_state_exact": true, "eor_after_every_route": false}});
        assert!(!recorded_pass(&wire));
        // A result without checks has nothing to pass.
        assert!(!recorded_pass(&json!({})));
    }

    #[test]
    fn slice_maxima_survive_the_render_reset() {
        use rustbgpd_telemetry::metrics::RibActorSliceStage;
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        let mut recorder = metrics.rib_actor_slice_recorder();
        recorder.observe(RibActorSliceStage::ActorPoll, Duration::from_millis(300));
        recorder.flush();
        // Seeded: a plain gather never publishes, so it reads no maximum.
        let unpublished = Snapshot::take(&metrics);
        assert_eq!(unpublished.total(SLICE_MAX), Some(0.0));
        let mut max = BTreeMap::new();
        drop(fold_slice_maxima(&metrics, &mut max));
        assert_eq!(max["actor_poll"], 300_000.0);
        // The next read publishes an empty window; the run's maximum stays.
        let snapshot = fold_slice_maxima(&metrics, &mut max);
        assert_eq!(snapshot.total(SLICE_MAX), Some(0.0));
        assert_eq!(max["actor_poll"], 300_000.0);
    }

    #[test]
    fn longest_brackets_only_the_window_observations() {
        let edges = |counts: [u64; 3]| vec![(0.1, counts[0]), (0.2, counts[1]), (0.5, counts[2])];
        let before = Buckets::from([("x".to_string(), (1, edges([1, 1, 1])))]);
        // One more turn in (0.1, 0.2], one in (0.2, 0.5], one past 0.5.
        let after = Buckets::from([
            ("x".to_string(), (3, edges([1, 2, 3]))),
            ("y".to_string(), (1, edges([0, 0, 0]))),
            ("z".to_string(), (0, edges([0, 0, 0]))),
        ]);
        let longest = longest(&before, &after);
        assert_eq!(
            longest["x"],
            json!({"observations": 2, "above_ms": 200.0, "at_most_ms": 500.0})
        );
        assert_eq!(
            longest["y"],
            json!({"observations": 1, "above_ms": 500.0, "at_most_ms": null})
        );
        // A label without observations in the window is left out.
        assert!(longest.get("z").is_none());
    }

    #[test]
    fn step_buckets_name_the_family_where_the_histogram_carries_one() {
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        // This tree's step histogram is keyed by scope alone.
        let keys: Vec<_> = buckets(&metrics, TURN_HISTOGRAMS[2].0, "scope")
            .into_keys()
            .collect();
        assert_eq!(keys, ["cursor", "keyed", "whole"]);
        // A tree that labels steps by family too.
        let options = prometheus::HistogramOpts::new("labeled_steps_seconds", "steps");
        let labeled = prometheus::HistogramVec::new(options, &["scope", "family"]).unwrap();
        labeled
            .with_label_values(&["cursor", "l2vpn_evpn"])
            .observe(0.01);
        labeled
            .with_label_values(&["whole", "ipv4_unicast"])
            .observe(0.01);
        metrics.registry().register(Box::new(labeled)).unwrap();
        let keys: Vec<_> = buckets(&metrics, "labeled_steps_seconds", "scope")
            .into_keys()
            .collect();
        assert_eq!(keys, ["cursor/l2vpn_evpn", "whole/ipv4_unicast"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credit_bytes_watch_reads_the_gauge_only_where_exported() {
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        let stop = Arc::new(AtomicBool::new(false));
        // This tree exports no byte gauge: no watch, and the result's
        // `drain_gauges.peak_credit_bytes` is null.
        assert!(watch_credit_bytes(&metrics, &stop).is_none());
        let gauge = prometheus::IntGauge::new("bgp_rib_outbound_credit_bytes", "bytes").unwrap();
        metrics
            .registry()
            .register(Box::new(gauge.clone()))
            .unwrap();
        gauge.set(7);
        let watch = watch_credit_bytes(&metrics, &stop).expect("the gauge is exported");
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.store(true, Ordering::Release);
        let (reads, peak) = watch.await.unwrap();
        assert!(reads > 0);
        assert_eq!(peak, Some(7.0));
    }

    #[tokio::test]
    async fn gauge_watch_reports_how_it_read_the_byte_gauge() {
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        let finish = |stop: &Arc<AtomicBool>| stop.store(true, Ordering::Release);
        // No byte gauge on this tree.
        let stop = Arc::new(AtomicBool::new(false));
        let watch = watch_gauges(metrics.clone(), Instant::now(), Arc::clone(&stop));
        tokio::task::yield_now().await;
        finish(&stop);
        let watch = watch.await.unwrap();
        assert_eq!(watch.credit_bytes_watch, "not exported");
        assert_eq!(watch.peak_credit_bytes, None);
        // A labeled family is absent from a gather until its first child:
        // a gauge that appears after the watch started was never read, and
        // the watch says so instead of reading as a tree without it. On
        // this current-thread runtime one yield runs the watch's start.
        let options = prometheus::Opts::new(CREDIT_BYTES, "bytes");
        let gauge = prometheus::IntGaugeVec::new(options, &["family"]).unwrap();
        metrics
            .registry()
            .register(Box::new(gauge.clone()))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let watch = watch_gauges(metrics.clone(), Instant::now(), Arc::clone(&stop));
        tokio::task::yield_now().await;
        gauge.with_label_values(&["ipv4_unicast"]).set(7);
        finish(&stop);
        let watch = watch.await.unwrap();
        assert_eq!(watch.credit_bytes_watch, "exported after start");
        assert_eq!(watch.peak_credit_bytes, None);
        // Exported from the start: dropping the cell's guard, as an early
        // return does, ends the blocking watch.
        let stop = Arc::new(AtomicBool::new(false));
        let guard = StopOnDrop(Arc::clone(&stop));
        let watch = watch_gauges(metrics.clone(), Instant::now(), Arc::clone(&stop));
        tokio::task::yield_now().await;
        drop(guard);
        let watch = tokio::time::timeout(Duration::from_secs(10), watch).await;
        // Stop it anyway, so a broken guard fails here instead of hanging
        // runtime shutdown on the blocking watch.
        finish(&stop);
        let watch = watch.expect("the guard stops the watch").unwrap();
        assert_eq!(watch.credit_bytes_watch, "watched");
    }

    #[test]
    fn seeded_slow_churn_delivery_stays_in_the_gap() {
        use crate::credit_wire::delivery;
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let injected = [(1, at(0))];
        // Churn stops at 100 ms; its last row arrives only at 1,000 ms; the
        // churn restarts at 1,300 ms and arrives at once.
        let arrivals = [(1, at(90)), (2, at(1_000)), (3, at(1_300))];
        let gap = |excluded| delivery(&injected, &arrivals, start, at(1_300), excluded).max_gap;
        let window = super::excluded_window(at(100), Some(at(1_000)), at(1_300));
        assert_eq!(window, Some((at(1_000), at(1_300))));
        assert_eq!(gap(window), Duration::from_millis(910));
        // Undelivered: nothing is excluded.
        assert_eq!(super::excluded_window(at(100), None, at(1_300)), None);
    }

    #[tokio::test]
    async fn round_trip_probe_ends_unfinished_when_the_rib_never_replies() {
        let (rib, mut inbox) = tokio::sync::mpsc::channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let cap = Duration::from_millis(100);
        let probe = super::probe_round_trips(rib, Instant::now(), Arc::clone(&stop), cap);
        // Handshake: the probe is in flight once its query is received;
        // holding the reply sender, the RIB never answers.
        let Some(RibUpdate::QueryLocRibCount { reply: _held }) = inbox.recv().await else {
            panic!("a round-trip query");
        };
        stop.store(true, Ordering::Release);
        let trips = tokio::time::timeout(Duration::from_secs(10), probe)
            .await
            .expect("the join ends within the probe cap")
            .unwrap()
            .unwrap();
        assert!(trips.unfinished);
        assert_eq!(trips.probes, 0);
        assert!(trips.longest_ms >= 100.0, "{}", trips.longest_ms);
    }

    #[test]
    fn row_credit_mirror_matches_the_rib() {
        let source = include_str!("../../../../crates/rib/src/outbound_credit.rs");
        for (name, value) in super::ROW_CREDIT {
            let declaration = format!("const {name}: usize = ");
            let line = source
                .lines()
                .find(|line| line.contains(&declaration))
                .unwrap_or_else(|| panic!("{name} not declared in outbound_credit.rs"));
            let literal = line.rsplit(" = ").next().unwrap().trim_end_matches(';');
            assert_eq!(
                literal.replace('_', "").parse::<usize>().unwrap(),
                value,
                "{name} drifted from the RIB"
            );
        }
    }

    #[test]
    fn vpn_release_pairs_rds_while_fill_keeps_distinct_prefixes() {
        let RibUpdate::VpnRoutesReceived {
            announced: fill, ..
        } = super::source_update(Family::Vpn, 0..2, super::BURST_VERSION, 100)
        else {
            panic!("expected VPN fill rows");
        };
        let RibUpdate::VpnRoutesReceived {
            announced: release, ..
        } = super::release_source_update(Family::Vpn, 0..2)
        else {
            panic!("expected VPN release rows");
        };
        for (index, route) in fill.iter().enumerate() {
            assert_eq!(route.nlri.route_distinguisher, super::EVPN_RD);
            assert_eq!(
                route.nlri.prefix,
                super::VpnPrefix::V4 {
                    addr: super::unicast_prefix(index),
                    len: 24
                }
            );
        }
        assert_eq!(release[0].nlri, fill[0].nlri);
        assert_eq!(release[1].nlri.prefix, release[0].nlri.prefix);
        assert_ne!(
            release[1].nlri.route_distinguisher,
            release[0].nlri.route_distinguisher
        );
        assert_eq!(release[1].nlri.labels, fill[1].nlri.labels);
    }

    #[test]
    fn churn_plan_withdraws_every_hundredth_and_reannounces_half() {
        let (withdrawn, reannounced) = churn_plan(4_096);
        assert_eq!(withdrawn.len(), 41);
        assert_eq!(reannounced.len(), 21);
        assert!(reannounced.iter().all(|index| withdrawn.contains(index)));
        let RibUpdate::RoutesReceived {
            withdrawn: prefixes,
            ..
        } = source_withdrawal(Family::Unicast, &withdrawn[..2])
        else {
            panic!("a route batch");
        };
        let indices: Vec<_> = prefixes
            .iter()
            .map(|&(prefix, _)| crate::credit_wire::unicast_index(prefix))
            .collect();
        assert_eq!(indices, [Some(0), Some(100)]);
        let RibUpdate::RoutesReceived { evpn_withdrawn, .. } =
            source_withdrawal(Family::Evpn, &withdrawn[..1])
        else {
            panic!("a route batch");
        };
        assert_eq!(evpn_withdrawn.len(), 1);
    }
}
