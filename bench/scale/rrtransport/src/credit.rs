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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    AttrSet, EvpnRibRoute, FlowSpecRoute, PeerId, RibManager, SelectionDeferralConfig,
    SelectionDeferralWaiterConfig, VpnRibRoute,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, AspaValidation, EthernetTagId, EvpnImet, EvpnRoute, Ipv4Prefix,
    Message, Origin, PathAttribute, Prefix, RouteDistinguisher, RpkiValidation, Safi,
};
use serde_json::{json, Value};
use tokio::net::TcpSocket;
use tokio::sync::{mpsc, watch};

use crate::credit_wire::{
    delivery, unicast_prefix, ChurnState, WireFamily, WireState, BURST_RANGE, CHURN_PREFIX,
    EVPN_ORIGINATOR, EVPN_RD,
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
/// Hold time of every receiver session, both ends.
const HOLD_SECS: u16 = 90;
/// The receiver stubs' own read timeout. A stub's deadline runs from its
/// last read and keeps running across a read pause, so it is longer than
/// the negotiated hold time; the daemon's sessions still use `HOLD_SECS`.
const READ_HOLD_SECS: u16 = 240;
/// Quiet period after every burst receiver is exact.
const QUIET: Duration = Duration::from_secs(2);

/// Families a cell can inject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Unicast,
    Evpn,
    Vpn,
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
            Self::FlowSpec => "flowspec",
        }
    }

    fn afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::Unicast => (Afi::Ipv4, Safi::Unicast),
            Self::Evpn => (Afi::L2Vpn, Safi::Evpn),
            Self::Vpn => (Afi::Ipv4, Safi::MplsVpn),
            Self::FlowSpec => (Afi::Ipv4, Safi::FlowSpec),
        }
    }

    fn wire(self) -> Result<WireFamily> {
        Ok(match self {
            Self::Unicast => WireFamily::Unicast,
            Self::Evpn => WireFamily::Evpn,
            _ => bail!("wire checks cover unicast and evpn only"),
        })
    }

    /// The row type the credit stages for this family.
    fn row_size_of(self) -> usize {
        match self {
            Self::Unicast => std::mem::size_of::<Route>(),
            Self::Evpn => std::mem::size_of::<EvpnRibRoute>(),
            Self::Vpn => std::mem::size_of::<VpnRibRoute>(),
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
            Self::Restart => !state.eor_premature && state.routes_after_eor == 0,
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
    // Distinct attributes per route: one UPDATE a route, about 180 bytes on
    // the wire, so a paused receiver's socket and writer budget absorb only
    // a small part of the burst and the rest stays charged to the credit.
    let path = (0..8).map(|hop| 64_496 + hop).collect();
    let communities = (0..24)
        .map(|tag| (65_000 << 16) | ((index + tag) & 0xffff))
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

fn vpn_route(index: usize, attrs: Arc<AttrSet>) -> VpnRibRoute {
    use rustbgpd_wire::vpn::{MplsLabelEntry, VpnNlri, VpnPrefix};
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry {
                label: 16 + u32::try_from(index % 1_000).expect("label fits"),
                traffic_class: 0,
                bottom_of_stack: true,
            }],
            route_distinguisher: RouteDistinguisher([0, 0, 0xfc, 0x00, 0, 0, 0, 1]),
            prefix: VpnPrefix::V4 {
                addr: unicast_prefix(index),
                len: 24,
            },
        },
        next_hop: IpAddr::V4(SOURCE),
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

/// One source UPDATE of `family` announcing `range` at `med`.
fn source_update(
    family: Family,
    range: std::ops::Range<usize>,
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
                announced: range.map(|index| vpn_route(index, attrs(index))).collect(),
                withdrawn: Vec::new(),
            };
        }
        Family::Unicast => {
            announced = range
                .map(|index| unicast_route(index, attrs(index), SOURCE))
                .collect();
        }
        Family::Evpn => evpn = range.map(|index| evpn_route(index, attrs(index))).collect(),
        Family::FlowSpec => {
            flowspec = range
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
            pending.push((ip, session, handshake));
        }
        let until = tokio::time::Instant::now() + deadline;
        for (ip, session, handshake) in pending {
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

/// One instrument sample.
#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    at_ms: f64,
    allocated: f64,
    credit_rows: f64,
    credit_bytes: Option<f64>,
    rss_kib: f64,
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
    peak_allocated: f64,
    peak_rss_kib: f64,
    first_refusal_ms: Option<f64>,
    /// Whole-table operations live at the sample that first saw a refusal.
    operations_live_at_first_refusal: Option<f64>,
    all_refused_ms: Option<f64>,
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
            let snapshot = Snapshot::take(&metrics);
            let gauge = |name| snapshot.total(name).unwrap_or(0.0);
            let sample = Sample {
                at_ms,
                allocated: gauge("jemalloc_allocated_bytes"),
                credit_rows: gauge("bgp_rib_outbound_credit_rows"),
                credit_bytes: snapshot.total("bgp_rib_outbound_credit_bytes"),
                rss_kib: rss_kib().map_or(0.0, |(rss, _)| rss as f64),
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
            instruments.peak_allocated = instruments.peak_allocated.max(sample.allocated);
            instruments.peak_rss_kib = instruments.peak_rss_kib.max(sample.rss_kib);
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
        "peak_sampled_rss_kib": instruments.peak_rss_kib,
        "peak_jemalloc_allocated_bytes": instruments.peak_allocated,
        "peak_credit_rows": instruments.peak_credit_rows,
        "peak_credit_bytes": instruments.peak_credit_bytes,
        "peak_operations_live": instruments.peak_operations_live,
        "peak_dirty_peers": instruments.peak_dirty_peers,
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
/// cell behind an RFC 4724 restart.
pub async fn exhaust(
    family: Family,
    trigger: Trigger,
    output: &Path,
    options: &Options,
) -> Result<bool> {
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
        "{} {}: {} receivers established",
        trigger.cell(),
        family.name(),
        receivers + 1
    );
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
        let state = Arc::new(Mutex::new(WireState::new(wire_family, rows, BURST_VERSION)));
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
        false,
        SAMPLE,
        Arc::clone(&sampling),
    );
    // The healthy receiver's churn runs until the cell ends.
    let churn_stop = Arc::new(AtomicBool::new(false));
    let churn_log = Arc::new(Mutex::new(Vec::new()));
    let start_churn = || {
        let rib = fixture.rib.clone();
        let stop = Arc::clone(&churn_stop);
        let log = Arc::clone(&churn_log);
        tokio::spawn(async move {
            let mut sequence = 1_u32;
            let mut tick = tokio::time::interval(CHURN_EVERY);
            while !stop.load(Ordering::Acquire) {
                tick.tick().await;
                let sent = Instant::now();
                if rib.send(churn_update(sequence)).await.is_err() {
                    return;
                }
                log.lock().expect("churn log").push((sequence, sent));
                sequence += 1;
            }
        })
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
    let window_start = if restart { t0 + release_sent } else { t0 };
    let churn = churn.take().unwrap_or_else(start_churn);

    tokio::time::sleep_until(tokio::time::Instant::from_std(t0 + pause)).await;
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
    tokio::time::sleep(QUIET).await;
    let end = Instant::now();
    churn_stop.store(true, Ordering::Release);
    churn.await?;
    sampling.store(true, Ordering::Release);
    let instruments = instruments.await?;
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
    let mut latest = Duration::ZERO;
    for ((state, _), ip) in collectors.iter().zip(&watched) {
        let state = state.lock().expect("wire state");
        exact += usize::from(state.exact());
        ordered += usize::from(trigger.eor_ordered(&state));
        missing += state.missing();
        after_eor += state.routes_after_eor;
        resets += state.resets;
        if let Some(at) = state.settled_at {
            latest = latest.max(at.saturating_duration_since(t0));
        }
        rows_json.push(json!({
            "peer": ip.to_string(),
            "exact": state.exact(),
            "missing": state.missing(),
            "eor_seen": state.eor_seen,
            "eor_premature": state.eor_premature,
            "routes_after_eor": state.routes_after_eor,
            "routes_before_eor": state.routes_before_eor,
            "eors": state.eors,
            "announced": state.announced,
            "withdrawals": state.withdrawals,
            "outside": state.outside,
            "decode_failures": state.decode_failures,
            "resets": state.resets,
            "credit_refusals": refused_by(ip),
        }));
    }
    let (arrivals, churn_resets) = {
        let state = churn_state.lock().expect("churn state");
        (state.arrivals.clone(), state.resets)
    };
    let injected = churn_log.lock().expect("churn log").clone();
    let unaffected = delivery(&injected, &arrivals, window_start, end);
    let refused_peers = watched.iter().filter(|ip| refused_by(ip) > 0.0).count();
    let healthy_ip = fixture.receivers[healthy].ip;
    let flaps = snapshot.total("bgp_session_flaps_total");
    let ms = |duration: Duration| duration.as_secs_f64() * 1e3;
    // The healthy receiver's session counts too.
    let resets = resets + churn_resets;
    let result = json!({
        "schema": "rrtransport-credit/1",
        "cell": trigger.cell(),
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
        },
        "checks": {
            "final_state_exact": exact == receivers,
            trigger.eor_check(): ordered == receivers,
            "no_session_resets": resets == 0 && down.is_empty(),
        },
        "wire": {
            "exact_receivers": exact,
            "missing_routes": missing,
            "routes_after_eor": after_eor,
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
                "peak of bgp_rib_outbound_credit_bytes (bgp_rib_outbound_credit_rows on a tree \
                 without it), summed over peers, equal to receivers x ceil(per-peer credit at \
                 shape.registered_peers / row) x row, plus at most one healthy row",
            ],
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
        },
        "unaffected": {
            "injected": unaffected.injected,
            "delivered": unaffected.delivered,
            "max_gap_ms": ms(unaffected.max_gap),
            "p50_latency_ms": ms(unaffected.p50),
            "p99_latency_ms": ms(unaffected.p99),
            "max_latency_ms": ms(unaffected.max),
            "resets": churn_resets,
        },
        "memory": memory_json(&instruments),
        "receivers": rows_json,
    });
    write_result(
        output,
        &format!("{}-{}.json", trigger.cell(), family.name()),
        &result,
    )?;
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
        .map(|s| (s.credit_rows, s.allocated))
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

    use super::{check_read_hold, recorded_pass, Options, Trigger};
    use crate::credit_wire::{Observed, WireFamily, WireState};

    fn parse(args: &[&str]) -> Options {
        Options::parse(&args.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap()
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
}
