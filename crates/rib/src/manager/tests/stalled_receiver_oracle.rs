//! Differential stalled-receiver oracle.
//!
//! Two real `RibManager` actors run the same randomized operation sequence on
//! one paused clock:
//!
//! - **Reference:** every receiver's outbound channel is effectively
//!   unbounded and is drained after every operation, so the RIB never sees
//!   backpressure.
//! - **Subject:** each receiver has a finite channel (1 to 4096 envelopes)
//!   and drains only when the generated schedule says so: stall, drain `k`,
//!   or drain everything. A full channel exercises dirty-marking, resync,
//!   refresh and replay during backlog, and flaps while owing.
//!
//! Each arm's receivers replay their envelopes through a small wire model:
//! the transport's marker filter (`EoR` dropped beside `BoRR`/`EoRR` toward an
//! RFC 7313 peer, markers cleared toward an RFC 2918-only peer), `BoRR` stale
//! marking and `EoRR` purge, RFC 4724 helper retention across a graceful end
//! with purge at the new session's `EoR`, and the session reset otherwise.
//! A flap discards the dying session's queued envelopes, as the transport
//! does.
//!
//! Operations: unicast IPv4/IPv6 and EVPN announce, modify and withdraw from
//! four sources; Add-Path `send_max` 1, 2, 8 and send-all; export-policy
//! changes (which also regroup); receiver stall, partial and full drain;
//! session flaps (also while dirty); inbound ROUTE-REFRESH; GR restart of a
//! source and its End-of-RIB sweep; an RFC 5291 prefix ORF with the initial
//! IPv4 `EoR` held until the first push; and operator replay. Peers 0 and 1
//! share one configuration, so they group for unicast while their EVPN feed
//! stays private.
//!
//! Properties, checked once every subject receiver has drained and no peer
//! is dirty:
//!
//! - P1, final state: each receiver's wire state (and the families it has
//!   seen an `EoR` for) equals the reference arm's. Each prefix is compared
//!   as its set of paths, since RFC 7911 path IDs are opaque. Stale paths a
//!   graceful end carried in with different values are compared only once
//!   their family's `EoR` has arrived.
//! - P2, no spurious withdrawal: never a withdrawal of a key the receiver
//!   does not hold.
//! - P3, barriers: no `BoRR` before the session's initial `EoR` for that
//!   family (RFC 7313 §4), `EoRR` only inside an open `BoRR`, and at every
//!   `EoR`, `EoRR` and replay terminal the peer already holds every path the
//!   reference held for that family after the operation that produced the
//!   marker (RFC 4724 §4, RFC 7313 §4, RFC 5291 §6). Routes a pending resync
//!   still owes a withdrawal may remain: that withdrawal is an ordinary later
//!   UPDATE.
//! - P4, per-key sequence: per (receiver, session, key), the collapsed value
//!   sequence equals the reference's, or is a prefix of it when the session
//!   ended with queued envelopes. Only keys the reference changed while the
//!   subject receiver was dirty (the deferral and its resync operation)
//!   relax to a subsequence. A key a graceful end carried into the session
//!   with a different value has no common starting point; P1-P3 still apply
//!   to it.
//! - P5, bounded retention: the peak queued envelopes per receiver stay
//!   within [`retention_bound`]. Peak queued rows are recorded too, so a
//!   later bound can pin them.
//!
//! `PROPTEST_CASES` and `PROPTEST_RNG_SEED` select the run; a failure is
//! shrunk by proptest and then by one-op deletion, and printed as a trace.
//! `ORACLE_TRACE=1` prints each operation and delivered envelope.
//!
//! Three open defects on main are tolerated only by their exact signature
//! ([`KNOWN`]); each has an ignored regression test with its minimized trace.
//! `ORACLE_STRICT=1` reports them as failures.
//!
//! Not modelled: VPN, LLGR, selection deferral, eBGP, RT-Constrain and the
//! owned-EVPN group path (off in production).

use std::collections::VecDeque;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use rustbgpd_bmp::BmpReplay;
use rustbgpd_wire::{EvpnRouteKey, RouteRefreshSubtype};

use super::update_groups_oracle::{NormMsg, normalize, permit_all_with};
use super::*;
use crate::update::OutboundRouteUpdate;

const PEERS: usize = 4;
const PREFIXES: u8 = 4;
const REFERENCE: usize = 0;
const SUBJECT: usize = 1;
/// "Unbounded" for the reference arm: never reached by a case.
const REFERENCE_CAPACITY: usize = 1 << 20;
const CAPACITIES: [usize; 8] = [1, 2, 3, 4, 8, 16, 64, 4096];
/// 0 is no Add-Path; `u32::MAX` is what negotiation maps send-all to.
const SEND_MAX: [u32; 5] = [0, 1, 2, 8, u32::MAX];
const CLUSTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TICK: Duration = Duration::from_millis(1010);
/// Rounds of drain + tick before the subject must be clean.
const QUIESCE_ROUNDS: usize = 48;
/// Consecutive quiet rounds that end quiescence.
const QUIET_ROUNDS: usize = 3;
/// Final rounds that must repeat one table for the known livelock.
const REPEAT_ROUNDS: usize = 8;
/// The signature of an open defect the default run tolerates;
/// `ORACLE_STRICT=1` reports it.
const KNOWN_REFRESH_RETRY_LIVELOCK: &str = "known: grouped refresh-retry livelock at one free slot";
/// The second open defect: an empty-view dirty resync drops an owed refresh
/// answer, and with it a GR peer's ORF-gated initial `EoR`.
const KNOWN_EMPTY_RESYNC_DROPS_REFRESH: &str =
    "known: empty-view resync drops an owed refresh and its initial EoR";
/// The third: a resync withdraws a route the peer's `EoRR` already purged.
const KNOWN_WITHDRAWAL_AFTER_EORR_PURGE: &str =
    "known: resync withdraws a route an EoRR already purged";
/// Every tolerated signature.
const KNOWN: [&str; 3] = [
    KNOWN_REFRESH_RETRY_LIVELOCK,
    KNOWN_EMPTY_RESYNC_DROPS_REFRESH,
    KNOWN_WITHDRAWAL_AFTER_EORR_PURGE,
];

const V4: (u16, u8) = (Afi::Ipv4 as u16, Safi::Unicast as u8);
const V6: (u16, u8) = (Afi::Ipv6 as u16, Safi::Unicast as u8);
const EVPN: (u16, u8) = (Afi::L2Vpn as u16, Safi::Evpn as u8);

fn peer_addr(peer: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 77, 0, u8::try_from(peer).unwrap() + 1)
}

fn peer_id(peer: usize) -> PeerId {
    peer_v4(peer_addr(peer))
}

fn wire_family(family: (Afi, Safi)) -> (u16, u8) {
    (family.0 as u16, family.1 as u8)
}

/// The largest number of envelopes a receiver may have queued. Today the
/// channel capacity bounds them by construction; the outbound redesign
/// (ADR-0145) pins its window here.
const fn retention_bound(capacity: usize) -> usize {
    capacity
}

#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independently negotiated session capability"
)]
struct PeerConfig {
    /// Subject channel capacity.
    capacity: usize,
    add_path: u32,
    /// RFC 7313 negotiated: `BoRR`/`EoRR` reach the wire.
    enhanced: bool,
    /// The peer's OPEN carries GR (it retains our routes across a graceful
    /// end and may restart).
    gr: bool,
    /// RFC 5291 prefix ORF negotiated for IPv4 unicast.
    orf: bool,
    v6: bool,
    evpn: bool,
}

impl PeerConfig {
    fn families(&self) -> Vec<(Afi, Safi)> {
        let mut families = vec![(Afi::Ipv4, Safi::Unicast)];
        if self.v6 {
            families.push((Afi::Ipv6, Safi::Unicast));
        }
        if self.evpn {
            families.push((Afi::L2Vpn, Safi::Evpn));
        }
        families
    }

    fn unicast(&self) -> Vec<(Afi, Safi)> {
        self.families()
            .into_iter()
            .filter(|(_, safi)| *safi == Safi::Unicast)
            .collect()
    }

    fn carries(&self, family: Fam) -> bool {
        match family {
            Fam::V4 => true,
            Fam::V6 => self.v6,
            Fam::Evpn => self.evpn,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fam {
    V4,
    V6,
    Evpn,
}

impl Fam {
    fn afi_safi(self) -> (Afi, Safi) {
        match self {
            Self::V4 => (Afi::Ipv4, Safi::Unicast),
            Self::V6 => (Afi::Ipv6, Safi::Unicast),
            Self::Evpn => (Afi::L2Vpn, Safi::Evpn),
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// Announce or modify (a new variant on a held key).
    Announce {
        src: usize,
        family: Fam,
        index: u8,
        variant: u8,
    },
    Withdraw {
        src: usize,
        family: Fam,
        index: u8,
    },
    /// Replace the export policy: 0 none, 1 deny prefix 0 (IPv4 and IPv6),
    /// 2 add a community, 3 deny prefixes 1 and 2.
    Policy {
        peer: usize,
        variant: u8,
    },
    /// Subject only: deliver `k` queued envelopes, or all of them.
    Drain {
        peer: usize,
        k: Option<u8>,
    },
    /// Advance past the dirty-resync interval.
    Tick,
    /// NOTIFICATION teardown and a new session.
    Flap {
        peer: usize,
    },
    /// Inbound ROUTE-REFRESH for one negotiated family.
    Refresh {
        peer: usize,
        family: Fam,
    },
    /// A GR peer's graceful end and immediate re-establishment; its routes
    /// stay stale until [`Op::SourceEor`].
    GrRestart {
        peer: usize,
    },
    /// The restarted peer's End-of-RIB for every family: the stale sweep.
    SourceEor {
        peer: usize,
    },
    /// Replace the IPv4 prefix ORF: `deny` is a prefix bitmask.
    Orf {
        peer: usize,
        deny: u8,
    },
    /// Explicit operator replay of the unicast families.
    Replay {
        peer: usize,
    },
}

fn v4_prefix(index: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 200, index, 0), 24)
}

fn v6_prefix(index: u8) -> Ipv6Prefix {
    Ipv6Prefix::new(
        Ipv6Addr::new(0x2001, 0xdb8, u16::from(index), 0, 0, 0, 0, 0),
        48,
    )
}

fn attributes(variant: u8) -> Vec<PathAttribute> {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100 + 50 * u32::from(variant % 3)),
    ];
    if variant >= 3 {
        attributes.push(PathAttribute::Communities(vec![0xFDE8_0007]));
    }
    attributes
}

fn unicast_route(src: usize, family: Fam, index: u8, variant: u8) -> Route {
    let addr = peer_addr(src);
    let (prefix, next_hop) = match family {
        Fam::V4 => (Prefix::V4(v4_prefix(index)), IpAddr::V4(addr)),
        _ => (
            Prefix::V6(v6_prefix(index)),
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0xffff,
                0,
                0,
                0,
                0,
                u16::from(addr.octets()[3]),
            )),
        ),
    };
    Route {
        prefix,
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: peer_v4(addr),
        attributes: AttrSet::new(attributes(variant)),
        received_at: crate::route::ReceivedAt::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: session_router_id(IpAddr::V4(addr)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: crate::route::AspaContextId::DEFAULT,
    }
}

fn evpn_route(src: usize, index: u8, variant: u8) -> EvpnRibRoute {
    let mut route = make_evpn_imet(peer_addr(src), 100 + u32::from(index));
    route.attributes = AttrSet::new(attributes(variant));
    route
}

fn policy(variant: u8) -> Option<rustbgpd_policy::PolicyChain> {
    match variant % 4 {
        0 => None,
        1 => Some(deny_prefixes_chain(&[
            Prefix::V4(v4_prefix(0)),
            Prefix::V6(v6_prefix(0)),
        ])),
        2 => Some(permit_all_with(rustbgpd_policy::RouteModifications {
            communities_add: vec![0xFDE8_0063],
            ..Default::default()
        })),
        _ => Some(deny_prefixes_chain(&[
            Prefix::V4(v4_prefix(1)),
            Prefix::V4(v4_prefix(2)),
            Prefix::V6(v6_prefix(2)),
        ])),
    }
}

fn orf_entries(deny: u8) -> Vec<AddressPrefixOrf> {
    let mut entries = vec![AddressPrefixOrf {
        action: OrfAction::RemoveAll,
        match_: OrfMatch::Permit,
        sequence: 0,
        min_len: 0,
        max_len: 0,
        prefix: None,
    }];
    for index in (0..PREFIXES).filter(|index| deny & (1 << index) != 0) {
        entries.push(AddressPrefixOrf {
            action: OrfAction::Add,
            match_: OrfMatch::Deny,
            sequence: u32::from(index) + 1,
            min_len: 0,
            max_len: 0,
            prefix: Some(Prefix::V4(v4_prefix(index))),
        });
    }
    entries.push(AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Permit,
        sequence: 100,
        min_len: 0,
        max_len: 32,
        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
    });
    entries
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    family: (u16, u8),
    nlri: String,
    path_id: u32,
}

/// The announced attributes, next hop and source, rendered once.
type Value = String;
type Table = BTreeMap<Key, Value>;
/// A prefix (or EVPN NLRI) without its path ID.
type Nlri = ((u16, u8), String);
/// Each prefix's sorted path values. RFC 7911 path IDs are opaque, so arms
/// compare the paths a prefix carries, not the IDs that carry them.
type PathSets = BTreeMap<Nlri, Vec<Value>>;

fn nlri(key: &Key) -> Nlri {
    (key.family, key.nlri.clone())
}

fn paths(table: &Table, prefix: &Nlri) -> Vec<Value> {
    let mut values: Vec<Value> = table
        .iter()
        .filter(|(key, _)| key.family == prefix.0 && key.nlri == prefix.1)
        .map(|(_, value)| value.clone())
        .collect();
    values.sort();
    values
}

fn path_sets(table: &Table, family: Option<(u16, u8)>) -> PathSets {
    let mut sets = PathSets::new();
    for (key, value) in table {
        if family.is_none_or(|family| key.family == family) {
            sets.entry(nlri(key)).or_default().push(value.clone());
        }
    }
    for values in sets.values_mut() {
        values.sort();
    }
    sets
}

/// A barrier and the family state the receiver held when it arrived.
#[derive(Debug)]
struct Barrier {
    arm: usize,
    peer: usize,
    session: u64,
    family: (u16, u8),
    op: usize,
    kind: &'static str,
    state: PathSets,
}

/// One arm's view of one receiver's wire.
#[derive(Default)]
struct Wire {
    session: u64,
    enhanced: bool,
    held: Table,
    /// RFC 4724 §4.2: kept across a graceful end until our `EoR`.
    gr_stale: BTreeSet<Key>,
    /// Open RFC 7313 refresh windows and their not-yet-replaced keys.
    refresh_stale: BTreeMap<(u16, u8), BTreeSet<Key>>,
    /// Keys an `EoRR` purged and nothing has announced since.
    eorr_purged: BTreeSet<Key>,
    eor: BTreeSet<(u16, u8)>,
    /// Collapsed per-(session, prefix) path-set sequence, one entry per
    /// envelope that changed it; the empty set is "not held".
    history: BTreeMap<(u64, Nlri), Vec<Vec<Value>>>,
    /// Each prefix's set when its envelope began, until [`Self::commit`].
    before: BTreeMap<Nlri, Vec<Value>>,
    /// Sessions that ended with queued envelopes the peer never received.
    truncated: BTreeSet<u64>,
    /// Prefixes whose path set changed in each operation.
    touched: BTreeMap<usize, BTreeSet<(u64, Nlri)>>,
}

impl Wire {
    fn record(&mut self, key: &Key, value: Option<Value>) {
        let prefix = nlri(key);
        if !self.before.contains_key(&prefix) {
            let before = paths(&self.held, &prefix);
            self.before.insert(prefix, before);
        }
        match value {
            Some(value) => {
                self.held.insert(key.clone(), value);
            }
            None => {
                self.held.remove(key);
            }
        }
    }

    fn start_session(&mut self, session: u64, enhanced: bool, retain: bool) {
        self.session = session;
        self.enhanced = enhanced;
        self.refresh_stale.clear();
        self.eorr_purged.clear();
        self.eor.clear();
        if retain {
            // "To deal with possible consecutive restarts, a route (from
            // the peer) previously marked as stale MUST be deleted."
            for key in std::mem::take(&mut self.gr_stale) {
                self.held.remove(&key);
            }
            self.gr_stale = self.held.keys().cloned().collect();
        } else {
            self.held.clear();
            self.gr_stale.clear();
        }
    }

    fn purge(&mut self, keys: impl IntoIterator<Item = Key>) {
        for key in keys {
            if self.held.contains_key(&key) {
                self.record(&key, None);
            }
        }
    }

    /// Close an envelope: record each changed prefix's new path set.
    fn commit(&mut self, op: usize) {
        for (prefix, before) in std::mem::take(&mut self.before) {
            let after = paths(&self.held, &prefix);
            if after != before {
                self.history
                    .entry((self.session, prefix.clone()))
                    .or_default()
                    .push(after);
                self.touched
                    .entry(op)
                    .or_default()
                    .insert((self.session, prefix));
            }
        }
    }

    /// Replay one envelope produced during `op` onto the wire.
    #[expect(
        clippy::too_many_lines,
        reason = "one pass mirrors the transport's phase order"
    )]
    fn apply(
        &mut self,
        arm: usize,
        peer: usize,
        op: usize,
        message: NormMsg,
        replay: bool,
        barriers: &mut Vec<Barrier>,
    ) -> Result<(), String> {
        let NormMsg {
            announce,
            withdraw,
            mut end_of_rib,
            mut refresh_markers,
            evpn_announce,
            evpn_withdraw,
            ..
        } = message;
        // `transport/src/session/outbound.rs`: outside a replay, an RFC 7313
        // peer gets EoRR in place of an EoR beside refresh markers, and an
        // RFC 2918 peer gets no markers at all.
        if !replay {
            if self.enhanced {
                end_of_rib.retain(|family| {
                    !refresh_markers
                        .iter()
                        .any(|(afi, safi, _)| (*afi, *safi) == *family)
                });
            } else {
                refresh_markers.clear();
            }
        }
        let session = self.session;
        let where_ = |what: &str| {
            format!(
                "{what} ({} peer {peer} session {session}, produced at op {op})",
                arm_name(arm)
            )
        };
        for (afi, safi, _) in refresh_markers
            .iter()
            .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::BoRR)
        {
            let family = wire_family((*afi, *safi));
            if !self.eor.contains(&family) {
                return Err(where_(&format!(
                    "P3: BoRR for {family:?} before the session's initial EoR"
                )));
            }
            let stale = self
                .held
                .keys()
                .filter(|key| key.family == family)
                .cloned()
                .collect();
            self.refresh_stale.insert(family, stale);
        }
        let mut withdrawn: Vec<Key> = withdraw
            .iter()
            .map(|(prefix, path_id)| Key {
                family: match prefix {
                    Prefix::V4(_) => V4,
                    Prefix::V6(_) => V6,
                },
                nlri: prefix.to_string(),
                path_id: *path_id,
            })
            .collect();
        let mut announced: Vec<(Key, Value)> = announce
            .iter()
            .map(
                |(prefix, path_id, next_hop, src, attrs, next_hop_override)| {
                    (
                        Key {
                            family: match prefix {
                                Prefix::V4(_) => V4,
                                Prefix::V6(_) => V6,
                            },
                            nlri: prefix.to_string(),
                            path_id: *path_id,
                        },
                        format!("{next_hop} {src} {attrs:?} {next_hop_override:?}"),
                    )
                },
            )
            .collect();
        withdrawn.extend(evpn_withdraw.iter().map(|nlri| Key {
            family: EVPN,
            nlri: nlri.clone(),
            path_id: 0,
        }));
        announced.extend(evpn_announce.iter().map(|row| {
            (
                Key {
                    family: EVPN,
                    nlri: row.0.clone(),
                    path_id: 0,
                },
                format!(
                    "{:?}",
                    (&row.1, &row.2, &row.3, &row.4, &row.5, &row.6, &row.7)
                ),
            )
        }));
        for key in &withdrawn {
            if !self.held.contains_key(key) {
                // Known defect: a refresh answered while a grouped member
                // still owes withdrawals leaves them owed after the EoRR has
                // purged those routes.
                let known = if self.eorr_purged.contains(key) {
                    format!(" ({KNOWN_WITHDRAWAL_AFTER_EORR_PURGE})")
                } else {
                    String::new()
                };
                return Err(where_(&format!(
                    "P2: withdrawal of {key:?}, which the receiver does not hold{known}"
                )));
            }
            self.record(key, None);
            self.gr_stale.remove(key);
            for stale in self.refresh_stale.values_mut() {
                stale.remove(key);
            }
        }
        for (key, value) in announced {
            self.eorr_purged.remove(&key);
            self.record(&key, Some(value));
            self.gr_stale.remove(&key);
            for stale in self.refresh_stale.values_mut() {
                stale.remove(&key);
            }
        }
        let mut barrier = |wire: &mut Self, family, kind| {
            wire.commit(op);
            barriers.push(Barrier {
                arm,
                peer,
                session: wire.session,
                family,
                op,
                kind,
                state: path_sets(&wire.held, Some(family)),
            });
        };
        for (afi, safi, _) in refresh_markers
            .iter()
            .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::EoRR)
        {
            let family = wire_family((*afi, *safi));
            let Some(stale) = self.refresh_stale.remove(&family) else {
                return Err(where_(&format!("P3: EoRR for {family:?} without a BoRR")));
            };
            self.eorr_purged.extend(stale.iter().cloned());
            self.purge(stale);
            barrier(self, family, "EoRR");
        }
        for family in end_of_rib {
            let family = wire_family(family);
            let kind = if replay {
                "replay terminal"
            } else if self.eor.contains(&family) {
                "later EoR"
            } else {
                "initial EoR"
            };
            self.eor.insert(family);
            let stale: Vec<Key> = self
                .gr_stale
                .iter()
                .filter(|key| key.family == family)
                .cloned()
                .collect();
            for key in &stale {
                self.gr_stale.remove(key);
            }
            self.purge(stale);
            barrier(self, family, kind);
        }
        self.commit(op);
        Ok(())
    }
}

fn tracing_ops() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var_os("ORACLE_TRACE").is_some())
}

fn arm_name(arm: usize) -> &'static str {
    if arm == REFERENCE {
        "reference"
    } else {
        "subject"
    }
}

/// One `RibManager` and its receivers.
struct Arm {
    tx: mpsc::Sender<RibUpdate>,
    handle: tokio::task::JoinHandle<()>,
    rx: Vec<Option<mpsc::Receiver<OutboundRouteUpdate>>>,
    /// The operation that produced each queued envelope, in queue order.
    stamps: Vec<VecDeque<usize>>,
    wire: Vec<Wire>,
    /// (produced, left the queue, rows) for every envelope.
    retention: Vec<Vec<(usize, usize, usize)>>,
    /// Reply and replay-enrollment receivers, kept for the whole case so no
    /// command looks abandoned.
    replies: Vec<Box<dyn std::any::Any>>,
}

impl Arm {
    fn spawn() -> Self {
        let (tx, rx) = mpsc::channel(512);
        let manager = RibManager::new(rx, dummy_query_rx(), None, Some(CLUSTER), BgpMetrics::new());
        Self {
            tx,
            handle: tokio::spawn(manager.run()),
            rx: (0..PEERS).map(|_| None).collect(),
            stamps: vec![VecDeque::new(); PEERS],
            wire: (0..PEERS).map(|_| Wire::default()).collect(),
            retention: vec![Vec::new(); PEERS],
            replies: Vec::new(),
        }
    }

    /// A reply sender whose receiver lives as long as the arm.
    fn reply<T: 'static>(&mut self) -> oneshot::Sender<T> {
        let (reply, response) = oneshot::channel();
        self.replies.push(Box::new(response));
        reply
    }

    async fn send(&self, update: RibUpdate) {
        self.tx.send(update).await.expect("RIB actor alive");
    }

    /// A FIFO round trip: every earlier update and its sends are done.
    async fn quiesce(&self) {
        let (reply, response) = oneshot::channel();
        self.send(RibUpdate::QueryBestRoutes {
            deadline: full_snapshot_query_deadline(),
            reply,
        })
        .await;
        response.await.expect("RIB actor alive");
    }

    async fn dirty(&self, peer: usize) -> bool {
        let (reply, response) = oneshot::channel();
        self.send(RibUpdate::TestQueryPeerOutboundDirty {
            peer: peer_id(peer),
            reply,
        })
        .await;
        response.await.expect("RIB actor alive")
    }

    fn rows(update: &OutboundRouteUpdate) -> usize {
        update.announce.len()
            + update.withdraw.len()
            + update.evpn_announce.len()
            + update.evpn_withdraw.len()
    }

    /// Deliver up to `k` queued envelopes (all with `None`) during `op`.
    fn deliver(
        &mut self,
        arm: usize,
        peer: usize,
        op: usize,
        k: Option<usize>,
        barriers: &mut Vec<Barrier>,
    ) -> Result<Vec<NormMsg>, String> {
        let mut delivered = Vec::new();
        let Some(rx) = self.rx[peer].as_mut() else {
            return Ok(delivered);
        };
        while k.is_none_or(|k| delivered.len() < k) {
            let Ok(update) = rx.try_recv() else { break };
            let produced = self.stamps[peer]
                .pop_front()
                .expect("every queued envelope is stamped");
            self.retention[peer].push((produced, op, Self::rows(&update)));
            let message = normalize(&update);
            if tracing_ops() {
                eprintln!(
                    "  {} peer {peer} <- (op {produced}) {message:?}",
                    arm_name(arm)
                );
            }
            self.wire[peer].apply(
                arm,
                peer,
                produced,
                message.clone(),
                update.replay.is_some(),
                barriers,
            )?;
            delivered.push(message);
        }
        Ok(delivered)
    }

    /// Stamp the envelopes `op` enqueued and return each queue's depth.
    fn stamp(&mut self, op: usize) -> Vec<usize> {
        (0..PEERS)
            .map(|peer| {
                let queued = self.rx[peer].as_ref().map_or(0, mpsc::Receiver::len);
                let stamps = &mut self.stamps[peer];
                assert!(queued >= stamps.len(), "queues only shrink by delivery");
                stamps.extend(std::iter::repeat_n(op, queued - stamps.len()));
                queued
            })
            .collect()
    }

    /// The transport discards a dying session's queue.
    fn discard(&mut self, peer: usize, op: usize) {
        let Some(mut rx) = self.rx[peer].take() else {
            return;
        };
        let mut lost = false;
        while let Ok(update) = rx.try_recv() {
            let produced = self.stamps[peer].pop_front().expect("stamped");
            self.retention[peer].push((produced, op, Self::rows(&update)));
            lost = true;
        }
        if lost {
            let session = self.wire[peer].session;
            self.wire[peer].truncated.insert(session);
        }
    }
}

struct Harness {
    config: [PeerConfig; PEERS],
    arms: [Arm; 2],
    session: [u64; PEERS],
    /// A GR restart whose End-of-RIB is still owed.
    restarting: [bool; PEERS],
    op: usize,
    barriers: Vec<Barrier>,
    /// The reference wire after each operation: (session, table) per peer.
    snapshots: Vec<Vec<(u64, Table)>>,
    /// Subject dirty after each operation.
    dirty: Vec<[bool; PEERS]>,
    /// Subject (peer, session, prefix) a graceful end carried in with a
    /// path set different from the reference's.
    carried: BTreeSet<(usize, u64, Nlri)>,
    peak_envelopes: [usize; PEERS],
}

impl Harness {
    async fn new(config: [PeerConfig; PEERS]) -> Result<Self, String> {
        let mut harness = Self {
            config,
            arms: [Arm::spawn(), Arm::spawn()],
            session: [1; PEERS],
            restarting: [false; PEERS],
            op: 0,
            barriers: Vec::new(),
            snapshots: Vec::new(),
            dirty: Vec::new(),
            carried: BTreeSet::new(),
            peak_envelopes: [0; PEERS],
        };
        for peer in 0..PEERS {
            harness.establish(peer, false, false).await;
        }
        harness.end_op().await?;
        Ok(harness)
    }

    async fn both(&self, update: impl Fn() -> RibUpdate) {
        for arm in &self.arms {
            arm.send(update()).await;
        }
    }

    /// The transport's Established sequence: OPEN context, then `PeerUp` on a
    /// new channel.
    async fn establish(&mut self, peer: usize, restarted: bool, retain: bool) {
        let config = self.config[peer];
        let session_id = self.session[peer];
        let families = config.families();
        for arm in &mut self.arms {
            arm.wire[peer].start_session(session_id, config.enhanced, retain);
        }
        // Compared after retention: a stale route from an earlier graceful
        // end is gone by now.
        let carried = retain.then(|| {
            let reference = path_sets(&self.arms[REFERENCE].wire[peer].held, None);
            let subject = path_sets(&self.arms[SUBJECT].wire[peer].held, None);
            reference
                .iter()
                .filter(|(prefix, values)| subject.get(*prefix) != Some(*values))
                .chain(
                    subject
                        .iter()
                        .filter(|(prefix, values)| reference.get(*prefix) != Some(*values)),
                )
                .map(|(prefix, _)| prefix.clone())
                .collect::<Vec<_>>()
        });
        for carried in carried.into_iter().flatten() {
            self.carried.insert((peer, session_id, carried));
        }
        for (index, arm) in self.arms.iter_mut().enumerate() {
            arm.send(RibUpdate::SetPeerGracefulRestartContext {
                peer: peer_id(peer),
                session_id,
                peer_restart_state: restarted,
                peer_gr_helper: config.gr,
                peer_gr_families: if config.gr { families.clone() } else { vec![] },
                peer_enhanced_refresh: config.enhanced,
                peer_llgr_families: vec![],
                local_llgr_stale_time: 0,
            })
            .await;
            let capacity = if index == REFERENCE {
                REFERENCE_CAPACITY
            } else {
                config.capacity
            };
            let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
            arm.rx[peer] = Some(outbound_rx);
            let add_path = config.add_path != 0;
            arm.send(RibUpdate::PeerUp {
                per_client_best: false,
                interpret_rfc1997: true,
                session_id,
                peer: peer_id(peer),
                peer_asn: 65000,
                peer_router_id: peer_addr(peer),
                outbound_tx,
                export_policy: None,
                sendable_families: families.clone(),
                is_ebgp: false,
                route_reflector_client: true,
                orr_vantage: None,
                add_path_send_families: if add_path { config.unicast() } else { vec![] },
                add_path_send_max: config.add_path,
                negotiated_orf_recv: if config.orf {
                    vec![(Afi::Ipv4, Safi::Unicast)]
                } else {
                    vec![]
                },
                negotiated_llgr_families: vec![],
            })
            .await;
        }
    }

    async fn tick(&self) {
        tokio::time::advance(TICK).await;
        // A quiesce can be served ahead of the due resync; the second
        // round trip cannot (see `Oracle::settle`).
        for arm in &self.arms {
            arm.quiesce().await;
        }
        for arm in &self.arms {
            arm.quiesce().await;
        }
    }

    /// Finish operation `self.op`: drain the reference, stamp the subject,
    /// record the reference wire and the subject's dirty state.
    async fn end_op(&mut self) -> Result<(), String> {
        for arm in &self.arms {
            arm.quiesce().await;
        }
        let op = self.op;
        let reference = &mut self.arms[REFERENCE];
        reference.stamp(op);
        for peer in 0..PEERS {
            reference.deliver(REFERENCE, peer, op, None, &mut self.barriers)?;
        }
        self.snapshots.push(
            reference
                .wire
                .iter()
                .map(|wire| (wire.session, wire.held.clone()))
                .collect(),
        );
        let depths = self.arms[SUBJECT].stamp(op);
        let mut dirty = [false; PEERS];
        for peer in 0..PEERS {
            self.peak_envelopes[peer] = self.peak_envelopes[peer].max(depths[peer]);
            if self.arms[REFERENCE].dirty(peer).await {
                return Err(format!(
                    "INVALID: the reference arm marked peer {peer} dirty at op {op}"
                ));
            }
            dirty[peer] = self.arms[SUBJECT].dirty(peer).await;
        }
        self.dirty.push(dirty);
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per generated operation"
    )]
    async fn apply(&mut self, op: &Op) -> Result<(), String> {
        self.op += 1;
        if tracing_ops() {
            eprintln!("op {}: {op:?}", self.op);
        }
        match *op {
            Op::Announce {
                src,
                family,
                index,
                variant,
            } => {
                if self.config[src].carries(family) {
                    let session_id = self.session[src];
                    self.both(|| {
                        let (announced, evpn_announced) = if family == Fam::Evpn {
                            (vec![], vec![evpn_route(src, index, variant)])
                        } else {
                            (vec![unicast_route(src, family, index, variant)], vec![])
                        };
                        RibUpdate::RoutesReceived {
                            peer: peer_id(src),
                            session_id,
                            announced,
                            withdrawn: vec![],
                            flowspec_announced: vec![],
                            flowspec_withdrawn: vec![],
                            evpn_announced,
                            evpn_withdrawn: vec![],
                            validated_with: None,
                        }
                    })
                    .await;
                }
            }
            Op::Withdraw { src, family, index } => {
                if self.config[src].carries(family) {
                    let session_id = self.session[src];
                    self.both(|| {
                        let (withdrawn, evpn_withdrawn): (_, Vec<EvpnRouteKey>) = match family {
                            Fam::V4 => (vec![(Prefix::V4(v4_prefix(index)), 0)], vec![]),
                            Fam::V6 => (vec![(Prefix::V6(v6_prefix(index)), 0)], vec![]),
                            Fam::Evpn => (vec![], vec![evpn_route(src, index, 0).key()]),
                        };
                        RibUpdate::RoutesReceived {
                            peer: peer_id(src),
                            session_id,
                            announced: vec![],
                            withdrawn,
                            flowspec_announced: vec![],
                            flowspec_withdrawn: vec![],
                            evpn_announced: vec![],
                            evpn_withdrawn,
                            validated_with: None,
                        }
                    })
                    .await;
                }
            }
            Op::Policy { peer, variant } => {
                // The reply arrives at commit; the quiesce below orders it.
                for arm in &mut self.arms {
                    let reply = arm.reply();
                    arm.send(RibUpdate::ReplacePeerExportPolicy {
                        peer: peer_id(peer),
                        export_policy: policy(variant),
                        reply,
                    })
                    .await;
                }
            }
            Op::Drain { peer, k } => {
                self.arms[SUBJECT].deliver(
                    SUBJECT,
                    peer,
                    self.op,
                    k.map(usize::from),
                    &mut self.barriers,
                )?;
            }
            Op::Tick => self.tick().await,
            Op::Flap { peer } => {
                let session_id = self.session[peer];
                self.restarting[peer] = false;
                self.both(|| RibUpdate::PeerDown {
                    peer: peer_id(peer),
                    session_id,
                })
                .await;
                self.reconnect(peer, false).await;
            }
            Op::Refresh { peer, family } => {
                if self.config[peer].carries(family) {
                    let session_id = self.session[peer];
                    let (afi, safi) = family.afi_safi();
                    self.both(|| RibUpdate::RouteRefreshRequest {
                        queued: Arc::default(),
                        peer: peer_id(peer),
                        session_id,
                        afi,
                        safi,
                    })
                    .await;
                }
            }
            Op::GrRestart { peer } => {
                if self.config[peer].gr && !self.restarting[peer] {
                    let session_id = self.session[peer];
                    let families = self.config[peer].families();
                    self.both(|| RibUpdate::PeerGracefulRestart {
                        peer: peer_id(peer),
                        session_id,
                        restart_time: 120,
                        stale_routes_time: 360,
                        gr_families: families.clone(),
                        peer_llgr_capable: false,
                        peer_llgr_families: vec![],
                        llgr_stale_time: 0,
                    })
                    .await;
                    self.restarting[peer] = true;
                    self.reconnect(peer, true).await;
                }
            }
            Op::SourceEor { peer } => {
                if self.restarting[peer] {
                    self.restarting[peer] = false;
                    let session_id = self.session[peer];
                    for (afi, safi) in self.config[peer].families() {
                        self.both(|| RibUpdate::EndOfRib {
                            peer: peer_id(peer),
                            session_id,
                            afi,
                            safi,
                        })
                        .await;
                    }
                }
            }
            Op::Orf { peer, deny } => {
                if self.config[peer].orf {
                    let session_id = self.session[peer];
                    for arm in &mut self.arms {
                        let reply = arm.reply();
                        arm.send(RibUpdate::PeerOrfUpdate {
                            peer: peer_id(peer),
                            session_id,
                            afi: Afi::Ipv4,
                            safi: Safi::Unicast,
                            when: WhenToRefresh::Immediate,
                            entries: orf_entries(deny),
                            reply,
                        })
                        .await;
                    }
                }
            }
            Op::Replay { peer } => {
                let session_id = self.session[peer];
                let families = self.config[peer].unicast();
                for arm in &mut self.arms {
                    let (token, enrolled) = BmpReplay::new(Duration::from_secs(3600));
                    arm.replies.push(Box::new(enrolled));
                    let reply = arm.reply();
                    arm.send(RibUpdate::ReplayPeerOutbound {
                        peer: peer_id(peer),
                        session_id,
                        families: families.clone(),
                        replay: token,
                        reply,
                    })
                    .await;
                }
            }
        }
        self.end_op().await
    }

    /// A new session on a new channel. A graceful end toward a GR peer keeps
    /// our routes on its side as stale.
    async fn reconnect(&mut self, peer: usize, graceful: bool) {
        let op = self.op;
        for arm in &mut self.arms {
            arm.quiesce().await;
            arm.stamp(op);
            arm.discard(peer, op);
        }
        self.session[peer] += 1;
        self.establish(peer, graceful, graceful && self.config[peer].gr)
            .await;
    }

    /// Drain and tick until every subject receiver is clean and quiet.
    async fn quiesce(&mut self) -> Result<(), String> {
        let mut quiet = 0;
        let mut rounds: Vec<Vec<Vec<NormMsg>>> = Vec::new();
        for _ in 0..QUIESCE_ROUNDS {
            self.op += 1;
            let mut round = Vec::new();
            for peer in 0..PEERS {
                round.push(self.arms[SUBJECT].deliver(
                    SUBJECT,
                    peer,
                    self.op,
                    None,
                    &mut self.barriers,
                )?);
            }
            let delivered: usize = round.iter().map(Vec::len).sum();
            rounds.push(round);
            self.tick().await;
            self.end_op().await?;
            if tracing_ops() {
                eprintln!(
                    "op {}: quiesce round, dirty {:?}",
                    self.op,
                    self.dirty.last()
                );
            }
            let clean = !self.dirty.last().unwrap().contains(&true)
                && self.arms[SUBJECT].stamps.iter().all(VecDeque::is_empty);
            quiet = if clean && delivered == 0 {
                quiet + 1
            } else {
                0
            };
            if quiet == QUIET_ROUNDS {
                return Ok(());
            }
        }
        let dirty = *self.dirty.last().unwrap();
        // Known defect: a grouped member with one free slot per tick spends
        // it on a full-table resync, its owed ROUTE-REFRESH response is then
        // refused and re-marks it dirty, and the next tick repeats the same
        // table forever.
        let repeating = (0..PEERS).filter(|&peer| dirty[peer]).all(|peer| {
            let last: Vec<&Vec<NormMsg>> = rounds
                .iter()
                .rev()
                .take(REPEAT_ROUNDS)
                .map(|round| &round[peer])
                .collect();
            self.config[peer].capacity == 1
                && last.iter().all(|sent| {
                    sent.len() == 1
                        && sent[0] == last[0][0]
                        && sent[0].end_of_rib.is_empty()
                        && sent[0].refresh_markers.is_empty()
                })
        });
        let known = if repeating {
            format!(" ({KNOWN_REFRESH_RETRY_LIVELOCK})")
        } else {
            String::new()
        };
        Err(format!(
            "liveness: subject not clean after {QUIESCE_ROUNDS} drain rounds (dirty \
             {dirty:?}){known}"
        ))
    }

    /// Ops in which `peer` was dirty or ran the resync that cleaned it.
    fn deferred_ops(&self, peer: usize) -> BTreeSet<usize> {
        (0..self.dirty.len())
            .filter(|&op| self.dirty[op][peer] || (op > 0 && self.dirty[op - 1][peer]))
            .collect()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the five properties read best side by side"
    )]
    fn check(&self) -> Result<(), String> {
        for barrier in &self.barriers {
            let (session, table) = &self.snapshots[barrier.op][barrier.peer];
            let expected = path_sets(table, Some(barrier.family));
            // Every path the reference holds must have reached the peer
            // ahead of the marker. The peer may still hold routes a pending
            // resync will withdraw: a withdrawal after a marker is an
            // ordinary later UPDATE.
            let complete = expected.iter().all(|(prefix, values)| {
                barrier
                    .state
                    .get(prefix)
                    .is_some_and(|held| values.iter().all(|value| held.contains(value)))
            });
            if *session != barrier.session || !complete {
                return Err(format!(
                    "P3: {} peer {} {} for {:?} produced at op {} (session {}) arrived with \
                     state {:?}; the reference held {:?} (session {session}) after that op",
                    arm_name(barrier.arm),
                    barrier.peer,
                    barrier.kind,
                    barrier.family,
                    barrier.op,
                    barrier.session,
                    barrier.state,
                    expected,
                ));
            }
        }
        for peer in 0..PEERS {
            let reference = &self.arms[REFERENCE].wire[peer];
            let subject = &self.arms[SUBJECT].wire[peer];
            // A prefix a graceful end carried in with different stale paths
            // (the subject lost queued envelopes at the end) converges only
            // at the family's End-of-RIB on the new session.
            let settled = |sets: PathSets| -> PathSets {
                sets.into_iter()
                    .filter(|(prefix, _)| {
                        reference.eor.contains(&prefix.0)
                            || !self
                                .carried
                                .contains(&(peer, reference.session, prefix.clone()))
                    })
                    .collect()
            };
            let routes_match = reference.session == subject.session
                && settled(path_sets(&reference.held, None))
                    == settled(path_sets(&subject.held, None));
            if !routes_match || reference.eor != subject.eor {
                // Known defect: only an initial EoR of a GR + ORF peer is
                // missing.
                let config = self.config[peer];
                let known = if routes_match
                    && config.gr
                    && config.orf
                    && subject.eor.is_subset(&reference.eor)
                {
                    format!(" ({KNOWN_EMPTY_RESYNC_DROPS_REFRESH})")
                } else {
                    String::new()
                };
                return Err(format!(
                    "P1: peer {peer} final wire differs{known}\n reference (session {}, EoR \
                     {:?}): {:?}\n subject (session {}, EoR {:?}): {:?}",
                    reference.session,
                    reference.eor,
                    reference.held,
                    subject.session,
                    subject.eor,
                    subject.held
                ));
            }
            let deferred = self.deferred_ops(peer);
            let covered: BTreeSet<&(u64, Nlri)> = deferred
                .iter()
                .filter_map(|op| reference.touched.get(op))
                .flatten()
                .collect();
            let keys: BTreeSet<&(u64, Nlri)> = reference
                .history
                .keys()
                .chain(subject.history.keys())
                .collect();
            let empty = Vec::new();
            for key in keys {
                let expected = reference.history.get(key).unwrap_or(&empty);
                let actual = subject.history.get(key).unwrap_or(&empty);
                // The two wires entered this session from different held
                // values, so their sequences have no common start.
                if self.carried.contains(&(peer, key.0, key.1.clone())) {
                    continue;
                }
                let relaxed = covered.contains(key);
                let ok = if relaxed {
                    is_subsequence(actual, expected)
                } else if subject.truncated.contains(&key.0) {
                    expected.starts_with(actual)
                } else {
                    actual == expected
                };
                if !ok {
                    return Err(format!(
                        "P4: peer {peer} session {} key {:?} (relaxed: {relaxed})\n reference: \
                         {expected:?}\n subject: {actual:?}",
                        key.0, key.1
                    ));
                }
            }
            let bound = retention_bound(self.config[peer].capacity);
            if self.peak_envelopes[peer] > bound {
                return Err(format!(
                    "P5: peer {peer} queued {} envelopes, over the bound {bound}",
                    self.peak_envelopes[peer]
                ));
            }
        }
        Ok(())
    }

    /// Peak rows queued for each subject receiver.
    fn peak_rows(&self) -> Vec<usize> {
        self.arms[SUBJECT]
            .retention
            .iter()
            .map(|envelopes| {
                (0..=self.op)
                    .map(|op| {
                        envelopes
                            .iter()
                            .filter(|(produced, left, _)| *produced <= op && op < *left)
                            .map(|(_, _, rows)| rows)
                            .sum::<usize>()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .collect()
    }

    async fn finish(self) {
        for arm in self.arms {
            drop(arm.tx);
            arm.handle.await.expect("RIB actor exits cleanly");
        }
    }
}

fn is_subsequence<T: PartialEq>(needle: &[T], haystack: &[T]) -> bool {
    let mut rest = haystack.iter();
    needle
        .iter()
        .all(|item| rest.any(|candidate| candidate == item))
}

/// Peak retention a run observed, for the summary line.
#[derive(Clone, Copy, Debug, Default)]
struct Peaks {
    envelopes: usize,
    rows: usize,
    dirty_ops: usize,
}

fn run(config: [PeerConfig; PEERS], ops: &[Op]) -> Result<Peaks, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a paused runtime");
    runtime.block_on(async {
        let mut harness = Harness::new(config).await?;
        for op in ops {
            harness.apply(op).await?;
        }
        harness.quiesce().await?;
        harness.check()?;
        let peaks = Peaks {
            envelopes: harness.peak_envelopes.iter().copied().max().unwrap_or(0),
            rows: harness.peak_rows().into_iter().max().unwrap_or(0),
            dirty_ops: harness
                .dirty
                .iter()
                .filter(|dirty| dirty.contains(&true))
                .count(),
        };
        harness.finish().await;
        Ok(peaks)
    })
}

fn peer_config_strategy() -> impl Strategy<Value = PeerConfig> {
    (
        proptest::sample::select(&CAPACITIES[..]),
        proptest::sample::select(&SEND_MAX[..]),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(capacity, add_path, enhanced, gr, orf, v6, evpn)| PeerConfig {
                capacity,
                add_path,
                enhanced,
                gr,
                orf,
                v6,
                evpn,
            },
        )
}

/// Peers 0 and 1 share a plain all-family configuration, so their unicast
/// families group while their EVPN feed stays private; 2 and 3 vary.
fn config_strategy() -> impl Strategy<Value = [PeerConfig; PEERS]> {
    (
        proptest::collection::vec(peer_config_strategy(), PEERS),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(peers, gr, enhanced)| {
            let mut config: [PeerConfig; PEERS] = peers.try_into().unwrap();
            for plain in &mut config[..2] {
                *plain = PeerConfig {
                    add_path: 0,
                    orf: false,
                    v6: true,
                    evpn: true,
                    gr,
                    enhanced,
                    ..*plain
                };
            }
            config
        })
}

fn family_strategy() -> impl Strategy<Value = Fam> {
    prop_oneof![3 => Just(Fam::V4), 2 => Just(Fam::V6), 2 => Just(Fam::Evpn)]
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let peer = || 0..PEERS;
    prop_oneof![
        8 => (peer(), family_strategy(), 0..PREFIXES, 0..5u8).prop_map(
            |(src, family, index, variant)| Op::Announce { src, family, index, variant }
        ),
        3 => (peer(), family_strategy(), 0..PREFIXES)
            .prop_map(|(src, family, index)| Op::Withdraw { src, family, index }),
        1 => (peer(), 0..4u8).prop_map(|(peer, variant)| Op::Policy { peer, variant }),
        4 => (peer(), proptest::option::of(0..4u8)).prop_map(|(peer, k)| Op::Drain { peer, k }),
        2 => Just(Op::Tick),
        1 => peer().prop_map(|peer| Op::Flap { peer }),
        2 => (peer(), family_strategy()).prop_map(|(peer, family)| Op::Refresh { peer, family }),
        1 => peer().prop_map(|peer| Op::GrRestart { peer }),
        1 => peer().prop_map(|peer| Op::SourceEor { peer }),
        1 => (peer(), 0..16u8).prop_map(|(peer, deny)| Op::Orf { peer, deny }),
        1 => peer().prop_map(|peer| Op::Replay { peer }),
    ]
}

/// The failed property's label (`P1`..`P5`, `liveness`, `INVALID`), or the
/// panic text.
fn label(reason: &str) -> &str {
    ["P1:", "P2:", "P3:", "P4:", "P5:", "liveness:", "INVALID:"]
        .into_iter()
        .find(|label| reason.contains(label))
        .unwrap_or(reason)
}

/// Greedy one-op deletion to a fixpoint, keeping the failing property.
fn minimize(config: [PeerConfig; PEERS], mut ops: Vec<Op>, reason: &str) -> Vec<Op> {
    let wanted = label(reason).to_string();
    loop {
        let before = ops.len();
        let mut index = 0;
        while index < ops.len() {
            let mut fewer = ops.clone();
            fewer.remove(index);
            if run(config, &fewer).is_err_and(|reason| label(&reason) == wanted) {
                ops = fewer;
            } else {
                index += 1;
            }
        }
        if ops.len() == before {
            return ops;
        }
    }
}

#[test]
fn stalled_receivers_converge_to_the_unbounded_reference() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let strategy = (
        config_strategy(),
        proptest::collection::vec(op_strategy(), 1..48),
    );
    let strict = std::env::var_os("ORACLE_STRICT").is_some();
    let peaks = std::cell::Cell::new(Peaks::default());
    let allowed = std::cell::Cell::new([0_usize; KNOWN.len()]);
    let result = runner.run(&strategy, |(config, ops)| {
        let observed = match run(config, &ops) {
            Err(reason) if !strict && KNOWN.iter().any(|known| reason.contains(known)) => {
                let mut counts = allowed.get();
                for (count, known) in counts.iter_mut().zip(KNOWN) {
                    *count += usize::from(reason.contains(known));
                }
                allowed.set(counts);
                return Ok(());
            }
            observed => observed.map_err(TestCaseError::fail)?,
        };
        let seen = peaks.get();
        peaks.set(Peaks {
            envelopes: seen.envelopes.max(observed.envelopes),
            rows: seen.rows.max(observed.rows),
            dirty_ops: seen.dirty_ops + observed.dirty_ops,
        });
        Ok(())
    });
    eprintln!("stalled-receiver oracle peaks: {:?}", peaks.get());
    for (known, count) in KNOWN.iter().zip(allowed.get()) {
        eprintln!("stalled-receiver oracle cases allowed as {known}: {count}");
    }
    let Err(error) = result else {
        return;
    };
    let proptest::test_runner::TestError::Fail(reason, (config, ops)) = error else {
        panic!("{error}");
    };
    let reason = reason.to_string();
    let ops = minimize(config, ops, &reason);
    let reason = run(config, &ops).err().unwrap_or(reason);
    panic!("{reason}\nconfig: {config:#?}\nops: {ops:#?}");
}

/// Minimized by the oracle. Peer 0 is a grouped unicast member with a
/// one-envelope channel that its receiver empties once per resync tick. A
/// ROUTE-REFRESH arrives while the channel holds the initial End-of-RIB, so
/// the response is refused and owed. Each later tick, the dirty resync sends
/// the member's whole table into the one free slot, the owed response
/// (`retry_pending_refresh` straight after the resync commit) finds the
/// channel full and marks the member dirty again, and the next tick sends
/// the same table. The refresh never completes. Un-ignore with the fix.
#[test]
#[ignore = "open defect: grouped refresh-retry livelock at one free slot"]
fn grouped_refresh_retry_converges_with_one_free_slot() {
    run(livelock_config(), &livelock_ops()).unwrap();
}

/// The default run tolerates the open livelock only by its exact signature.
#[test]
fn known_refresh_retry_livelock_signature_matches_its_trace() {
    let reason = run(livelock_config(), &livelock_ops()).expect_err("the open livelock reproduces");
    assert!(reason.contains(KNOWN_REFRESH_RETRY_LIVELOCK), "{reason}");
}

fn livelock_config() -> [PeerConfig; PEERS] {
    let plain = |all| PeerConfig {
        capacity: 1,
        add_path: 0,
        enhanced: false,
        gr: false,
        orf: false,
        v6: all,
        evpn: all,
    };
    [plain(true), plain(true), plain(false), plain(false)]
}

fn livelock_ops() -> Vec<Op> {
    vec![
        Op::Refresh {
            peer: 0,
            family: Fam::V4,
        },
        Op::Announce {
            src: 1,
            family: Fam::V4,
            index: 0,
            variant: 0,
        },
        Op::Announce {
            src: 1,
            family: Fam::V4,
            index: 1,
            variant: 0,
        },
    ]
}

/// Minimized by the oracle. Peer 3 negotiated GR and an IPv4 prefix ORF and
/// has a one-envelope channel. After a NOTIFICATION flap, its new session's
/// initial IPv4 `EoR` waits for the first ROUTE-REFRESH (RFC 5291 §6). That
/// refresh arrives while the channel still holds the EVPN `EoR`, so its
/// answer is refused and owed (`pending_refresh`) and the peer is marked
/// dirty. The dirty resync then finds an empty export view and takes the
/// empty-inventory path in `distribute_changes`, which clears the dirty
/// mark without `flush_pending_eor` or `retry_pending_refresh` (the two
/// other clear sites call both). The refresh is never answered and the
/// IPv4 `EoR` is never sent (RFC 4724 §4). Un-ignore with the fix.
#[test]
#[ignore = "open defect: empty-view resync drops an owed refresh and its initial EoR"]
fn refused_gate_lifting_refresh_still_sends_the_initial_eor() {
    run(lost_eor_config(), &lost_eor_ops()).unwrap();
}

#[test]
fn known_empty_resync_signature_matches_its_trace() {
    let reason = run(lost_eor_config(), &lost_eor_ops()).expect_err("the open defect reproduces");
    assert!(
        reason.contains(KNOWN_EMPTY_RESYNC_DROPS_REFRESH),
        "{reason}"
    );
}

fn lost_eor_config() -> [PeerConfig; PEERS] {
    let mut config = livelock_config();
    config[3] = PeerConfig {
        gr: true,
        orf: true,
        evpn: true,
        ..config[3]
    };
    config
}

fn lost_eor_ops() -> Vec<Op> {
    vec![
        Op::Flap { peer: 3 },
        Op::Refresh {
            peer: 3,
            family: Fam::V4,
        },
    ]
}

/// Minimized by the oracle. Peers 0 and 1 are grouped and negotiated RFC
/// 7313. Peer 1 (three envelopes) holds peer 0's IPv6 route; peer 0 flaps
/// while peer 1's channel is full, so peer 1 goes dirty owing the
/// withdrawal. Peer 1 then sends a ROUTE-REFRESH for IPv6: the answer is
/// `BoRR`, the current (empty) table and `EoRR`, so the peer purges the route
/// (RFC 7313 §4). The member's owed withdrawal survives the refresh, and the
/// next dirty resync withdraws a route the peer no longer holds. Un-ignore
/// with the fix.
#[test]
#[ignore = "open defect: resync withdraws a route an EoRR already purged"]
fn refresh_answer_settles_withdrawals_owed_to_a_dirty_member() {
    run(purge_config(), &purge_ops()).unwrap();
}

#[test]
fn known_withdrawal_after_eorr_purge_signature_matches_its_trace() {
    let reason = run(purge_config(), &purge_ops()).expect_err("the open defect reproduces");
    assert!(
        reason.contains(KNOWN_WITHDRAWAL_AFTER_EORR_PURGE),
        "{reason}"
    );
}

fn purge_config() -> [PeerConfig; PEERS] {
    let mut config = livelock_config();
    config[0].enhanced = true;
    config[1] = PeerConfig {
        capacity: 3,
        enhanced: true,
        ..config[1]
    };
    config
}

fn purge_ops() -> Vec<Op> {
    vec![
        Op::Announce {
            src: 0,
            family: Fam::V6,
            index: 0,
            variant: 0,
        },
        Op::Announce {
            src: 2,
            family: Fam::V4,
            index: 0,
            variant: 0,
        },
        Op::Flap { peer: 0 },
        Op::Drain { peer: 1, k: None },
        Op::Refresh {
            peer: 1,
            family: Fam::V6,
        },
    ]
}
