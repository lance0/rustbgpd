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
//! is dirty. Each records a changed value only, so a one-off duplicate of an
//! unchanged route or table is invisible by construction:
//!
//! - P1, final state: each receiver's wire state (and the families it has
//!   seen an `EoR` for) equals the reference arm's. Each prefix is compared
//!   as its set of paths, since RFC 7911 path IDs are opaque. Stale paths a
//!   graceful end carried in with different values are compared only once
//!   their family's `EoR` has arrived.
//! - P2, no spurious withdrawal: never a withdrawal of a key the receiver
//!   does not hold.
//! - P3, barriers: no `BoRR` before the session's initial `EoR` for that
//!   family (RFC 7313 §4), `EoRR` only inside an open `BoRR`, every `BoRR`
//!   closed by an `EoRR` once quiet, and a replay terminal carrying markers
//!   only. At every `EoR`, `EoRR` and replay terminal the family's wire state
//!   equals the reference's after the operation that produced the marker
//!   (RFC 4724 §4, RFC 7313 §4, RFC 5291 §6). While the subject receiver is
//!   deferred, it need only hold every reference path: routes a pending
//!   resync still owes a withdrawal may remain, as that withdrawal is an
//!   ordinary later UPDATE.
//! - P4, per-key sequence: per (receiver, session, key), the collapsed value
//!   sequence, each value stamped with the operation that produced it,
//!   equals the reference's, or is a prefix of it for a key a flap discarded
//!   queued envelopes of. The key relaxes only inside a deferral: the
//!   operations in which the subject receiver was dirty, owed a
//!   refresh answer in the key's family, or owed the key or its whole family
//!   (ADR-0145 slice 1b's logged deferral, read through the product's test
//!   hook once per operation and session), through the settling operation.
//!   Inside an interval the subject's values are a
//!   subsequence of the reference's and match its state at the interval's
//!   close; outside every interval they match exactly. A key a graceful end
//!   carried into the session with a different value has no common starting
//!   point; P1-P3 still apply
//!   to it.
//! - P5, bounded retention: the peak queued envelopes per receiver stay
//!   within [`retention_bound`]. Peak queued rows are recorded too, so a
//!   later bound can pin them.
//!
//! `PROPTEST_CASES` and `PROPTEST_RNG_SEED` select the run; a failure is
//! shrunk by proptest and then by one-op deletion, and printed as a trace.
//! `ORACLE_TRACE=1` prints each operation and delivered envelope.
//!
//! An open defect may be tolerated only by its exact signature
//! ([`KNOWN`], empty now), with an ignored regression test holding its
//! minimized trace. A tolerated defect excuses only its own observation:
//! the case still runs every other property. `ORACLE_STRICT=1` reports it as
//! a failure. A run of the default case count or more also fails when any
//! [`Coverage`] counter stays at zero.
//!
//! The actor's wall-clock poll budget is unbounded here, as in the EVPN
//! recovery differential, so a loaded host cannot reslice a resync tick and
//! `RUSTBGPD_TEST_FLUSH_BUDGET_US` has no effect. Outcomes are reproducible
//! for a seed; exact traces can vary by one resync where the manager iterates
//! a hash set.
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
use crate::update::{OutboundOwed, OutboundRouteUpdate};

const PEERS: usize = 4;
const PREFIXES: u8 = 4;
const REFERENCE: usize = 0;
const SUBJECT: usize = 1;
/// "Unbounded" for the reference arm: never reached by a case.
const REFERENCE_CAPACITY: usize = 1 << 20;
/// 4096 is the lag-free control; the rest fill under the generated churn.
const CAPACITIES: [usize; 7] = [1, 2, 3, 4, 6, 8, 4096];
/// 0 is no Add-Path; `u32::MAX` is what negotiation maps send-all to.
const SEND_MAX: [u32; 5] = [0, 1, 2, 8, u32::MAX];
const CLUSTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TICK: Duration = Duration::from_millis(1010);
/// Rounds of drain + tick before the subject must be clean.
const QUIESCE_ROUNDS: usize = 48;
/// Consecutive quiet rounds that end quiescence.
const QUIET_ROUNDS: usize = 3;
/// The default case count, below which coverage floors are not enforced.
const DEFAULT_CASES: u32 = 256;
/// Every tolerated open-defect signature; `ORACLE_STRICT=1` reports them.
/// None is open now.
const KNOWN: [&str; 0] = [];

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
/// An envelope's producing operation and resulting path set.
type HistoryEvent = (usize, Vec<Value>);

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

/// One owed key, or a family owed whole (`None`), as the product's test hook
/// reports it: the family, then the key rendered like [`Nlri`]'s.
type Owed = ((u16, u8), Option<String>);

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
    eor: BTreeSet<(u16, u8)>,
    /// Collapsed per-(session, prefix) path-set sequence, one entry per
    /// envelope that changed it, with the operation that produced the
    /// envelope; the empty set is "not held".
    history: BTreeMap<(u64, Nlri), Vec<HistoryEvent>>,
    /// Equal GR-retained paths are the starting value of a new session.
    initial: BTreeMap<(u64, Nlri), Vec<Value>>,
    /// Each prefix's set when its envelope began, until [`Self::commit`].
    before: BTreeMap<Nlri, Vec<Value>>,
    /// First producing operation a flap discarded an envelope for, by
    /// (session, prefix). Earlier clean operations still compare exactly.
    discarded_from: BTreeMap<(u64, Nlri), usize>,
    /// Known-defect signatures this wire tolerated.
    tolerated: BTreeSet<&'static str>,
}

impl Wire {
    /// Replay a discarded queue without changing the receiver's real state.
    fn discard_shadow(&self) -> Self {
        Self {
            session: self.session,
            enhanced: self.enhanced,
            held: self.held.clone(),
            gr_stale: self.gr_stale.clone(),
            refresh_stale: self.refresh_stale.clone(),
            eor: self.eor.clone(),
            ..Self::default()
        }
    }

    /// Markers can remove stale keys without carrying an explicit withdrawal.
    fn discarded_changes(
        &mut self,
        peer: usize,
        op: usize,
        message: NormMsg,
        replay: bool,
    ) -> BTreeSet<Nlri> {
        self.apply(SUBJECT, peer, op, message, replay, None)
            .expect("discarded envelopes do not validate delivery");
        std::mem::take(&mut self.history)
            .into_keys()
            .map(|(_, prefix)| prefix)
            .collect()
    }

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
        self.initial.extend(
            path_sets(&self.held, None)
                .into_iter()
                .map(|(key, values)| ((session, key), values)),
        );
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
                    .entry((self.session, prefix))
                    .or_default()
                    .push((op, after));
            }
        }
    }

    /// Replay one envelope; absent barriers mean a discarded shadow, not delivery.
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
        mut barriers: Option<&mut Vec<Barrier>>,
    ) -> Result<(), String> {
        let delivered = barriers.is_some();
        let NormMsg {
            announce,
            withdraw,
            mut end_of_rib,
            mut refresh_markers,
            evpn_announce,
            evpn_withdraw,
            ..
        } = message;
        let session = self.session;
        let where_ = |what: &str| {
            format!(
                "{what} ({} peer {peer} session {session}, produced at op {op})",
                arm_name(arm)
            )
        };
        // `transport/src/session/replay.rs` sends only the markers of an
        // envelope that carries a replay token.
        if delivered
            && replay
            && !(announce.is_empty()
                && withdraw.is_empty()
                && evpn_announce.is_empty()
                && evpn_withdraw.is_empty()
                && refresh_markers.is_empty())
        {
            return Err(where_(
                "P3: a replay terminal carries rows or refresh markers",
            ));
        }
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
        for (afi, safi, _) in refresh_markers
            .iter()
            .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::BoRR)
        {
            let family = wire_family((*afi, *safi));
            if delivered && !self.eor.contains(&family) {
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
            if delivered && !self.held.contains_key(key) {
                return Err(where_(&format!(
                    "P2: withdrawal of {key:?}, which the receiver does not hold"
                )));
            }
            self.record(key, None);
            self.gr_stale.remove(key);
            for stale in self.refresh_stale.values_mut() {
                stale.remove(key);
            }
        }
        for (key, value) in announced {
            self.record(&key, Some(value));
            self.gr_stale.remove(&key);
            for stale in self.refresh_stale.values_mut() {
                stale.remove(&key);
            }
        }
        let mut barrier = |wire: &mut Self, family, kind| {
            wire.commit(op);
            if let Some(barriers) = &mut barriers {
                barriers.push(Barrier {
                    arm,
                    peer,
                    session: wire.session,
                    family,
                    op,
                    kind,
                    state: path_sets(&wire.held, Some(family)),
                });
            }
        };
        for (afi, safi, _) in refresh_markers
            .iter()
            .filter(|(_, _, kind)| *kind == RouteRefreshSubtype::EoRR)
        {
            let family = wire_family((*afi, *safi));
            let Some(stale) = self.refresh_stale.remove(&family) else {
                if delivered {
                    return Err(where_(&format!("P3: EoRR for {family:?} without a BoRR")));
                }
                continue;
            };
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
    fn spawn(arm: usize, subject_credit: Option<usize>) -> Self {
        let (tx, rx) = mpsc::channel(512);
        let mut manager =
            RibManager::new(rx, dummy_query_rx(), None, Some(CLUSTER), BgpMetrics::new());
        // Every resync tick runs to completion, whatever the host load.
        manager.flush_poll_budget = Duration::MAX;
        // A credit override applies to the subject; the reference keeps the
        // default credit, which no case reaches.
        if arm == REFERENCE {
            manager.outbound_row_credit_override = None;
        } else if let Some(credit) = subject_credit {
            manager.outbound_row_credit_override = Some(credit);
        }
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
    async fn round_trip(&self) {
        let (reply, response) = oneshot::channel();
        self.send(RibUpdate::QueryBestRoutes {
            deadline: full_snapshot_query_deadline(),
            reply,
        })
        .await;
        response.await.expect("RIB actor alive");
    }

    /// What `peer` is owed, read once (the read consumes the product's log
    /// of keys marked since the previous one): the refresh answers deferred
    /// behind a live whole-table operation or a full channel (not a dirty
    /// resync), and the private-family keys and whole families owed now or
    /// since the previous read.
    async fn owed_state(&self, peer: usize) -> OutboundOwed {
        let (reply, response) = oneshot::channel();
        self.send(RibUpdate::TestQueryPeerOutboundOwed {
            peer: peer_id(peer),
            reply,
        })
        .await;
        response.await.expect("RIB actor alive")
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
            + update.unicast_withdrawals().count()
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
                Some(&mut *barriers),
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
        let wire = &mut self.wire[peer];
        let mut shadow = wire.discard_shadow();
        while let Ok(update) = rx.try_recv() {
            let produced = self.stamps[peer].pop_front().expect("stamped");
            self.retention[peer].push((produced, op, Self::rows(&update)));
            let message = normalize(&update);
            let prefixes = message
                .announce
                .iter()
                .map(|row| (row.0, row.1))
                .chain(message.unicast_withdrawals().copied())
                .map(|(prefix, path_id)| Key {
                    family: match prefix {
                        Prefix::V4(_) => V4,
                        Prefix::V6(_) => V6,
                    },
                    nlri: prefix.to_string(),
                    path_id,
                })
                .chain(
                    message
                        .evpn_announce
                        .iter()
                        .map(|row| row.0.clone())
                        .chain(message.evpn_withdraw.iter().cloned())
                        .map(|nlri| Key {
                            family: EVPN,
                            nlri,
                            path_id: 0,
                        }),
                );
            for key in prefixes {
                wire.discarded_from
                    .entry((wire.session, nlri(&key)))
                    .or_insert(produced);
            }
            for prefix in shadow.discarded_changes(peer, produced, message, update.replay.is_some())
            {
                wire.discarded_from
                    .entry((wire.session, prefix))
                    .or_insert(produced);
            }
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
    /// Subject queue depth after the previous operation.
    depths: [usize; PEERS],
    /// Subject refresh-answer debt after each operation: the families each
    /// peer is owed an answer in.
    refresh_owed: Vec<[BTreeSet<(u16, u8)>; PEERS]>,
    /// Subject owed keys after each operation (and marked during it).
    owed: Vec<[BTreeSet<Owed>; PEERS]>,
    /// Owed keys still pending at the end of each operation, excluding
    /// marks already settled in that operation.
    owed_pending: Vec<[BTreeSet<Owed>; PEERS]>,
    tolerated: BTreeSet<&'static str>,
    coverage: Coverage,
}

impl Harness {
    async fn new(
        config: [PeerConfig; PEERS],
        subject_credit: Option<usize>,
    ) -> Result<Self, String> {
        let mut harness = Self {
            config,
            arms: [
                Arm::spawn(REFERENCE, subject_credit),
                Arm::spawn(SUBJECT, subject_credit),
            ],
            session: [1; PEERS],
            restarting: [false; PEERS],
            op: 0,
            barriers: Vec::new(),
            snapshots: Vec::new(),
            dirty: Vec::new(),
            carried: BTreeSet::new(),
            peak_envelopes: [0; PEERS],
            depths: [0; PEERS],
            refresh_owed: Vec::new(),
            owed: Vec::new(),
            owed_pending: Vec::new(),
            tolerated: BTreeSet::new(),
            coverage: Coverage::default(),
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
        // The actor can serve the first round trip ahead of the resync timer
        // that woke with it, but it runs that resync before the second.
        for arm in &self.arms {
            arm.round_trip().await;
        }
        for arm in &self.arms {
            arm.round_trip().await;
        }
    }

    /// Finish operation `self.op`: drain the reference, stamp the subject,
    /// record the reference wire and the subject's dirty state.
    async fn end_op(&mut self) -> Result<(), String> {
        for arm in &self.arms {
            arm.round_trip().await;
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
        let mut refresh_owed: [BTreeSet<(u16, u8)>; PEERS] = Default::default();
        let mut owed: [BTreeSet<Owed>; PEERS] = Default::default();
        let mut owed_pending: [BTreeSet<Owed>; PEERS] = Default::default();
        let was_dirty = self.dirty.last().copied().unwrap_or_default();
        for peer in 0..PEERS {
            self.peak_envelopes[peer] = self.peak_envelopes[peer].max(depths[peer]);
            let capacity = self.config[peer].capacity;
            if depths[peer] == capacity && self.depths[peer] < capacity {
                self.coverage.capacity_crossings += 1;
            }
            if self.arms[REFERENCE].dirty(peer).await {
                return Err(format!(
                    "INVALID: the reference arm marked peer {peer} dirty at op {op}"
                ));
            }
            dirty[peer] = self.arms[SUBJECT].dirty(peer).await;
            if dirty[peer] && !was_dirty[peer] {
                self.coverage.dirty_episodes += 1;
            }
            let debt = self.arms[SUBJECT].owed_state(peer).await;
            refresh_owed[peer] = debt.refresh.into_iter().map(wire_family).collect();
            owed[peer] = debt.owed.into_iter().collect();
            owed_pending[peer] = debt.owed_pending.into_iter().collect();
            if !owed[peer].is_empty() {
                self.coverage.owing_ops += 1;
            }
            if !self.arms[REFERENCE].owed_state(peer).await.owed.is_empty() {
                return Err(format!(
                    "INVALID: the reference arm owed keys to peer {peer} at op {op}"
                ));
            }
        }
        self.depths = depths.try_into().expect("one depth per peer");
        self.dirty.push(dirty);
        self.refresh_owed.push(refresh_owed);
        self.owed.push(owed);
        self.owed_pending.push(owed_pending);
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
        let dirty = self.dirty.last().copied().unwrap_or_default();
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
                // The reply arrives at commit; the round trip below orders it.
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
                self.coverage.flaps_while_dirty += usize::from(dirty[peer]);
                self.both(|| RibUpdate::PeerDown {
                    peer: peer_id(peer),
                    session_id,
                })
                .await;
                self.reconnect(peer, false).await;
            }
            Op::Refresh { peer, family } => {
                if self.config[peer].carries(family) {
                    let backlog = dirty[peer] || !self.arms[SUBJECT].stamps[peer].is_empty();
                    self.coverage.refreshes_during_backlog += usize::from(backlog);
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
                    self.coverage.flaps_while_dirty += usize::from(dirty[peer]);
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
                    self.coverage.gr_sweeps += 1;
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
                    // The push lifts a gate still holding a GR peer's initial
                    // IPv4 EoR. The reference is drained after every op, so a
                    // missing EoR there is held, not merely queued.
                    let held =
                        self.config[peer].gr && !self.arms[REFERENCE].wire[peer].eor.contains(&V4);
                    self.coverage.orf_holds += usize::from(held);
                    let session_id = self.session[peer];
                    for arm in &mut self.arms {
                        let reply = arm.reply();
                        arm.send(RibUpdate::PeerOrfUpdate {
                            peer: peer_id(peer),
                            session_id,
                            afi: Afi::Ipv4,
                            safi: Safi::Unicast,
                            when: WhenToRefresh::Immediate,
                            groups: vec![orf_entries(deny)],
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
            arm.round_trip().await;
            arm.stamp(op);
            arm.discard(peer, op);
            // The test log is peer-keyed; old-session marks end at this fence.
            let _ = arm.owed_state(peer).await;
        }
        self.session[peer] += 1;
        self.establish(peer, graceful, graceful && self.config[peer].gr)
            .await;
    }

    /// Drain and tick until every subject receiver is clean and quiet.
    async fn drain_until_quiet(&mut self) -> Result<(), String> {
        let mut quiet = 0;
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
            self.tick().await;
            self.end_op().await?;
            if tracing_ops() {
                eprintln!("op {}: drain round, dirty {:?}", self.op, self.dirty.last());
            }
            let clean = !self.dirty.last().unwrap().contains(&true)
                && self
                    .refresh_owed
                    .last()
                    .unwrap()
                    .iter()
                    .all(BTreeSet::is_empty)
                && self.owed.last().unwrap().iter().all(BTreeSet::is_empty)
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
        let refresh_owed = self.refresh_owed.last().unwrap();
        let owed = self.owed.last().unwrap();
        Err(format!(
            "liveness: subject not clean after {QUIESCE_ROUNDS} drain rounds (dirty \
             {dirty:?}, refresh answers owed {refresh_owed:?}, keys owed {owed:?})"
        ))
    }

    /// Deferrals of one (peer, session, key), closed at the operation that
    /// settled its last debt. A same-op mark and settlement never relaxes
    /// the following clean operation.
    fn deferrals(&self, peer: usize, key: &(u64, Nlri)) -> Vec<Deferral> {
        let (_, (family, nlri)) = key;
        let names_key = |owed: &BTreeSet<Owed>| {
            owed.contains(&(*family, None)) || owed.contains(&(*family, Some(nlri.clone())))
        };
        deferral_intervals(
            self.snapshots.len(),
            key.0,
            |op| self.snapshots[op][peer].0,
            |op| {
                self.dirty[op][peer]
                    || self.refresh_owed[op][peer].contains(family)
                    || names_key(&self.owed_pending[op][peer])
            },
            |op| names_key(&self.owed[op][peer]),
        )
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
    fn check(&mut self) -> Result<(), String> {
        // RFC 7313 §4: every BoRR is closed by an EoRR once both arms are
        // quiet.
        for (arm, side) in self.arms.iter().enumerate() {
            for (peer, wire) in side.wire.iter().enumerate() {
                if let Some(family) = wire.refresh_stale.keys().next() {
                    return Err(format!(
                        "P3: {} peer {peer} BoRR for {family:?} never closed by an EoRR",
                        arm_name(arm)
                    ));
                }
            }
        }
        let deferred: Vec<BTreeSet<usize>> =
            (0..PEERS).map(|peer| self.deferred_ops(peer)).collect();
        for barrier in &self.barriers {
            let (session, table) = &self.snapshots[barrier.op][barrier.peer];
            let expected = path_sets(table, Some(barrier.family));
            // A deferred subject receiver must hold every reference path
            // ahead of the marker, but may still hold routes a pending resync
            // will withdraw: a withdrawal after a marker is an ordinary later
            // UPDATE. Otherwise the family matches exactly.
            let complete = if barrier.arm == SUBJECT && deferred[barrier.peer].contains(&barrier.op)
            {
                expected.iter().all(|(prefix, values)| {
                    barrier
                        .state
                        .get(prefix)
                        .is_some_and(|held| values.iter().all(|value| held.contains(value)))
                })
            } else {
                expected == barrier.state
            };
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
                return Err(format!(
                    "P1: peer {peer} final wire differs\n reference (session {}, EoR \
                     {:?}): {:?}\n subject (session {}, EoR {:?}): {:?}",
                    reference.session,
                    reference.eor,
                    reference.held,
                    subject.session,
                    subject.eor,
                    subject.held
                ));
            }
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
                // Only envelopes the queue actually discarded bound this suffix.
                let discarded_from = subject.discarded_from.get(key).copied();
                let initial = reference.initial.get(key).map_or(&[][..], Vec::as_slice);
                let verdict = compare_in_deferrals(
                    expected,
                    actual,
                    initial,
                    &self.deferrals(peer, key),
                    discarded_from,
                );
                if let Err(reason) = verdict {
                    return Err(format!(
                        "P4: peer {peer} session {} key {:?}: {reason}\n reference: \
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

/// One key's deferral on one session. A flap interrupts an interval;
/// otherwise its final operation must settle on the reference state.
#[derive(Debug, PartialEq, Eq)]
struct Deferral {
    start: usize,
    end: usize,
    settled: bool,
}

fn deferral_intervals(
    ops: usize,
    session: u64,
    session_at: impl Fn(usize) -> u64,
    pending: impl Fn(usize) -> bool,
    marked: impl Fn(usize) -> bool,
) -> Vec<Deferral> {
    let mut intervals = Vec::new();
    let mut start = None;
    for op in 0..ops {
        if session_at(op) != session {
            if let Some(start) = start.take() {
                intervals.push(Deferral {
                    start,
                    end: op - 1,
                    settled: false,
                });
            }
            continue;
        }
        let pending = pending(op);
        if pending || marked(op) {
            start.get_or_insert(op);
        }
        if !pending && let Some(start) = start.take() {
            intervals.push(Deferral {
                start,
                end: op,
                settled: true,
            });
        }
    }
    if let Some(start) = start {
        intervals.push(Deferral {
            start,
            end: ops - 1,
            settled: false,
        });
    }
    intervals
}

/// Exact event values outside deferrals, an ordered subsequence inside,
/// and equal state at every settled close. `discarded_from` is the first
/// producing operation whose envelope the queue actually discarded.
/// At that operation only, a delivered prefix is valid: one operation can
/// enqueue several envelopes and a flap can discard a suffix of them.
fn compare_in_deferrals(
    expected: &[HistoryEvent],
    actual: &[HistoryEvent],
    initial: &[Value],
    intervals: &[Deferral],
    discarded_from: Option<usize>,
) -> Result<(), String> {
    let within = |events: &[HistoryEvent], start: usize, end: usize| {
        events
            .iter()
            .filter(|(op, _)| (start..=end).contains(op))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>()
    };
    let state_at = |events: &[HistoryEvent], end: usize| {
        events
            .iter()
            .take_while(|(op, _)| *op <= end)
            .last()
            .map_or_else(|| initial.to_vec(), |(_, value)| value.clone())
    };
    let last = discarded_from.unwrap_or(usize::MAX);
    let mut start = 0;
    for interval in intervals
        .iter()
        .take_while(|interval| interval.start <= last)
    {
        if start < interval.start
            && within(actual, start, interval.start - 1)
                != within(expected, start, interval.start - 1)
        {
            return Err(format!(
                "outside any deferral, ops {start}..{} differ",
                interval.start
            ));
        }
        let end = interval.end.min(last);
        if !is_subsequence(
            &within(actual, interval.start, end),
            &within(expected, interval.start, end),
        ) {
            return Err(format!(
                "inside the deferral at ops {}..={end}, not a subsequence",
                interval.start
            ));
        }
        if interval.settled
            && discarded_from.is_none_or(|last| interval.end < last)
            && state_at(actual, end) != state_at(expected, end)
        {
            return Err(format!(
                "the deferral at ops {}..={end} closed on a different state",
                interval.start
            ));
        }
        if end == last {
            return Ok(());
        }
        start = end + 1;
    }
    if discarded_from.is_some() {
        if start < last && within(actual, start, last - 1) != within(expected, start, last - 1) {
            return Err(format!("outside any deferral, ops {start}..{last} differ"));
        }
        if !within(expected, last, last).starts_with(&within(actual, last, last)) {
            return Err(format!("outside any deferral, op {last} is not a prefix"));
        }
    } else if within(actual, start, last) != within(expected, start, last) {
        return Err(format!("outside any deferral, ops {start}..={last} differ"));
    }
    Ok(())
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
}

/// How often a run reached each backpressure state. A run of the default
/// case count fails if any stays at zero, so a change that stops producing
/// one cannot leave the oracle quietly vacuous.
#[derive(Clone, Copy, Debug, Default)]
struct Coverage {
    /// A subject queue reached its capacity.
    capacity_crossings: usize,
    /// A subject receiver went from clean to dirty.
    dirty_episodes: usize,
    /// A flap or GR restart of a dirty receiver.
    flaps_while_dirty: usize,
    /// A ROUTE-REFRESH from a receiver that was dirty or had queued output.
    refreshes_during_backlog: usize,
    /// A restarted source's End-of-RIB swept its stale routes.
    gr_sweeps: usize,
    /// An ORF push lifted a gate that still held the initial IPv4 `EoR`.
    orf_holds: usize,
    /// Operations after which a subject receiver owed keys. Reported, not a
    /// floor: only a small row credit makes receivers owe.
    owing_ops: usize,
}

impl Coverage {
    fn add(&mut self, other: Self) {
        self.capacity_crossings += other.capacity_crossings;
        self.dirty_episodes += other.dirty_episodes;
        self.flaps_while_dirty += other.flaps_while_dirty;
        self.refreshes_during_backlog += other.refreshes_during_backlog;
        self.gr_sweeps += other.gr_sweeps;
        self.orf_holds += other.orf_holds;
        self.owing_ops += other.owing_ops;
    }

    fn missing(&self) -> Vec<&'static str> {
        [
            ("capacity_crossings", self.capacity_crossings),
            ("dirty_episodes", self.dirty_episodes),
            ("flaps_while_dirty", self.flaps_while_dirty),
            ("refreshes_during_backlog", self.refreshes_during_backlog),
            ("gr_sweeps", self.gr_sweeps),
            ("orf_holds", self.orf_holds),
        ]
        .into_iter()
        .filter(|(_, count)| *count == 0)
        .map(|(name, _)| name)
        .collect()
    }
}

/// A case that held every property, apart from the known defects it
/// tolerated.
struct Outcome {
    peaks: Peaks,
    coverage: Coverage,
    tolerated: BTreeSet<&'static str>,
}

/// [`run`], with a panic turned into a failure (so minimizing and the final
/// rerun keep the trace) and each tolerated known defect turned into one
/// when `strict`.
fn evaluate(config: [PeerConfig; PEERS], ops: &[Op], strict: bool) -> Result<Outcome, String> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(config, ops)))
        .unwrap_or_else(|panic| Err(format!("panic: {}", panic_message(&*panic))))?;
    if strict && let Some(known) = outcome.tolerated.first() {
        return Err(format!("{known} (ORACLE_STRICT)"));
    }
    Ok(outcome)
}

/// The panic's message.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
        .unwrap_or_default()
}

fn run(config: [PeerConfig; PEERS], ops: &[Op]) -> Result<Outcome, String> {
    run_seeded(config, ops, |_| {})
}

/// [`run`], with `seed` applied to the quiet harness just before the
/// properties are checked: a checker's red proof plants a broken observation.
fn run_seeded(
    config: [PeerConfig; PEERS],
    ops: &[Op],
    seed: impl FnOnce(&mut Harness),
) -> Result<Outcome, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a paused runtime");
    runtime.block_on(async {
        let mut harness = Harness::new(config, None).await?;
        for op in ops {
            harness.apply(op).await?;
        }
        harness.drain_until_quiet().await?;
        seed(&mut harness);
        harness.check()?;
        let mut tolerated = std::mem::take(&mut harness.tolerated);
        for arm in &harness.arms {
            for wire in &arm.wire {
                tolerated.extend(wire.tolerated.iter().copied());
            }
        }
        let outcome = Outcome {
            peaks: Peaks {
                envelopes: harness.peak_envelopes.iter().copied().max().unwrap_or(0),
                rows: harness.peak_rows().into_iter().max().unwrap_or(0),
            },
            coverage: harness.coverage,
            tolerated,
        };
        harness.finish().await;
        Ok(outcome)
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
        4 => (peer(), proptest::option::of(1..4u8)).prop_map(|(peer, k)| Op::Drain { peer, k }),
        2 => Just(Op::Tick),
        1 => peer().prop_map(|peer| Op::Flap { peer }),
        2 => (peer(), family_strategy()).prop_map(|(peer, family)| Op::Refresh { peer, family }),
        1 => peer().prop_map(|peer| Op::GrRestart { peer }),
        1 => peer().prop_map(|peer| Op::SourceEor { peer }),
        3 => (peer(), 0..16u8).prop_map(|(peer, deny)| Op::Orf { peer, deny }),
        1 => peer().prop_map(|peer| Op::Replay { peer }),
    ]
}

/// The failed property's label (`P1`..`P5`, `liveness`, `INVALID`), the
/// known signature a strict run reports, or the panic text.
fn label(reason: &str) -> &str {
    KNOWN
        .into_iter()
        .chain(["P1:", "P2:", "P3:", "P4:", "P5:", "liveness:", "INVALID:"])
        .find(|label| reason.contains(label))
        .unwrap_or(reason)
}

/// Greedy one-op deletion to a fixpoint, keeping the failing property. A
/// default run never fails on a tolerated signature, so shrinking cannot
/// land on a known defect in place of the failure that was found.
fn minimize(config: [PeerConfig; PEERS], mut ops: Vec<Op>, reason: &str, strict: bool) -> Vec<Op> {
    let wanted = label(reason).to_string();
    loop {
        let before = ops.len();
        let mut index = 0;
        while index < ops.len() {
            let mut fewer = ops.clone();
            fewer.remove(index);
            if evaluate(config, &fewer, strict).is_err_and(|reason| label(&reason) == wanted) {
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
    let cases = runner.config().cases;
    let strict = std::env::var_os("ORACLE_STRICT").is_some();
    let peaks = std::cell::Cell::new(Peaks::default());
    let coverage = std::cell::Cell::new(Coverage::default());
    let checked = std::cell::Cell::new(0_usize);
    let allowed = std::cell::Cell::new([0_usize; KNOWN.len()]);
    let result = runner.run(&strategy, |(config, ops)| {
        let observed = evaluate(config, &ops, strict).map_err(TestCaseError::fail)?;
        checked.set(checked.get() + 1);
        let mut counts = allowed.get();
        for (count, known) in counts.iter_mut().zip(KNOWN) {
            *count += usize::from(observed.tolerated.contains(known));
        }
        allowed.set(counts);
        let seen = peaks.get();
        peaks.set(Peaks {
            envelopes: seen.envelopes.max(observed.peaks.envelopes),
            rows: seen.rows.max(observed.peaks.rows),
        });
        let mut total = coverage.get();
        total.add(observed.coverage);
        coverage.set(total);
        Ok(())
    });
    eprintln!(
        "stalled-receiver oracle: {} cases checked, peaks {:?}, coverage {:?}",
        checked.get(),
        peaks.get(),
        coverage.get()
    );
    for (known, count) in KNOWN.iter().zip(allowed.get()) {
        eprintln!("stalled-receiver oracle cases tolerating {known}: {count}");
    }
    if let Err(error) = result {
        let proptest::test_runner::TestError::Fail(reason, (config, ops)) = error else {
            panic!("{error}");
        };
        let reason = reason.to_string();
        eprintln!("stalled-receiver oracle failure before minimizing: {reason}");
        let ops = minimize(config, ops, &reason, strict);
        let reason = evaluate(config, &ops, strict).err().unwrap_or(reason);
        panic!("{reason}\nconfig: {config:#?}\nops: {ops:#?}");
    }
    let missing = coverage.get().missing();
    assert!(
        cases < DEFAULT_CASES || missing.is_empty(),
        "coverage: {missing:?} never reached in {cases} cases"
    );
}

/// Minimized by the oracle. Peer 0 is a grouped unicast member with a
/// one-envelope channel that its receiver empties once per resync tick. A
/// ROUTE-REFRESH arrives while the channel holds the initial End-of-RIB, so
/// the response is refused and owed. Each later tick, the dirty resync sends
/// the member's whole table into the one free slot, the owed response
/// (`retry_pending_refresh` straight after the resync commit) finds the
/// channel full and marked the member dirty again, and the next tick sent
/// the same table, so the refresh never completed. A refused answer is now
/// refresh-only debt, answered once the live operation drains.
#[test]
fn grouped_refresh_retry_converges_with_one_free_slot() {
    assert_clean(&livelock_config(), &livelock_ops());
}

/// The case holds every property and tolerates nothing.
fn assert_clean(config: &[PeerConfig; PEERS], ops: &[Op]) {
    let outcome = run(*config, ops).unwrap();
    assert!(outcome.tolerated.is_empty(), "{:?}", outcome.tolerated);
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
/// empty-inventory path in `distribute_changes`, which must still flush the
/// pending `EoR` and retry the owed refresh, as the other clear sites do;
/// otherwise the refresh is never answered and the IPv4 `EoR` is never sent
/// (RFC 4724 §4). A refused answer is also refresh-only debt, retried on the
/// resync tick whatever the resync found.
#[test]
fn refused_gate_lifting_refresh_still_sends_the_initial_eor() {
    assert_clean(&lost_eor_config(), &lost_eor_ops());
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
/// (RFC 7313 §4). The answer must carry the member's owed withdrawal;
/// otherwise the next dirty resync withdraws a route the peer no longer
/// holds.
#[test]
fn refresh_answer_settles_withdrawals_owed_to_a_dirty_member() {
    assert_clean(&purge_config(), &purge_ops());
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

fn events(values: &[(usize, &str)]) -> Vec<HistoryEvent> {
    values
        .iter()
        .map(|(op, value)| (*op, vec![(*value).to_string()]))
        .collect()
}

/// A deferral settles on B, then a defect loses clean C and delivers D.
/// A whole-session subsequence comparison incorrectly accepts this history.
#[test]
fn a_clean_event_lost_after_a_deferral_fails_p4() {
    let reference = events(&[(1, "A"), (2, "B"), (3, "C"), (4, "D")]);
    let intervals = deferral_intervals(5, 1, |_| 1, |op| op == 1, |_| false);
    let subject = events(&[(2, "B"), (4, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
    let subject = events(&[(2, "B"), (3, "C"), (4, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_ok());
    // Reaching D later cannot excuse a stale state at the deferral's close.
    let subject = events(&[(1, "A"), (3, "C"), (4, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
}

/// Session 1 owes work at op 3; a flap creates session 2 at op 4. The new
/// session's first events stay exact even though the old session never settled.
#[test]
fn a_flap_ends_the_sessions_deferrals() {
    let session_at = |op: usize| if op < 4 { 1 } else { 2 };
    let intervals = deferral_intervals(7, 2, session_at, |op| op == 3, |_| false);
    assert_eq!(intervals, []);
    let reference = events(&[(4, "A"), (4, "B"), (5, "C")]);
    let subject = events(&[(4, "B"), (5, "C")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
    assert!(compare_in_deferrals(&reference, &reference, &[], &intervals, None).is_ok());
    assert_eq!(
        deferral_intervals(7, 1, session_at, |op| op == 3, |_| false),
        [Deferral {
            start: 3,
            end: 3,
            settled: false
        }],
    );
}

#[test]
fn adjacent_deferrals_each_check_their_close() {
    let intervals = deferral_intervals(5, 1, |_| 1, |op| op == 1 || op == 3, |_| false);
    assert_eq!(
        intervals,
        [
            Deferral {
                start: 1,
                end: 2,
                settled: true
            },
            Deferral {
                start: 3,
                end: 4,
                settled: true
            },
        ],
    );
    let reference = events(&[(1, "A"), (2, "B"), (3, "C"), (4, "D")]);
    let subject = events(&[(1, "A"), (4, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
    let subject = events(&[(2, "B"), (4, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_ok());
}

#[test]
fn a_same_op_settlement_does_not_relax_the_next_op() {
    let intervals = deferral_intervals(4, 1, |_| 1, |_| false, |op| op == 1);
    assert_eq!(
        intervals,
        [Deferral {
            start: 1,
            end: 1,
            settled: true
        }]
    );
    let reference = events(&[(1, "A"), (2, "B"), (2, "C"), (3, "D")]);
    let subject = events(&[(1, "A"), (2, "C"), (3, "D")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
}

#[test]
fn a_final_settlement_checks_state_without_a_later_operation() {
    let intervals = deferral_intervals(3, 1, |_| 1, |op| op == 1, |_| false);
    let reference = events(&[(1, "A"), (2, "B")]);
    let subject = events(&[(1, "A")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, None).is_err());
}

#[test]
fn a_retained_starting_value_can_survive_a_coalesced_cycle() {
    let intervals = deferral_intervals(3, 1, |_| 1, |op| op == 1, |_| false);
    let reference = events(&[(1, "B"), (2, "A")]);
    let initial = vec!["A".to_string()];
    assert!(compare_in_deferrals(&reference, &[], &initial, &intervals, None).is_ok());
    assert!(compare_in_deferrals(&reference, &[], &[], &intervals, None).is_err());
}

#[test]
fn a_flap_can_discard_a_suffix_but_not_a_clean_event_before_it() {
    let reference = events(&[(1, "A"), (2, "B"), (3, "C"), (4, "D")]);
    let subject = events(&[(1, "A"), (3, "C")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &[], Some(3)).is_err());
    let subject = events(&[(1, "A"), (2, "B")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &[], Some(2)).is_ok());
    let intervals = deferral_intervals(4, 1, |_| 1, |op| op == 1 || op == 2, |_| false);
    let subject = events(&[(2, "B")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &intervals, Some(2)).is_ok());
}

/// Peer 0's queue fills before B. The first drain/tick settles on B, or a
/// flap interrupts the old session's debt.
/// C and D are then admitted on an empty channel at ops 6 and 8.
fn deferred_history_case(flap: bool) -> ([PeerConfig; PEERS], Vec<Op>) {
    let mut config = [PeerConfig {
        capacity: 4096,
        add_path: 1,
        enhanced: false,
        gr: false,
        orf: false,
        v6: false,
        evpn: false,
    }; PEERS];
    // A replacement dump and its EoR must fit so its first route is clean.
    config[0].capacity = if flap { 2 } else { 1 };
    let announce = |variant| Op::Announce {
        src: 1,
        family: Fam::V4,
        index: 0,
        variant,
    };
    (
        config,
        vec![
            announce(0),
            announce(1),
            if flap {
                Op::Flap { peer: 0 }
            } else {
                Op::Drain { peer: 0, k: None }
            },
            Op::Tick,
            Op::Drain { peer: 0, k: None },
            announce(2),
            Op::Drain { peer: 0, k: None },
            announce(3),
            Op::Drain { peer: 0, k: None },
        ],
    )
}

/// A spent row charge makes a new key owed, then its withdrawal cancels
/// that debt before the harness observes the operation. The first query
/// consumes the only record of this transient mark: reading refresh debt
/// and key debt separately would lose it and make P4 reject the valid cycle.
#[tokio::test(start_paused = true)]
async fn end_op_keeps_a_key_marked_and_canceled_in_the_same_operation() {
    let (mut config, _) = deferred_history_case(false);
    config[0].capacity = 4096;
    let mut harness = Harness::new(config, Some(1)).await.unwrap();
    for peer in 0..PEERS {
        harness.apply(&Op::Drain { peer, k: None }).await.unwrap();
    }
    harness
        .apply(&Op::Announce {
            src: 1,
            family: Fam::V4,
            index: 1,
            variant: 0,
        })
        .await
        .unwrap();
    let before = harness.arms[SUBJECT].owed_state(0).await;
    assert_eq!(
        before.credit_rows, 1,
        "the queued route must spend the credit"
    );
    assert!(!before.resync);
    assert_eq!(before.owed, []);

    harness.op += 1;
    let observed_op = harness.op;
    for withdraw in [false, true] {
        harness
            .both(|| RibUpdate::RoutesReceived {
                peer: peer_id(1),
                session_id: 1,
                announced: if withdraw {
                    vec![]
                } else {
                    vec![unicast_route(1, Fam::V4, 0, 0)]
                },
                withdrawn: if withdraw {
                    vec![(Prefix::V4(v4_prefix(0)), 0)]
                } else {
                    vec![]
                },
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            })
            .await;
        // Order the mark before its cancellation without consuming the log.
        for arm in &harness.arms {
            arm.round_trip().await;
        }
    }
    harness.end_op().await.unwrap();
    let key = (V4, v4_prefix(0).to_string());
    assert!(harness.owed[observed_op][0].contains(&(V4, Some(key.1.clone()))));
    assert!(harness.owed_pending[observed_op][0].is_empty());
    assert!(harness.refresh_owed[observed_op][0].is_empty());
    assert!(!harness.dirty[observed_op][0]);
    assert_eq!(
        harness.deferrals(0, &(1, key)),
        [Deferral {
            start: observed_op,
            end: observed_op,
            settled: true,
        }],
    );
    harness.drain_until_quiet().await.unwrap();
    harness.check().unwrap();
    harness.finish().await;
}

#[test]
fn p4_rejects_a_dropped_clean_event_after_real_debt() {
    let (config, ops) = deferred_history_case(false);
    assert_clean(&config, &ops);
    let reason = run_seeded(config, &ops, |harness| {
        let key = (1, (V4, v4_prefix(0).to_string()));
        assert!(
            harness
                .deferrals(0, &key)
                .iter()
                .any(|interval| { interval.start <= 2 && interval.end < 6 && interval.settled })
        );
        let history = harness.arms[SUBJECT].wire[0].history.get_mut(&key).unwrap();
        assert_eq!(history.iter().filter(|(op, _)| *op == 6).count(), 1);
        history.retain(|(op, _)| *op != 6);
    })
    .err()
    .expect("P4 must reject the missing clean event despite equal final tables");
    assert!(reason.starts_with("P4: peer 0 session 1"), "{reason}");
    assert!(reason.contains("outside any deferral"), "{reason}");
}

#[test]
fn p4_rejects_a_dropped_clean_event_across_a_real_flap() {
    let (config, ops) = deferred_history_case(true);
    assert_clean(&config, &ops);
    let reason = run_seeded(config, &ops, |harness| {
        let prefix = (V4, v4_prefix(0).to_string());
        assert!(
            harness
                .deferrals(0, &(1, prefix.clone()))
                .iter()
                .any(|interval| { interval.start == 2 && interval.end == 2 && !interval.settled })
        );
        let key = (2, prefix);
        assert!(
            !harness
                .deferrals(0, &key)
                .iter()
                .any(|interval| { (interval.start..=interval.end).contains(&3) })
        );
        let history = harness.arms[SUBJECT].wire[0].history.get_mut(&key).unwrap();
        assert_eq!(history.iter().filter(|(op, _)| *op == 3).count(), 1);
        history.retain(|(op, _)| *op != 3);
    })
    .err()
    .expect("P4 must fence old debt off from the replacement session's first event");
    assert!(reason.starts_with("P4: peer 0 session 2"), "{reason}");
    assert!(reason.contains("outside any deferral"), "{reason}");
}

#[test]
fn only_the_actual_discard_operation_allows_a_partial_prefix() {
    let reference = events(&[(1, "A"), (2, "B"), (2, "C"), (2, "D"), (3, "E")]);
    let subject = events(&[(1, "A"), (2, "B"), (2, "C")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &[], Some(2)).is_ok());
    let subject = events(&[(1, "A"), (2, "C")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &[], Some(2)).is_err());
    let subject = events(&[(2, "B"), (2, "C")]);
    assert!(compare_in_deferrals(&reference, &subject, &[], &[], Some(2)).is_err());
    assert!(compare_in_deferrals(&reference, &[], &[], &[], Some(2)).is_err());
    assert!(compare_in_deferrals(&reference, &[], &[], &[], Some(1)).is_ok());
}

/// D is queued at op 8 and actually discarded by the final flap. Losing
/// delivered C at op 6 must still fail, even though B at op 4 is now the
/// subject history's last surviving entry.
#[test]
fn p4_rejects_a_dropped_clean_event_before_a_later_discard() {
    let (config, mut ops) = deferred_history_case(false);
    *ops.last_mut().unwrap() = Op::Flap { peer: 0 };
    assert_clean(&config, &ops);
    let reason = run_seeded(config, &ops, |harness| {
        let key = (1, (V4, v4_prefix(0).to_string()));
        assert_eq!(
            harness.arms[SUBJECT].wire[0].discarded_from.get(&key),
            Some(&8)
        );
        let history = harness.arms[SUBJECT].wire[0].history.get_mut(&key).unwrap();
        assert_eq!(history.iter().filter(|(op, _)| *op == 6).count(), 1);
        history.retain(|(op, _)| *op != 6);
        assert_eq!(history.last().unwrap().0, 4);
    })
    .err()
    .expect("an actual discard at op 8 cannot excuse a missing clean event at op 6");
    assert!(reason.starts_with("P4: peer 0 session 1"), "{reason}");
    assert!(reason.contains("outside any deferral"), "{reason}");
}

/// A flap may discard the marker that would purge a GR-retained route.
#[test]
fn discarded_orf_eor_can_end_a_gr_session() {
    let (config, ops) = discarded_orf_eor_case();
    assert_clean(&config, &ops);
}

fn discarded_orf_eor_case() -> ([PeerConfig; PEERS], [Op; 6]) {
    let mut config = livelock_config();
    config[2] = PeerConfig {
        capacity: 2,
        gr: true,
        orf: true,
        ..config[2]
    };
    (
        config,
        [
            Op::Announce {
                src: 0,
                family: Fam::V4,
                index: 2,
                variant: 0,
            },
            Op::Orf { peer: 2, deny: 8 },
            Op::Drain { peer: 2, k: None },
            Op::GrRestart { peer: 2 },
            Op::Orf { peer: 2, deny: 4 },
            Op::Flap { peer: 2 },
        ],
    )
}

#[test]
fn discarded_orf_eor_keeps_first_producing_operation() {
    let (config, ops) = discarded_orf_eor_case();
    let mut ops = ops.to_vec();
    ops.insert(5, Op::Orf { peer: 2, deny: 0 });
    run_seeded(config, &ops, |harness| {
        let key = (2, (V4, v4_prefix(2).to_string()));
        assert_eq!(
            harness.arms[SUBJECT].wire[2].discarded_from.get(&key),
            Some(&5)
        );
        let history = &harness.arms[REFERENCE].wire[2].history[&key];
        assert_eq!(
            history.iter().map(|(op, _)| *op).collect::<Vec<_>>(),
            [5, 6]
        );
    })
    .unwrap();
}

/// A later discarded marker cannot excuse an earlier missing clean event.
#[test]
fn discarded_orf_eor_preserves_the_clean_event_boundary() {
    let (config, ops) = discarded_orf_eor_case();
    let reason = run_seeded(config, &ops, |harness| {
        let key = (2, (V4, v4_prefix(2).to_string()));
        assert_eq!(
            harness.arms[SUBJECT].wire[2].discarded_from.get(&key),
            Some(&5)
        );
        let history = harness.arms[REFERENCE].wire[2]
            .history
            .get_mut(&key)
            .unwrap();
        assert_eq!(history.as_slice(), &[(5, Vec::<Value>::new())]);
        // Seed a lost clean observation before the real discarded EoR.
        history.insert(0, (4, vec!["missing clean event".into()]));
    })
    .err()
    .expect("a discarded EoR at op 5 cannot excuse a missing clean event at op 4");
    assert!(reason.starts_with("P4: peer 2 session 2"), "{reason}");
    assert!(reason.contains("outside any deferral"), "{reason}");
}

fn stale_marker_wire(enhanced: bool) -> (Wire, [Key; 3]) {
    let keys = [
        Key {
            family: V4,
            nlri: v4_prefix(0).to_string(),
            path_id: 0,
        },
        Key {
            family: V4,
            nlri: v4_prefix(1).to_string(),
            path_id: 0,
        },
        Key {
            family: V6,
            nlri: v6_prefix(0).to_string(),
            path_id: 0,
        },
    ];
    let wire = Wire {
        session: 2,
        enhanced,
        held: keys
            .iter()
            .cloned()
            .map(|key| (key, "old".into()))
            .collect(),
        gr_stale: keys.iter().cloned().collect(),
        eor: BTreeSet::from([V4, V6]),
        ..Wire::default()
    };
    (wire, keys)
}

#[test]
fn discarded_marker_shadow_follows_queue_order() {
    let (wire, [a, b, v6]) = stale_marker_wire(true);
    let held = wire.held.clone();
    let mut shadow = wire.discard_shadow();
    let refreshed = NormMsg {
        refresh_markers: vec![(Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR)],
        announce: vec![(
            Prefix::V4(v4_prefix(0)),
            0,
            IpAddr::V4(peer_addr(0)),
            peer_id(0),
            vec![],
            None,
        )],
        ..NormMsg::default()
    };
    assert_eq!(
        shadow.discarded_changes(2, 3, refreshed, false),
        BTreeSet::from([nlri(&a)])
    );
    let end = NormMsg {
        refresh_markers: vec![(Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::EoRR)],
        ..NormMsg::default()
    };
    assert_eq!(
        shadow.discarded_changes(2, 5, end, false),
        BTreeSet::from([nlri(&b)])
    );
    let v4_eor = NormMsg {
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        ..NormMsg::default()
    };
    assert!(shadow.discarded_changes(2, 6, v4_eor, false).is_empty());
    let v6_eor = NormMsg {
        end_of_rib: vec![(Afi::Ipv6, Safi::Unicast)],
        ..NormMsg::default()
    };
    assert_eq!(
        shadow.discarded_changes(2, 7, v6_eor, true),
        BTreeSet::from([nlri(&v6)])
    );
    assert_eq!(shadow.held.keys().collect::<Vec<_>>(), vec![&a]);
    assert_eq!(wire.held, held, "discard cannot deliver shadow changes");
    assert_eq!(wire.gr_stale.len(), 3);
    assert!(wire.history.is_empty());
}

#[test]
fn discarded_marker_shadow_uses_delivery_filters() {
    for enhanced in [false, true] {
        let (mut delivered, [a, b, _]) = stale_marker_wire(enhanced);
        delivered.refresh_stale.insert(V4, BTreeSet::new());
        let mut shadow = delivered.discard_shadow();
        let message = NormMsg {
            end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
            refresh_markers: vec![(Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::EoRR)],
            ..NormMsg::default()
        };
        let changed = shadow.discarded_changes(2, 5, message.clone(), false);
        let expected = if enhanced {
            BTreeSet::new()
        } else {
            BTreeSet::from([nlri(&a), nlri(&b)])
        };
        assert_eq!(changed, expected);
        delivered
            .apply(SUBJECT, 2, 5, message, false, Some(&mut Vec::new()))
            .unwrap();
        assert_eq!(shadow.held, delivered.held);
        assert_eq!(shadow.gr_stale, delivered.gr_stale);
        assert_eq!(shadow.refresh_stale, delivered.refresh_stale);
    }
}

#[test]
fn discarded_marker_shadow_checks_only_delivered_envelopes() {
    let cases = [
        (
            "P2:",
            NormMsg {
                withdraw: vec![(Prefix::V4(v4_prefix(2)), 0)],
                ..NormMsg::default()
            },
        ),
        (
            "P3:",
            NormMsg {
                refresh_markers: vec![(Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR)],
                ..NormMsg::default()
            },
        ),
        (
            "P3:",
            NormMsg {
                refresh_markers: vec![(Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::EoRR)],
                ..NormMsg::default()
            },
        ),
    ];
    for (property, message) in cases {
        let (mut delivered, _) = stale_marker_wire(true);
        delivered.eor.clear();
        let mut shadow = delivered.discard_shadow();
        let error = delivered
            .apply(SUBJECT, 2, 5, message.clone(), false, Some(&mut Vec::new()))
            .unwrap_err();
        assert!(error.starts_with(property), "{error}");
        assert!(shadow.discarded_changes(2, 5, message, false).is_empty());
    }
}
