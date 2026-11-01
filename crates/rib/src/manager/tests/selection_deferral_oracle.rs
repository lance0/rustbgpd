//! Model-checked GR selection hold.
//!
//! Random operation sequences drive a real `RibManager` through the matrix
//! of a selection hold, exempt local RTBH and host routes, Add-Path ranks,
//! backpressure, refused recovery proof, an Address Prefix ORF and the
//! receiver's session flaps (a new channel and session id, with RFC 4724
//! stale retention at a GR-capable peer), and a grouped receiver's moves
//! to the per-peer path through slow-peer isolation, a peer-context export
//! policy or a conditional-advertisement attachment. A tiny reference model
//! keeps the local and received intent; the receiver's wire is rebuilt from
//! the updates it actually got. Every route carries a unique identity
//! community, so a wire row names the exact injection it came from.
//!
//! Invariants:
//! - I1, never unblackhole: after every UPDATE, in the hold or outside it, a
//!   prefix whose fresh export carries an exempt path and that had an exempt
//!   row on the wire keeps one; after a drain in the hold with a free writer,
//!   admitted proof and no ORF gate, every such prefix carries a live exempt
//!   row.
//! - I2, exact convergence: after release and drain, the wire equals a fresh
//!   session's full dump, computed from the final intent alone. Add-Path
//!   path IDs are opaque, so each prefix's paths are compared, not its keys.
//! - I3: `actual_unicast_advertised_count` equals the wire key count.
//! - I4, no resurrection: a deleted or replaced exempt path is never
//!   announced again.
//! - I5, prompt removal: after a drain with a free writer in the hold, an
//!   exempt row the operator deleted has left the wire, unless it is the
//!   prefix's last exempt row while an exempt export is still intended.
//! - I6, send limit: after every UPDATE, no prefix carries more paths from
//!   the current session than the receiver's Add-Path `send_max`, or more
//!   than one without Add-Path.
//! - I7, a deadline waits for its own backlog: when the source restarts
//!   under GR and its refresh (every path again, then End-of-RIB) is queued
//!   before its stale deadline, that deadline never expires
//!   (`bgp_gr_timer_expired_total`), however long an earlier deadline's
//!   drain runs past it.
//!
//! Before the hold, a timer race restarts the source and a GR peer that
//! never returns, then runs a segment through the real actor loop on a
//! paused clock: queued input it does not drain (a bulk UPDATE of
//! withdrawals, the source's refresh) and advances to the next GR deadline,
//! each followed by one actor turn. The segment settles when its queue
//! closes and the actor hands the manager back.
//!
//! Each case fixes one receiver configuration (private or grouped,
//! single-best or Add-Path, per-client-best, ORF, prefix limit, and whether
//! its first session arrives inside the hold), builds a pre-hold table,
//! starts the hold, runs the operations, then releases and drains. The
//! receiver's session may flap before and during the hold. The source peer
//! sends several Add-Path paths per prefix, on prefixes that also carry
//! local paths. Not modelled: IPv6, LLGR, leases, export policy edits, a
//! second hold, more than one receiver, and timer expiry other than GR
//! stale deadlines (the ORF and RT-Constrain End-of-RIB caps and selection
//! deferral are 60 s, beyond every advance).
//!
//! Known open defects are allowed only by their exact signature, each
//! naming its ticket (`allowed`). `ORACLE_STRICT=1` disables every
//! allowance and `ORACLE_STRICT=LAN-2692,...` only the listed ones, which
//! reproduces them. `PROPTEST_CASES` scales the case count for a deep run;
//! `ORACLE_TRACE` prints each operation and wire update. A failure prints a
//! sequence minimized by one-op deletion.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use super::selection_deferral_dirty_rtbh::{
    connect, connect_session, manager_with_dormant_waiter, private_policy,
};
use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 82);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
const OBSERVER_SESSION: u64 = 82;
const SOURCE_SESSION: u64 = 81;
const WAITER_SESSION: u64 = 83;
/// A GR-capable peer that restarts and never returns: the other owner of a
/// GR deadline in a timer race.
const ABSENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 84);
const ABSENT_SESSION: u64 = 84;
/// Withdrawals in one bulk UPDATE: three route chunks, so draining it takes
/// several actor turns.
const BULK_WITHDRAWALS: usize = 3 * ROUTES_RECEIVED_CHUNK_SIZE;
/// Two host routes and one aggregate carry local intent; two aggregates
/// carry received routes.
const PREFIXES: usize = 5;
const LOCAL_PREFIXES: usize = 3;
const PATH_IDS: [u32; 3] = [17, 23, 29];
const ADD_PATH_MAX: usize = 2;
/// `65000:n` names injection `n`.
const IDENTITY_ASN: u32 = 65000;
const DRAIN_ROUNDS: usize = 16;

fn prefix(index: usize) -> Prefix {
    let (octets, len) = [
        ([198, 51, 100, 1], 32),
        ([198, 51, 100, 2], 32),
        ([203, 0, 113, 0], 24),
        ([100, 64, 1, 0], 24),
        ([100, 64, 2, 0], 24),
    ][index];
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len))
}

/// `prefix#path_id=injection`, sorted.
fn show<'a>(wire: impl IntoIterator<Item = (&'a (Prefix, u32), &'a usize)>) -> String {
    let mut rows: Vec<_> = wire
        .into_iter()
        .map(|((prefix, path_id), injection)| format!("{prefix}#{path_id}={injection}"))
        .collect();
    rows.sort();
    format!("[{}]", rows.join(", "))
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent axis of the receiver matrix"
)]
#[derive(Clone, Copy, Debug)]
struct Config {
    /// Grouped receivers share an update group; Add-Path is always private.
    grouped: bool,
    add_path: bool,
    per_client_best: bool,
    /// The receiver negotiates Address Prefix ORF receive.
    orf: bool,
    /// A configured prefix limit makes recovery depend on exact proof.
    limit: bool,
    /// The receiver's first session establishes inside the hold.
    late: bool,
}

#[derive(Clone, Debug)]
enum Op {
    /// Inject or replace a local path; preference picks its rank.
    Inject {
        prefix: usize,
        path: usize,
        preference: u32,
        blackhole: bool,
    },
    Delete {
        prefix: usize,
        path: usize,
    },
    /// Receive or replace one of the source peer's Add-Path paths on any
    /// prefix, beside local paths; preference picks its rank, and
    /// `blackhole` tags it with BLACKHOLE.
    Receive {
        prefix: usize,
        path: usize,
        preference: u32,
        blackhole: bool,
    },
    ReceiveWithdraw {
        prefix: usize,
        path: usize,
    },
    /// Replace the receiver's ORF with one denying the masked prefixes.
    Orf {
        deny: u8,
    },
    /// Toggle an export-policy BLACKHOLE tag on the current local (or
    /// received) path at `(prefix, path)`, matched by prefix and
    /// `LOCAL_PREF`; `exclusive` instead makes it the prefix's only tagged
    /// path, in one policy replacement. Private receivers only.
    Tag {
        prefix: usize,
        path: usize,
        received: bool,
        exclusive: bool,
    },
    /// Free the writer and run the receiver's dirty resync now, so every
    /// change held behind backpressure lands in one pass.
    Resync,
    Backpressure(bool),
    /// Free the writer; the receiver's dirty retry then fails its
    /// admission-proof allocation.
    RefuseProof,
    Drain,
    /// The receiver's session ends and re-establishes on a new channel and
    /// session id, as the transport does. The dying session decides what
    /// happens to it: a clean end (`notification` false) toward a peer whose
    /// OPEN listed GR families reaches the RIB as `PeerGracefulRestart`,
    /// otherwise as `PeerDown`; and a peer whose OPEN carried any GR
    /// capability keeps our routes as stale after a clean end (RFC 4724
    /// 4.2), until our End-of-RIB on the new session. `helper` and
    /// `gr_families` describe the new session's OPEN; `writer_full` fills
    /// the new channel before its initial table.
    Reconnect {
        notification: bool,
        helper: bool,
        gr_families: bool,
        writer_full: bool,
    },
    /// Move a grouped receiver onto the per-peer path (`on`) or back,
    /// through a production trigger. Exports are unchanged.
    Regroup {
        kind: RegroupKind,
        on: bool,
    },
    /// A GR-capable session ends cleanly, which the transport reports as
    /// `PeerGracefulRestart` with a `restart` s Restart Time. The source
    /// re-establishes at once (`PeerUp` with the restart flag), which
    /// rearms its window to `stale` s (RFC 4724 4.2); the absent peer never
    /// returns. A peer whose window is still open does not restart again.
    RestartPeer {
        source: bool,
        restart: u8,
        stale: u8,
    },
    /// Queue, without draining it, one extended UPDATE from the source
    /// withdrawing [`BULK_WITHDRAWALS`] prefixes it never announced: a
    /// backlog that takes several actor turns and changes no route.
    QueueBulk,
    /// Queue, without draining it, the restarted source's refresh: every
    /// live received path again, then its End-of-RIB. Only before its GR
    /// deadline; once that has passed, nothing.
    QueueRefresh,
    /// Move the paused clock to the earliest GR deadline still ahead, then
    /// give the actor one turn.
    AdvanceToDeadline,
}

impl Op {
    /// Runs inside an open actor segment rather than settling it first.
    fn in_segment(&self) -> bool {
        matches!(
            self,
            Self::QueueBulk | Self::QueueRefresh | Self::AdvanceToDeadline
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum RegroupKind {
    /// The transport's slow-peer isolation flag (`PeerSlowState`).
    Slow,
    /// An export policy with peer context (`ReplacePeerExportPolicy`).
    PeerPolicy,
    /// A conditional advertisement attached to the receiver, controlling
    /// only a prefix outside the model.
    Conditional,
}

/// A conditional advertisement that controls and observes only prefixes
/// outside the model, attached to `attached` when given.
fn unrelated_conditional(attached: Option<PeerId>) -> crate::ConditionalAdvertisementSet {
    let policy = rustbgpd_policy::rpol::RpolFile::parse(
        "policy unrelated { term t { if route.prefix == 192.0.2.250/32 { accept } } \
         term rest { reject } }",
    )
    .expect("clean rpol")
    .compile_policy(
        "unrelated",
        &[],
        &mut rustbgpd_policy::sets::SetStore::new(),
    )
    .expect("policy exists");
    let name: std::sync::Arc<str> = std::sync::Arc::from("unrelated");
    crate::ConditionalAdvertisementSet {
        definitions: vec![crate::ConditionalAdvertisement {
            name: name.clone(),
            advertise_policy: rustbgpd_policy::PolicyChain::from_named(vec![
                rustbgpd_policy::NamedPolicy::from_rpol(
                    "unrelated".to_string(),
                    std::sync::Arc::new(policy),
                ),
            ]),
            advertise_if: crate::ConditionalAdvertiseIf::Present,
            condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(Prefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 251), 32),
            ))],
            condition_policy: None,
            settle_time: Duration::ZERO,
            retiring: false,
        }],
        attachments: attached
            .into_iter()
            .map(|peer| (peer.addr().into(), vec![name.clone()]))
            .collect(),
    }
}

fn config_strategy() -> impl Strategy<Value = Config> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(grouped, add_path, per_client_best, orf, limit, late)| Config {
                // Add-Path and ORF receivers are always private.
                grouped: grouped && !add_path && !orf,
                add_path,
                per_client_best,
                orf,
                limit,
                late,
            },
        )
}

fn intent_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..LOCAL_PREFIXES, 0..PATH_IDS.len(), 0u32..3, any::<bool>()).prop_map(
            |(prefix, path, preference, blackhole)| Op::Inject {
                prefix,
                path,
                preference,
                blackhole,
            }
        ),
        2 => (0..LOCAL_PREFIXES, 0..PATH_IDS.len())
            .prop_map(|(prefix, path)| Op::Delete { prefix, path }),
        2 => (0..PREFIXES, 0..PATH_IDS.len(), 0u32..3, any::<bool>()).prop_map(
            |(prefix, path, preference, blackhole)| Op::Receive {
                prefix,
                path,
                preference,
                blackhole,
            }
        ),
        1 => (0..PREFIXES, 0..PATH_IDS.len())
            .prop_map(|(prefix, path)| Op::ReceiveWithdraw { prefix, path }),
        1 => (0u8..1 << PREFIXES).prop_map(|deny| Op::Orf { deny }),
        1 => (0..PREFIXES, 0..PATH_IDS.len(), any::<bool>(), any::<bool>()).prop_map(
            |(prefix, path, received, exclusive)| Op::Tag {
                prefix,
                path,
                received,
                exclusive,
            }
        ),
    ]
}

fn reconnect_strategy() -> impl Strategy<Value = Op> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
        |(notification, helper, gr_families, writer_full)| Op::Reconnect {
            notification,
            // Families come only inside a GR capability.
            helper: helper || gr_families,
            gr_families,
            writer_full,
        },
    )
}

/// Before the hold: intent, backpressure that coalesces several changes
/// into one pass, and session flaps whose GR helper keeps our rows as stale
/// across the reconnect.
fn setup_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => intent_strategy(),
        1 => any::<bool>().prop_map(Op::Backpressure),
        1 => Just(Op::Resync),
        1 => reconnect_strategy(),
    ]
}

/// A timer race: both GR peers restart, in either order, and then a
/// segment of blocks, each queueing input without draining it and then
/// advancing to the next deadline, with input left queued at its end. The
/// absent peer's deadline is usually the earlier one.
fn timer_race_strategy() -> impl Strategy<Value = Vec<Op>> {
    let queued = || {
        proptest::collection::vec(
            prop_oneof![Just(Op::QueueBulk), Just(Op::QueueRefresh)],
            0..3,
        )
    };
    let block = queued().prop_map(|mut ops| {
        ops.push(Op::AdvanceToDeadline);
        ops
    });
    (
        1u8..=2,
        2u8..=4,
        any::<bool>(),
        proptest::collection::vec(block, 1..4),
        queued(),
    )
        .prop_map(
            |(absent_restart, source_stale, absent_first, blocks, tail)| {
                let segment = blocks.into_iter().flatten().chain(tail);
                let absent = Op::RestartPeer {
                    source: false,
                    restart: absent_restart,
                    stale: 0,
                };
                let source = Op::RestartPeer {
                    source: true,
                    restart: 1,
                    stale: source_stale,
                };
                let mut ops = if absent_first {
                    vec![absent, source]
                } else {
                    vec![source, absent]
                };
                ops.extend(segment);
                ops
            },
        )
}

/// The ops before the hold: single setup ops and whole timer races. A case
/// keeps about as many setup ops as before races existed (mean 3.4 against
/// 3.5) and adds about one race.
fn pre_hold_strategy() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(
        prop_oneof![
            3 => setup_strategy().prop_map(|op| vec![op]),
            1 => timer_race_strategy(),
        ],
        0..10,
    )
    .prop_map(|parts| parts.into_iter().flatten().collect())
}

fn hold_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => intent_strategy(),
        2 => any::<bool>().prop_map(Op::Backpressure),
        2 => Just(Op::RefuseProof),
        2 => Just(Op::Drain),
        1 => Just(Op::Resync),
        2 => (
            prop_oneof![
                Just(RegroupKind::Slow),
                Just(RegroupKind::PeerPolicy),
                Just(RegroupKind::Conditional),
            ],
            any::<bool>()
        )
            .prop_map(|(kind, on)| Op::Regroup { kind, on }),
        2 => reconnect_strategy(),
    ]
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent property of the modelled path"
)]
struct Injection {
    prefix: usize,
    preference: u32,
    exempt: bool,
    /// Injected or received carrying BLACKHOLE, before export policy.
    community: bool,
    live: bool,
    /// The operator deleted it (a replacement only retires it).
    deleted: bool,
}

/// The real run loop while a timer segment is open.
struct Actor {
    tx: mpsc::Sender<RibUpdate>,
    run: Pin<Box<dyn Future<Output = RibManager>>>,
}

/// The GR peer that restarted and never returns.
struct Absent {
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    deadline: tokio::time::Instant,
}

/// The source's open GR window.
struct SourceGr {
    deadline: tokio::time::Instant,
    /// Received paths still stale: held at the restart, not received again.
    stale: BTreeSet<(usize, usize)>,
    /// Its refresh was queued before the deadline.
    refreshed: bool,
    /// The source's `bgp_gr_timer_expired_total` at the restart.
    expired: f64,
}

/// A source connection: GR families in its OPEN, the restart flag on a
/// re-establishment.
fn connect_source(
    manager: &mut RibManager,
    session_id: u64,
    restarting: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    connect_session(manager, SOURCE, session_id, 64, true, restarting, false)
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "the model tracks independent per-case history, gate and session flags"
)]
struct Harness {
    config: Config,
    manager: RibManager,
    tx: mpsc::Sender<OutboundRouteUpdate>,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    source: mpsc::Receiver<OutboundRouteUpdate>,
    waiter: Option<mpsc::Receiver<OutboundRouteUpdate>>,
    occupied: Vec<mpsc::OwnedPermit<OutboundRouteUpdate>>,
    /// Receiver wire: key to the injection it carries.
    wire: HashMap<(Prefix, u32), usize>,
    injections: Vec<Injection>,
    local: BTreeMap<(usize, usize), usize>,
    received: BTreeMap<(usize, usize), usize>,
    deny: u8,
    orf_gated: bool,
    held: bool,
    /// Prefix to the exempt injections on its wire rows at the last check.
    blackholed: BTreeMap<usize, BTreeSet<usize>>,
    /// The receiver's current transport session.
    session: u64,
    /// Keys a GR helper retains as stale from a previous session until our
    /// End-of-RIB on the current one.
    stale: HashSet<(Prefix, u32)>,
    /// The current session's peer OPEN carried a GR capability: it keeps
    /// our routes as stale when the session ends cleanly.
    helper: bool,
    /// The current session's peer OPEN listed GR families.
    gr_families: bool,
    /// The receiver has an established session.
    registered: bool,
    /// I1 per UPDATE; the checker's own tests clear it for a control that
    /// checks only after the channel.
    per_update_i1: bool,
    /// The receiver's configured export policy has peer context; a new
    /// session registers with it.
    peer_policy: bool,
    /// Export-policy BLACKHOLE tags, by prefix and `LOCAL_PREF`.
    tags: BTreeSet<(usize, u32)>,
    /// Whether each key's row, as last announced, carried BLACKHOLE.
    wire_tag: HashMap<(Prefix, u32), bool>,
    /// The paused clock and timer driver timer segments run on.
    rt: Rc<tokio::runtime::Runtime>,
    /// The run loop while a segment is open; `manager` is then a stand-in.
    actor: Option<Actor>,
    /// The source's current transport session.
    source_session: u64,
    absent: Option<Absent>,
    source_gr: Option<SourceGr>,
    /// An I7 violation a settled segment found, reported by `observe`.
    timer_failure: Option<String>,
}

type Checked = Result<(), TestCaseError>;

impl Harness {
    fn new(config: Config) -> Self {
        let rt = Rc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .expect("a paused runtime"),
        );
        let _clock = rt.enter();
        let mut manager = manager_with_dormant_waiter();
        let source = connect_source(&mut manager, SOURCE_SESSION, false);
        let observer = peer_v4(OBSERVER);
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: observer,
            session_id: OBSERVER_SESSION,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: vec![],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        let (tx, rx) = mpsc::channel(4);
        let mut harness = Self {
            config,
            manager,
            tx,
            rx,
            source,
            waiter: None,
            occupied: Vec::new(),
            wire: HashMap::new(),
            injections: Vec::new(),
            local: BTreeMap::new(),
            received: BTreeMap::new(),
            deny: 0,
            orf_gated: config.orf,
            held: false,
            blackholed: BTreeMap::new(),
            session: OBSERVER_SESSION,
            stale: HashSet::new(),
            helper: true,
            gr_families: true,
            registered: false,
            per_update_i1: true,
            peer_policy: false,
            tags: BTreeSet::new(),
            wire_tag: HashMap::new(),
            rt: Rc::clone(&rt),
            actor: None,
            source_session: SOURCE_SESSION,
            absent: None,
            source_gr: None,
            timer_failure: None,
        };
        if !config.late {
            harness.establish();
        }
        harness
    }

    /// The transport's Established sequence on the current channel and
    /// session: staged context, `PeerUp`, `PeerAddPathLimits`, then the
    /// configured limit and the peer's first ORF.
    fn establish(&mut self) {
        self.registered = true;
        let observer = peer_v4(OBSERVER);
        let session_id = self.session;
        self.manager.handle_update(RibUpdate::SetPeerExportContext {
            peer: observer,
            session_id,
            local_role: None,
        });
        self.manager.handle_update(RibUpdate::SetPeerRsControl {
            peer: observer,
            session_id,
            rs_control_asn: None,
        });
        self.manager
            .handle_update(RibUpdate::SetPeerExportPolicyCounters {
                peer: observer,
                session_id,
                counters: crate::update::ExportPolicyCounters::default(),
            });
        self.manager
            .handle_update(RibUpdate::SetPeerGracefulRestartContext {
                peer: observer,
                session_id,
                peer_restart_state: false,
                peer_gr_helper: self.helper,
                peer_gr_families: if self.gr_families {
                    vec![FAMILY]
                } else {
                    vec![]
                },
                peer_enhanced_refresh: true,
                peer_llgr_families: vec![],
                local_llgr_stale_time: 0,
            });
        self.manager.handle_update(RibUpdate::SetPeerPolicyContext {
            peer: observer,
            session_id,
            peer_group: None,
        });
        self.register();
        self.manager.handle_update(RibUpdate::PeerAddPathLimits {
            peer: observer,
            session_id,
            limits: if self.config.add_path {
                vec![(FAMILY, u32::try_from(ADD_PATH_MAX).unwrap())]
            } else {
                vec![]
            },
        });
        let config = self.config;
        let harness = self;
        if config.limit {
            super::outbound_prefix_limits::prepare(
                &mut harness.manager,
                1,
                super::outbound_prefix_limits::limit_config(&[(observer, Some(64), None)], &[]),
            )
            .unwrap();
            super::outbound_prefix_limits::apply(&mut harness.manager, 1, true).unwrap();
        }
        if config.orf {
            harness.push_orf(0);
        }
    }

    /// A production session flap: the old channel and its queued updates
    /// die, a new channel and session id register.
    fn reconnect(&mut self, flap: &Op) {
        let &Op::Reconnect {
            notification,
            helper,
            gr_families,
            writer_full,
        } = flap
        else {
            unreachable!("only a Reconnect flaps the session")
        };
        let observer = peer_v4(OBSERVER);
        // `fsm.rs`: GR retention of the peer's routes needs its GR families
        // and an end that is not a NOTIFICATION teardown.
        if self.gr_families && !notification {
            self.manager.handle_update(RibUpdate::PeerGracefulRestart {
                peer: observer,
                session_id: self.session,
                restart_time: 120,
                stale_routes_time: 360,
                gr_families: vec![FAMILY],
                peer_llgr_capable: false,
                peer_llgr_families: vec![],
                llgr_stale_time: 0,
            });
        } else {
            self.manager.handle_update(RibUpdate::PeerDown {
                peer: observer,
                session_id: self.session,
            });
        }
        // The transport discards the dying session's queued updates.
        self.occupied.clear();
        while self.rx.try_recv().is_ok() {}
        if self.helper && !notification {
            // RFC 4724 4.2: a peer that advertised the GR capability keeps
            // our routes as stale after the session ends, and deletes them
            // at our End-of-RIB on the new session. "To deal with possible
            // consecutive restarts, a route (from the peer) previously
            // marked as stale MUST be deleted."
            for key in std::mem::take(&mut self.stale) {
                self.wire.remove(&key);
            }
            self.stale = self.wire.keys().copied().collect();
            self.blackholed = self.exempt_rows();
        } else {
            // A NOTIFICATION, or a peer without GR, drops our routes: no
            // blackhole survives the reset.
            self.wire.clear();
            self.stale.clear();
            self.blackholed.clear();
        }
        self.helper = helper;
        self.gr_families = gr_families;
        let (tx, rx) = mpsc::channel(4);
        self.tx = tx;
        self.rx = rx;
        self.session += 1000;
        if writer_full {
            let writer = self.tx.clone();
            self.occupied =
                std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
        }
        self.establish();
    }

    fn register(&mut self) {
        let mut up =
            super::lifecycle::test_peer_up(peer_v4(OBSERVER), self.session, self.tx.clone());
        if let RibUpdate::PeerUp {
            export_policy,
            per_client_best,
            add_path_send_families,
            add_path_send_max,
            sendable_families,
            negotiated_orf_recv,
            ..
        } = &mut up
        {
            *sendable_families = vec![FAMILY];
            *per_client_best = self.config.per_client_best;
            *export_policy = self.export_policy();
            if self.config.add_path {
                *add_path_send_families = vec![FAMILY];
                *add_path_send_max = u32::try_from(ADD_PATH_MAX).unwrap();
            }
            if self.config.orf {
                *negotiated_orf_recv = vec![FAMILY];
            }
        }
        self.manager.handle_update(up);
        if self.config.orf {
            // Re-registration clears the session's filter and re-arms the
            // initial-advertisement gate until the peer refreshes.
            self.deny = 0;
            self.orf_gated = true;
        }
    }

    fn push_orf(&mut self, deny: u8) {
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
                sequence: u32::try_from(index).unwrap() + 1,
                min_len: 0,
                max_len: 0,
                prefix: Some(prefix(index)),
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
        let (reply, mut response) = oneshot::channel();
        self.manager.handle_update(RibUpdate::PeerOrfUpdate {
            peer: peer_v4(OBSERVER),
            session_id: self.session,
            afi: FAMILY.0,
            safi: FAMILY.1,
            when: WhenToRefresh::Immediate,
            entries,
            reply,
        });
        response.try_recv().unwrap().unwrap();
        self.deny = deny;
        self.orf_gated = false;
    }

    fn identity(route: &Route) -> usize {
        route
            .communities()
            .iter()
            .find(|community| *community >> 16 == IDENTITY_ASN)
            .map(|community| (community & 0xffff) as usize)
            .expect("every modelled route carries its identity")
    }

    fn new_injection(
        &mut self,
        prefix: usize,
        preference: u32,
        exempt: bool,
        community: bool,
    ) -> usize {
        self.injections.push(Injection {
            prefix,
            preference,
            exempt,
            community,
            live: true,
            deleted: false,
        });
        self.injections.len() - 1
    }

    fn retire(&mut self, injection: Option<usize>) {
        if let Some(injection) = injection {
            self.injections[injection].live = false;
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match keeps every operation's daemon call beside its model update"
    )]
    fn apply(&mut self, op: &Op) {
        if !op.in_segment() {
            self.settle();
        }
        match *op {
            Op::Inject {
                prefix: index,
                path,
                preference,
                blackhole,
            } => {
                // Unique per path and variant, and even, so ranks never tie
                // with each other or with a received path.
                let preference = 100 + 2 * (u32::try_from(path).unwrap() + 3 * preference);
                let exempt = index < 2 || blackhole;
                let injection = self.new_injection(index, preference, exempt, blackhole);
                let Prefix::V4(v4) = prefix(index) else {
                    unreachable!()
                };
                let mut route = make_route_with_lp(v4, SOURCE, preference);
                set_peer(&mut route, crate::PeerId::LOCAL);
                route.origin_type = crate::route::RouteOrigin::Local;
                route.path_id = PATH_IDS[path];
                let mut communities =
                    vec![(IDENTITY_ASN << 16) | u32::try_from(injection).unwrap()];
                if blackhole {
                    communities.push(rustbgpd_wire::COMMUNITY_BLACKHOLE);
                }
                route.attributes = AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath { segments: vec![] }),
                    PathAttribute::LocalPref(preference),
                    PathAttribute::Communities(communities),
                ]);
                let (reply, mut result) = oneshot::channel();
                self.manager
                    .handle_update(RibUpdate::InjectRoute { route, reply });
                result.try_recv().unwrap().unwrap();
                let old = self.local.insert((index, path), injection);
                self.retire(old);
            }
            Op::Delete {
                prefix: index,
                path,
            } => {
                let (reply, mut result) = oneshot::channel();
                self.manager.handle_update(RibUpdate::WithdrawInjected {
                    prefix: prefix(index),
                    path_id: PATH_IDS[path],
                    allow_missing: true,
                    owner: String::new(),
                    override_owner: false,
                    reply,
                });
                result.try_recv().unwrap().unwrap();
                let old = self.local.remove(&(index, path));
                if let Some(old) = old {
                    self.injections[old].deleted = true;
                }
                self.retire(old);
            }
            Op::Receive {
                prefix: index,
                path,
                preference,
                blackhole,
            } => {
                // Odd, so a received path never ties a local one.
                let preference = 101 + 2 * (u32::try_from(path).unwrap() + 3 * preference);
                let injection = self.new_injection(index, preference, false, blackhole);
                let route = Self::received_route(index, path, preference, blackhole, injection);
                self.receive(vec![route], vec![]);
                let old = self.received.insert((index, path), injection);
                self.retire(old);
                if let Some(gr) = &mut self.source_gr {
                    gr.stale.remove(&(index, path));
                }
            }
            Op::ReceiveWithdraw {
                prefix: index,
                path,
            } => {
                self.receive(vec![], vec![(prefix(index), PATH_IDS[path])]);
                let old = self.received.remove(&(index, path));
                self.retire(old);
                if let Some(gr) = &mut self.source_gr {
                    gr.stale.remove(&(index, path));
                }
            }
            Op::Orf { deny } => {
                // A receiver with no session yet sends no ORF.
                if self.config.orf && self.registered {
                    self.push_orf(deny);
                }
            }
            Op::Backpressure(true) => {
                if self.occupied.is_empty() {
                    let writer = self.tx.clone();
                    self.occupied =
                        std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
                }
            }
            Op::Backpressure(false) => self.occupied.clear(),
            Op::RefuseProof => {
                // Freeing the writer starts the dirty retry that is refused.
                self.occupied.clear();
                self.manager
                    .pending_group_admitted
                    .fail_next_allocation_for_test();
                self.manager.distribute_changes_to_targets(
                    &HashSet::new(),
                    &HashSet::from([peer_v4(OBSERVER)]),
                );
                self.manager
                    .pending_group_admitted
                    .disarm_allocation_failure_for_test();
            }
            Op::Tag {
                prefix: index,
                path,
                received,
                exclusive,
            } => self.tag(index, path, received, exclusive),
            Op::Resync => {
                self.occupied.clear();
                self.manager.distribute_changes_to_targets(
                    &HashSet::new(),
                    &HashSet::from([peer_v4(OBSERVER)]),
                );
            }
            Op::Reconnect { .. } if self.registered => self.reconnect(op),
            // A receiver whose first session is still to come has none to
            // flap.
            Op::Drain | Op::Reconnect { .. } => {}
            Op::Regroup { kind, on } => self.regroup(kind, on),
            Op::RestartPeer {
                source: true,
                restart,
                stale,
            } => self.restart_source(restart, stale),
            Op::RestartPeer {
                source: false,
                restart,
                ..
            } => self.restart_absent(restart),
            Op::QueueBulk => self.queue_bulk(),
            Op::QueueRefresh => self.queue_refresh(),
            Op::AdvanceToDeadline => self.advance_to_deadline(),
        }
    }

    /// Best first: a fresh path before a GR-stale one (RFC 4724 tier,
    /// `best_path::stale_rank`), then higher `LOCAL_PREF`.
    fn rank(&self, injection: usize) -> (bool, std::cmp::Reverse<u32>) {
        let stale = self.source_gr.as_ref().is_some_and(|gr| {
            gr.stale
                .iter()
                .any(|key| self.received.get(key) == Some(&injection))
        });
        (
            stale,
            std::cmp::Reverse(self.injections[injection].preference),
        )
    }

    /// The source's route for injection `injection` at `(index, path)`.
    fn received_route(
        index: usize,
        path: usize,
        preference: u32,
        blackhole: bool,
        injection: usize,
    ) -> Route {
        let Prefix::V4(v4) = prefix(index) else {
            unreachable!()
        };
        let mut route = make_route_with_lp(v4, SOURCE, preference);
        route.path_id = PATH_IDS[path];
        let mut communities = vec![(IDENTITY_ASN << 16) | u32::try_from(injection).unwrap()];
        if blackhole {
            communities.push(rustbgpd_wire::COMMUNITY_BLACKHOLE);
        }
        AttrSet::edit(&mut route.attributes, |attributes| {
            attributes.push(PathAttribute::Communities(communities));
        });
        route
    }

    fn source_expirations(&self) -> f64 {
        let peer = SOURCE.to_string();
        counter_metric_value(
            &self.manager.metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", peer.as_str())],
        )
    }

    /// The source's clean end under GR, then its re-establishment with the
    /// restart flag, as the transport reports them.
    fn restart_source(&mut self, restart: u8, stale: u8) {
        if self.source_gr.is_some() {
            return;
        }
        let rt = Rc::clone(&self.rt);
        let _clock = rt.enter();
        self.manager.handle_update(RibUpdate::PeerGracefulRestart {
            peer: peer_v4(SOURCE),
            session_id: self.source_session,
            restart_time: u16::from(restart),
            stale_routes_time: u64::from(stale),
            gr_families: vec![FAMILY],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        });
        self.source_session += 1000;
        self.source = connect_source(&mut self.manager, self.source_session, true);
        self.source_gr = Some(SourceGr {
            deadline: self.manager.gr_stale_deadlines[&peer_v4(SOURCE)],
            stale: self.received.keys().copied().collect(),
            refreshed: false,
            expired: self.source_expirations(),
        });
    }

    /// The absent peer's session comes up and ends cleanly under GR; it
    /// never returns, so its deadline sweeps it.
    fn restart_absent(&mut self, restart: u8) {
        if self.absent.is_some() {
            return;
        }
        let rt = Rc::clone(&self.rt);
        let _clock = rt.enter();
        let rx = connect(&mut self.manager, ABSENT, 64, true, true);
        self.manager.handle_update(RibUpdate::PeerGracefulRestart {
            peer: peer_v4(ABSENT),
            session_id: ABSENT_SESSION,
            restart_time: u16::from(restart),
            stale_routes_time: 360,
            gr_families: vec![FAMILY],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        });
        self.absent = Some(Absent {
            rx,
            deadline: self.manager.gr_stale_deadlines[&peer_v4(ABSENT)],
        });
    }

    /// Open a segment: the real run loop takes the manager, reading a fresh
    /// primary queue.
    fn start_actor(&mut self) {
        if self.actor.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel(64);
        let stand_in = RibManager::new(
            mpsc::channel(1).1,
            dummy_query_rx(),
            None,
            None,
            BgpMetrics::new(),
        );
        let mut manager = std::mem::replace(&mut self.manager, stand_in);
        manager.rx = rx;
        // As `run()` does, so suspension and the primary run budget behave
        // as in production.
        let recorder = manager.metrics.rib_actor_slice_recorder();
        let suspended = std::sync::Arc::clone(&manager.actor_suspended);
        self.actor = Some(Actor {
            tx,
            run: Box::pin(super::super::slice_timing::TimedActor::new(
                manager.run_actor(),
                recorder,
                suspended,
            )),
        });
    }

    fn queue(&mut self, update: RibUpdate) {
        self.start_actor();
        self.actor
            .as_ref()
            .expect("an open segment")
            .tx
            .try_send(update)
            .expect("the primary queue has room");
    }

    fn queue_bulk(&mut self) {
        let withdrawn = (0..BULK_WITHDRAWALS)
            .map(|i| {
                let host = Ipv4Addr::from(0x0a80_0000 + u32::try_from(i).unwrap());
                (Prefix::V4(Ipv4Prefix::new(host, 32)), 0)
            })
            .collect();
        self.queue(RibUpdate::RoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: self.source_session,
            announced: vec![],
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
    }

    /// Every live received path again as a fresh injection, then the
    /// source's End-of-RIB, queued before its deadline.
    fn queue_refresh(&mut self) {
        let now = {
            let _clock = self.rt.enter();
            tokio::time::Instant::now()
        };
        if self
            .source_gr
            .as_ref()
            .is_none_or(|gr| gr.refreshed || now >= gr.deadline)
        {
            return;
        }
        let paths: Vec<_> = self
            .received
            .iter()
            .map(|(&key, &old)| (key, old))
            .collect();
        let mut announced = Vec::new();
        for ((index, path), old) in paths {
            let preference = self.injections[old].preference;
            let blackhole = self.injections[old].community;
            let injection = self.new_injection(index, preference, false, blackhole);
            announced.push(Self::received_route(
                index, path, preference, blackhole, injection,
            ));
            self.received.insert((index, path), injection);
            self.retire(Some(old));
        }
        if !announced.is_empty() {
            self.queue(RibUpdate::RoutesReceived {
                peer: peer_v4(SOURCE),
                session_id: self.source_session,
                announced,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            });
        }
        self.queue(RibUpdate::EndOfRib {
            peer: peer_v4(SOURCE),
            session_id: self.source_session,
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        let gr = self.source_gr.as_mut().expect("checked above");
        gr.refreshed = true;
        gr.stale.clear();
    }

    /// The earliest GR deadline still ahead, then one actor turn.
    fn advance_to_deadline(&mut self) {
        let rt = Rc::clone(&self.rt);
        let now = {
            let _clock = rt.enter();
            tokio::time::Instant::now()
        };
        let next = [
            self.absent.as_ref().map(|absent| absent.deadline),
            self.source_gr.as_ref().map(|gr| gr.deadline),
        ]
        .into_iter()
        .flatten()
        .filter(|&deadline| deadline > now)
        .min();
        if let Some(deadline) = next {
            rt.block_on(tokio::time::advance(deadline - now));
        }
        self.start_actor();
        let _clock = rt.enter();
        let actor = self.actor.as_mut().expect("just started");
        assert!(
            actor
                .run
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "the run loop ends only when its queue closes"
        );
    }

    /// Close the segment's queue, let the run loop drain it and fire every
    /// due deadline, take the manager back, and apply the GR outcome.
    fn settle(&mut self) {
        let Some(Actor { tx, mut run }) = self.actor.take() else {
            return;
        };
        drop(tx);
        let rt = Rc::clone(&self.rt);
        let _clock = rt.enter();
        let mut context = Context::from_waker(Waker::noop());
        self.manager = (0..100_000)
            .find_map(|_| match run.as_mut().poll(&mut context) {
                Poll::Ready(manager) => Some(manager),
                Poll::Pending => None,
            })
            .expect("the run loop drains its closed queue");
        let now = tokio::time::Instant::now();
        let Some(gr) = &self.source_gr else {
            return;
        };
        if gr.refreshed {
            let expired = self.source_expirations();
            if expired > gr.expired {
                self.timer_failure = Some(format!(
                    "I7: the source's GR deadline expired although its refresh was queued before it; \
                     expirations {} -> {expired}",
                    gr.expired
                ));
            }
            self.source_gr = None;
        } else if now >= gr.deadline {
            // The deadline swept every path still stale.
            for key in gr.stale.clone() {
                let old = self.received.remove(&key);
                self.retire(old);
            }
            self.source_gr = None;
        }
    }

    /// Tag the current path at `(index, path)` with BLACKHOLE through the
    /// receiver's export policy; a grouped receiver keeps its group policy.
    fn tag(&mut self, index: usize, path: usize, received: bool, exclusive: bool) {
        if self.config.grouped || !self.registered {
            return;
        }
        let paths = if received {
            &self.received
        } else {
            &self.local
        };
        let Some(&injection) = paths.get(&(index, path)) else {
            return;
        };
        let tag = (index, self.injections[injection].preference);
        if exclusive {
            self.tags.retain(|&(tagged, _)| tagged != index);
            self.tags.insert(tag);
        } else if !self.tags.remove(&tag) {
            self.tags.insert(tag);
        }
        let export_policy = self.export_policy();
        let (reply, mut response) = oneshot::channel();
        self.manager
            .handle_update(RibUpdate::ReplacePeerExportPolicy {
                peer: peer_v4(OBSERVER),
                export_policy,
                reply,
            });
        response.try_recv().unwrap().unwrap();
    }

    /// The receiver's export policy: peer context keeps a private receiver
    /// out of update groups, and each tag adds BLACKHOLE to its path.
    fn export_policy(&self) -> Option<rustbgpd_policy::PolicyChain> {
        if self.config.grouped && !self.peer_policy {
            return None;
        }
        let mut chain =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let template = chain.policies[0].policy.entries[0].clone();
        let mut private = template.clone();
        private.prefix = None;
        private.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![u32::MAX],
            peer_groups: vec![],
        });
        let mut entries = vec![private];
        for &(index, local_pref) in &self.tags {
            let mut tag = template.clone();
            tag.prefix = Some(prefix(index));
            tag.match_local_pref_ge = Some(local_pref);
            tag.match_local_pref_le = Some(local_pref);
            tag.action = rustbgpd_policy::PolicyAction::Permit;
            tag.modifications.communities_add = vec![rustbgpd_wire::COMMUNITY_BLACKHOLE];
            entries.push(tag);
        }
        chain.policies[0].policy.entries = entries;
        Some(rustbgpd_policy::PolicyChain::from_named(chain.policies))
    }

    /// Only a grouped receiver has a group to leave; a private one already
    /// takes the per-peer path.
    fn regroup(&mut self, kind: RegroupKind, on: bool) {
        if !self.config.grouped || !self.registered {
            return;
        }
        let observer = peer_v4(OBSERVER);
        match kind {
            RegroupKind::Slow => self.manager.handle_update(RibUpdate::PeerSlowState {
                peer: observer,
                session_id: self.session,
                slow: on,
            }),
            RegroupKind::PeerPolicy => {
                self.peer_policy = on;
                let (reply, mut response) = oneshot::channel();
                self.manager
                    .handle_update(RibUpdate::ReplacePeerExportPolicy {
                        peer: observer,
                        export_policy: self.export_policy(),
                        reply,
                    });
                response.try_recv().unwrap().unwrap();
            }
            RegroupKind::Conditional => {
                let (reply, mut capture) = oneshot::channel();
                self.manager
                    .handle_update(RibUpdate::InstallConditionalAdvertisements {
                        set: unrelated_conditional(on.then_some(observer)),
                        swapping_datasets: vec![],
                        reply,
                    });
                capture.try_recv().unwrap();
            }
        }
    }

    fn receive(&mut self, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) {
        self.manager.handle_update(RibUpdate::RoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: self.source_session,
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut self.manager);
    }

    /// Apply what the receiver got; I4 holds for every announcement.
    fn observe(&mut self) -> Result<usize, TestCaseError> {
        if let Some(reason) = self.timer_failure.take() {
            return Err(TestCaseError::fail(reason));
        }
        // An open segment's updates are read once it settles, after its GR
        // outcome reaches the model.
        if self.actor.is_some() {
            return Ok(0);
        }
        // The source and waiter never backpressure: only the receiver
        // retries.
        while self.source.try_recv().is_ok() {}
        while self
            .absent
            .as_mut()
            .is_some_and(|absent| absent.rx.try_recv().is_ok())
        {}
        while self
            .waiter
            .as_mut()
            .is_some_and(|waiter| waiter.try_recv().is_ok())
        {}
        let mut updates = 0;
        while let Ok(update) = self.rx.try_recv() {
            updates += 1;
            if std::env::var("ORACLE_TRACE").is_ok() {
                eprintln!(
                    "  wire: announce {:?} withdraw {:?} eor {:?} markers {:?}",
                    update
                        .announce
                        .iter()
                        .map(|route| (route.prefix, route.path_id, Self::identity(route)))
                        .collect::<Vec<_>>(),
                    update.withdraw,
                    update.end_of_rib,
                    update.refresh_markers
                );
            }
            // I6: a GR helper rightly keeps the ended session's stale
            // ordinary row until our End-of-RIB; inside the hold only a key
            // whose prefix a fresh session would not advertise at all may
            // leave.
            if self.held
                && update.withdraw.iter().any(|key| {
                    self.stale.contains(key)
                        && self
                            .wire
                            .get(key)
                            .is_some_and(|&injection| !self.injections[injection].exempt)
                })
            {
                let expected = self.expected();
                for key in &update.withdraw {
                    let retained = self.stale.contains(key)
                        && self
                            .wire
                            .get(key)
                            .is_some_and(|&injection| !self.injections[injection].exempt);
                    prop_assert!(
                        !retained || !expected.keys().any(|wanted| wanted.0 == key.0),
                        "I6: withdrew the stale ordinary row {}#{} a GR helper keeps inside the hold; wire {}",
                        key.0,
                        key.1,
                        show(&self.wire)
                    );
                }
            }
            for key in &update.withdraw {
                self.wire.remove(key);
                self.stale.remove(key);
            }
            // The transport sends an envelope's withdrawals as their own
            // UPDATEs before its announcements, then the leading blackholing
            // rows (`exempt_announce`) in slices of their own, then the rest.
            // Within each part it groups rows by attributes, slices them by
            // an adaptive budget, and sends body NLRI before MP_REACH, so any
            // order is possible: apply each part's ordinary rows before its
            // blackholing ones, the worst order, and check the peer's state
            // after the withdrawals and after every announcement.
            self.apply_announcements(&update)?;
            // Our End-of-RIB ends a GR helper's retention: it purges every
            // stale row this session did not re-announce.
            if update.end_of_rib.contains(&FAMILY) && !self.stale.is_empty() {
                for key in std::mem::take(&mut self.stale) {
                    self.wire.remove(&key);
                }
                if self.per_update_i1 {
                    self.check_blackholed()?;
                }
            }
        }
        Ok(updates)
    }

    /// I4 for every announcement; I1 and I6 after the withdrawals and after
    /// each announcement, in the worst order the transport may send them.
    fn apply_announcements(&mut self, update: &OutboundRouteUpdate) -> Checked {
        /// One part's rows, ordinary before blackholing.
        fn worst(part: &[Route]) -> Vec<&Route> {
            let (exempt, ordinary): (Vec<&Route>, Vec<&Route>) = part.iter().partition(|route| {
                route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
                    || crate::manager::helpers::unicast_deferral_exempt(route)
            });
            ordinary.into_iter().chain(exempt).collect()
        }
        self.check_send_limit()?;
        if self.per_update_i1 {
            self.check_blackholed()?;
        }
        let (lead, rest) = update
            .announce
            .split_at(update.exempt_announce.min(update.announce.len()));
        for route in worst(lead).into_iter().chain(worst(rest)) {
            let injection = Self::identity(route);
            let resurrected = self.injections[injection].exempt && !self.injections[injection].live;
            prop_assert!(
                !resurrected,
                "I4: removed exempt injection {injection} re-announced at {:?}",
                (route.prefix, route.path_id)
            );
            let key = (route.prefix, route.path_id);
            self.wire.insert(key, injection);
            self.wire_tag.insert(
                key,
                route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE),
            );
            self.stale.remove(&key);
            self.check_send_limit()?;
            if self.per_update_i1 {
                self.check_blackholed()?;
            }
        }
        Ok(())
    }

    /// I6: no prefix carries more of this session's paths than the
    /// receiver may be sent. A GR helper's stale rows from an earlier
    /// session are not this session's.
    fn check_send_limit(&self) -> Checked {
        let limit = if self.config.add_path {
            ADD_PATH_MAX
        } else {
            1
        };
        let mut paths = BTreeMap::<Prefix, usize>::new();
        for key in self.wire.keys().filter(|key| !self.stale.contains(*key)) {
            *paths.entry(key.0).or_default() += 1;
        }
        for (prefix, count) in paths {
            prop_assert!(
                count <= limit,
                "I6: {prefix} carries {count} paths, over the send limit {limit}; wire {}",
                show(&self.wire)
            );
        }
        Ok(())
    }

    fn drain(&mut self) -> Checked {
        for _ in 0..DRAIN_ROUNDS {
            self.manager
                .distribute_changes(&HashSet::new(), &HashSet::new());
            if self.observe()? == 0 {
                break;
            }
        }
        Ok(())
    }

    /// A fresh session's full dump of the current intent.
    fn expected(&self) -> BTreeMap<(Prefix, u32), usize> {
        let mut expected = BTreeMap::new();
        for index in 0..PREFIXES {
            if self.config.orf && self.deny & (1 << index) != 0 {
                continue;
            }
            let mut paths: Vec<usize> = self
                .local
                .range((index, 0)..(index + 1, 0))
                .map(|(_, &injection)| injection)
                .chain(
                    self.received
                        .range((index, 0)..(index + 1, 0))
                        .map(|(_, &injection)| injection),
                )
                .collect();
            paths.sort_by_key(|&injection| self.rank(injection));
            if self.config.add_path {
                for (rank, &injection) in paths.iter().take(ADD_PATH_MAX).enumerate() {
                    expected.insert((prefix(index), u32::try_from(rank).unwrap() + 1), injection);
                }
            } else if let Some(&injection) = paths.first() {
                expected.insert((prefix(index), 0), injection);
            }
        }
        expected
    }

    /// Prefix to the injections its blackholing wire rows carry: exempt,
    /// or carrying BLACKHOLE as sent, after export policy.
    fn exempt_rows(&self) -> BTreeMap<usize, BTreeSet<usize>> {
        let mut rows = BTreeMap::<_, BTreeSet<_>>::new();
        for (key, &injection) in &self.wire {
            let row = &self.injections[injection];
            if row.exempt || self.wire_tag.get(key).copied().unwrap_or(false) {
                rows.entry(row.prefix).or_default().insert(injection);
            }
        }
        rows
    }

    /// A known open defect that explains `index` losing its exempt rows
    /// during the hold, or `None`.
    fn known_unblackhole(&self, index: usize, fallback: bool) -> Option<&'static str> {
        // LAN-2692: under refused proof, an Add-Path
        // receiver withdraws a removed exempt path while its exempt
        // replacement still waits for admission.
        let removed = self.blackholed[&index]
            .iter()
            .all(|&injection| !self.injections[injection].live);
        if self.config.add_path && fallback && removed {
            return allowed("LAN-2692");
        }
        None
    }

    /// Prefixes whose export carries an exempt path: during the hold, which
    /// exports exempt local paths alone, every prefix with a live one
    /// however received paths rank; otherwise a fresh dump's.
    fn wanted_blackholes(&self) -> BTreeSet<usize> {
        if self.held {
            return self
                .local
                .iter()
                .filter(|&(&(index, _), &injection)| {
                    self.injections[injection].exempt
                        && !(self.config.orf && self.deny & (1 << index) != 0)
                })
                .map(|(&(index, _), _)| index)
                .collect();
        }
        self.expected()
            .values()
            .map(|&injection| &self.injections[injection])
            .filter(|injection| {
                injection.exempt
                    || injection.community
                    || self
                        .tags
                        .contains(&(injection.prefix, injection.preference))
            })
            .map(|injection| injection.prefix)
            .collect()
    }

    /// I1's safety half, after every UPDATE: a prefix that should be
    /// blackholed keeps an exempt row once it had one.
    fn check_blackholed(&mut self) -> Checked {
        let wanted = self.wanted_blackholes();
        let blackholed = self.exempt_rows();
        let fallback = self
            .manager
            .group_recovery_fallback(peer_v4(OBSERVER))
            .is_some();
        for &index in self
            .blackholed
            .keys()
            .filter(|index| wanted.contains(index))
        {
            prop_assert!(
                blackholed.contains_key(&index)
                    || self.known_unblackhole(index, fallback).is_some(),
                "I1: {} lost its exempt row {}; wire {}",
                prefix(index),
                if self.held {
                    "during the hold"
                } else {
                    "outside the hold"
                },
                show(&self.wire)
            );
        }
        self.blackholed = blackholed;
        Ok(())
    }

    /// A known open defect that explains a deleted exempt row still on the
    /// wire after a drain in the hold, or `None`.
    fn known_stale_blackhole(&self, key: (Prefix, u32)) -> Option<&'static str> {
        // LAN-2727: a GR helper keeps the ended session's deleted RTBH
        // stale until release while its prefix still has another route:
        // the helper may hold that route at the key instead, and keeping a
        // route it rightly holds comes first.
        let candidate = (0..PREFIXES)
            .find(|&index| prefix(index) == key.0)
            .is_some_and(|index| {
                self.local
                    .range((index, 0)..(index + 1, 0))
                    .next()
                    .is_some()
                    || self
                        .received
                        .range((index, 0)..(index + 1, 0))
                        .next()
                        .is_some()
            });
        if self.stale.contains(&key) && candidate {
            return allowed("LAN-2727");
        }
        None
    }

    /// I5 after a drain with a free writer in the hold: an exempt row the
    /// operator deleted has left the wire, unless it is the prefix's last
    /// exempt row while an exempt export is still intended (never
    /// unblackhole: LAN-2674 and LAN-2692 keep it until its replacement is
    /// admitted).
    fn check_deleted_blackholes(&self) -> Checked {
        let wanted = self.wanted_blackholes();
        for (&(prefix_key, path_id), &injection) in &self.wire {
            let row = &self.injections[injection];
            if !row.exempt || !row.deleted {
                continue;
            }
            let exempt_rows = self
                .wire
                .values()
                .filter(|&&other| {
                    let other = &self.injections[other];
                    other.prefix == row.prefix && other.exempt
                })
                .count();
            let last_blackhole = wanted.contains(&row.prefix) && exempt_rows == 1;
            prop_assert!(
                last_blackhole || self.known_stale_blackhole((prefix_key, path_id)).is_some(),
                "I5: deleted exempt injection {injection} still on the wire at {prefix_key}#{path_id} \
                 after a drain in the hold; wire {}",
                show(&self.wire)
            );
        }
        Ok(())
    }

    /// I1's liveness half after a clean drain in the hold, and I5.
    fn check_hold(&mut self, drained: bool) -> Checked {
        if drained && self.occupied.is_empty() {
            self.check_deleted_blackholes()?;
        }
        let wanted = self.wanted_blackholes();
        let settled = drained
            && self.occupied.is_empty()
            && !self.orf_gated
            && self
                .manager
                .group_recovery_fallback(peer_v4(OBSERVER))
                .is_none();
        if settled {
            for index in &wanted {
                let live = self.blackholed.get(index).is_some_and(|rows| {
                    rows.iter()
                        .any(|&injection| self.injections[injection].live)
                });
                prop_assert!(
                    live,
                    "I1: settled hold does not carry {}'s live exempt row; wire {}",
                    prefix(*index),
                    show(&self.wire)
                );
            }
        }
        Ok(())
    }

    fn release(&mut self) -> Checked {
        if std::env::var("ORACLE_TRACE").is_ok() {
            eprintln!("Release");
        }
        self.occupied.clear();
        self.manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: WAITER_SESSION,
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        self.held = false;
        self.observe()?;
        self.drain()?;
        self.resync_ticks()?;
        if self.orf_gated {
            // The peer's refresh opens the re-armed gate.
            self.push_orf(self.deny);
            self.observe()?;
            self.drain()?;
            self.resync_ticks()?;
        }
        // Production re-arms the timer while work stays runnable, so work
        // the ticks never clear would spin it forever.
        prop_assert!(
            !self.manager.resync_tick_pending(),
            "resync work still runnable after {DRAIN_ROUNDS} release ticks"
        );
        Ok(())
    }

    /// The actor arms its resync timer while `resync_tick_pending` reports
    /// runnable work, such as an End-of-RIB held back at release, so that
    /// work lands within a tick of the release.
    fn resync_ticks(&mut self) -> Checked {
        for _ in 0..DRAIN_ROUNDS {
            if !self.manager.resync_tick_pending() {
                break;
            }
            self.manager.resync_dirty_peers_bounded();
            self.observe()?;
            self.drain()?;
        }
        Ok(())
    }

    /// `rows` with each prefix's Add-Path keys renumbered 1.. in a fixed
    /// path order, repeated paths last. RFC 7911 path IDs are opaque and the
    /// daemon keeps a path's key for as long as it is sent, so a long-lived
    /// session's keys need not match a fresh dump's.
    fn renumbered(
        &self,
        rows: impl IntoIterator<Item = ((Prefix, u32), usize)>,
    ) -> BTreeMap<(Prefix, u32), usize> {
        if !self.config.add_path {
            return rows.into_iter().collect();
        }
        let mut paths = BTreeMap::<Prefix, Vec<usize>>::new();
        for ((prefix, _), injection) in rows {
            paths.entry(prefix).or_default().push(injection);
        }
        let mut renumbered = BTreeMap::new();
        for (prefix, mut injections) in paths {
            injections.sort_unstable();
            let mut repeated = Vec::new();
            injections.dedup_by(|next, kept| {
                let same = next == kept;
                if same {
                    repeated.push(*next);
                }
                same
            });
            injections.sort_by_key(|&injection| (self.rank(injection), injection));
            for (key, injection) in (1..).zip(injections.into_iter().chain(repeated)) {
                renumbered.insert((prefix, key), injection);
            }
        }
        renumbered
    }

    fn check_converged(&mut self) -> Checked {
        let expected = self.renumbered(self.expected());
        let wire = self.renumbered(self.wire.iter().map(|(&key, &value)| (key, value)));
        prop_assert!(
            wire == expected,
            "I2: released wire {} differs from a fresh dump {}",
            show(&wire),
            show(&expected)
        );
        // The paths match; each must also carry BLACKHOLE exactly as its
        // current export intends, so a policy retag that announced nothing
        // cannot pass on the old rows.
        for (key, &injection) in &self.wire {
            let row = &self.injections[injection];
            let intended = row.community || self.tags.contains(&(row.prefix, row.preference));
            let sent = self.wire_tag.get(key).copied().unwrap_or(false);
            prop_assert!(
                sent == intended,
                "I2: {}#{} carries BLACKHOLE {sent}, but its export intends {intended}; wire {}",
                key.0,
                key.1,
                show(&self.wire)
            );
        }
        let actual = self
            .manager
            .actual_unicast_advertised_count(peer_v4(OBSERVER));
        prop_assert!(
            actual == wire.len(),
            "I3: actual advertised count {actual} differs from {} wire keys",
            wire.len()
        );
        Ok(())
    }
}

fn run(config: Config, setup: &[Op], hold: &[Op]) -> Checked {
    let mut harness = Harness::new(config);
    let rt = Rc::clone(&harness.rt);
    let _clock = rt.enter();
    harness.observe()?;
    for op in setup {
        if !op.in_segment() {
            // A settled segment's updates reach the wire checks before the
            // next op changes the intent they are checked against.
            harness.settle();
            harness.observe()?;
        }
        harness.apply(op);
        harness.observe()?;
    }
    harness.settle();
    harness.observe()?;
    harness.drain()?;
    prop_assert!(
        config.late
            || harness
                .manager
                .grouped_member_of(peer_v4(OBSERVER))
                .is_some()
                == config.grouped,
        "the configuration names the receiver's real distribution mode"
    );
    harness.blackholed = harness.exempt_rows();
    harness.waiter = Some(connect(&mut harness.manager, WAITER, 64, true, false));
    harness.held = true;
    prop_assert!(harness.manager.selection_deferred(FAMILY));
    harness.observe()?;
    if config.late {
        // The receiver's first session establishes inside the hold.
        harness.establish();
        harness.observe()?;
    }
    for op in hold {
        if std::env::var("ORACLE_TRACE").is_ok() {
            eprintln!(
                "{op:?}: dirty={} fallback={:?} orf_pending={:?}",
                harness.manager.dirty_peers.contains(&peer_v4(OBSERVER)),
                harness.manager.group_recovery_fallback(peer_v4(OBSERVER)),
                harness.manager.peer_orf_pending.get(&peer_v4(OBSERVER))
            );
        }
        harness.apply(op);
        harness.observe()?;
        let drained = matches!(op, Op::Drain);
        if drained {
            harness.drain()?;
        }
        harness.check_hold(drained)?;
    }
    harness.release()?;
    harness.check_converged()
}

/// `Some(tag)` unless `ORACLE_STRICT` disables this allowance: `1`
/// disables every allowance, a comma-separated list only those tags.
fn allowed(tag: &'static str) -> Option<&'static str> {
    match std::env::var("ORACLE_STRICT") {
        Err(_) => Some(tag),
        Ok(strict) => {
            (strict != "1" && !strict.split(',').any(|disabled| disabled == tag)).then_some(tag)
        }
    }
}

/// The panic's message.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
        .unwrap_or_default()
}

/// The failing invariant's message, or a panic's.
fn failure(config: Config, setup: &[Op], hold: &[Op]) -> Option<String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(config, setup, hold))) {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(panic) => Some(panic_message(&*panic)),
    }
}

/// The failed invariant's label (`I1`..`I4`), or a panic's first clause.
fn invariant(reason: &str) -> &str {
    let reason = reason.strip_prefix("Case failed: ").unwrap_or(reason);
    reason.split(':').next().unwrap_or_default()
}

/// Greedy one-op deletion to a fixpoint, keeping the same failing
/// invariant: proptest's shrinker stops at the first deletion that passes.
fn minimize(
    config: Config,
    mut setup: Vec<Op>,
    mut hold: Vec<Op>,
    label: &str,
) -> (Vec<Op>, Vec<Op>) {
    let same = |setup: &[Op], hold: &[Op]| {
        failure(config, setup, hold).is_some_and(|message| invariant(&message) == label)
    };
    loop {
        let before = setup.len() + hold.len();
        let mut index = 0;
        while index < hold.len() {
            let mut fewer = hold.clone();
            fewer.remove(index);
            if same(&setup, &fewer) {
                hold = fewer;
            } else {
                index += 1;
            }
        }
        let mut index = 0;
        while index < setup.len() {
            let mut fewer = setup.clone();
            fewer.remove(index);
            if same(&fewer, &hold) {
                setup = fewer;
            } else {
                index += 1;
            }
        }
        if setup.len() + hold.len() == before {
            return (setup, hold);
        }
    }
}

#[test]
fn gr_hold_matches_a_fresh_session_model() {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(128);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let strategy = (
        config_strategy(),
        pre_hold_strategy(),
        proptest::collection::vec(hold_strategy(), 1..40),
    );
    let Err(error) = runner.run(&strategy, |(config, setup, hold)| {
        run(config, &setup, &hold)
    }) else {
        return;
    };
    let proptest::test_runner::TestError::Fail(reason, (config, setup, hold)) = error else {
        panic!("{error}");
    };
    let reason = reason.to_string();
    let label = invariant(&reason).to_string();
    let (setup, hold) = minimize(config, setup, hold, &label);
    let reason = failure(config, &setup, &hold).unwrap_or(reason);
    panic!("{reason}\nminimized: {config:#?}\nsetup: {setup:#?}\nhold: {hold:#?}");
}

/// I1 must see a withdraw and re-announce split across two UPDATEs: the
/// peer is unblackholed between them, though the channel's end state
/// matches its start.
#[test]
fn i1_catches_a_transient_unblackhole_between_updates() {
    let config = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let transient = |per_update: bool| {
        let mut harness = Harness::new(config);
        harness.apply(&Op::Inject {
            prefix: 0,
            path: 0,
            preference: 0,
            blackhole: false,
        });
        harness.drain().unwrap();
        let host = prefix(0);
        assert_eq!(harness.wire.get(&(host, 0)), Some(&0));
        harness.blackholed = harness.exempt_rows();
        let Prefix::V4(v4) = host else { unreachable!() };
        let mut route = make_route_with_lp(v4, SOURCE, 100);
        route.attributes = AttrSet::new(vec![PathAttribute::Communities(vec![IDENTITY_ASN << 16])]);
        // A seeded transient: the live RTBH row leaves and comes back.
        harness
            .tx
            .try_send(OutboundRouteUpdate {
                withdraw: vec![(host, 0)],
                ..OutboundRouteUpdate::default()
            })
            .unwrap();
        harness
            .tx
            .try_send(OutboundRouteUpdate {
                announce: Arc::new(vec![route]),
                ..OutboundRouteUpdate::default()
            })
            .unwrap();
        harness.held = true;
        harness.per_update_i1 = per_update;
        let observed = harness.observe().map(|_| ());
        if observed.is_ok() {
            assert_eq!(
                harness.wire.get(&(host, 0)),
                Some(&0),
                "the end state matches"
            );
        }
        observed.and_then(|()| harness.check_blackholed())
    };
    let error = transient(true).expect_err("per-update I1 sees the gap");
    assert!(
        error
            .to_string()
            .contains("I1: 198.51.100.1/32 lost its exempt row")
    );
    assert!(
        transient(false).is_ok(),
        "a check after the whole channel cannot see it"
    );
}

/// One envelope that withdraws the live RTBH key and announces its
/// exempt replacement reaches the peer as two UPDATEs, withdrawals first:
/// I1 must see the gap between the phases.
#[test]
fn i1_catches_an_unblackhole_between_an_envelopes_phases() {
    let config = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let replaced = |between_phases: bool| {
        let mut harness = Harness::new(config);
        harness.apply(&Op::Inject {
            prefix: 0,
            path: 0,
            preference: 0,
            blackhole: false,
        });
        harness.apply(&Op::Inject {
            prefix: 0,
            path: 1,
            preference: 1,
            blackhole: false,
        });
        harness.drain().unwrap();
        let host = prefix(0);
        assert_eq!(harness.wire.get(&(host, 0)), Some(&1));
        harness.blackholed = harness.exempt_rows();
        let Prefix::V4(v4) = host else { unreachable!() };
        let mut route = make_route_with_lp(v4, SOURCE, 100);
        route.path_id = 7;
        route.attributes = AttrSet::new(vec![PathAttribute::Communities(vec![IDENTITY_ASN << 16])]);
        // A seeded envelope: drop the live row's key, announce injection
        // 0 (still live and exempt) under another key.
        harness
            .tx
            .try_send(OutboundRouteUpdate {
                withdraw: vec![(host, 0)],
                announce: Arc::new(vec![route]),
                ..OutboundRouteUpdate::default()
            })
            .unwrap();
        harness.held = true;
        harness.per_update_i1 = between_phases;
        let observed = harness.observe().map(|_| ());
        observed.and_then(|()| harness.check_blackholed())
    };
    let error = replaced(true).expect_err("the phase gap unblackholes the peer");
    assert!(
        error
            .to_string()
            .contains("I1: 198.51.100.1/32 lost its exempt row")
    );
    assert!(
        replaced(false).is_ok(),
        "a check after the whole envelope cannot see it"
    );
}

/// One envelope that announces an ordinary row over the last exempt row's
/// Add-Path key, then a live exempt row at the next key, reaches the peer
/// as two UPDATEs (their attributes differ): I1 must see the gap.
#[test]
fn i1_catches_an_unblackhole_between_an_envelopes_announcements() {
    let config = Config {
        grouped: false,
        add_path: true,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let swapped = |per_announcement: bool| {
        let mut harness = Harness::new(config);
        harness.apply(&Op::Inject {
            prefix: 2,
            path: 0,
            preference: 0,
            blackhole: true,
        });
        harness.drain().unwrap();
        let aggregate = prefix(2);
        assert_eq!(harness.wire.get(&(aggregate, 1)), Some(&0));
        harness.blackholed = harness.exempt_rows();
        // A live ordinary row the seeded envelope moves onto key 1.
        let ordinary = harness.new_injection(2, 120, false, false);
        let Prefix::V4(v4) = aggregate else {
            unreachable!()
        };
        let row = |injection: usize, path_id| {
            let mut route = make_route_with_lp(v4, SOURCE, 100);
            route.path_id = path_id;
            route.attributes = AttrSet::new(vec![PathAttribute::Communities(vec![
                (IDENTITY_ASN << 16) | u32::try_from(injection).unwrap(),
            ])]);
            route
        };
        harness
            .tx
            .try_send(OutboundRouteUpdate {
                announce: Arc::new(vec![row(ordinary, 1), row(0, 2)]),
                ..OutboundRouteUpdate::default()
            })
            .unwrap();
        harness.held = true;
        harness.per_update_i1 = per_announcement;
        let observed = harness.observe().map(|_| ());
        observed.and_then(|()| harness.check_blackholed())
    };
    let error = swapped(true).expect_err("the gap between announcements unblackholes the peer");
    assert!(
        error
            .to_string()
            .contains("I1: 203.0.113.0/24 lost its exempt row")
    );
    assert!(
        swapped(false).is_ok(),
        "a check after all announcements cannot see it"
    );
}

/// I5: an RTBH the operator deletes during the hold leaves the wire inside
/// the hold, for private and grouped receivers, before and after the
/// receiver's session flaps onto a new channel, and under a refused proof.
#[test]
fn deleted_rtbh_leaves_the_wire_inside_the_hold() {
    let config = |grouped| Config {
        grouped,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let setup = vec![
        Op::Inject {
            prefix: 0,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::Receive {
            prefix: 3,
            path: 0,
            preference: 0,
            blackhole: false,
        },
    ];
    let delete = Op::Delete { prefix: 0, path: 0 };
    let plain = vec![
        Op::Backpressure(true),
        delete.clone(),
        Op::Backpressure(false),
        Op::Drain,
    ];
    let reconnected = |notification| {
        vec![
            Op::Reconnect {
                notification,
                helper: true,
                gr_families: true,
                writer_full: false,
            },
            Op::Drain,
            delete.clone(),
            Op::Drain,
        ]
    };
    // The RTBH predates the dirty retry, so a refused proof does not keep it.
    let refused = vec![
        Op::Backpressure(true),
        Op::Inject {
            prefix: 1,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::RefuseProof,
        delete.clone(),
        Op::Drain,
    ];
    let cases = [
        ("private", config(false), plain.clone()),
        ("private, proof refused", config(false), refused.clone()),
        ("grouped, proof refused", config(true), refused),
        ("grouped", config(true), plain),
        ("private, reset", config(false), reconnected(true)),
        ("grouped, reset", config(true), reconnected(true)),
        (
            "private, flapped toward a GR helper",
            config(false),
            reconnected(false),
        ),
        (
            "grouped, flapped toward a GR helper",
            config(true),
            reconnected(false),
        ),
    ];
    let failed: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, config, hold)| {
            failure(config, &setup, &hold).map(|reason| format!("{name}: {reason}"))
        })
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

/// The wire model drops a row a GR helper already held as stale when the
/// session flaps again before our End-of-RIB (RFC 4724 4.2).
#[test]
fn consecutive_flaps_drop_rows_already_stale() {
    let mut harness = Harness::new(Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    });
    harness.apply(&Op::Inject {
        prefix: 0,
        path: 0,
        preference: 0,
        blackhole: false,
    });
    harness.drain().unwrap();
    let key = (prefix(0), 0);
    let flap = Op::Reconnect {
        notification: false,
        helper: true,
        gr_families: true,
        writer_full: true,
    };
    harness.apply(&flap);
    harness.observe().unwrap();
    assert!(
        harness.stale.contains(&key),
        "the first flap retains the row"
    );
    harness.apply(&flap);
    harness.observe().unwrap();
    assert!(
        !harness.wire.contains_key(&key) && harness.blackholed.is_empty(),
        "the second flap deletes the row the first left stale"
    );
}

/// I5's last-row exception covers only a prefix's single exempt row: with
/// two obsolete RTBH rows and the replacement still pending, it flags both.
#[test]
fn i5_flags_obsolete_rtbh_rows_beyond_the_last() {
    let mut harness = Harness::new(Config {
        grouped: false,
        add_path: true,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    });
    for path in [1, 2] {
        let obsolete = harness.new_injection(0, 0, true, false);
        harness.injections[obsolete].live = false;
        harness.injections[obsolete].deleted = true;
        harness.wire.insert((prefix(0), path), obsolete);
    }
    let pending = harness.new_injection(0, 1, true, false);
    harness.local.insert((0, 2), pending);
    assert!(harness.check_deleted_blackholes().is_err());
    harness.wire.remove(&(prefix(0), 2));
    assert!(harness.check_deleted_blackholes().is_ok());
}

/// I5 across a clean flap toward a GR helper: the peer keeps the ended
/// session's rows stale until our End-of-RIB, which the hold defers, so an
/// RTBH deleted before the new session re-sends it must be withdrawn on the
/// new session inside the hold. The two minimized flap orders, for host and
/// BLACKHOLE-aggregate RTBHs, private and grouped. Red proof: without the
/// carried stale exempt keys every case keeps the deleted RTBH.
#[test]
fn stale_rtbh_at_a_gr_helper_leaves_the_wire_inside_the_hold() {
    let flap = |writer_full| Op::Reconnect {
        notification: false,
        helper: true,
        gr_families: true,
        writer_full,
    };
    let mut failed = Vec::new();
    for grouped in [false, true] {
        let config = Config {
            grouped,
            add_path: false,
            per_client_best: false,
            orf: false,
            limit: false,
            late: false,
        };
        for (prefix, blackhole) in [(1, false), (2, true)] {
            let inject = Op::Inject {
                prefix,
                path: 1,
                preference: 0,
                blackhole,
            };
            let delete = Op::Delete { prefix, path: 1 };
            let orders = [
                (
                    "delete behind the new writer",
                    vec![
                        inject.clone(),
                        flap(true),
                        delete.clone(),
                        Op::Backpressure(false),
                        Op::Drain,
                    ],
                ),
                (
                    "delete stuck before the flap",
                    vec![
                        inject.clone(),
                        Op::Backpressure(true),
                        delete.clone(),
                        flap(false),
                        Op::Drain,
                    ],
                ),
            ];
            for (order, hold) in orders {
                if let Some(reason) = failure(config, &[], &hold) {
                    failed.push(format!(
                        "grouped={grouped} prefix {prefix} {order}: {reason}"
                    ));
                }
            }
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// A grouped receiver's session ends cleanly toward a GR helper while an
/// RTBH host is on the wire; the new session registers behind a full
/// writer, the writer frees, and the host is deleted before the new table
/// is admitted. Its resync then leaves it dirty but partially caught up,
/// with the received ordinary row still held, and that must not hold back
/// the stale RTBH's withdrawal.
#[test]
fn partially_caught_up_reconnect_withdraws_a_stale_rtbh() {
    let config = Config {
        grouped: true,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let setup = [Op::Receive {
        prefix: 3,
        path: 0,
        preference: 0,
        blackhole: false,
    }];
    let hold = [
        Op::Inject {
            prefix: 0,
            path: 2,
            preference: 0,
            blackhole: false,
        },
        Op::Reconnect {
            notification: false,
            helper: false,
            gr_families: false,
            writer_full: true,
        },
        Op::Backpressure(false),
        Op::Delete { prefix: 0, path: 2 },
        Op::Drain,
    ];
    if let Some(reason) = failure(config, &setup, &hold) {
        panic!("{reason}");
    }
}

/// I6 against the over-carry: a grouped receiver holds an ordinary aggregate,
/// misses an RTBH that replaces it behind a full writer, and flaps toward a
/// GR helper; the RTBH is deleted before the new session's table is
/// admitted, and the aggregate is desired again but held. The helper keeps
/// its stale aggregate until release. Red proof:
/// without the desired-row check the flush withdraws it.
#[test]
fn stale_ordinary_row_survives_an_over_carried_rtbh_key() {
    let setup = [Op::Inject {
        prefix: 2,
        path: 0,
        preference: 0,
        blackhole: false,
    }];
    let hold = [
        Op::Backpressure(true),
        Op::Inject {
            prefix: 2,
            path: 1,
            preference: 2,
            blackhole: true,
        },
        Op::Reconnect {
            notification: false,
            helper: true,
            gr_families: true,
            writer_full: true,
        },
        Op::Delete { prefix: 2, path: 1 },
        Op::Backpressure(false),
        Op::Drain,
    ];
    // Grouped only: behind a full writer a private Adj-RIB-Out keeps the
    // aggregate, so the RTBH key is never carried. The private form is
    // `private_helper_keeps_its_stale_ordinary_row_under_a_dropped_rtbh`.
    let config = Config {
        grouped: true,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    if let Some(reason) = failure(config, &setup, &hold) {
        panic!("{reason}");
    }
}

/// I5 across a flap before the hold arms: the GR helper keeps our RTBH
/// stale, the new session's table waits behind a full writer, a waiter then
/// arms the hold and the RTBH is deleted. The helper must not keep the
/// deleted RTBH until release. A fresh session's writer starts empty, so
/// this pins the mechanism, not a production sequence; the deferred
/// registration in `gr_helper_stale_exempt` is the reachable one. Red
/// proof: without carrying the exempt keys of a helper teardown outside a
/// hold, it does.
#[test]
fn pre_hold_flap_leaves_a_deleted_rtbh_stale() {
    let config = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let setup = [
        Op::Inject {
            prefix: 1,
            path: 2,
            preference: 0,
            blackhole: false,
        },
        Op::Reconnect {
            notification: false,
            helper: false,
            gr_families: false,
            writer_full: true,
        },
    ];
    let hold = [
        Op::Delete { prefix: 1, path: 2 },
        Op::Backpressure(false),
        Op::Drain,
    ];
    if let Some(reason) = failure(config, &setup, &hold) {
        panic!("{reason}");
    }
}

/// A carried RTBH key whose prefix still has another route waits; once
/// that route is deleted too, the next flush withdraws the stale RTBH
/// inside the hold. Red proof: dropping the waiting keys after the first
/// flush leaves it until release.
#[test]
fn waiting_stale_rtbh_leaves_once_its_prefix_has_no_route() {
    let reconnect = Op::Reconnect {
        notification: false,
        helper: false,
        gr_families: false,
        writer_full: true,
    };
    let cases = [
        (
            Config {
                grouped: false,
                add_path: false,
                per_client_best: false,
                orf: false,
                limit: false,
                late: false,
            },
            vec![
                Op::Inject {
                    prefix: 2,
                    path: 0,
                    preference: 0,
                    blackhole: true,
                },
                Op::Inject {
                    prefix: 2,
                    path: 1,
                    preference: 0,
                    blackhole: false,
                },
                reconnect.clone(),
                Op::Delete { prefix: 2, path: 0 },
                Op::RefuseProof,
                Op::Delete { prefix: 2, path: 1 },
                Op::Drain,
            ],
        ),
        (
            Config {
                grouped: false,
                add_path: true,
                per_client_best: false,
                orf: false,
                limit: false,
                late: false,
            },
            vec![
                Op::Inject {
                    prefix: 1,
                    path: 1,
                    preference: 0,
                    blackhole: false,
                },
                Op::Inject {
                    prefix: 1,
                    path: 0,
                    preference: 0,
                    blackhole: false,
                },
                reconnect,
                Op::Delete { prefix: 1, path: 1 },
                Op::RefuseProof,
                Op::Delete { prefix: 1, path: 0 },
                Op::Drain,
            ],
        ),
    ];
    let failed: Vec<_> = cases
        .into_iter()
        .filter_map(|(config, hold)| failure(config, &[], &hold))
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

/// Each `Regroup` trigger really moves a grouped receiver onto the per-peer
/// path and back, so the op cannot pass vacuously.
#[test]
fn regroup_triggers_move_a_grouped_receiver() {
    let config = Config {
        grouped: true,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    for kind in [
        RegroupKind::Slow,
        RegroupKind::PeerPolicy,
        RegroupKind::Conditional,
    ] {
        let mut harness = Harness::new(config);
        let observer = peer_v4(OBSERVER);
        assert!(harness.manager.grouped_member_of(observer).is_some());
        harness.apply(&Op::Regroup { kind, on: true });
        assert!(
            harness.manager.grouped_member_of(observer).is_none(),
            "{kind:?} on leaves the group"
        );
        harness.apply(&Op::Regroup { kind, on: false });
        assert!(
            harness.manager.grouped_member_of(observer).is_some(),
            "{kind:?} off rejoins a group"
        );
    }
}

/// A grouped receiver that leaves its group while dirty still owes the
/// withdrawal of a row deleted behind its full writer. Red proof: dropping
/// the leaver's owed withdrawals in `recompute_update_group` fails every
/// trigger here.
#[test]
fn regroup_leaver_keeps_its_owed_withdrawals() {
    let setup = vec![
        Op::Inject {
            prefix: 0,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::Inject {
            prefix: 2,
            path: 0,
            preference: 0,
            blackhole: false,
        },
    ];
    let mut failed = Vec::new();
    for per_client_best in [false, true] {
        let config = Config {
            grouped: true,
            add_path: false,
            per_client_best,
            orf: false,
            limit: false,
            late: false,
        };
        for kind in [
            RegroupKind::Slow,
            RegroupKind::PeerPolicy,
            RegroupKind::Conditional,
        ] {
            for prefix in [0, 2] {
                let hold = [
                    Op::Backpressure(true),
                    Op::Delete { prefix, path: 0 },
                    Op::Regroup { kind, on: true },
                    Op::Backpressure(false),
                    Op::Drain,
                ];
                if let Some(reason) = failure(config, &setup, &hold) {
                    failed.push(format!(
                        "pcb={per_client_best} {kind:?} prefix {prefix}: {reason}"
                    ));
                }
            }
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// I5 under refused proof: an RTBH the refused retry itself admitted, then
/// deleted in the hold, leaves the wire inside the hold. Single-best (a),
/// and Add-Path (b) where the deleted path holds the key an unadmitted
/// exempt path would take while another exempt row covers the prefix.
#[test]
fn refused_retry_admitted_rtbh_leaves_the_wire_inside_the_hold() {
    let single = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let host = |path, preference| Op::Inject {
        prefix: 1,
        path,
        preference,
        blackhole: false,
    };
    let cases = [
        (
            "a: single-best",
            single,
            vec![
                Op::Backpressure(true),
                host(2, 0),
                Op::RefuseProof,
                Op::Delete { prefix: 1, path: 2 },
                Op::Drain,
            ],
        ),
        (
            "b: Add-Path with a covering exempt row",
            Config {
                add_path: true,
                ..single
            },
            vec![
                host(0, 0),
                Op::Backpressure(true),
                host(2, 0),
                Op::RefuseProof,
                host(1, 0),
                Op::Delete { prefix: 1, path: 0 },
                Op::Drain,
            ],
        ),
    ];
    let failed: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, config, hold)| {
            failure(config, &[], &hold).map(|reason| format!("{name}: {reason}"))
        })
        .collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

/// The minimized hold-start case, checked between each envelope's phases
/// with every allowance off: a frozen ordinary path at `#1` and an exempt
/// RTBH path at `#2` keep their keys when the hold starts, so the prefix
/// never loses its blackhole.
#[test]
fn hold_start_keeps_add_path_rtbh_key_between_phases() {
    for (per_client_best, limit) in [(false, false), (true, false), (false, true), (true, true)] {
        let config = Config {
            grouped: false,
            add_path: true,
            per_client_best,
            orf: false,
            limit,
            late: false,
        };
        let setup = [
            Op::Inject {
                prefix: 2,
                path: 1,
                preference: 2,
                blackhole: false,
            },
            Op::Inject {
                prefix: 2,
                path: 0,
                preference: 0,
                blackhole: true,
            },
        ];
        if let Some(reason) = failure(config, &setup, &[]) {
            panic!("{config:?}: {reason}");
        }
    }
    // A source promoted to RTBH while a demoted one leaves, in one
    // backpressured pass, takes over the leaving RTBH row's key, so the swap
    // is one in-place replacement.
    let config = Config {
        grouped: false,
        add_path: true,
        per_client_best: false,
        orf: true,
        limit: false,
        late: false,
    };
    let inject = |prefix, path, preference, blackhole| Op::Inject {
        prefix,
        path,
        preference,
        blackhole,
    };
    let hold = [
        inject(2, 1, 0, true),
        Op::Backpressure(true),
        inject(2, 0, 0, true),
        inject(2, 1, 0, false),
        Op::Backpressure(false),
        Op::Drain,
        Op::Orf { deny: 8 },
    ];
    if let Some(reason) = failure(config, &[inject(2, 0, 0, false)], &hold) {
        panic!("rtbh swap: {reason}");
    }
}

/// I6 shapes: a hold never puts more than `send_max` paths on a prefix.
/// 1. In one pass, an ordinary source at `#1` is promoted to RTBH and takes
///    over the deleted RTBH row's `#2`; the freeze backstop keeps its old
///    `#1`, which must count against the limit when a new RTBH path arrives.
/// 2. In one pass, a frozen row holds `#1`, an ordinary source at `#2` is
///    promoted and a higher-ranked RTBH path arrives: the promoted source's
///    own `#2` is reserved before a new key is allocated.
#[test]
fn hold_keeps_add_path_rows_within_send_max() {
    let config = Config {
        grouped: false,
        add_path: true,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let inject = |path, preference, blackhole| Op::Inject {
        prefix: 2,
        path,
        preference,
        blackhole,
    };
    let cases = [
        (
            "retained own row",
            vec![inject(0, 2, false), inject(1, 1, true)],
            vec![
                Op::Backpressure(true),
                inject(0, 2, true),
                Op::Delete { prefix: 2, path: 1 },
                Op::Backpressure(false),
                Op::Drain,
                inject(2, 0, true),
            ],
        ),
        (
            "reserved own key",
            vec![inject(0, 2, false), inject(1, 1, false)],
            vec![
                Op::Backpressure(true),
                inject(1, 1, true),
                inject(2, 3, true),
                Op::Backpressure(false),
                Op::Drain,
            ],
        ),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, setup, hold)| {
            failure(config, &setup, &hold).map(|reason| format!("{name}: {reason}"))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Outside a hold, an ordinary path that outranks an announced RTBH path
/// takes a new key: the RTBH row keeps its key, so no UPDATE leaves the
/// prefix without its blackhole. Rank-ordered keys re-announced `#1` with
/// the ordinary path before the RTBH path reached `#2`.
#[test]
fn add_path_rtbh_keeps_its_key_when_an_ordinary_path_outranks_it() {
    for per_client_best in [false, true] {
        let config = Config {
            grouped: false,
            add_path: true,
            per_client_best,
            orf: false,
            limit: false,
            late: false,
        };
        let setup = [
            Op::Inject {
                prefix: 2,
                path: 0,
                preference: 0,
                blackhole: true,
            },
            Op::Inject {
                prefix: 2,
                path: 1,
                preference: 2,
                blackhole: false,
            },
        ];
        if let Some(reason) = failure(config, &setup, &[]) {
            panic!("{config:?}: {reason}");
        }
    }
}

/// Outside a hold, deleting the ordinary path ranked above an RTBH path
/// withdraws only the deleted path's key. Rank-ordered keys withdrew the
/// RTBH path's `#2` before re-announcing it at `#1`.
#[test]
fn add_path_rtbh_keeps_its_key_when_the_path_above_it_is_deleted() {
    for per_client_best in [false, true] {
        let config = Config {
            grouped: false,
            add_path: true,
            per_client_best,
            orf: false,
            limit: false,
            late: false,
        };
        let setup = [
            Op::Inject {
                prefix: 2,
                path: 0,
                preference: 2,
                blackhole: false,
            },
            Op::Inject {
                prefix: 2,
                path: 1,
                preference: 0,
                blackhole: true,
            },
            Op::Delete { prefix: 2, path: 0 },
        ];
        if let Some(reason) = failure(config, &setup, &[]) {
            panic!("{config:?}: {reason}");
        }
    }
}

/// One pass that demotes an RTBH source to an ordinary path and adds a new
/// RTBH path (here a hold's backpressured release) hands the demoted path's
/// key to the new RTBH path in place; the demoted path takes another key.
/// Keeping the demoted path on its key replaced the last blackhole with an
/// ordinary row before the new RTBH path reached its own key.
#[test]
fn add_path_new_rtbh_takes_over_a_demoted_rtbh_key() {
    for per_client_best in [false, true] {
        let config = Config {
            grouped: false,
            add_path: true,
            per_client_best,
            orf: false,
            limit: false,
            late: false,
        };
        let setup = [Op::Inject {
            prefix: 2,
            path: 1,
            preference: 0,
            blackhole: true,
        }];
        let hold = [
            Op::Backpressure(true),
            Op::Inject {
                prefix: 2,
                path: 1,
                preference: 0,
                blackhole: false,
            },
            Op::Inject {
                prefix: 2,
                path: 0,
                preference: 0,
                blackhole: true,
            },
        ];
        if let Some(reason) = failure(config, &setup, &hold) {
            panic!("{config:?}: {reason}");
        }
    }
}

fn add_path_config() -> Config {
    Config {
        grouped: false,
        add_path: true,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    }
}

/// A GR helper keeps `#1` (ordinary) and `#2` (RTBH) as stale across a
/// reconnect outside the hold. The new session's dump plans keys on an
/// empty table and puts the RTBH path at `#1`, the ordinary one at `#2`:
/// if the ordinary row went first, `#2` would replace the stale RTBH row
/// while `#1` still held the stale ordinary row, so the dump sends every
/// blackholing row before any ordinary one.
#[test]
fn gr_reconnect_dump_sends_rtbh_rows_first() {
    let setup = [
        Op::Inject {
            prefix: 2,
            path: 0,
            preference: 2,
            blackhole: false,
        },
        Op::Inject {
            prefix: 2,
            path: 1,
            preference: 0,
            blackhole: true,
        },
        Op::Reconnect {
            notification: false,
            helper: true,
            gr_families: true,
            writer_full: false,
        },
    ];
    if let Some(reason) = failure(add_path_config(), &setup, &[]) {
        panic!("{reason}");
    }
}

/// An RTBH path added during the hold takes a fresh key beside the frozen
/// ordinary row and keeps it at release, though it now ranks first:
/// renumbering by rank would swap the two rows' keys at release.
#[test]
fn hold_added_rtbh_keeps_its_key_at_release() {
    let setup = [Op::Inject {
        prefix: 2,
        path: 0,
        preference: 0,
        blackhole: false,
    }];
    let hold = [Op::Inject {
        prefix: 2,
        path: 1,
        preference: 2,
        blackhole: true,
    }];
    if let Some(reason) = failure(add_path_config(), &setup, &hold) {
        panic!("{reason}");
    }
}

/// Two received paths of one peer fill the send limit before the hold; an
/// RTBH path added during it replaces a frozen received row in place.
#[test]
fn hold_rtbh_displaces_a_frozen_received_row_at_the_limit() {
    let receive = |path| Op::Receive {
        prefix: 2,
        path,
        preference: 0,
        blackhole: false,
    };
    let setup = [receive(0), receive(1)];
    let hold = [Op::Inject {
        prefix: 2,
        path: 0,
        preference: 2,
        blackhole: true,
    }];
    if let Some(reason) = failure(add_path_config(), &setup, &hold) {
        panic!("{reason}");
    }
}

/// Outside a hold, one pass deletes a local RTBH path at `#1` while the
/// received path at `#2` gains BLACKHOLE. The received path must take over
/// `#1` in place, its old `#2` leaving, rather than keep `#2` while the
/// withdraw phase removes `#1`, the prefix's last blackhole, before the new
/// blackhole is announced.
#[test]
fn received_path_gaining_blackhole_takes_over_a_deleted_rtbh_key() {
    let setup = [
        Op::Inject {
            prefix: 2,
            path: 0,
            preference: 2,
            blackhole: true,
        },
        Op::Receive {
            prefix: 2,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::Backpressure(true),
        Op::Delete { prefix: 2, path: 0 },
        Op::Receive {
            prefix: 2,
            path: 0,
            preference: 0,
            blackhole: true,
        },
        Op::Backpressure(false),
        Op::Drain,
    ];
    if let Some(reason) = failure(add_path_config(), &setup, &[]) {
        panic!("{reason}");
    }
}

/// One pass (a dirty resync after backpressure) deletes a local RTBH path at
/// `#1` while export policy starts tagging the local ordinary path at `#2`
/// with BLACKHOLE: the tagged path takes over `#1` in place.
#[test]
fn policy_tagged_path_takes_over_a_deleted_rtbh_key() {
    let setup = [
        Op::Inject {
            prefix: 2,
            path: 0,
            preference: 2,
            blackhole: true,
        },
        Op::Inject {
            prefix: 2,
            path: 1,
            preference: 0,
            blackhole: false,
        },
        Op::Backpressure(true),
        Op::Delete { prefix: 2, path: 0 },
        Op::Tag {
            prefix: 2,
            path: 1,
            received: false,
            exclusive: false,
        },
        Op::Resync,
    ];
    if let Some(reason) = failure(add_path_config(), &setup, &[]) {
        panic!("{reason}");
    }
}

/// One export-policy replacement drops the BLACKHOLE tag of the path at
/// `#1` and tags the path at `#2`: the newly tagged path takes over `#1` in
/// place, so the untagged path never replaces the prefix's last blackhole
/// first.
#[test]
fn policy_retag_moves_the_blackhole_key_in_place() {
    let setup = [
        Op::Inject {
            prefix: 2,
            path: 0,
            preference: 2,
            blackhole: false,
        },
        Op::Inject {
            prefix: 2,
            path: 1,
            preference: 0,
            blackhole: false,
        },
        Op::Tag {
            prefix: 2,
            path: 0,
            received: false,
            exclusive: false,
        },
        Op::Tag {
            prefix: 2,
            path: 1,
            received: false,
            exclusive: true,
        },
    ];
    if let Some(reason) = failure(add_path_config(), &setup, &[]) {
        panic!("{reason}");
    }
}

/// One distribution window: peer P1 withdraws its BLACKHOLE path at `#1`
/// while peer P2's path at `#2` gains BLACKHOLE. After the withdraw phase
/// the receiver must still hold a blackhole for the prefix.
#[test]
fn received_blackhole_moves_between_peers_in_one_window() {
    let (updates, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    super::distribution_window::untimed_window(&mut manager);
    let (first, second) = (Ipv4Addr::new(192, 0, 2, 91), Ipv4Addr::new(192, 0, 2, 92));
    let _first = connect(&mut manager, first, 64, false, false);
    let _second = connect(&mut manager, second, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(observer, OBSERVER_SESSION, tx);
    if let RibUpdate::PeerUp {
        export_policy,
        add_path_send_families,
        add_path_send_max,
        sendable_families,
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY];
        *export_policy = Some(private_policy(None));
        *add_path_send_families = vec![FAMILY];
        *add_path_send_max = u32::try_from(ADD_PATH_MAX).unwrap();
    }
    manager.handle_update(up);
    let Prefix::V4(v4) = prefix(2) else {
        unreachable!()
    };
    let path = |from: Ipv4Addr, preference: u32, blackhole: bool| {
        let mut route = make_route_with_lp(v4, from, preference);
        if blackhole {
            AttrSet::edit(&mut route.attributes, |attributes| {
                attributes.push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_BLACKHOLE,
                ]));
            });
        }
        route
    };
    let received = |from: Ipv4Addr, announced: Vec<Route>, withdrawn| RibUpdate::RoutesReceived {
        peer: peer_v4(from),
        session_id: u64::from(from.octets()[3]),
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    let blackhole = |route: &Route| {
        route
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    };
    let mut wire = HashMap::new();
    manager.handle_update(received(first, vec![path(first, 200, true)], vec![]));
    drain_route_chunks(&mut manager);
    manager.handle_update(received(second, vec![path(second, 100, false)], vec![]));
    drain_route_chunks(&mut manager);
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            wire.insert(route.path_id, blackhole(route));
        }
    }
    assert_eq!(wire, HashMap::from([(1, true), (2, false)]));
    // The second update is already queued when the first settles, so the
    // distribution window admits it and both land in one pass.
    updates
        .try_send(received(second, vec![path(second, 100, true)], vec![]))
        .unwrap();
    manager.handle_update(received(first, vec![], vec![(prefix(2), 0)]));
    drain_route_chunks(&mut manager);
    assert!(
        updates.capacity() == updates.max_capacity(),
        "the window took the queued update"
    );
    while let Ok(update) = rx.try_recv() {
        for key in &update.withdraw {
            wire.remove(&key.1);
        }
        assert!(
            wire.values().any(|&blackholed| blackholed),
            "the withdraw phase left the prefix without a blackhole: {wire:?}"
        );
        for route in update.announce.iter() {
            wire.insert(route.path_id, blackhole(route));
        }
    }
    assert_eq!(wire, HashMap::from([(1, true)]));
}

/// One pass replaces an ordinary path at `#1` and an RTBH path at `#2` with
/// two new BLACKHOLE paths, the higher-ranked one carrying OTC toward an
/// RFC 9234 peer. The OTC gate drops that one after planning, so it must not
/// take over the departing RTBH key: the sendable RTBH path replaces `#2` in
/// place, and the withdraw phase only removes `#1`.
#[test]
fn otc_blocked_path_never_takes_the_departing_rtbh_key() {
    let mut manager = manager_with_dormant_waiter();
    let observer = peer_v4(OBSERVER);
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer: observer,
        session_id: OBSERVER_SESSION,
        local_role: Some(rustbgpd_wire::BgpRole::Peer),
    });
    let (tx, mut rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(observer, OBSERVER_SESSION, tx);
    if let RibUpdate::PeerUp {
        export_policy,
        add_path_send_families,
        add_path_send_max,
        sendable_families,
        ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY];
        *export_policy = Some(private_policy(None));
        *add_path_send_families = vec![FAMILY];
        *add_path_send_max = u32::try_from(ADD_PATH_MAX).unwrap();
    }
    manager.handle_update(up);
    let Prefix::V4(v4) = prefix(2) else {
        unreachable!()
    };
    let local = |path_id: u32, preference: u32, blackhole: bool, otc: bool| {
        let mut route = make_route_with_lp(v4, SOURCE, preference);
        set_peer(&mut route, crate::PeerId::LOCAL);
        route.origin_type = crate::route::RouteOrigin::Local;
        route.path_id = path_id;
        AttrSet::edit(&mut route.attributes, |attributes| {
            if blackhole {
                attributes.push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_BLACKHOLE,
                ]));
            }
            if otc {
                attributes.push(PathAttribute::OnlyToCustomer(65_001));
            }
        });
        route
    };
    let inject = |manager: &mut RibManager, route| {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
    };
    let delete = |manager: &mut RibManager, path_id| {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::WithdrawInjected {
            prefix: prefix(2),
            path_id,
            allow_missing: false,
            owner: String::new(),
            override_owner: false,
            reply,
        });
        assert!(result.try_recv().unwrap().unwrap().removed);
    };
    let blackhole = |route: &Route| {
        route
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    };
    let mut wire = HashMap::new();
    inject(&mut manager, local(17, 300, false, false));
    inject(&mut manager, local(23, 100, true, false));
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            wire.insert(route.path_id, blackhole(route));
        }
    }
    assert_eq!(wire, HashMap::from([(1, false), (2, true)]));
    // A full writer holds every change for one dirty resync.
    let writer = manager.outbound_peers[&observer].clone();
    let occupied: Vec<_> = std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
    delete(&mut manager, 17);
    delete(&mut manager, 23);
    inject(&mut manager, local(29, 500, true, true));
    inject(&mut manager, local(31, 400, true, false));
    drop(occupied);
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    let mut announced = 0;
    while let Ok(update) = rx.try_recv() {
        for key in &update.withdraw {
            wire.remove(&key.1);
        }
        assert!(
            wire.values().any(|&blackholed| blackholed),
            "the withdraw phase left the prefix without a blackhole: {wire:?}"
        );
        for route in update.announce.iter() {
            assert_eq!(route.path_id, 2, "only the sendable RTBH path is announced");
            announced += 1;
            wire.insert(route.path_id, blackhole(route));
        }
    }
    assert_eq!(announced, 1);
    assert_eq!(wire, HashMap::from([(2, true)]));
}

/// I2 compares the exported BLACKHOLE state, not only path identities: a
/// row still carrying a tag its export no longer intends (a policy retag
/// that announced nothing) fails, and the converged wire passes.
#[test]
fn i2_catches_a_stale_blackhole_tag() {
    let tagged = |stale: bool| {
        let mut harness = Harness::new(add_path_config());
        harness.apply(&Op::Inject {
            prefix: 2,
            path: 0,
            preference: 2,
            blackhole: false,
        });
        harness.apply(&Op::Inject {
            prefix: 2,
            path: 1,
            preference: 0,
            blackhole: false,
        });
        harness.drain().unwrap();
        harness.apply(&Op::Tag {
            prefix: 2,
            path: 0,
            received: false,
            exclusive: false,
        });
        harness.drain().unwrap();
        harness.apply(&Op::Tag {
            prefix: 2,
            path: 1,
            received: false,
            exclusive: true,
        });
        harness.drain().unwrap();
        if stale {
            // Seed the old placement: the first path still tagged on the
            // wire, the second not.
            for (key, &injection) in &harness.wire {
                let first = harness.injections[injection].preference
                    == harness.injections[harness.local[&(2, 0)]].preference;
                harness.wire_tag.insert(*key, first);
            }
        }
        harness.check_converged()
    };
    assert!(tagged(false).is_ok(), "the retag converges");
    let error = tagged(true).expect_err("a stale tag placement fails I2");
    assert!(error.to_string().contains("I2:"), "{error}");
}

/// A GR-helper flap before the hold leaves our host route stale while the
/// new session waits behind a full writer, and the route is deleted before
/// the hold. Release frees the writer but leaves the End-of-RIB pending;
/// the resync timer the actor arms for it sends that End-of-RIB, so the
/// helper purges the stale row.
#[test]
fn release_tick_sends_the_end_of_rib_that_purges_a_stale_row() {
    let config = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let setup = [
        Op::Inject {
            prefix: 0,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::Reconnect {
            notification: false,
            helper: false,
            gr_families: false,
            writer_full: true,
        },
        Op::Delete { prefix: 0, path: 0 },
    ];
    if let Some(reason) = failure(config, &setup, &[]) {
        panic!("{reason}");
    }
}

/// The timer race the actor's GR sweep once lost: the absent peer's
/// deadline falls due with a bulk UPDATE queued, its drain runs past the
/// source's later deadline, and the source's refresh, queued after the
/// earlier cutoff but before its own deadline, must still close its window.
/// Red proof: sweeping every deadline up to the current time at the earlier
/// turn expires the source's deadline (I7).
#[test]
fn queued_refresh_closes_its_window_behind_an_earlier_drain() {
    let config = Config {
        grouped: false,
        add_path: false,
        per_client_best: false,
        orf: false,
        limit: false,
        late: false,
    };
    let setup = [
        Op::Receive {
            prefix: 3,
            path: 0,
            preference: 0,
            blackhole: false,
        },
        Op::RestartPeer {
            source: false,
            restart: 1,
            stale: 0,
        },
        Op::RestartPeer {
            source: true,
            restart: 1,
            stale: 3,
        },
        Op::QueueBulk,
        Op::AdvanceToDeadline,
        Op::QueueRefresh,
        Op::AdvanceToDeadline,
    ];
    if let Some(reason) = failure(config, &setup, &[Op::Drain]) {
        panic!("{reason}");
    }
}
