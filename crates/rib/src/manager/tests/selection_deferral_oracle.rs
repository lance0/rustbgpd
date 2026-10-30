//! Model-checked GR selection hold.
//!
//! Random operation sequences drive a real `RibManager` through the matrix
//! of a selection hold, exempt local RTBH and host routes, Add-Path ranks,
//! backpressure, refused recovery proof, an Address Prefix ORF and the
//! receiver's session flaps (a new channel and session id, with RFC 4724
//! stale retention at a GR-capable peer). A tiny reference model
//! keeps the local and received intent; the receiver's wire is rebuilt from
//! the updates it actually got. Every route carries a unique identity
//! community, so a wire row names the exact injection it came from.
//!
//! Invariants:
//! - I1, never unblackhole: after every UPDATE in the hold, a prefix whose
//!   fresh export carries an exempt path and that had an exempt row on the
//!   wire keeps one; after a drain with a free writer, admitted proof and no
//!   ORF gate, every such prefix carries a live exempt row.
//! - I2, exact convergence: after release and drain, the wire equals a fresh
//!   session's full dump, computed from the final intent alone.
//! - I3: `actual_unicast_advertised_count` equals the wire key count.
//! - I4, no resurrection: a deleted or replaced exempt path is never
//!   announced again.
//! - I5, prompt removal: after a drain with a free writer in the hold, an
//!   exempt row the operator deleted has left the wire, unless it is the
//!   prefix's last exempt row while an exempt export is still intended.
//!
//! Each case fixes one receiver configuration (private or grouped,
//! single-best or Add-Path, per-client-best, ORF, prefix limit, and whether
//! its first session arrives inside the hold), builds a pre-hold table,
//! starts the hold, runs the operations, then releases and drains. Received routes stay on their own prefixes, so the model never
//! ranks a received path against a local one. Not modelled: IPv6, LLGR,
//! leases, export policy edits, a second hold, more than one receiver.
//!
//! Known open defects are allowed only by their exact signature, each
//! naming its ticket (`allowed`). `ORACLE_STRICT=1` disables every
//! allowance and `ORACLE_STRICT=LAN-2692,...` only the listed ones, which
//! reproduces them. `PROPTEST_CASES` scales the case count for a deep run;
//! `ORACLE_TRACE` prints each operation and wire update. A failure prints a
//! sequence minimized by one-op deletion.

use std::collections::HashMap;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter, private_policy};
use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 82);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
const OBSERVER_SESSION: u64 = 82;
const SOURCE_SESSION: u64 = 81;
const WAITER_SESSION: u64 = 83;
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
    Receive {
        prefix: usize,
    },
    ReceiveWithdraw {
        prefix: usize,
    },
    /// Replace the receiver's ORF with one denying the masked prefixes.
    Orf {
        deny: u8,
    },
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
        1 => (LOCAL_PREFIXES..PREFIXES).prop_map(|prefix| Op::Receive { prefix }),
        1 => (LOCAL_PREFIXES..PREFIXES).prop_map(|prefix| Op::ReceiveWithdraw { prefix }),
        1 => (0u8..1 << PREFIXES).prop_map(|deny| Op::Orf { deny }),
    ]
}

fn hold_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => intent_strategy(),
        2 => any::<bool>().prop_map(Op::Backpressure),
        2 => Just(Op::RefuseProof),
        2 => Just(Op::Drain),
        2 => (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
            |(notification, helper, gr_families, writer_full)| Op::Reconnect {
                notification,
                // Families come only inside a GR capability.
                helper: helper || gr_families,
                gr_families,
                writer_full,
            }
        ),
    ]
}

struct Injection {
    prefix: usize,
    preference: u32,
    exempt: bool,
    live: bool,
    /// The operator deleted it (a replacement only retires it).
    deleted: bool,
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
    received: BTreeMap<usize, usize>,
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
}

type Checked = Result<(), TestCaseError>;

impl Harness {
    fn new(config: Config) -> Self {
        let mut manager = manager_with_dormant_waiter();
        let source = connect(&mut manager, SOURCE, 64, false, false);
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
            if !self.config.grouped {
                *export_policy = Some(private_policy(None));
            }
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

    fn new_injection(&mut self, prefix: usize, preference: u32, exempt: bool) -> usize {
        self.injections.push(Injection {
            prefix,
            preference,
            exempt,
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
        match *op {
            Op::Inject {
                prefix: index,
                path,
                preference,
                blackhole,
            } => {
                // Unique per path and variant, so ranks never tie.
                let preference = 100 + u32::try_from(path).unwrap() + 3 * preference;
                let exempt = index < 2 || blackhole;
                let injection = self.new_injection(index, preference, exempt);
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
            Op::Receive { prefix: index } => {
                let injection = self.new_injection(index, 100, false);
                let Prefix::V4(v4) = prefix(index) else {
                    unreachable!()
                };
                let mut route = make_route_with_lp(v4, SOURCE, 100);
                AttrSet::edit(&mut route.attributes, |attributes| {
                    attributes.push(PathAttribute::Communities(vec![
                        (IDENTITY_ASN << 16) | u32::try_from(injection).unwrap(),
                    ]));
                });
                self.receive(vec![route], vec![]);
                let old = self.received.insert(index, injection);
                self.retire(old);
            }
            Op::ReceiveWithdraw { prefix: index } => {
                self.receive(vec![], vec![(prefix(index), 0)]);
                let old = self.received.remove(&index);
                self.retire(old);
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
            Op::Drain => {}
            Op::Reconnect { .. } => self.reconnect(op),
        }
    }

    fn receive(&mut self, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) {
        self.manager.handle_update(RibUpdate::RoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: SOURCE_SESSION,
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
        // The source and waiter never backpressure: only the receiver
        // retries.
        while self.source.try_recv().is_ok() {}
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
            for key in &update.withdraw {
                self.wire.remove(key);
                self.stale.remove(key);
            }
            // The transport sends an envelope's withdrawals as their own
            // UPDATEs before its announcements, and splits announcements with
            // different attributes into separate UPDATEs. Check the peer's
            // state after the withdrawals and after every announcement: one
            // UPDATE per announcement is stricter than the wire, and exempt
            // and ordinary rows never share attributes.
            self.apply_announcements(&update)?;
            // Our End-of-RIB ends a GR helper's retention: it purges every
            // stale row this session did not re-announce.
            if update.end_of_rib.contains(&FAMILY) && !self.stale.is_empty() {
                for key in std::mem::take(&mut self.stale) {
                    self.wire.remove(&key);
                }
                if self.held {
                    self.check_blackholed()?;
                }
            }
        }
        Ok(updates)
    }

    /// I4 for every announcement; I1 after the withdrawals and after each
    /// announcement while the hold lasts.
    fn apply_announcements(&mut self, update: &OutboundRouteUpdate) -> Checked {
        if self.held {
            self.check_blackholed()?;
        }
        for route in update.announce.iter() {
            let injection = Self::identity(route);
            let resurrected = self.injections[injection].exempt && !self.injections[injection].live;
            prop_assert!(
                !resurrected,
                "I4: removed exempt injection {injection} re-announced at {:?}",
                (route.prefix, route.path_id)
            );
            let key = (route.prefix, route.path_id);
            self.wire.insert(key, injection);
            self.stale.remove(&key);
            if self.held {
                self.check_blackholed()?;
            }
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
                .chain(self.received.get(&index).copied())
                .collect();
            paths
                .sort_by_key(|&injection| std::cmp::Reverse(self.injections[injection].preference));
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

    /// Prefix to the exempt injections its wire rows carry.
    fn exempt_rows(&self) -> BTreeMap<usize, BTreeSet<usize>> {
        let mut rows = BTreeMap::<_, BTreeSet<_>>::new();
        for &injection in self.wire.values() {
            let row = &self.injections[injection];
            if row.exempt {
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

    /// Prefixes whose fresh export carries an exempt path.
    fn wanted_blackholes(&self) -> BTreeSet<usize> {
        self.expected()
            .values()
            .map(|&injection| &self.injections[injection])
            .filter(|injection| injection.exempt)
            .map(|injection| injection.prefix)
            .collect()
    }

    /// I1's safety half, after every UPDATE in the hold: a prefix that
    /// should be blackholed keeps an exempt row once it had one.
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
                "I1: {} lost its exempt row during the hold; wire {}",
                prefix(index),
                show(&self.wire)
            );
        }
        self.blackholed = blackholed;
        Ok(())
    }

    /// A known open defect that explains a deleted exempt row still on the
    /// wire after a drain in the hold, or `None`.
    fn known_stale_blackhole(&self, key: (Prefix, u32)) -> Option<&'static str> {
        // LAN-2703: a GR helper keeps a row from the session that ended as
        // stale until our End-of-RIB, which the hold defers to release; a
        // row deleted before the new session re-sent it is never withdrawn.
        if self.stale.contains(&key) {
            return allowed("LAN-2703");
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
        if self.orf_gated {
            // The peer's refresh opens the re-armed gate.
            self.push_orf(self.deny);
            self.observe()?;
            self.drain()?;
        }
        Ok(())
    }

    fn check_converged(&mut self) -> Checked {
        let expected = self.expected();
        let wire: BTreeMap<_, _> = self
            .wire
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        prop_assert!(
            wire == expected,
            "I2: released wire {} differs from a fresh dump {}",
            show(&wire),
            show(&expected)
        );
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
    harness.observe()?;
    for op in setup {
        harness.apply(op);
        harness.observe()?;
    }
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
        proptest::collection::vec(intent_strategy(), 0..6),
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
    let transient = |held: bool| {
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
        harness.held = held;
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
    let replaced = |held: bool, between_phases: bool| {
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
        harness.held = held && between_phases;
        let observed = harness.observe().map(|_| ());
        harness.held = held;
        observed.and_then(|()| harness.check_blackholed())
    };
    let error = replaced(true, true).expect_err("the phase gap unblackholes the peer");
    assert!(
        error
            .to_string()
            .contains("I1: 198.51.100.1/32 lost its exempt row")
    );
    assert!(
        replaced(true, false).is_ok(),
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
        let ordinary = harness.new_injection(2, 120, false);
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
        harness.held = per_announcement;
        let observed = harness.observe().map(|_| ());
        harness.held = true;
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
        Op::Receive { prefix: 3 },
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
        let obsolete = harness.new_injection(0, 0, true);
        harness.injections[obsolete].live = false;
        harness.injections[obsolete].deleted = true;
        harness.wire.insert((prefix(0), path), obsolete);
    }
    let pending = harness.new_injection(0, 1, true);
    harness.local.insert((0, 2), pending);
    assert!(harness.check_deleted_blackholes().is_err());
    harness.wire.remove(&(prefix(0), 2));
    assert!(harness.check_deleted_blackholes().is_ok());
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
