//! Cold authoritative replacement: physical actor polls and the synchronous export oracle.
mod memo_capacity;

use std::future::{Future, poll_fn};

use super::*;
use crate::manager::tests::update_groups::{community_chain, deny_statement};
use crate::update::{PeerExportPolicyReplacement, PeerExportPolicyRestoreReceipt, RibCommandError};
use rustbgpd_policy::PolicyChain;

const OLD: u32 = 0xFDE8_000B;
const NEW: u32 = 0xFDE8_000C;
const PAGE: usize = crate::loc_rib::REGISTRATION_PAGE_SIZE;
const MOVERS: [u8; 2] = [1, 2];

fn cutoff(tag: u32) -> u32 {
    if tag == NEW { 150 } else { 200 }
}

fn policy(tag: u32) -> PolicyChain {
    let mut policies = community_chain(tag).policies;
    let mut deny = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    deny.prefix = None;
    deny.match_local_pref_ge = Some(cutoff(tag));
    policies[0].policy.entries.insert(0, deny);
    PolicyChain::from_named(policies)
}

type Feed = mpsc::Receiver<OutboundRouteUpdate>;
type Wire = BTreeMap<Prefix, (PeerId, u32, Vec<u32>)>;

// Envelope grouping and ordering of distinct prefixes may differ across hash seeds.
// Retain every announcement, withdrawal and their per-prefix order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Delta {
    Withdraw,
    Announce(PeerId, IpAddr, Arc<crate::attr_set::AttrSet>),
}

type Deltas = BTreeMap<Prefix, Vec<Delta>>;

fn fold(rx: &mut Feed, wire: &mut Wire) -> Deltas {
    let mut deltas = Deltas::new();
    while let Ok(update) = rx.try_recv().map(delivered) {
        for &(prefix, path_id) in update.unicast_withdrawals() {
            assert_eq!(path_id, 0);
            wire.remove(&prefix);
            deltas.entry(prefix).or_default().push(Delta::Withdraw);
        }
        for row in update.announce.iter() {
            assert_eq!(row.path_id, 0);
            deltas.entry(row.prefix).or_default().push(Delta::Announce(
                row.peer,
                row.next_hop,
                Arc::clone(&row.attributes),
            ));
            wire.insert(
                row.prefix,
                (row.peer, row.local_pref(), row.communities().to_vec()),
            );
        }
    }
    deltas
}

struct Fleet {
    manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    feeds: Vec<Feed>,
    wire: Vec<Wire>,
    last_deltas: Vec<Deltas>,
}

impl Fleet {
    fn new(rows: u16, sparse: bool, initial_tag: u32) -> Self {
        let (mut manager, tx, _) = fixture(0);
        manager.first_group_build_min_routes = usize::MAX;
        let all = (0..rows)
            .map(|i| {
                let pref = if i % 11 == 0 {
                    220
                } else if i % 5 == 0 {
                    170
                } else {
                    100
                };
                route(prefixes(i)[0], SOURCE, pref)
            })
            .collect();
        manager.handle_update(test_routes_received(peer_v4(SOURCE), all));
        drain_route_chunks(&mut manager);
        if sparse {
            let mut update = test_routes_received(peer_v4(SOURCE), vec![]);
            let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
                unreachable!()
            };
            withdrawn.extend(
                (0..rows)
                    .filter(|i| i % 2 != 0)
                    .map(|i| (prefixes(i)[0], 0)),
            );
            manager.handle_update(update);
            drain_route_chunks(&mut manager);
        }
        let mut feeds = Vec::new();
        for n in MOVERS {
            let peer = receiver(n);
            manager.handle_update(RibUpdate::SetPeerRsControl {
                peer,
                session_id: 1,
                rs_control_asn: Some(64512),
            });
            let (out, rx) = mpsc::channel(128);
            let mut up = test_peer_up(peer, 1, out);
            let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
                unreachable!()
            };
            *export_policy = Some(policy(initial_tag));
            manager.handle_update(up);
            assert_eq!(manager.peer_rs_control[&peer], 64512);
            feeds.push(rx);
        }
        let mut f = Self {
            manager,
            tx,
            feeds,
            wire: vec![Wire::new(); MOVERS.len()],
            last_deltas: Vec::new(),
        };
        f.read();
        let accepted = f
            .manager
            .loc_rib
            .iter()
            .filter(|r| r.local_pref() < cutoff(initial_tag))
            .count();
        assert!(f.wire.iter().all(|view| view.len() == accepted));
        assert_eq!(
            f.manager.grouped_member_of(receiver(1)),
            f.manager.grouped_member_of(receiver(2))
        );
        f
    }

    fn read(&mut self) {
        self.last_deltas = self
            .feeds
            .iter_mut()
            .zip(&mut self.wire)
            .map(|(rx, wire)| fold(rx, wire))
            .collect();
    }
}

enum Reply {
    Forward(oneshot::Receiver<Result<Vec<PeerId>, RibCommandError>>),
    Restore(oneshot::Receiver<Result<Vec<PeerExportPolicyRestoreReceipt>, RibCommandError>>),
}

impl Reply {
    // A shared forward leaves no residuals. Mandatory restore acknowledges each
    // member in reverse application order; neither outcome can pass on fallback.
    fn received(&mut self) -> bool {
        use oneshot::error::TryRecvError::Empty;
        match self {
            Self::Forward(rx) => match rx.try_recv() {
                Ok(Ok(deferred)) => assert!(deferred.is_empty(), "{deferred:?}"),
                Err(Empty) => return false,
                other => panic!("unexpected forward reply {other:?}"),
            },
            Self::Restore(rx) => match rx.try_recv() {
                Ok(Ok(actual)) => assert_eq!(
                    actual,
                    [
                        PeerExportPolicyRestoreReceipt::Restored { peer: receiver(2) },
                        PeerExportPolicyRestoreReceipt::Restored { peer: receiver(1) },
                    ]
                ),
                Err(Empty) => return false,
                other => panic!("unexpected restore reply {other:?}"),
            },
        }
        true
    }
}

fn command(target: &PolicyChain, restore: bool) -> (RibUpdate, Reply) {
    // The live candidate bank is observable even while the staged policy is private.
    let replacements = MOVERS
        .into_iter()
        .map(|n| PeerExportPolicyReplacement {
            peer: receiver(n),
            export_policy: Some(target.share()),
        })
        .collect();
    if restore {
        let (reply, rx) = oneshot::channel();
        (
            RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            },
            Reply::Restore(rx),
        )
    } else {
        let (reply, rx) = oneshot::channel();
        (
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            },
            Reply::Forward(rx),
        )
    }
}

#[derive(Debug, Default)]
struct Counts {
    discovery: usize,
    repairs: usize,
    staged: usize,
    sync_rows: usize,
}

fn counters() -> Counts {
    use crate::manager::slice_timing::{checkpoints, group_work};
    let counts = group_work();
    let (discovery, repairs) = crate::loc_rib::REGISTRATION_VISITS.get();
    Counts {
        discovery,
        repairs,
        staged: counts.get("group_staged_key").copied().unwrap_or(0),
        sync_rows: checkpoints()
            .get(crate::manager::GROUP_TABLE_BUILD_ROW)
            .copied()
            .unwrap_or(0),
    }
}

#[derive(Debug, Default)]
struct Measurement {
    polls: usize,
    peak: usize,
    discovery: usize,
    repairs: usize,
    staged: usize,
    sync_rows: usize,
}

async fn physical_work(rows: u16, restore: bool) -> Measurement {
    let (initial, target) = if restore { (NEW, OLD) } else { (OLD, NEW) };
    let Fleet {
        mut manager,
        tx,
        mut feeds,
        mut wire,
        ..
    } = Fleet::new(rows, true, initial);
    manager.first_group_build_min_routes = 1;
    let (update, mut reply) = command(&policy(target), restore);
    tx.try_send(update).unwrap();
    let mut actor = Box::pin(manager.run_actor());
    let mut tx = Some(tx);
    let mut result = Measurement::default();
    let mut injected = false;
    poll_fn(|cx| {
        let before = counters();
        let polled = actor.as_mut().poll(cx);
        let after = counters();
        let discovery = after.discovery - before.discovery;
        let repairs = after.repairs - before.repairs;
        let sync = after.sync_rows - before.sync_rows;
        let visits = discovery + repairs + sync;
        result.peak = result.peak.max(visits);
        result.polls += usize::from(visits > 0);
        result.discovery += discovery;
        result.repairs += repairs;
        result.sync_rows += sync;
        result.staged += after.staged - before.staged;
        for (rx, view) in feeds.iter_mut().zip(&mut wire) {
            fold(rx, view);
        }
        if tx.is_some() && reply.received() {
            tx.take();
            cx.waker().wake_by_ref();
        } else if !injected
            && discovery > 0
            && let Some(tx) = &tx
        {
            tx.try_send(test_routes_received(
                peer_v4(OTHER),
                vec![route(prefixes(2)[0], OTHER, 140)],
            ))
            .unwrap();
            injected = true;
        }
        polled
    })
    .await;
    result
}

async fn check_physical_work(restore: bool) {
    let small = physical_work(4096, restore).await;
    let large = physical_work(8192, restore).await;
    eprintln!("restore={restore}; 2048 live: {small:?}; 4096 live: {large:?}");
    for (live, count) in [(2048, &small), (4096, &large)] {
        assert!(
            count.peak > 0 && count.peak <= PAGE,
            "{live} live: {count:?}"
        );
        assert_eq!(count.sync_rows, 0, "{count:?}");
        assert!(
            count.discovery > live,
            "empty physical buckets must be charged: {count:?}"
        );
        assert!(count.repairs > 0 && count.staged >= live, "{count:?}");
    }
    assert!(large.polls > small.polls, "{small:?}, {large:?}");
}

#[tokio::test]
async fn authoritative_reload_bounds_discovery_and_repairs_per_physical_poll() {
    check_physical_work(false).await;
}

#[tokio::test]
async fn authoritative_restore_bounds_discovery_and_repairs_per_physical_poll() {
    check_physical_work(true).await;
}

fn start(fleet: &mut Fleet, target: &PolicyChain, restore: bool) -> Reply {
    let (command, reply) = command(target, restore);
    fleet.manager.handle_update(command);
    reply
}

fn finish_reload(fleet: &mut Fleet, reply: &mut Reply) {
    for _ in 0..128 {
        if reply.received() {
            fleet.read();
            return;
        }
        fleet.manager.advance_first_group_build();
    }
    panic!("reload failed to reply");
}

fn walked(fleet: &mut Fleet) -> [Prefix; 3] {
    for _ in 0..32 {
        fleet.manager.advance_first_group_build();
        let keys: Vec<_> = fleet
            .manager
            .loc_rib
            .iter()
            .filter(|r| r.local_pref() == 100 && fleet.manager.first_group_contains(r.prefix))
            .map(|r| r.prefix)
            .take(3)
            .collect();
        if let Ok(keys) = keys.try_into() {
            return keys;
        }
    }
    panic!("no unpublished page of eligible destination rows");
}

fn writes(fleet: &mut Fleet, keys: [Prefix; 3], marker: Prefix) {
    let [removed, changed, denied] = keys;
    let mut withdrawn = test_routes_received(peer_v4(SOURCE), vec![]);
    let RibUpdate::RoutesReceived {
        withdrawn: keys, ..
    } = &mut withdrawn
    else {
        unreachable!()
    };
    keys.push((removed, 0));
    fleet.manager.handle_update(withdrawn);
    drain_route_chunks(&mut fleet.manager);
    fleet.manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![
            route(changed, OTHER, 130),
            route(denied, OTHER, 225),
            route(marker, OTHER, 120),
        ],
    ));
    drain_route_chunks(&mut fleet.manager);
    assert!(fleet.manager.loc_rib.get(&removed).is_none());
    for key in [changed, denied, marker] {
        assert_eq!(
            fleet.manager.loc_rib.get(&key).unwrap().peer,
            peer_v4(OTHER)
        );
    }
    fleet.read();
}

fn bank(chain: &PolicyChain) -> (u64, Vec<Vec<u64>>) {
    (
        chain.hit_counters().evals(),
        chain.hit_counters().snapshot(),
    )
}

fn expected_table(manager: &RibManager, tag: u32) -> Wire {
    manager
        .loc_rib
        .iter()
        .filter(|r| r.local_pref() < cutoff(tag))
        .map(|r| (r.prefix, (r.peer, r.local_pref(), vec![tag])))
        .collect()
}

fn check_group_and_wire(fleet: &Fleet, tag: u32, removed: Prefix) {
    let expected = expected_table(&fleet.manager, tag);
    for (n, view) in MOVERS.into_iter().zip(&fleet.wire) {
        let peer = receiver(n);
        assert_eq!(view, &expected, "remote admitted inventory for {peer}");
        let group = &fleet.manager.group_ribs[&fleet.manager.grouped_member_of(peer).unwrap()];
        let table: Wire = group
            .table
            .iter()
            .map(|r| (r.prefix, (r.peer, r.local_pref(), r.communities().to_vec())))
            .collect();
        assert_eq!(table, expected, "installed table for {peer}");
        let keys = fleet
            .manager
            .loc_rib
            .iter()
            .map(|r| r.prefix)
            .chain(std::iter::once(removed))
            .collect();
        let observed: HashSet<_> = group
            .policy_filtered_for_member(peer, &keys)
            .into_iter()
            .collect();
        let expected_denials: HashSet<_> = fleet
            .manager
            .loc_rib
            .iter()
            .filter(|r| r.local_pref() >= cutoff(tag))
            .map(|r| PolicyFilteredRouteKey {
                target_peer: peer,
                source_peer: r.peer,
                prefix: r.prefix,
                path_id: 0,
            })
            .collect();
        assert_eq!(
            observed, expected_denials,
            "denial source and prefix for {peer}"
        );
    }
}

#[test]
fn authoritative_reload_repairs_displaced_winners_and_withdrawals_behind_the_cursor() {
    for (initial, target, restore) in [(OLD, NEW, false), (NEW, OLD, true)] {
        let mut paced = Fleet::new(4096, false, initial);
        let mut synchronous = Fleet::new(4096, false, initial);
        paced.manager.first_group_build_min_routes = 1;
        let target_chain = policy(target);
        let mut pending = start(&mut paced, &target_chain, restore);
        let keys = walked(&mut paced);
        assert!(!pending.received());
        let marker = prefixes(60_000)[0];
        for fleet in [&mut paced, &mut synchronous] {
            writes(fleet, keys, marker);
            check_group_and_wire(fleet, initial, keys[0]);
            assert_eq!(fleet.wire[0][&marker].2, [initial]);
        }
        assert!(
            !pending.received(),
            "ordinary UPDATE installed and exported under OLD"
        );
        assert_eq!(
            paced.last_deltas, synchronous.last_deltas,
            "intervening OLD updates"
        );
        let mut immediate = start(&mut synchronous, &policy(target), restore);
        assert!(
            immediate.received(),
            "unpaced control must apply synchronously"
        );
        synchronous.read();
        finish_reload(&mut paced, &mut pending);
        assert_eq!(
            paced.last_deltas, synchronous.last_deltas,
            "per-prefix reload announcements and withdrawals"
        );
        for fleet in [&paced, &synchronous] {
            check_group_and_wire(fleet, target, keys[0]);
        }
        for n in MOVERS {
            let peer = receiver(n);
            assert_eq!(
                retained_policy_rejection_keys(&paced.manager, peer),
                retained_policy_rejection_keys(&synchronous.manager, peer),
            );
            assert_eq!(
                paced.manager.neighbor_rib_snapshot(peer).policy_stats,
                synchronous.manager.neighbor_rib_snapshot(peer).policy_stats,
            );
            assert_eq!(
                bank(paced.manager.export_policy_for(peer).unwrap()),
                bank(synchronous.manager.export_policy_for(peer).unwrap()),
                "only the final winner per prefix contributes to published term counters",
            );
        }
    }
}

#[test]
fn authoritative_reload_keeps_policy_counters_private_until_commit() {
    let mut fleet = Fleet::new(4096, false, OLD);
    fleet.manager.first_group_build_min_routes = 1;
    let target = policy(NEW);
    let candidate_before = bank(&target);
    let old = fleet
        .manager
        .export_policy_for(receiver(1))
        .unwrap()
        .share();
    let old_before = bank(&old);
    let stats = fleet
        .manager
        .neighbor_rib_snapshot(receiver(1))
        .policy_stats;
    // Direct PeerUp in the fixture has no actor-loop publication boundary.
    fleet.manager.publish_export_roster();
    let reader = fleet.manager.export_roster();
    let before_roster = reader.load();
    let visible_before = MOVERS.map(|n| {
        let hits = before_roster.for_peer(receiver(n)).unwrap();
        (hits.id(), hits.evals(), hits.snapshot())
    });
    let mut pending = start(&mut fleet, &target, false);
    let before = counters();
    walked(&mut fleet);
    assert!(
        counters().staged > before.staged,
        "private rows actually evaluated"
    );
    assert!(!pending.received());
    assert_eq!(
        bank(&target),
        candidate_before,
        "uncommitted candidate term hits escaped"
    );
    assert_eq!(bank(&old), old_before, "staging charged OLD");
    // The normal actor loop can publish after any build page. The roster
    // reader lives off-actor and must still expose both OLD instances.
    fleet.manager.publish_export_roster();
    let during = reader.load();
    assert_eq!(during.version(), before_roster.version());
    assert_eq!(
        MOVERS.map(|n| {
            let hits = during.for_peer(receiver(n)).unwrap();
            (hits.id(), hits.evals(), hits.snapshot())
        }),
        visible_before
    );
    assert_eq!(
        fleet
            .manager
            .neighbor_rib_snapshot(receiver(1))
            .policy_stats,
        stats
    );
    assert_eq!(fleet.manager.export_policy_for(receiver(1)).unwrap(), &old);
    finish_reload(&mut fleet, &mut pending);
    // The terminal handler publishes before acknowledging; do not explicitly
    // publish here or the test would mask a missing acknowledgement barrier.
    let after = reader.load();
    assert!(after.version() > during.version());
    for n in MOVERS {
        let peer = receiver(n);
        let hits = after.for_peer(peer).unwrap();
        assert_ne!(hits.id(), before_roster.for_peer(peer).unwrap().id());
        assert!(Arc::ptr_eq(
            hits,
            fleet
                .manager
                .export_policy_for(peer)
                .unwrap()
                .hit_counters()
        ));
    }
    let group = &fleet.manager.group_ribs[&fleet.manager.grouped_member_of(receiver(1)).unwrap()];
    let committed = group.export_chain.as_ref().unwrap().hit_counters();
    assert_eq!(committed.evals(), 4096);
    let denied = fleet
        .manager
        .loc_rib
        .iter()
        .filter(|r| r.local_pref() >= cutoff(NEW))
        .count() as u64;
    assert_eq!(committed.term_hits(0, 0), Some(denied));
    assert_eq!(committed.term_hits(0, 1), Some(4096 - denied));
}
