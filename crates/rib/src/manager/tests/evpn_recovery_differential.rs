//! Owned-group EVPN recovery against the private control. The same input,
//! with receivers held back while routes churn, then recovered, refreshed,
//! churned and withdrawn, must leave every receiver with the same routes in
//! both runs and must never withdraw a route a receiver does not hold. This
//! covers section F's named recovery paths: end-state parity with no
//! spurious withdrawal.

use super::evpn_group_storage::{received, register};
use super::*;
use crate::PeerId;
use crate::update::EvpnRecoveryResetOutcome;
use rustbgpd_wire::{EthernetTagId, EvpnRoute, EvpnRouteKey};
use std::collections::BTreeMap;

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

fn route(tag: u32, target: u16) -> EvpnRibRoute {
    let mut route = received(target);
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        panic!("IMET fixture");
    };
    imet.ethernet_tag = EthernetTagId(tag);
    route
}

struct Receiver {
    peer: PeerId,
    output: mpsc::Receiver<OutboundRouteUpdate>,
    routes: BTreeMap<EvpnRouteKey, EvpnRibRoute>,
    spurious: Vec<EvpnRouteKey>,
}

/// One receiver's routes after a phase, in key order.
type Phase = Vec<BTreeMap<EvpnRouteKey, EvpnRibRoute>>;

struct Run {
    manager: RibManager,
    receivers: Vec<Receiver>,
    source: PeerId,
    owned: bool,
    recovered: usize,
}

impl Run {
    fn start(owned: bool) -> Self {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(
            rx,
            dummy_query_rx(),
            None,
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            BgpMetrics::new(),
        );
        manager.flush_poll_budget = Duration::MAX;
        let mut receivers = Vec::new();
        for suffix in 30..34 {
            let peer = PeerId::from_addr(Ipv4Addr::new(192, 0, 2, suffix).into());
            let (sender, mut output) = mpsc::channel(8);
            register(&mut manager, peer, sender);
            while output.try_recv().is_ok() {}
            receivers.push(Receiver {
                peer,
                output,
                routes: BTreeMap::new(),
                spurious: Vec::new(),
            });
        }
        let gid = manager.grouped_member_of(receivers[0].peer).unwrap();
        assert!(
            receivers
                .iter()
                .all(|receiver| manager.grouped_member_of(receiver.peer) == Some(gid))
        );
        if owned {
            manager
                .group_ribs
                .get_mut(&gid)
                .unwrap()
                .set_evpn_ownership_for_test(true);
            for receiver in &receivers {
                assert!(manager.register_evpn_recovery(receiver.peer, false));
            }
        }
        manager.evpn_recovery_reset = Some(Arc::new(|request, reply| {
            let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            panic!("no recovery reset is expected: {:?}", request.cause);
        }));
        let source = route(1, 100).peer;
        manager.ribs.insert(source, AdjRibIn::new(source));
        Self {
            manager,
            receivers,
            source,
            owned,
            recovered: 0,
        }
    }

    fn drain(&mut self) {
        for receiver in &mut self.receivers {
            while let Ok(update) = receiver.output.try_recv() {
                // Withdrawals precede announcements within one update.
                for key in update.evpn_withdraw {
                    if receiver.routes.remove(&key).is_none() {
                        receiver.spurious.push(key);
                    }
                }
                for route in update.evpn_announce.iter() {
                    receiver.routes.insert(route.key(), route.clone());
                }
            }
        }
    }

    /// Fill a receiver's queue so the next changes miss it.
    fn block(&mut self, index: usize) {
        let peer = self.receivers[index].peer;
        while self.manager.outbound_peers[&peer]
            .try_send(OutboundRouteUpdate::default())
            .is_ok()
        {}
    }

    fn announce(&mut self, routes: Vec<EvpnRibRoute>) {
        self.manager
            .process_evpn_announce_chunk(self.source, routes);
    }

    fn withdraw(&mut self, keys: Vec<EvpnRouteKey>) {
        self.manager.process_evpn_withdraw_chunk(self.source, keys);
    }

    /// Note recoveries that hold provenance, then drain and resync until
    /// every receiver is clean.
    fn heal(&mut self) -> Phase {
        if self.owned {
            self.recovered += self
                .receivers
                .iter()
                .filter(|receiver| {
                    self.manager
                        .evpn_recovery_handle(receiver.peer)
                        .is_some_and(|handle| !self.manager.evpn_recovery.is_dormant(handle))
                })
                .count();
        }
        for _ in 0..64 {
            self.drain();
            if self.manager.dirty_peers.is_empty() {
                break;
            }
            self.manager.resync_dirty_peers_bounded();
            for receiver in &self.receivers {
                self.manager.flush_pending_eor(receiver.peer);
            }
        }
        self.drain();
        assert!(self.manager.dirty_peers.is_empty(), "every receiver healed");
        let desired: BTreeMap<_, _> = self
            .manager
            .loc_rib
            .iter_evpn()
            .map(|route| (route.key(), route.clone()))
            .collect();
        for receiver in &self.receivers {
            assert_eq!(
                receiver.routes.keys().collect::<Vec<_>>(),
                desired.keys().collect::<Vec<_>>(),
                "receiver {} converged, owned: {}",
                receiver.peer,
                self.owned
            );
        }
        self.receivers
            .iter()
            .map(|receiver| receiver.routes.clone())
            .collect()
    }
}

/// Capture under backpressure, recovery, a refresh replay during churn,
/// admission into a retained proof, churn with a held member, and
/// withdrawal of everything. `table` routes start the run; later routes use
/// tags from 1000, so the same steps cover sparse and dense proofs.
fn scenario(owned: bool, table: u32) -> (Vec<Phase>, Vec<Vec<EvpnRouteKey>>, usize) {
    let mut run = Run::start(owned);
    let mut phases = Vec::new();
    run.announce((1..=table).map(|tag| route(tag, 100)).collect());
    phases.push(run.heal());

    // Two members miss withdrawals, replacements, additions and a
    // transient route; their recovery must withdraw exactly what they hold.
    run.block(0);
    run.block(1);
    run.withdraw(vec![route(1, 100).key(), route(2, 100).key()]);
    run.announce(vec![
        route(3, 200),
        route(4, 200),
        route(1013, 100),
        route(1014, 100),
    ]);
    run.announce(vec![route(1015, 100)]);
    run.withdraw(vec![route(1015, 100).key()]);
    phases.push(run.heal());

    // A refresh replay for a member held back while routes change.
    run.block(2);
    let peer = run.receivers[2].peer;
    run.manager
        .handle_route_refresh_request(peer, EVPN.0, EVPN.1);
    run.withdraw(vec![route(5, 100).key()]);
    run.announce(vec![route(1016, 100), route(6, 300)]);
    phases.push(run.heal());

    // An owed end-of-RIB marker keeps an owned member's proof after its
    // complete feed, so later deltas are admitted into that proof and its
    // withdrawals are checked against it.
    let held = run.receivers[1].peer;
    run.manager
        .pending_eor
        .entry(held)
        .or_default()
        .insert(EVPN);
    run.block(1);
    run.announce(vec![route(1020, 100)]);
    run.drain();
    // Room for the complete feed only: the marker after it is refused.
    for _ in 0..7 {
        run.manager.outbound_peers[&held]
            .try_send(OutboundRouteUpdate::default())
            .unwrap();
    }
    run.manager.resync_dirty_peers_bounded();
    run.drain();
    if owned {
        let handle = run.manager.evpn_recovery_handle(held).unwrap();
        assert!(
            !run.manager.evpn_recovery.is_dormant(handle),
            "the owed marker keeps the proof"
        );
        assert_eq!(
            run.manager.evpn_recovery.dense_for_test(handle),
            Some(table >= 300)
        );
        run.recovered += 1;
    }
    run.announce(vec![route(1021, 100)]);
    run.drain();
    run.withdraw(vec![route(1020, 100).key(), route(1021, 100).key()]);
    phases.push(run.heal());

    // Churn while one member is held, then withdraw everything.
    run.block(3);
    run.withdraw((7..=10).map(|tag| route(tag, 100).key()).collect());
    run.announce(vec![route(1017, 100)]);
    phases.push(run.heal());
    let remaining: Vec<_> = run
        .manager
        .loc_rib
        .iter_evpn()
        .map(EvpnRibRoute::key)
        .collect();
    run.block(0);
    run.withdraw(remaining);
    phases.push(run.heal());
    let spurious = run
        .receivers
        .iter()
        .map(|receiver| receiver.spurious.clone())
        .collect();
    (phases, spurious, run.recovered)
}

#[test]
fn owned_recovery_matches_private_routes_without_spurious_withdrawals() {
    // Twelve routes keep proofs as sorted entries; 300 make them bitsets.
    for table in [12, 300] {
        assert_owned_matches_private(table);
    }
}

fn assert_owned_matches_private(table: u32) {
    let (private, private_spurious, _) = scenario(false, table);
    let (owned, owned_spurious, recovered) = scenario(true, table);
    assert!(
        recovered >= 4,
        "owned recovery held provenance {recovered} times"
    );
    assert!(
        private_spurious.iter().all(Vec::is_empty),
        "{private_spurious:?}"
    );
    assert!(
        owned_spurious.iter().all(Vec::is_empty),
        "{owned_spurious:?}"
    );
    assert_eq!(owned.len(), private.len());
    for (phase, (owned, private)) in owned.iter().zip(&private).enumerate() {
        for (receiver, (owned, private)) in owned.iter().zip(private).enumerate() {
            assert_eq!(
                owned.keys().collect::<Vec<_>>(),
                private.keys().collect::<Vec<_>>(),
                "phase {phase} receiver {receiver}"
            );
            for (key, route) in owned {
                assert!(
                    crate::manager::helpers::evpn_routes_equal(route, &private[key]),
                    "phase {phase} receiver {receiver} route {key:?}"
                );
            }
        }
    }
}
