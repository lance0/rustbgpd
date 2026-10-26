use super::evpn_group_storage::{fixture, received, register};
use super::update_groups::community_chain;
use super::*;
use crate::PeerId;
use crate::manager::helpers::evpn_routes_equal;
use crate::manager::update_groups::GroupMembership;
use crate::update::{EvpnRecoveryResetOutcome, PeerExportPolicyReplacement};
use rustbgpd_wire::{EthernetTagId, EvpnRoute, EvpnRouteKey};

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

fn route(tag: u32, target: u16) -> EvpnRibRoute {
    let mut route = received(target);
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        panic!("IMET fixture");
    };
    imet.ethernet_tag = EthernetTagId(tag);
    route
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the fleet regression keeps blocked OLD, regroup and ordered recovery in one causal fixture"
)]
fn evpn_all_members_backpressured_regroup_preserves_old_and_releases_proof() {
    let (mut manager, first, old_gid, first_output) = fixture();
    manager.flush_poll_budget = Duration::MAX;
    let mut outputs = vec![(first, first_output)];
    manager
        .group_ribs
        .get_mut(&old_gid)
        .unwrap()
        .set_evpn_ownership_for_test(false);
    for suffix in 31..38 {
        let peer = PeerId::from_addr(Ipv4Addr::new(192, 0, 2, suffix).into());
        let (sender, mut output) = mpsc::channel(8);
        register(&mut manager, peer, sender);
        while output.try_recv().is_ok() {}
        assert_eq!(manager.grouped_member_of(peer), Some(old_gid));
        outputs.push((peer, output));
    }
    manager
        .group_ribs
        .get_mut(&old_gid)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    for &(peer, _) in &outputs {
        assert!(manager.register_evpn_recovery(peer, false));
    }
    let reset_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&reset_requests);
    manager.evpn_recovery_reset = Some(Arc::new(move |request, reply| {
        seen.lock().unwrap().push(request);
        let _ = reply.send(EvpnRecoveryResetOutcome::Executed);
        true
    }));
    let old: Vec<_> = (1..=4).map(|tag| route(tag, 100)).collect();
    let old_keys: HashSet<_> = old.iter().map(EvpnRibRoute::key).collect();
    let source = old[0].peer;
    manager.ribs.insert(source, AdjRibIn::new(source));
    manager.process_evpn_announce_chunk(source, old.clone());
    let mut remote = HashMap::new();
    let mut dormant_bytes = HashMap::new();
    for (peer, output) in &mut outputs {
        let update = output.try_recv().unwrap();
        assert_eq!(update.evpn_announce.len(), 4);
        assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
        remote.insert(
            *peer,
            update
                .evpn_announce
                .iter()
                .map(|r| (r.key(), r.clone()))
                .collect::<HashMap<_, _>>(),
        );
        assert!(output.try_recv().is_err());
        assert_eq!(manager.evpn_admitted_count(*peer), 4);
        assert!(
            manager
                .evpn_recovery
                .is_dormant(manager.evpn_recovery_handle(*peer).unwrap())
        );
        dormant_bytes.insert(*peer, manager.evpn_recovery.peer_usage(*peer).retained);
        for _ in 0..8 {
            manager.outbound_peers[peer]
                .try_send(OutboundRouteUpdate::default())
                .unwrap();
        }
        assert!(matches!(
            manager.outbound_peers[peer].try_send(OutboundRouteUpdate::default()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }
    let dormant_total = manager.evpn_recovery.daemon_usage().retained;

    // Every receiver stays blocked through OLD removal, same-key replacement,
    // a new route, and a transient desired route never admitted to any member.
    manager.process_evpn_withdraw_chunk(source, vec![old[0].key()]);
    manager.process_evpn_announce_chunk(source, vec![route(2, 200), route(5, 100), route(6, 100)]);
    manager.process_evpn_withdraw_chunk(source, vec![route(6, 100).key()]);
    for &(peer, _) in &outputs {
        let handle = manager.evpn_recovery_handle(peer).unwrap();
        assert!(manager.dirty_peers.contains(&peer));
        assert!(manager.group_ribs[&old_gid].dirty_members.contains(&peer));
        assert_eq!(
            manager
                .evpn_recovery
                .proof_keys(handle)
                .unwrap()
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            old_keys
        );
        assert!(manager.evpn_recovery.peer_usage(peer).retained > dormant_bytes[&peer]);
        assert_eq!(manager.evpn_admitted_count(peer), 4);
        assert!(!manager.evpn_recovery_reset_pending(peer));
    }

    // Prepare the dormant owned destination explicitly: production ownership
    // remains disabled. The policy replacement itself uses the real transaction.
    let policy = community_chain(0xFC00_0001);
    let previous = manager.export_chains.get(&first).cloned();
    manager.export_chains.insert(first, Some(policy.clone()));
    let GroupMembership::Grouped(destination) = manager.compute_update_group_membership(first)
    else {
        panic!("groupable destination");
    };
    assert_ne!(destination, old_gid);
    manager.ensure_group_table(destination, first);
    manager
        .group_ribs
        .get_mut(&destination)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    let desired_keys = HashSet::from([
        route(2, 200).key(),
        route(3, 100).key(),
        route(4, 100).key(),
        route(5, 100).key(),
    ]);
    manager.stage_group_evpn_keys(destination, &desired_keys);
    assert!(manager.group_ribs[&destination].members.is_empty());
    match previous {
        Some(previous) => {
            manager.export_chains.insert(first, previous);
        }
        None => {
            manager.export_chains.remove(&first);
        }
    }
    for &(peer, _) in &outputs {
        manager.pending_eor.insert(peer, HashSet::from([EVPN]));
    }
    manager
        .apply_export_policy_replacements_synchronously(
            outputs
                .iter()
                .map(|&(peer, _)| PeerExportPolicyReplacement {
                    peer,
                    export_policy: Some(policy.clone()),
                })
                .collect(),
        )
        .unwrap();
    assert!(
        !manager.group_ribs.contains_key(&old_gid),
        "last OLD member left"
    );
    assert_eq!(manager.group_ribs[&destination].members.len(), 8);
    for &(peer, _) in &outputs {
        assert_eq!(manager.evpn_grouped_member_of(peer), Some(destination));
        let handle = manager.evpn_recovery_handle(peer).unwrap();
        assert_eq!(
            manager
                .evpn_recovery
                .proof_keys(handle)
                .unwrap()
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            old_keys
        );
        assert!(!manager.evpn_recovery.is_dormant(handle));
        assert!(manager.dirty_peers.contains(&peer));
        assert!(!manager.evpn_feed_is_current(peer));
        manager.flush_pending_eor(peer);
        assert!(manager.pending_eor[&peer].contains(&EVPN));
    }
    #[cfg(feature = "bench-internals")]
    {
        let receipt = manager.bench_evpn_group_receipt();
        assert_eq!(receipt.peers.len(), outputs.len());
        assert_eq!(receipt.retained_recovery_members, outputs.len());
        assert!(receipt.peers.iter().all(|row| row.retained_recovery));
    }
    let blocked_usage = manager.evpn_recovery.daemon_usage();
    assert!(blocked_usage.retained > dormant_total);
    assert!(reset_requests.lock().unwrap().is_empty());

    // Release one bounded receiver at a time. Other members must retain their
    // exact OLD proof until their own data and terminal marker are admitted.
    for index in 0..outputs.len() {
        let (peer, output) = &mut outputs[index];
        let peer = *peer;
        for _ in 0..8 {
            let filler = output.try_recv().unwrap();
            assert!(
                filler.evpn_announce.is_empty()
                    && filler.evpn_withdraw.is_empty()
                    && filler.end_of_rib.is_empty()
            );
        }
        assert!(output.try_recv().is_err());
        manager.resync_dirty_peers_bounded();
        manager.flush_pending_eor(peer);
        let mut withdrawn = HashSet::<EvpnRouteKey>::new();
        let mut announced = HashSet::new();
        let mut terminal_count = 0;
        let remote = remote.get_mut(&peer).unwrap();
        while let Ok(update) = output.try_recv() {
            assert_eq!(
                terminal_count, 0,
                "nothing follows the EVPN terminal marker"
            );
            for key in update.evpn_withdraw {
                assert!(
                    old_keys.contains(&key),
                    "never withdraw an unadmitted desired key"
                );
                assert!(withdrawn.insert(key), "no duplicate withdrawals");
                assert!(remote.remove(&key).is_some());
            }
            for route in update.evpn_announce.iter() {
                assert!(announced.insert(route.key()), "no duplicate replay rows");
                remote.insert(route.key(), route.clone());
            }
            if update.end_of_rib.contains(&EVPN) {
                terminal_count += 1;
                assert_eq!(remote.keys().copied().collect::<HashSet<_>>(), desired_keys);
                for key in &desired_keys {
                    assert!(remote[key].communities().contains(&0xFC00_0001));
                    assert!(
                        evpn_routes_equal(
                            &remote[key],
                            manager.group_ribs[&destination]
                                .table
                                .get_evpn(key)
                                .unwrap()
                        ),
                        "terminal covers current post-policy route values"
                    );
                }
            }
        }
        assert_eq!(terminal_count, 1);
        assert_eq!(withdrawn, HashSet::from([old[0].key()]));
        assert_eq!(announced, desired_keys);
        assert_eq!(manager.evpn_admitted_count(peer), 4);
        assert!(!manager.dirty_peers.contains(&peer));
        assert!(!manager.evpn_advertised_resync_in_progress(peer));
        assert!(!manager.has_evpn_feed_completion(peer));
        assert!(!manager.evpn_recovery_reset_pending(peer));
        assert!(
            manager
                .evpn_recovery
                .is_dormant(manager.evpn_recovery_handle(peer).unwrap())
        );
        assert_eq!(
            manager.evpn_recovery.peer_usage(peer).retained,
            dormant_bytes[&peer]
        );
        #[cfg(feature = "bench-internals")]
        {
            let receipt = manager.bench_evpn_group_receipt();
            let remaining = &outputs[index + 1..];
            assert_eq!(receipt.peers.len(), outputs.len());
            assert_eq!(receipt.retained_recovery_members, remaining.len());
            for row in &receipt.peers {
                assert_eq!(
                    row.retained_recovery,
                    remaining.iter().any(|(blocked, _)| *blocked == row.peer),
                    "receipt must follow each member's actual settlement"
                );
            }
        }
        for &(blocked, _) in &outputs[index + 1..] {
            let handle = manager.evpn_recovery_handle(blocked).unwrap();
            assert_eq!(
                manager
                    .evpn_recovery
                    .proof_keys(handle)
                    .unwrap()
                    .unwrap()
                    .into_iter()
                    .collect::<HashSet<_>>(),
                old_keys
            );
            assert!(manager.evpn_recovery.peer_usage(blocked).retained > dormant_bytes[&blocked]);
            assert!(manager.dirty_peers.contains(&blocked));
        }
    }
    assert_eq!(manager.evpn_recovery.daemon_usage().retained, dormant_total);
    #[cfg(feature = "bench-internals")]
    {
        let receipt = manager.bench_evpn_group_receipt();
        assert_eq!(receipt.retained_recovery_members, 0);
        assert!(receipt.peers.iter().all(|row| !row.retained_recovery));
        assert_eq!(receipt.retained_provenance_bytes, dormant_total);
        for row in &receipt.peers {
            assert_eq!(row.retained_provenance_bytes, dormant_bytes[&row.peer]);
        }
    }
    assert_eq!(manager.evpn_feed_receipt_count, 0);
    assert!(
        reset_requests.lock().unwrap().is_empty(),
        "no reset requested or acknowledged by the component callback"
    );
    for &(peer, _) in &outputs {
        let usage = manager.evpn_recovery.peer_usage(peer);
        assert!(usage.peak > dormant_bytes[&peer]);
        eprintln!(
            "evpn fleet peer={peer} dormant={} retained={} peak={}",
            dormant_bytes[&peer], usage.retained, usage.peak
        );
        manager.handle_update(RibUpdate::PeerDown {
            peer,
            session_id: 7,
        });
        assert_eq!(manager.evpn_recovery.peer_usage(peer).retained, 0);
    }
    let final_usage = manager.evpn_recovery.daemon_usage();
    assert_eq!(final_usage.retained, size_of_val(&manager.evpn_recovery));
    eprintln!(
        "evpn fleet daemon dormant={dormant_total} blocked={} peak={} final={}",
        blocked_usage.retained, final_usage.peak, final_usage.retained
    );
}
