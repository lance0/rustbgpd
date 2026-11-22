//! Count the full resyncs built for peers outside each caller's scope. Drive the
//! manager directly so the paced tick cannot enter the measured interval.
use super::*;
use crate::manager::tests::{evpn_group_storage, update_groups};
use crate::update::{
    ExportPolicyCohortOutcome, PeerExportPolicyReplacement, PeerExportPolicyRestoreReceipt,
};

const FIRST: usize = 100;
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

fn unrelated(manager: &mut RibManager, count: usize, event: impl FnOnce(&mut RibManager)) -> usize {
    let source = peer_v4(Ipv4Addr::new(198, 18, 0, 84));
    register_test_peer(manager, source, 0);
    manager.handle_update(routes_from(source, 0, 84, 1));
    drain_route_chunks(manager);
    let mut receivers: Vec<_> = (FIRST..FIRST + count)
        .map(|i| join(manager, i, false, None).0)
        .collect();
    let gid = manager.grouped_member_of(member(FIRST)).unwrap();
    for (offset, output) in receivers.iter_mut().enumerate() {
        let peer = member(FIRST + offset);
        assert_eq!(manager.grouped_member_of(peer), Some(gid));
        let mut marker_count = 0;
        while let Ok(update) = output.try_recv() {
            marker_count += update
                .announce
                .iter()
                .filter(|r| r.prefix == Prefix::V4(prefix(84, 0)))
                .count();
        }
        assert_eq!(marker_count, 1, "initial table of {peer}");
        assert!(
            !manager.outbound_operation_live(peer),
            "initial dump still queued for {peer}"
        );
        assert!(manager.mark_outbound_dirty(peer));
    }
    manager.adj_rib_out_commit_stats.watched_resync_builds =
        Some((member(FIRST), member(FIRST + count - 1), 0));
    event(manager);
    let (_, _, builds) = manager
        .adj_rib_out_commit_stats
        .watched_resync_builds
        .take()
        .unwrap();
    let sent: usize = receivers
        .iter_mut()
        .map(|rx| {
            std::iter::from_fn(|| rx.try_recv().ok())
                .map(|u| {
                    u.announce
                        .iter()
                        .filter(|r| r.prefix == Prefix::V4(prefix(84, 0)))
                        .count()
                })
                .sum::<usize>()
        })
        .sum();
    assert_eq!(
        sent, builds,
        "every counted writer is admissible and replays its marker"
    );
    builds
}

fn bar(caller: &str, mut measure: impl FnMut(usize) -> usize) {
    let rows = [SMALL, LARGE].map(|count| (count, measure(count)));
    eprintln!("{caller}: (unrelated dirty members, inline full resyncs) = {rows:?}");
    assert!(
        rows[0].1 == rows[1].1 && rows[0].1 <= 1,
        "{caller}: {rows:?}"
    );
}

fn target() -> PeerId {
    peer_v4(Ipv4Addr::new(203, 0, 113, 20))
}

fn target_with(
    manager: &mut RibManager,
    configure: impl FnOnce(&mut RibUpdate),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, mut rx) = mpsc::channel(64);
    let mut up = test_peer_up(target(), 1, tx);
    configure(&mut up);
    manager.handle_update(up);
    while rx.try_recv().is_ok() {}
    rx
}

#[test]
fn policy_cohort_commit() {
    bar("clean policy cohort commit", |count| {
        let (mut manager, peers, _outputs) =
            update_groups::direct_clean_transition_manager(2, 2, None);
        let policy = update_groups::community_chain(0xFDE8_2102);
        unrelated(&mut manager, count, |m| {
            let mut reply = update_groups::start_clean_transition(m, &peers, &policy);
            loop {
                let before = m.adj_rib_out_commit_stats.watched_resync_builds.unwrap().2;
                let (_, outcome) = update_groups::step_parked_transition(m);
                if outcome == "committed" {
                    assert_eq!(before, 0, "a preparation poll rebuilt an unrelated member");
                    break;
                }
                assert_eq!(outcome, "continue");
            }
            assert_eq!(
                reply.try_recv().unwrap().unwrap(),
                ExportPolicyCohortOutcome::Committed
            );
        })
    });
}

#[test]
fn refresh_peer_outbound() {
    bar("RefreshPeerOutbound", |count| {
        let (_tx, mut manager) = manager();
        let _output = target_with(&mut manager, |_| {});
        unrelated(&mut manager, count, |m| {
            let (reply, mut rx) = oneshot::channel();
            m.handle_update(RibUpdate::RefreshPeerOutbound {
                peer: target(),
                reply,
            });
            rx.try_recv().unwrap().unwrap();
        })
    });
}

#[test]
fn orf_immediate() {
    bar("ORF immediate", |count| {
        let (_tx, mut manager) = manager();
        let _output = target_with(&mut manager, |up| {
            if let RibUpdate::PeerUp {
                negotiated_orf_recv,
                ..
            } = up
            {
                negotiated_orf_recv.push(V4);
            }
        });
        assert!(manager.peer_orf_pending[&target()].contains(&V4));
        unrelated(&mut manager, count, |m| {
            let (reply, mut rx) = oneshot::channel();
            m.handle_update(RibUpdate::PeerOrfUpdate {
                peer: target(),
                session_id: 1,
                afi: V4.0,
                safi: V4.1,
                when: rustbgpd_wire::WhenToRefresh::Immediate,
                groups: vec![],
                reply,
            });
            rx.try_recv().unwrap().unwrap();
            assert!(
                !m.peer_orf_pending
                    .get(&target())
                    .is_some_and(|g| g.contains(&V4))
            );
        })
    });
}

#[test]
fn rtc_membership_change() {
    bar("received RTC membership change", |count| {
        let (_tx, mut manager) = manager();
        let _output = target_with(&mut manager, |up| {
            if let RibUpdate::PeerUp {
                sendable_families, ..
            } = up
            {
                sendable_families.push((Afi::Ipv4, Safi::RtConstrain));
            }
        });
        assert!(manager.vpn_grouped_member_of(target()).is_none());
        let r = make_rtc_rib_route(Ipv4Addr::new(203, 0, 113, 20), 123, 100);
        unrelated(&mut manager, count, |m| {
            m.handle_update(RibUpdate::RtcRoutesReceived {
                peer: target(),
                session_id: 1,
                announced: vec![r],
                withdrawn: vec![],
            });
            drain_route_chunks(m);
            assert_eq!(m.peer_rt_membership[&target()].entries.len(), 1);
        })
    });
}

#[test]
fn orr_topology_change() {
    bar(
        "received BGP-LS topology, ORR vantage becomes resolved",
        |count| {
            let (_tx, mut manager) = manager();
            let _output = target_with(&mut manager, |up| {
                if let RibUpdate::PeerUp {
                    orr_vantage,
                    route_reflector_client,
                    is_ebgp,
                    ..
                } = up
                {
                    *orr_vantage = Some(vantage_at_node_a());
                    *route_reflector_client = true;
                    *is_ebgp = false;
                }
            });
            let topo = crate::orr::fixtures::square_topology(Ipv4Addr::new(198, 51, 100, 1));
            unrelated(&mut manager, count, |m| {
                m.handle_update(RibUpdate::BgpLsRoutesReceived {
                    peer: external(),
                    session_id: 0,
                    announced: topo,
                    withdrawn: vec![],
                });
                drain_route_chunks(m);
                m.settle_orr_rebuild();
                assert_eq!(m.orr.resolved.get(&vantage_at_node_a()), Some(&true));
            })
        },
    );
}

#[test]
fn peer_slow_state() {
    bar("slow-state regroup", |count| {
        let (_tx, mut manager) = manager();
        let _output = join(
            &mut manager,
            0,
            false,
            Some(update_groups::community_chain(1)),
        )
        .0;
        let prior = manager.grouped_member_of(member(0)).unwrap();
        unrelated(&mut manager, count, |m| {
            m.handle_update(RibUpdate::PeerSlowState {
                peer: member(0),
                session_id: 1,
                slow: true,
            });
            assert_ne!(m.grouped_member_of(member(0)), Some(prior));
        })
    });
}

#[test]
fn family_sendable() {
    bar("family becomes sendable", |count| {
        let (_tx, mut manager) = manager();
        let _output = update_groups::register_withheld_v6_peer(&mut manager, target());
        let family = (Afi::Ipv6, Safi::Unicast);
        unrelated(&mut manager, count, |m| {
            m.handle_update(RibUpdate::PeerFamilySendable {
                peer: target(),
                session_id: 0,
                family,
                add_path_send_limit: None,
            });
            assert!(m.peer_sendable_families[&target()].contains(&family));
        })
    });
}

#[test]
fn dataset_member_fallback() {
    use crate::manager::tests::update_groups_oracle::{dataset_prefix_data, dataset_prefix_policy};

    bar(
        "dataset reevaluation, private-family member fallback",
        |count| {
            let (_tx, mut manager) = manager();
            let _output = target_with(&mut manager, |up| {
                if let RibUpdate::PeerUp {
                    sendable_families, ..
                } = up
                {
                    sendable_families.push(EVPN);
                }
            });
            unrelated(&mut manager, count, |m| {
                let (reply, mut rx) = oneshot::channel();
                m.handle_reevaluate_peer_export_policies(&[target()], None, reply);
                rx.try_recv().unwrap().unwrap();
            })
        },
    );

    // A sibling the request omitted still owns a withdrawal if its shared
    // policy reads the changed dataset.
    let (_tx, mut manager) = manager();
    let key = Prefix::V4(prefix(84, 0));
    let (dataset, chain) = dataset_prefix_policy(key, true);
    let mut requested = target_with(&mut manager, |up| {
        if let RibUpdate::PeerUp {
            export_policy,
            sendable_families,
            ..
        } = up
        {
            *export_policy = Some(chain.clone());
            sendable_families.push(EVPN);
        }
    });
    let (mut sibling, _) = join(&mut manager, FIRST, false, Some(chain));
    let gid = manager.grouped_member_of(target()).unwrap();
    assert_eq!(manager.grouped_member_of(member(FIRST)), Some(gid));
    let source = external();
    register_test_peer(&mut manager, source, 0);
    manager.handle_update(routes_from(source, 0, 84, 1));
    drain_route_chunks(&mut manager);
    for output in [&mut requested, &mut sibling] {
        assert!(
            std::iter::from_fn(|| output.try_recv().ok())
                .any(|update| update.announce.iter().any(|route| route.prefix == key))
        );
    }
    assert!(dataset.refresh(dataset_prefix_data(key, false)).is_some());
    let (reply, mut rx) = oneshot::channel();
    manager.handle_reevaluate_peer_export_policies(&[target()], None, reply);
    rx.try_recv().unwrap().unwrap();
    for output in [&mut requested, &mut sibling] {
        assert!(std::iter::from_fn(|| output.try_recv().ok()).any(|update| {
            update
                .unicast_withdrawals()
                .any(|&withdraw| withdraw == (key, 0))
        }));
    }
}

#[test]
fn synchronous_export_replacement() {
    bar("synchronous export-policy replacement", |count| {
        let (_tx, mut manager) = manager();
        let _output = target_with(&mut manager, |_| {});
        unrelated(&mut manager, count, |m| {
            m.replace_peer_export_policy_synchronously(
                target(),
                Some(update_groups::community_chain(5)),
            )
            .unwrap();
            assert!(m.export_chains[&target()].is_some());
        })
    });
}

#[test]
fn conditional_attachment_change() {
    bar("conditional advertisement attachment change", |count| {
        let (_tx, mut manager) = manager();
        let _output = join(
            &mut manager,
            0,
            false,
            Some(update_groups::community_chain(1)),
        )
        .0;
        let name: Arc<str> = Arc::from("conditional");
        let set = crate::ConditionalAdvertisementSet {
            definitions: vec![crate::ConditionalAdvertisement {
                name: name.clone(),
                advertise_policy: Default::default(),
                advertise_if: crate::ConditionalAdvertiseIf::Absent,
                condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(Prefix::V4(
                    prefix(83, 0),
                ))],
                condition_policy: None,
                settle_time: Duration::ZERO,
                retiring: false,
            }],
            attachments: [(member(0).endpoint().unwrap(), vec![name])]
                .into_iter()
                .collect(),
        };
        unrelated(&mut manager, count, |m| {
            m.handle_install_conditional_advertisements(set, &[]);
            assert!(m.peer_has_conditional_advertisements(member(0)));
        })
    });
}

#[test]
fn selection_family_release() {
    let family = (Afi::Ipv4, Safi::FlowSpec);
    let waiter = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    bar("selection release of an unrelated family", |count| {
        let (_tx, manager) = manager();
        let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: waiter.into(),
                families: vec![family],
            }],
        });
        arm_selection_waiter(&mut manager, waiter, &[family]);
        assert!(manager.selection_deferred(family));
        unrelated(&mut manager, count, |m| {
            let transition = m.selection_deferral_end_of_rib(waiter, 77, family).unwrap();
            m.apply_selection_deferral_transitions([transition], "test End-of-RIB");
            assert!(!m.selection_deferred(family));
        })
    });
}

#[derive(Clone, Copy, Debug)]
enum EvpnEvent {
    Announcement,
    Targeted,
    PeerDown,
    GrEntry,
    GrSweep,
    GrEndOfRib,
    GrPromote,
    LlgrSweep,
    EndRouteRefresh,
}

fn evpn_announce(m: &mut RibManager, route: EvpnRibRoute) {
    let mut update = test_routes_received(route.peer, vec![]);
    let RibUpdate::RoutesReceived { evpn_announced, .. } = &mut update else {
        unreachable!()
    };
    evpn_announced.push(route);
    m.handle_update(update);
    drain_route_chunks(m);
}

fn gr_entry(m: &mut RibManager, source: PeerId, llgr: bool) {
    m.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![EVPN],
        peer_llgr_capable: llgr,
        peer_llgr_families: if llgr {
            vec![rustbgpd_wire::LlgrFamily {
                afi: EVPN.0,
                safi: EVPN.1,
                forwarding_preserved: false,
                stale_time: 600,
            }]
        } else {
            vec![]
        },
        llgr_stale_time: 600,
    });
}

fn owned_evpn(event: EvpnEvent, count: usize) -> usize {
    let (mut manager, receiver, gid, mut output) = evpn_group_storage::fixture();
    let route = evpn_group_storage::received(100);
    let source = route.peer;
    let key = route.key();
    register_test_peer(&mut manager, source, 0);
    assert_eq!(manager.evpn_grouped_member_of(receiver), Some(gid));
    if !matches!(event, EvpnEvent::Announcement) {
        evpn_announce(&mut manager, route.clone());
        assert!(manager.loc_rib.get_evpn(&key).is_some());
        assert!(std::iter::from_fn(|| output.try_recv().ok()).any(|u| !u.evpn_announce.is_empty()));
    }
    if matches!(
        event,
        EvpnEvent::GrSweep | EvpnEvent::LlgrSweep | EvpnEvent::GrEndOfRib | EvpnEvent::GrPromote
    ) {
        gr_entry(
            &mut manager,
            source,
            matches!(event, EvpnEvent::LlgrSweep | EvpnEvent::GrPromote),
        );
        assert!(manager.loc_rib.get_evpn(&key).unwrap().is_stale);
    }
    if matches!(event, EvpnEvent::LlgrSweep) {
        manager.sweep_gr_stale(source);
        assert!(manager.loc_rib.get_evpn(&key).unwrap().is_llgr_stale);
    }
    if matches!(event, EvpnEvent::GrEndOfRib) {
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: source,
            session_id: 2,
            peer_restart_state: true,
            peer_gr_helper: true,
            peer_gr_families: vec![EVPN],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        manager.handle_update(registering_peer_up(source, 2));
        assert!(manager.loc_rib.get_evpn(&key).unwrap().is_stale);
    }
    if matches!(event, EvpnEvent::EndRouteRefresh) {
        manager.handle_begin_route_refresh(source, EVPN.0, EVPN.1);
        assert!(manager.refresh_stale_evpn[&source].contains_key(&key));
    }
    unrelated(&mut manager, count, |m| match event {
        EvpnEvent::Announcement => {
            evpn_announce(m, route);
            assert!(m.loc_rib.get_evpn(&key).is_some());
        }
        EvpnEvent::Targeted => {
            m.distribute_evpn_keys_to_peer(receiver, &HashSet::from([key]), &mut || {});
            assert!(m.loc_rib.get_evpn(&key).is_some());
        }
        EvpnEvent::GrEntry => {
            gr_entry(m, source, false);
            assert!(m.loc_rib.get_evpn(&key).unwrap().is_stale);
        }
        EvpnEvent::GrPromote => {
            m.sweep_gr_stale(source);
            assert!(m.loc_rib.get_evpn(&key).unwrap().is_llgr_stale);
        }
        EvpnEvent::PeerDown
        | EvpnEvent::GrEndOfRib
        | EvpnEvent::GrSweep
        | EvpnEvent::LlgrSweep
        | EvpnEvent::EndRouteRefresh => {
            match event {
                EvpnEvent::PeerDown => m.handle_update(RibUpdate::PeerDown {
                    peer: source,
                    session_id: 0,
                }),
                EvpnEvent::GrEndOfRib => m.handle_update(RibUpdate::EndOfRib {
                    peer: source,
                    session_id: 2,
                    afi: EVPN.0,
                    safi: EVPN.1,
                }),
                EvpnEvent::GrSweep => m.sweep_gr_stale(source),
                EvpnEvent::LlgrSweep => m.sweep_llgr_stale(source, &[EVPN]),
                EvpnEvent::EndRouteRefresh => m.handle_end_route_refresh(source, EVPN.0, EVPN.1),
                _ => unreachable!(),
            }
            assert!(m.loc_rib.get_evpn(&key).is_none());
        }
    })
}

macro_rules! evpn_caller {
    ($name:ident, $event:ident) => {
        #[test]
        fn $name() {
            bar(stringify!($name), |count| {
                owned_evpn(EvpnEvent::$event, count)
            });
        }
    };
}
evpn_caller!(evpn_announcement, Announcement);
evpn_caller!(evpn_targeted, Targeted);
evpn_caller!(evpn_source_down, PeerDown);
evpn_caller!(evpn_source_gr, GrEntry);
evpn_caller!(evpn_gr_sweep, GrSweep);
evpn_caller!(evpn_llgr_sweep, LlgrSweep);
evpn_caller!(evpn_gr_to_llgr, GrPromote);
evpn_caller!(evpn_gr_eor_purge, GrEndOfRib);
evpn_caller!(evpn_eorr_purge, EndRouteRefresh);

// A rollback names its full captured roster, including peers whose policy
// the forward operation never moved. Only the target has a different chain.
fn mixed_replacements(count: usize) -> Vec<PeerExportPolicyReplacement> {
    let mut replacements = vec![PeerExportPolicyReplacement {
        peer: target(),
        export_policy: Some(update_groups::community_chain(5)),
    }];
    replacements.extend(
        (FIRST..FIRST + count).map(|index| PeerExportPolicyReplacement {
            peer: member(index),
            export_policy: None,
        }),
    );
    replacements
}

#[test]
fn policy_rollback_with_unchanged_dirty_members() {
    bar(
        "rollback snapshot containing unchanged dirty members",
        |count| {
            let (_tx, mut manager) = manager();
            let _output = target_with(&mut manager, |_| {});
            unrelated(&mut manager, count, |m| {
                let (reply, mut rx) = oneshot::channel();
                let replacements = mixed_replacements(count);
                let expected: Vec<_> = replacements
                    .iter()
                    .rev()
                    .map(|r| PeerExportPolicyRestoreReceipt::Restored { peer: r.peer })
                    .collect();
                m.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                });
                assert_eq!(rx.try_recv().unwrap().unwrap(), expected);
                assert_eq!(
                    m.export_chains[&target()],
                    Some(update_groups::community_chain(5))
                );
                assert!((FIRST..FIRST + count).all(|index| m.dirty_peers.contains(&member(index))));
            })
        },
    );
}

#[test]
fn paced_policy_replacement() {
    bar(
        "one paced policy change plus unchanged dirty members",
        |count| {
            let (_tx, mut manager) = manager();
            let _output = target_with(&mut manager, |_| {});
            unrelated(&mut manager, count, |m| {
                let (reply, mut rx) = oneshot::channel();
                m.handle_update(RibUpdate::ApplyPacedExportPolicies {
                    replacements: mixed_replacements(count),
                    cost: None,
                    reply,
                });
                let outcome = rx.try_recv().unwrap().unwrap();
                assert_eq!(outcome.applied, count + 1);
                assert!(outcome.pending.is_empty());
                assert!(m.export_chains[&target()].is_some());
            })
        },
    );
}

#[test]
fn authoritative_policy_command() {
    for duplicate in [false, true] {
        let caller = if duplicate {
            "authoritative duplicate fallback with unchanged dirty members"
        } else {
            "authoritative policy change plus unchanged dirty members"
        };
        bar(caller, |count| {
            let (_tx, mut manager) = manager();
            let _output = target_with(&mut manager, |_| {});
            unrelated(&mut manager, count, |m| {
                let (reply, mut rx) = oneshot::channel();
                let mut replacements = mixed_replacements(count);
                if duplicate {
                    replacements.push(replacements.last().unwrap().clone());
                }
                m.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                });
                assert!(rx.try_recv().unwrap().unwrap().is_empty());
                assert!(m.export_chains[&target()].is_some());
            })
        });
    }
}

#[test]
fn ordinary_unicast_change_control() {
    bar("unrelated one-route change control", |count| {
        let (_tx, mut manager) = manager();
        unrelated(&mut manager, count, |m| {
            m.handle_update(routes_from(external(), 0, 83, 1));
            drain_route_chunks(m);
            assert_eq!(
                m.dirty_peers
                    .iter()
                    .filter(|p| (member(FIRST)..=member(FIRST + count - 1)).contains(p))
                    .count(),
                count
            );
        })
    });
}

#[test]
fn owned_evpn_metadata_change_and_targeted_restage_leave_sibling_debt_for_tick() {
    use crate::manager::tests::evpn_policy_pacing::{evpn_fleet, evpn_row};

    bar("same owned group with unchanged member exports", |count| {
        let mut fleet = evpn_fleet(count + 1, 1, true);
        let m = &mut fleet.manager;
        let target = fleet.members[0];
        let gid = m.evpn_grouped_member_of(target).unwrap();
        let mut route = evpn_row(1);
        let key = route.key();
        let stamp = m.group_ribs[&gid].evpn_table_stamp;

        register_test_peer(m, external(), 0);
        for &peer in &fleet.members {
            assert!(m.mark_outbound_dirty(peer));
        }
        // Every member really owes this new unicast row.
        m.handle_update(routes_from(external(), 0, 84, 1));
        drain_route_chunks(m);
        assert!(fleet.outputs.iter_mut().all(|rx| rx.try_recv().is_err()));
        m.adj_rib_out_commit_stats.watched_resync_builds =
            Some((fleet.members[1], fleet.members[count], 0));

        // OLD and NEW differ in storage. The wire export is identical for
        // every member, including the ones with pre-existing unicast debt.
        route.is_stale = true;
        m.process_evpn_announce_chunk(fleet.source, vec![route]);
        assert_ne!(m.group_ribs[&gid].evpn_table_stamp, stamp);
        assert!(m.group_ribs[&gid].evpn_entry(&key).unwrap().route.is_stale);
        assert!(m.dirty_peers.contains(&target));
        m.distribute_evpn_keys_to_peer(target, &HashSet::from([key]), &mut || {});
        let (_, _, builds) = m
            .adj_rib_out_commit_stats
            .watched_resync_builds
            .take()
            .unwrap();
        assert!(!m.dirty_peers.contains(&target));
        assert!(fleet.members[1..].iter().all(|p| m.dirty_peers.contains(p)));
        assert!(
            fleet.outputs[1..]
                .iter_mut()
                .all(|rx| rx.try_recv().is_err())
        );

        for _ in 0..count {
            if m.dirty_peers.is_empty() {
                break;
            }
            m.resync_dirty_peers_bounded();
        }
        for (&peer, rx) in fleet.members.iter().zip(&mut fleet.outputs) {
            assert!(!m.dirty_peers.contains(&peer));
            let mut announced = Vec::new();
            while let Ok(update) = rx.try_recv() {
                announced.extend(update.announce.iter().map(|r| r.prefix));
                assert!(update.evpn_withdraw.is_empty());
                assert!(update.evpn_announce.iter().all(|r| r.key() == key));
            }
            assert_eq!(announced, [Prefix::V4(prefix(84, 0))]);
            assert_eq!(m.evpn_admitted_count(peer), 1);
        }
        builds
    });
}
