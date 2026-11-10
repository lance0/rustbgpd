use super::*;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

fn connect_unicast(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    gr_waiter: bool,
    receive_orf: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: gr_waiter,
        peer_gr_families: if gr_waiter { vec![FAMILY] } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: if receive_orf { vec![FAMILY] } else { vec![] },
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

#[test]
fn non_gr_orf_refresh_completes_initial_eor_owed_through_selection_hold() {
    let source_addr = Ipv4Addr::new(10, 0, 0, 1);
    let source = peer_v4(source_addr);
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: source.into(),
                families: vec![FAMILY],
            }],
        });
    let _source_rx = connect_unicast(&mut manager, source, 11, true, false);
    let mut target_rx = connect_unicast(&mut manager, target, 22, false, true);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 11,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            source_addr,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert!(manager.selection_convergence_held(FAMILY));
    assert!(target_rx.try_recv().is_err());
    assert!(manager.eor_withheld(target, FAMILY));

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.peer_orf_pending[&target].contains(&FAMILY));
    assert!(manager.eor_pending(target).contains(&FAMILY));
    assert!(
        target_rx.try_recv().is_err(),
        "ORF still holds the initial table"
    );

    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer: target,
        session_id: 22,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut announced = vec![];
    let mut eors = 0;
    while let Ok(update) = target_rx.try_recv() {
        assert!(
            update.refresh_markers.is_empty(),
            "initial EoR is still owed"
        );
        assert_eq!(
            update.unicast_withdrawals().copied().collect::<Vec<_>>(),
            [] as [(rustbgpd_wire::Prefix, u32); 0]
        );
        for route in update.announce.iter() {
            assert_eq!(eors, 0, "route data must precede the initial EoR");
            announced.push((route.prefix, route.peer));
        }
        for family in update.end_of_rib {
            assert_eq!(family, FAMILY);
            eors += 1;
        }
    }
    assert_eq!(announced, vec![(prefix, source)]);
    assert_eq!(eors, 1, "the non-GR peer still needs its initial EoR");
    assert!(manager.eor_pending(target).is_empty());
    assert!(manager.eor_behind_orf_table(target).is_empty());
    assert!(!manager.peer_orf_pending.contains_key(&target));
    assert!(!manager.retain_initial_group_admitted(target));
    assert!(!manager.pending_group_admitted.contains_record(target));
    manager.settle_eor_now(target);
    assert!(
        target_rx.try_recv().is_err(),
        "initial completion is consumed once"
    );
}

fn interface_peer(address: &str, interface: &str) -> PeerId {
    PeerId::allocate_interface_only(crate::PeerEndpoint::new(
        address.parse().unwrap(),
        Some(interface),
    ))
}

/// A planned restart whose roster is interface-only neighbors (ADR-0142),
/// named by interface before any of them has a handle.
fn interface_roster_manager(interfaces: &[&str]) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_selection_deferral(
        SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: interfaces
                .iter()
                .map(|&interface| SelectionDeferralWaiterConfig {
                    peer: crate::EorGraceTarget::Interface(interface.into()),
                    families: vec![FAMILY],
                })
                .collect(),
        },
    )
}

fn end_of_rib(manager: &mut RibManager, peer: PeerId, session_id: u64) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer,
        session_id,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    drain_route_chunks(manager);
}

fn end_of_rib_count(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> usize {
    std::iter::from_fn(|| rx.try_recv().ok())
        .flat_map(|update| update.end_of_rib)
        .filter(|family| *family == FAMILY)
        .count()
}

/// An unnumbered spine whose GR neighbors are all interface-only still
/// defers selection: the first leaf to finish does not get our End-of-RIB
/// (and purge its stale routes from us) before the other leaf's routes
/// have arrived (RFC 4724 §4.1).
#[test]
fn interface_only_waiters_hold_end_of_rib_until_every_leaf_completes() {
    let mut manager = interface_roster_manager(&["swp1", "swp2"]);
    let leaf1 = interface_peer("fe80::1", "swp1");
    let leaf2 = interface_peer("fe80::2", "swp2");
    let mut leaf1_rx = connect_unicast(&mut manager, leaf1, 11, true, false);
    let _leaf2_rx = connect_unicast(&mut manager, leaf2, 22, true, false);

    end_of_rib(&mut manager, leaf1, 11);
    assert!(
        manager.selection_convergence_held(FAMILY),
        "the second leaf's End-of-RIB is still awaited"
    );
    assert_eq!(
        end_of_rib_count(&mut leaf1_rx),
        0,
        "our End-of-RIB waits for deferral release"
    );

    end_of_rib(&mut manager, leaf2, 22);
    assert!(!manager.selection_convergence_held(FAMILY));
    assert_eq!(end_of_rib_count(&mut leaf1_rx), 1);
    assert!(leaf1.release());
    assert!(leaf2.release());
}

/// A retired binding (an address change keeps the neighbor's handle) keeps
/// the neighbor in the roster; removing the neighbor from configuration
/// before its first session takes its entry out.
#[test]
fn interface_only_waiter_survives_binding_retirement_but_not_neighbor_removal() {
    let mut manager = interface_roster_manager(&["swp1", "swp2", "swp3"]);
    manager.handle_update(RibUpdate::RetireEorGraceInterface {
        interface: "swp3".into(),
    });
    let leaf1 = interface_peer("fe80::1", "swp1");
    let leaf2 = interface_peer("fe80::2", "swp2");
    let leaf3 = interface_peer("fe80::3", "swp3");
    let _leaf2_rx = connect_unicast(&mut manager, leaf2, 22, true, false);
    let _first_rx = connect_unicast(&mut manager, leaf1, 11, true, false);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: leaf1,
        label: None,
        keep_series: true,
    });
    manager.handle_update(RibUpdate::RebindPeer {
        peer: leaf1,
        endpoint: crate::PeerEndpoint::new("fe80::9".parse().unwrap(), Some("swp1")),
    });
    let mut leaf1_rx = connect_unicast(&mut manager, leaf1, 12, true, false);
    let _leaf3_rx = connect_unicast(&mut manager, leaf3, 33, true, false);

    end_of_rib(&mut manager, leaf2, 22);
    assert!(
        manager.selection_convergence_held(FAMILY),
        "the rebound leaf is still awaited"
    );
    end_of_rib(&mut manager, leaf1, 12);
    assert!(
        !manager.selection_convergence_held(FAMILY),
        "a session on the removed neighbor's interface is not awaited"
    );
    assert_eq!(end_of_rib_count(&mut leaf1_rx), 1);
    for peer in [leaf1, leaf2, leaf3] {
        assert!(peer.release());
    }
}

/// Removing an interface-only neighbor ends its roster entry even after a
/// session bound it: a retired binding whose cleanup is still unconfirmed
/// keeps its handle, and a later session of that handle must not hold the
/// family the remaining leaves have completed.
#[test]
fn interface_only_waiter_ends_with_its_neighbor_after_binding() {
    let mut manager = interface_roster_manager(&["swp1", "swp2"]);
    let leaf1 = interface_peer("fe80::1", "swp1");
    let leaf2 = interface_peer("fe80::2", "swp2");
    let _leaf2_rx = connect_unicast(&mut manager, leaf2, 22, true, false);
    let _first_rx = connect_unicast(&mut manager, leaf1, 11, true, false);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: leaf1,
        label: None,
        keep_series: true,
    });
    assert!(
        manager.selection_convergence_held(FAMILY),
        "leaf2 still blocks"
    );
    manager.handle_update(RibUpdate::RetireEorGraceInterface {
        interface: "swp1".into(),
    });
    let _again_rx = connect_unicast(&mut manager, leaf1, 12, true, false);
    end_of_rib(&mut manager, leaf2, 22);
    assert!(
        !manager.selection_convergence_held(FAMILY),
        "the removed neighbor's handle is no longer awaited"
    );
    for peer in [leaf1, leaf2] {
        assert!(peer.release());
    }
}
