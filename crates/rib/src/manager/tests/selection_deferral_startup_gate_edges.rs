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
                peer: source,
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
    assert!(manager.pending_eor_held(target, FAMILY));

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.peer_orf_pending[&target].contains(&FAMILY));
    assert!(manager.pending_eor[&target].contains(&FAMILY));
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
        assert_eq!(update.withdraw, [] as [(rustbgpd_wire::Prefix, u32); 0]);
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
    assert!(!manager.pending_eor.contains_key(&target));
    assert!(!manager.gr_deferred_eor.contains_key(&target));
    assert!(!manager.peer_orf_pending.contains_key(&target));
    assert!(!manager.retain_initial_group_admitted(target));
    assert!(!manager.pending_group_admitted.contains_record(target));
    manager.flush_pending_eor(target);
    assert!(
        target_rx.try_recv().is_err(),
        "initial completion is consumed once"
    );
}
