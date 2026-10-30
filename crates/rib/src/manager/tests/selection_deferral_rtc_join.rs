use super::*;
use crate::update::OutboundRouteUpdate;

const VPN: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const RTC: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 62);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 63);
const LATE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 64);
const SOURCE_SESSION: u64 = 161;
const WAITER_SESSION: u64 = 163;
const LATE_SESSION: u64 = 164;

fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    families: &[(Afi, Safi)],
    waiter: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { vec![VPN] } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy: None,
        sendable_families: families.to_vec(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn interest(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) {
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer: peer_v4(address),
        session_id,
        announced: vec![make_rtc_rib_route(address, 100, 100)],
        withdrawn: vec![],
    });
    drain_route_chunks(manager);
}

fn eor(manager: &mut RibManager, address: Ipv4Addr, session_id: u64, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(address),
        session_id,
        afi: family.0,
        safi: family.1,
    });
}

fn assert_vpn_still_held(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    while let Ok(update) = receiver.try_recv() {
        assert!(
            update.vpn_announce.is_empty(),
            "VPN route escaped the active selection hold"
        );
        assert_eq!(update.vpn_withdraw, [] as [crate::route::VpnRibRouteKey; 0]);
        assert!(!update.end_of_rib.contains(&VPN));
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the transcript distinguishes empty initial interest from a route becoming eligible during a held dirty resync"
)]
fn rtc_interest_added_during_vpn_hold_survives_an_empty_dirty_resync() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![VPN],
            }],
        });
    let _source_rx = connect(&mut manager, SOURCE, SOURCE_SESSION, &[VPN], false);
    let mut observer_rx = connect(&mut manager, OBSERVER, 162, &[VPN, RTC], false);
    interest(&mut manager, OBSERVER, 162);
    eor(&mut manager, OBSERVER, 162, RTC);
    let route = make_vpn_rib_route_with_rts(SOURCE, 73, vec![rt(100)]);
    let key = route.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: SOURCE_SESSION,
        announced: vec![route],
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    assert!(!manager.selection_deferred(VPN));
    let mut preselected = vec![];
    while let Ok(update) = observer_rx.try_recv() {
        preselected.extend(update.vpn_announce.iter().map(VpnRibRoute::key));
    }
    assert_eq!(
        preselected,
        vec![key.clone()],
        "the canonical group already owns the frozen VPN row"
    );

    let _waiter_rx = connect(&mut manager, WAITER, WAITER_SESSION, &[VPN], true);
    assert!(manager.selection_deferred(VPN));
    let late = peer_v4(LATE);
    let mut late_rx = connect(&mut manager, LATE, LATE_SESSION, &[VPN, RTC], false);
    let gid = manager
        .vpn_grouped_member_of(late)
        .expect("VPN+RTC member is grouped");
    assert_eq!(manager.vpn_grouped_member_of(peer_v4(OBSERVER)), Some(gid));
    assert_eq!(manager.group_ribs[&gid].table.vpn_len(), 1);
    assert!(!manager.peer_rt_membership[&late].matches_any(&[rt(100)]));
    assert_vpn_still_held(&mut late_rx);
    eprintln!(
        "late empty-interest initial: dirty={} initial_pending={} proof={}",
        manager.dirty_peers.contains(&late),
        manager.retain_initial_group_admitted(late),
        manager.pending_group_admitted.contains_record(late),
    );

    // The new RTC interest now covers the preselected route, but it cannot
    // cross VPN selection; its refused delta enters ordinary dirty recovery.
    interest(&mut manager, LATE, LATE_SESSION);
    assert!(manager.peer_rt_membership[&late].matches_any(&[rt(100)]));
    assert!(
        manager.dirty_peers.contains(&late),
        "the selection-held membership delta must not count as admission"
    );
    assert_vpn_still_held(&mut late_rx);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(manager.selection_deferred(VPN));
    assert_vpn_still_held(&mut late_rx);
    eprintln!(
        "after held dirty resync: dirty={} initial_pending={} proof={}",
        manager.dirty_peers.contains(&late),
        manager.retain_initial_group_admitted(late),
        manager.pending_group_admitted.contains_record(late),
    );
    // Complete the independent RTC membership marker before the VPN gate.
    eor(&mut manager, LATE, LATE_SESSION, RTC);
    assert!(manager.pending_eor[&late].contains(&VPN));
    assert_vpn_still_held(&mut late_rx);

    eor(&mut manager, WAITER, WAITER_SESSION, VPN);
    assert!(!manager.selection_convergence_held(VPN));
    // A still-dirty member may finish on its ordinary retry after release.
    // Drive that retry rather than requiring synchronous clean admission.
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let mut announced = vec![];
    let mut vpn_eors = 0;
    while let Ok(update) = late_rx.try_recv() {
        assert!(
            update.vpn_withdraw.is_empty(),
            "the late member held no VPN route to withdraw"
        );
        for route in update.vpn_announce.iter() {
            assert_eq!(vpn_eors, 0, "VPN data must precede its initial EoR");
            announced.push(route.key());
        }
        if update.end_of_rib.contains(&VPN) {
            assert_eq!(
                announced,
                vec![key.clone()],
                "VPN EoR overtook the newly eligible frozen row"
            );
            vpn_eors += 1;
        }
    }
    assert_eq!(announced, vec![key]);
    assert_eq!(vpn_eors, 1);
    assert!(!manager.dirty_peers.contains(&late));
    assert!(
        !manager
            .pending_eor
            .get(&late)
            .is_some_and(|families| families.contains(&VPN))
    );
    assert!(!manager.retain_initial_group_admitted(late));
    assert!(!manager.pending_group_admitted.contains_record(late));
}
