use super::*;

const PATHS_PER_SESSION: u32 = 1024;
const FAMILIES: [(Afi, Safi); 6] = [
    (Afi::Ipv4, Safi::Unicast),
    (Afi::Ipv6, Safi::Unicast),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv6, Safi::MplsVpn),
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv6, Safi::LabeledUnicast),
];

fn announce_cycle(peer: PeerId, family: (Afi, Safi), session_id: u64) -> RibUpdate {
    let address = Ipv4Addr::new(192, 0, 2, 1);
    let prefix = if family.0 == Afi::Ipv4 {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24))
    } else {
        Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64))
    };
    let first = u32::try_from(session_id).unwrap() * PATHS_PER_SESSION;
    let ids = first..first + PATHS_PER_SESSION;
    match family.1 {
        Safi::Unicast => RibUpdate::RoutesReceived {
            peer,
            session_id,
            announced: ids
                .map(|path_id| {
                    let mut route = make_route(Ipv4Prefix::new(address, 32), address);
                    route.prefix = prefix;
                    route.path_id = path_id;
                    route
                })
                .collect(),
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        },
        Safi::MplsVpn => RibUpdate::VpnRoutesReceived {
            peer,
            session_id,
            announced: ids
                .map(|path_id| {
                    let mut route = make_vpn_rib_route(address, 1, 100, 100);
                    route.nlri.prefix = match prefix {
                        Prefix::V4(p) => VpnPrefix::v4(p.addr, p.len).unwrap(),
                        Prefix::V6(p) => VpnPrefix::v6(p.addr, p.len).unwrap(),
                    };
                    route.path_id = path_id;
                    route
                })
                .collect(),
            withdrawn: vec![],
        },
        Safi::LabeledUnicast => RibUpdate::LabeledRoutesReceived {
            peer,
            session_id,
            announced: ids
                .map(|path_id| {
                    let mut route = make_labeled_rib_route(address, 1, 100, 100);
                    route.nlri.prefix = prefix;
                    route.path_id = path_id;
                    route
                })
                .collect(),
            withdrawn: vec![],
        },
        _ => unreachable!(),
    }
}

// Fixed diagnostic: one key per family, 1024 fresh IDs per session, no EoR.
#[tokio::test(start_paused = true)]
async fn llgr_add_path_cycle_diagnostic() {
    for family in FAMILIES {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let peer = PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let llgr_families = vec![rustbgpd_wire::LlgrFamily {
            afi: family.0,
            safi: family.1,
            forwarding_preserved: true,
            stale_time: 3600,
        }];
        let mut original_deadline = None;
        for session_id in 1..=4 {
            manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
                peer,
                session_id,
                peer_restart_state: true,
                peer_gr_helper: true,
                peer_gr_families: vec![family],
                peer_enhanced_refresh: false,
                peer_llgr_families: llgr_families.clone(),
                local_llgr_stale_time: 3600,
            });
            let mut registration = registering_peer_up(peer, session_id);
            if let RibUpdate::PeerUp {
                negotiated_llgr_families,
                ..
            } = &mut registration
            {
                *negotiated_llgr_families = vec![family];
            }
            manager.handle_update(registration);
            let update = announce_cycle(peer, family, session_id);
            let started = std::time::Instant::now();
            manager.handle_update(update);
            while manager.process_next_route_chunk() {}
            let insert_us = started.elapsed().as_micros();
            let rib = &manager.ribs[&peer];
            let count = match family.1 {
                Safi::Unicast => rib.len(),
                Safi::MplsVpn => rib.vpn_len(),
                Safi::LabeledUnicast => rib.labeled_len(),
                _ => unreachable!(),
            };
            if session_id != 3 {
                eprintln!(
                    "LLGR_CYCLE {family:?} cycles={session_id} paths={count} insert_us={insert_us}"
                );
            }
            assert_eq!(
                count,
                usize::try_from(session_id).unwrap() * PATHS_PER_SESSION as usize
            );
            manager.handle_update(RibUpdate::PeerGracefulRestart {
                peer,
                session_id,
                restart_time: 1,
                stale_routes_time: 1,
                gr_families: vec![family],
                peer_llgr_capable: true,
                peer_llgr_families: llgr_families.clone(),
                llgr_stale_time: 3600,
            });
            tokio::time::advance(Duration::from_secs(2)).await;
            manager.sweep_gr_stale(peer);
            let deadline = manager.llgr_stale_deadlines[&(peer, family.0, family.1)];
            assert_eq!(*original_deadline.get_or_insert(deadline), deadline);
        }
        let deadline = original_deadline.unwrap();
        tokio::time::advance(deadline - tokio::time::Instant::now()).await;
        manager.sweep_expired_llgr_stale(deadline);
        assert!(
            manager
                .ribs
                .get(&peer)
                .is_none_or(|rib| { rib.len() + rib.vpn_len() + rib.labeled_len() == 0 })
        );
        assert!(
            !manager
                .llgr_stale_deadlines
                .contains_key(&(peer, family.0, family.1))
        );
    }
}
