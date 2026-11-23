//! A private-EVPN receiver whose dirty resync runs inside an EVPN selection
//! hold, through the public events: an export-policy replacement into a
//! full channel, a withdrawal, the graceful-restart waiter's session, the
//! resync, the waiter's End-of-RIB. The resync enumerates no EVPN key (the
//! family is deferred); the withdrawal missed before the hold still reaches
//! the receiver after the release.

use std::collections::BTreeSet;

use super::*;
use crate::update::OutboundRouteUpdate;

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 4);
const RECEIVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn session(address: Ipv4Addr) -> u64 {
    u64::from(address.octets()[3])
}

/// An export chain of the receiver's own: it holds EVPN in its own
/// Adj-RIB-Out (private, no update group).
fn private_chain(denied_asn: u32) -> rustbgpd_policy::PolicyChain {
    let mut chain = deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
    let entry = &mut chain.policies[0].policy.entries[0];
    entry.prefix = None;
    entry.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![denied_asn],
        peer_groups: vec![],
    });
    rustbgpd_policy::PolicyChain::from_named(chain.policies)
}

fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    capacity: usize,
    waiter: bool,
    private: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    let export_policy = private.then(|| private_chain(65001));
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: session(address),
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { vec![EVPN] } else { vec![] },
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id: session(address),
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy,
        sendable_families: vec![EVPN],
        is_ebgp: false,
        route_reflector_client: true,
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

fn received(manager: &mut RibManager, announce: &[u32], withdraw: &[u32]) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: session(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: announce
            .iter()
            .map(|&tag| make_evpn_imet(SOURCE, tag))
            .collect(),
        evpn_withdrawn: withdraw
            .iter()
            .map(|&tag| make_evpn_imet(SOURCE, tag).key())
            .collect(),
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// The receiver's EVPN table as written to its session.
fn write(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    table: &mut BTreeSet<rustbgpd_wire::EvpnRouteKey>,
) {
    while let Ok(update) = rx.try_recv().map(delivered) {
        for key in &update.evpn_withdraw {
            assert!(table.remove(key), "withdrawal of an unheld {key:?}");
        }
        for route in update.evpn_announce.iter() {
            table.insert(route.key());
        }
    }
}

fn loc_rib_evpn(manager: &RibManager) -> BTreeSet<rustbgpd_wire::EvpnRouteKey> {
    manager
        .loc_rib
        .iter_evpn()
        .map(crate::route::EvpnRibRoute::key)
        .collect()
}

#[test]
fn a_withdrawal_missed_before_an_evpn_hold_reaches_a_private_receiver_after_release() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(192, 0, 2, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![EVPN],
        }],
    });
    let receiver = peer_v4(RECEIVER);
    let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
    // Two envelopes of room: a slow reader fills it with two passes.
    let mut out = connect(&mut manager, RECEIVER, 2, false, true);
    let mut table = BTreeSet::new();
    write(&mut out, &mut table);
    assert!(
        !manager.selection_deferred(EVPN),
        "dormant waiter: no hold yet"
    );

    // 1. The receiver holds X (tag 1) and Y (tag 2).
    received(&mut manager, &[1, 2], &[]);
    write(&mut out, &mut table);
    assert_eq!(table, loc_rib_evpn(&manager), "initial table");
    assert!(table.contains(&make_evpn_imet(SOURCE, 1).key()));
    assert!(
        manager.evpn_grouped_member_of(receiver).is_none(),
        "private EVPN"
    );
    assert!(!manager.has_private_evpn_handoff(receiver));

    // 2. Slow reader: two passes fill its channel. An operator export-policy
    //    replacement for the receiver makes it dirty (its resync cannot be
    //    admitted into the full channel), then X is withdrawn.
    received(&mut manager, &[10], &[]);
    received(&mut manager, &[11], &[]);
    assert!(manager.outbound_channel_full(receiver));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: receiver,
        export_policy: Some(private_chain(65002)),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    assert!(
        manager.dirty_peers.contains(&receiver),
        "the changed policy's retry is blocked by the full channel"
    );
    received(&mut manager, &[], &[1]);

    // 3. The configured GR waiter connects: the EVPN hold arms.
    let mut waiter_rx = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(EVPN), "EVPN hold armed");

    // 4. The reader drains; the dirty resync runs inside the hold.
    write(&mut out, &mut table);
    for _ in 0..64 {
        if !manager.dirty_peers.contains(&receiver) {
            break;
        }
        manager.resync_dirty_peers_bounded();
        write(&mut out, &mut table);
    }
    let x = make_evpn_imet(SOURCE, 1).key();

    // 5. The waiter's End-of-RIB releases the hold.
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: session(WAITER),
        afi: EVPN.0,
        safi: EVPN.1,
    });
    assert!(!manager.selection_deferred(EVPN), "released");
    write(&mut out, &mut table);
    for _ in 0..1000 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        write(&mut out, &mut table);
        while waiter_rx.try_recv().is_ok() {}
    }
    assert!(
        !table.contains(&x),
        "withdrawal lost: receiver still holds X"
    );
    assert_eq!(table, loc_rib_evpn(&manager), "receiver table == Loc-RIB");
}
