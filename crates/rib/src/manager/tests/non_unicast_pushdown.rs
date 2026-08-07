//! The non-unicast listing surfaces evaluate the caller's filter inside the
//! RIB task, so the actor copies only matching rows.
//!
//! Before this, every one of these queries cloned the whole family table onto
//! the single-threaded actor loop and let the API discard the remainder — no
//! updates, withdrawals, or best-path ran for the duration of that copy.

use super::*;
use crate::update::RibRowFilter;

/// Two peers' rows in every non-unicast family, in the Loc-RIB.
fn manager_with_two_peers_per_family() -> (RibManager, IpAddr, IpAddr) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let kept = Ipv4Addr::new(10, 0, 0, 1);
    let dropped = Ipv4Addr::new(10, 0, 0, 2);

    for (index, peer) in [kept, dropped].into_iter().enumerate() {
        let octet = u8::try_from(index).unwrap();
        let evpn = make_evpn_imet(peer, 100 + u32::from(octet));
        manager
            .loc_rib
            .recompute_evpn(evpn.key(), std::iter::once(&evpn));
        let bgpls = make_bgpls_route(peer, 0x40 + octet, 100);
        manager
            .loc_rib
            .recompute_bgpls(bgpls.key(), std::iter::once(&bgpls));
        let vpn = make_vpn_rib_route(peer, 40 + octet, 1040, 100);
        manager
            .loc_rib
            .recompute_vpn(vpn.nlri.key(), std::iter::once(&vpn));
        let labeled = make_labeled_rib_route(peer, 50 + octet, 1050, 100);
        manager
            .loc_rib
            .recompute_labeled(labeled.nlri.prefix, std::iter::once(&labeled));
        let rtc = make_rtc_rib_route(peer, 60 + u16::from(octet), 100);
        manager
            .loc_rib
            .recompute_rtc(rtc.key(), std::iter::once(&rtc));
    }

    // FlowSpec selection is keyed by rule, not by peer, so two peers on one
    // rule collapse to a single best. Give each peer its own family instead —
    // the filter under test is the address family.
    let v4 = make_flowspec_route(kept);
    manager
        .loc_rib
        .recompute_flowspec(v4.selection_key(), std::iter::once(&v4));
    let mut v6 = make_flowspec_route(dropped);
    v6.afi = Afi::Ipv6;
    manager
        .loc_rib
        .recompute_flowspec(v6.selection_key(), std::iter::once(&v6));

    (manager, IpAddr::V4(kept), IpAddr::V4(dropped))
}

fn by_peer<T: 'static>(peer: IpAddr, of: fn(&T) -> IpAddr) -> RibRowFilter<T> {
    Box::new(move |row: &T| of(row) == peer)
}

/// Every non-unicast surface hands its predicate to the actor, and the actor
/// returns only matching rows — the copy is the answer, not the table.
#[test]
fn filters_are_applied_inside_the_actor() {
    let (mut manager, kept, dropped) = manager_with_two_peers_per_family();

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnRoutes {
        filter: Some(by_peer(kept, |row: &crate::route::EvpnRibRoute| row.peer)),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(rows.len(), 1, "EVPN filter must run inside the actor");
    assert_eq!(rows[0].peer, kept);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBgpLsRoutes {
        filter: Some(by_peer(kept, |row: &BgpLsRibRoute| row.peer)),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(rows.len(), 1, "BGP-LS filter must run inside the actor");
    assert_eq!(rows[0].peer, kept);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryVpnRoutes {
        filter: Some(by_peer(kept, |row: &VpnRibRoute| row.peer)),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(rows.len(), 1, "VPN filter must run inside the actor");
    assert_eq!(rows[0].peer, kept);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLabeledRoutes {
        filter: Some(by_peer(kept, |row: &crate::route::LabeledRibRoute| {
            row.peer
        })),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(rows.len(), 1, "labeled filter must run inside the actor");
    assert_eq!(rows[0].peer, kept);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRtcRoutes {
        filter: Some(by_peer(kept, |row: &crate::route::RtcRibRoute| row.peer)),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(
        rows.len(),
        1,
        "RT-Constrain filter must run inside the actor"
    );
    assert_eq!(rows[0].peer, kept);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryFlowSpecRoutes {
        filter: Some(Box::new(|row: &FlowSpecRoute| row.afi == Afi::Ipv4)),
        reply,
    });
    let rows = rx.try_recv().expect("actor replies synchronously");
    assert_eq!(rows.len(), 1, "FlowSpec filter must run inside the actor");
    assert_eq!(rows[0].afi, Afi::Ipv4);

    assert_ne!(kept, dropped);
}

/// No filter still means the whole table: the caller asked for it.
#[test]
fn absent_filter_returns_every_row() {
    let (mut manager, _kept, _dropped) = manager_with_two_peers_per_family();

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnRoutes {
        filter: None,
        reply,
    });
    assert_eq!(rx.try_recv().unwrap().len(), 2);

    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryFlowSpecRoutes {
        filter: None,
        reply,
    });
    assert_eq!(rx.try_recv().unwrap().len(), 2);
}

/// An abandoned caller — a canceled RPC whose query was already queued behind
/// other actor work — must not be paid for at all. The predicate is never
/// invoked and nothing is cloned.
#[test]
fn canceled_listing_skips_the_scan() {
    let (mut manager, kept, _dropped) = manager_with_two_peers_per_family();
    let invoked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let counter = std::sync::Arc::clone(&invoked);
    let (reply, rx) = oneshot::channel();
    drop(rx);
    manager.handle_update(RibUpdate::QueryEvpnRoutes {
        filter: Some(Box::new(move |row: &crate::route::EvpnRibRoute| {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            row.peer == kept
        })),
        reply,
    });

    assert_eq!(
        invoked.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a dropped receiver must skip the scan entirely"
    );
}
