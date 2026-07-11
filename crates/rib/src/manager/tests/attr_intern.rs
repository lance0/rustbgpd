use super::*;

#[test]
fn evpn_withdraw_gcs_attr_intern_under_mac_mobility() {
    // Regression: RFC 7432 §7.7 MAC Mobility re-advertises the SAME EVPN route
    // key with a fresh attribute set on every move (the sequence number carried
    // in the MAC Mobility extended community increments each time). `insert_evpn`
    // interns each distinct attribute set, so the EVPN withdraw paths MUST GC the
    // intern table — otherwise every move permanently orphans one interned set
    // and the table grows unbounded under sustained mobility (observed as a
    // ~258 MB/h RSS leak on every node, RR included, in the M67 link-drain soak).
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    // Churn well past the bounded event-history ring so an unbounded intern
    // table is unmistakable: pre-fix this grows one orphaned interned set per
    // move (→ `moves` sets); post-fix the withdraw GC reclaims every set not
    // still referenced by the ring, so it plateaus at/below the ring capacity.
    let moves = u32::try_from(EVPN_ROUTE_EVENT_HISTORY_CAPACITY).unwrap() + 2000;
    for seq in 0..moves {
        // Same key, distinct attribute set per "move" — `Med(seq)` stands in
        // for the incrementing MAC Mobility sequence so each set interns anew.
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let key = route.key();
        manager.process_evpn_announce_chunk(peer, vec![route]);
        manager.process_evpn_withdraw_chunk(peer, vec![key]);
    }

    let intern = manager.attr_intern.len();
    assert!(
        intern <= EVPN_ROUTE_EVENT_HISTORY_CAPACITY,
        "EVPN attribute intern table grew unbounded under MAC-mobility churn: \
         {intern} interned sets after {moves} moves (must stay bounded by the \
         {EVPN_ROUTE_EVENT_HISTORY_CAPACITY}-entry event-history ring)"
    );
    assert_eq!(
        manager.ribs[&peer].evpn_len(),
        0,
        "every churned route was withdrawn from the Adj-RIB-In"
    );
}

#[test]
fn evpn_announce_replace_reclaims_attr_intern() {
    // The dominant M67 leak path: MAC Mobility re-advertises the SAME key with
    // a fresh attribute set on every move *without* an intervening withdraw
    // (the route is replaced in place, e.g. by originator re-injection). The
    // announce path must reclaim the stranded interned set or steady-state
    // re-advertise churn leaks unbounded.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let moves = u32::try_from(EVPN_ROUTE_EVENT_HISTORY_CAPACITY).unwrap() + 2000;
    for seq in 0..moves {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        manager.process_evpn_announce_chunk(peer, vec![route]);
    }

    let intern = manager.attr_intern.len();
    // Bounded by the event-history ring plus the single live route and the
    // in-flight event (~ring + 2); pre-fix this grew to `moves` (6096).
    let bound = EVPN_ROUTE_EVENT_HISTORY_CAPACITY + 16;
    assert!(
        intern <= bound,
        "EVPN re-advertise (replace, no withdraw) churn leaked the intern table: \
         {intern} interned sets after {moves} replaces (must stay bounded near the \
         {EVPN_ROUTE_EVENT_HISTORY_CAPACITY}-entry event-history ring, <= {bound})"
    );
    assert_eq!(
        manager.ribs[&peer].evpn_len(),
        1,
        "the same key collapses to a single live route"
    );
}

#[test]
fn handle_withdraw_evpn_gcs_attr_intern_for_injected_routes() {
    // Companion to the above for the locally-injected origination path
    // (`RibUpdate::WithdrawEvpn` -> `handle_withdraw_evpn`): re-originating a
    // MAC route on every mobility move churns a fresh interned set in the
    // LOCAL_PEER Adj-RIB-In, which must be GC'd on withdraw.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    for seq in 0..64u32 {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let key = route.key();
        manager.attr_intern.intern(&mut route.attributes);
        manager
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER))
            .insert_evpn(route);
        let (reply_tx, _reply_rx) = oneshot::channel();
        manager.handle_withdraw_evpn(key, reply_tx);
    }

    let intern = manager.attr_intern.len();
    assert!(
        intern <= 1,
        "injected EVPN re-origination leaked the intern table: {intern} sets (expected <= 1)"
    );
}

#[test]
fn unicast_withdraw_reclaims_selected_attr_intern_after_loc_rib_recompute() {
    // Pure withdraw of the current best path must GC after Loc-RIB recompute:
    // before that recompute, the selected-route Arc keeps the withdrawn
    // attribute set alive and a pre-recompute GC cannot reclaim it.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.attr_intern.len(), 1);

    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    assert_eq!(
        manager.ribs[&peer].len(),
        0,
        "withdraw batch must remove the route from Adj-RIB-In"
    );
    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "withdraw recompute must remove the selected Loc-RIB clone"
    );
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "post-recompute GC must reclaim the withdrawn route's interned attributes"
    );
}

#[test]
fn unicast_inject_replace_reclaims_attr_intern_after_loc_rib_recompute() {
    // The local injection path can replace the same prefix repeatedly without
    // an intervening withdraw. GC must run after recompute drops the selected
    // Loc-RIB clone of the previous local route; otherwise the final replaced
    // attribute set survives until one more unrelated GC event.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let moves = 5000u32;
    for seq in 0..moves {
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let (reply_tx, _reply_rx) = oneshot::channel();
        manager.handle_inject_route(route, reply_tx);
    }

    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        manager.attr_intern.len(),
        1,
        "injected unicast re-originations must leave only the live route's interned attrs"
    );
}

#[test]
fn unicast_withdraw_injected_reclaims_attr_intern_after_loc_rib_recompute() {
    // Withdrawing the selected local route must GC after recompute, because
    // the Loc-RIB clone keeps its interned attribute set alive during the
    // Adj-RIB-In removal itself.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    let (reply_tx, _reply_rx) = oneshot::channel();
    manager.handle_inject_route(route, reply_tx);
    assert_eq!(manager.attr_intern.len(), 1);

    let (reply_tx, _reply_rx) = oneshot::channel();
    manager.handle_withdraw_injected(Prefix::V4(prefix), 0, reply_tx);

    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "withdrawing the injected route must recompute it out of the Loc-RIB"
    );
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "withdraw-injected must reclaim the selected route's interned attrs"
    );
}

#[test]
fn llgr_eor_reclaims_stale_clear_attr_intern_after_loc_rib_recompute() {
    // LLGR promotion injects a local LLGR_STALE community through COW while
    // the Loc-RIB still holds the selected pre-promotion Arc. EoR later strips
    // that local community through another COW. The EoR path must GC after the
    // Loc-RIB recompute drops the stale selected-route clone, otherwise the old
    // interned set survives until an unrelated future GC event.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.attr_intern.len(), 1);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    });
    manager.sweep_gr_stale(peer);
    assert!(
        manager
            .ribs
            .get(&peer)
            .and_then(|rib| rib.iter().next())
            .is_some_and(|route| route.is_llgr_stale),
        "GR expiry should promote the retained route into LLGR stale state"
    );
    assert_eq!(
        manager.attr_intern.len(),
        1,
        "GR expiry must replace the pre-promotion set with one canonical live LLGR set"
    );

    // Re-advertise the route during the LLGR window: RFC 4724 §4.1 (via
    // RFC 9494 §4.2) removes any route still LLGR-stale at End-of-RIB, so
    // only a re-advertised route exercises the retained-route stale-clear
    // path this test pins.
    let mut readvertised = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    readvertised.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![readvertised]);

    manager.handle_update(RibUpdate::EndOfRib {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });

    assert!(
        manager
            .ribs
            .get(&peer)
            .and_then(|rib| rib.iter().next())
            .is_some_and(|route| !route.is_llgr_stale),
        "End-of-RIB should clear LLGR stale on the retained route"
    );
    assert_eq!(
        manager.attr_intern.len(),
        1,
        "only the re-advertised route's live interned set survives EoR — the \
         orphaned pre-promotion set stays reclaimed"
    );
}

#[test]
fn llgr_promotion_preserves_global_attribute_sharing() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefixes = [
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
    ];
    let routes = prefixes
        .into_iter()
        .map(|prefix| {
            let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
            route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
            route
        })
        .collect();
    manager.process_announce_chunk(peer, routes);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    });
    manager.sweep_gr_stale(peer);

    let rib = &manager.ribs[&peer];
    let first = rib
        .iter_prefix(&Prefix::V4(prefixes[0]))
        .next()
        .expect("first promoted route");
    let second = rib
        .iter_prefix(&Prefix::V4(prefixes[1]))
        .next()
        .expect("second promoted route");
    assert!(first.is_llgr_stale && second.is_llgr_stale);
    assert!(
        Arc::ptr_eq(&first.attributes, &second.attributes),
        "identical LLGR_STALE transformations must remain globally interned"
    );
}

#[test]
fn gr_expiry_reclaims_stale_attr_intern_after_loc_rib_recompute() {
    // Plain GR expiry removes the route from Adj-RIB-In while the selected
    // Loc-RIB clone still holds the interned attribute Arc. The second GC must
    // run after recompute drops that clone; otherwise one set survives per
    // expired selected route.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.attr_intern.len(), 1);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(peer, outbound_tx);
    manager.sweep_gr_stale(peer);

    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "GR expiry should remove the stale route from the Loc-RIB"
    );
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "GR expiry must reclaim the selected route's interned attrs after recompute"
    );
}

#[test]
fn unicast_announce_replace_reclaims_attr_intern() {
    // Unicast analogue of `evpn_announce_replace_reclaims_attr_intern`: a peer
    // re-advertises the SAME prefix with a fresh attribute set on every update
    // (e.g. MED / AS-path oscillation) and never withdraws it. Each distinct
    // set interns, so the announce path must reclaim the set stranded by the
    // in-place replacement — otherwise steady-state re-advertise churn leaks
    // unbounded. The GC fires only when a replacement occurred, so the
    // all-new-keys initial-load flood pays nothing.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let moves = 5000u32;
    for seq in 0..moves {
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        manager.process_announce_chunk(peer, vec![route]);
    }

    let intern = manager.attr_intern.len();
    assert_eq!(
        intern, 1,
        "unicast re-advertise (replace, no withdraw) churn leaked the intern table: \
         {intern} interned sets after {moves} replaces (must collapse to the single \
         live route's set)"
    );
    assert_eq!(
        manager.ribs[&peer].len(),
        1,
        "the same prefix collapses to one live route"
    );
}

#[test]
fn bgpls_withdraw_reclaims_attr_intern_after_loc_rib_recompute() {
    // BGP-LS routes use the same per-peer attribute intern table as unicast
    // and EVPN. A pure withdraw must GC after the affected Loc-RIB key is
    // recomputed; otherwise the selected route clone keeps the withdrawn
    // attribute set alive during the sweep and leaves one orphan behind per
    // churn cycle.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let moves = 256u32;
    for seq in 0..moves {
        let route = make_bgpls_route(peer_addr, 24, seq);
        let key = route.key();
        manager.handle_bgpls_routes_received(peer, vec![route], vec![]);
        manager.handle_bgpls_routes_received(peer, vec![], vec![key]);
    }

    assert_eq!(
        manager.ribs[&peer].bgpls_len(),
        0,
        "every churned BGP-LS route was withdrawn from the Adj-RIB-In"
    );
    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        0,
        "every churned BGP-LS route was removed from the Loc-RIB"
    );
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "BGP-LS pure-withdraw churn leaked the intern table: {} interned sets after {moves} withdraws",
        manager.attr_intern.len()
    );
}

#[test]
fn bgpls_pure_add_records_global_attr_intern_size() {
    // Intern-size telemetry must move on growth, not only on later
    // replacement/withdraw GC. BGP-LS is representative of the RR-only
    // families handled in manager/mod.rs: insert_* returns "replaced", so a
    // first-time route add grows the intern table while `needs_intern_gc`
    // remains false.
    let (_tx, rx) = mpsc::channel(8);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let route = make_bgpls_route(peer_addr, 24, 100);
    manager.handle_bgpls_routes_received(peer, vec![route], vec![]);

    assert_eq!(
        manager.attr_intern.len(),
        1,
        "the pure add should grow the global intern table"
    );
    let gauge = gauge_metric_value(&metrics, "bgp_rib_attr_intern_global_size", &[]);
    assert!(
        (gauge - 1.0).abs() < f64::EPSILON,
        "pure-add growth must be visible in the exported global gauge"
    );
}

#[test]
fn graceful_restart_entry_gcs_attr_intern_after_family_prune() {
    // A GR-down that preserves some families keeps the peer Adj-RIB-In shell
    // alive. If EVPN is not preserved, that GR entry prunes EVPN routes through
    // a direct removal path; the associated interned attribute sets must be
    // reclaimed immediately rather than leaking until a future unrelated
    // withdraw happens to run GC for this peer.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let rib = manager
        .ribs
        .entry(peer)
        .or_insert_with(|| AdjRibIn::new(peer));

    for seq in 0..64u32 {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100 + seq);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        manager.attr_intern.intern(&mut route.attributes);
        rib.insert_evpn(route);
    }
    assert_eq!(manager.attr_intern.len(), 64);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 0,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    let rib = manager
        .ribs
        .get(&peer)
        .expect("GR-preserved peer shell should stay alive");
    assert_eq!(rib.evpn_len(), 0, "EVPN was not GR-preserved");
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "GR family pruning must reclaim EVPN attribute intern entries"
    );
}

#[test]
fn graceful_restart_entry_gcs_attr_intern_for_loc_rib_selected_bgpls() {
    // BGP-LS is never GR-preserved, so a GR-down withdraws all of a peer's
    // BGP-LS routes. Unlike the EVPN prune test above (which inserts directly
    // into the Adj-RIB-In), these routes are SELECTED into the Loc-RIB via the
    // receive path, so the Loc-RIB holds a second Arc clone of each interned
    // attribute set. GC must therefore run AFTER the GR-entry Loc-RIB recompute;
    // otherwise the gc that runs before it is a no-op for every selected route
    // (strong_count is still 2) and each GR cycle leaks one interned set per
    // BGP-LS route.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let count = 64u32;
    for seq in 0..count {
        // Distinct payload suffix => distinct key; distinct LOCAL_PREF =>
        // distinct interned attribute set, so each route is selected into the
        // Loc-RIB carrying its own Arc clone.
        let route = make_bgpls_route(peer_addr, u8::try_from(seq).unwrap(), 100 + seq);
        manager.handle_bgpls_routes_received(peer, vec![route], vec![]);
    }
    assert_eq!(manager.attr_intern.len(), count as usize);
    assert_eq!(manager.loc_rib.iter_bgpls().count(), count as usize);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 0,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    let rib = manager
        .ribs
        .get(&peer)
        .expect("GR-preserved peer shell should stay alive");
    assert_eq!(rib.bgpls_len(), 0, "BGP-LS is never GR-preserved");
    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        0,
        "GR entry withdraws BGP-LS from the Loc-RIB"
    );
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "GR entry must reclaim the interned attribute sets of the Loc-RIB-selected \
         BGP-LS routes it withdraws (gc must run after the Loc-RIB recompute)"
    );
}

#[test]
fn enhanced_route_refresh_bgpls_eorr_gcs_attr_intern_for_swept_route() {
    // An Enhanced Route Refresh that sweeps an omitted BGP-LS route at EoRR must
    // reclaim that route's interned attribute set. The swept route was selected
    // into the Loc-RIB, so the Loc-RIB held a second Arc clone; GC must run
    // AFTER finish_route_refresh's Loc-RIB recompute, not before it. The two
    // routes carry DISTINCT attributes so the swept route has its own interned
    // set (identical attributes would share one set kept alive by the survivor,
    // masking the leak).
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let survivor = make_bgpls_route(peer_addr, 21, 100);
    let omitted = make_bgpls_route(peer_addr, 22, 200);
    manager.handle_bgpls_routes_received(peer, vec![survivor.clone(), omitted], vec![]);
    assert_eq!(manager.attr_intern.len(), 2);

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    });
    // Reannounce only the survivor; the omitted route stays stale and is swept.
    manager.handle_bgpls_routes_received(peer, vec![survivor], vec![]);
    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    });

    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        1,
        "EoRR sweeps the omitted BGP-LS route, leaving only the survivor"
    );
    assert_eq!(
        manager.attr_intern.len(),
        1,
        "EoRR sweep must reclaim the swept route's interned attribute set \
         (gc must run after finish_route_refresh's Loc-RIB recompute)"
    );
}

#[test]
fn enhanced_route_refresh_vpn_eorr_gcs_attr_intern_for_swept_route() {
    // Same ordering hazard as the BGP-LS test above, for SAFI 128: the swept
    // VPN route was selected into the Loc-RIB, so its interned attribute set
    // has a second Arc clone until finish_route_refresh's Loc-RIB recompute
    // drops it. GC must run after that recompute. Distinct LOCAL_PREF values
    // give each route its own interned set so the leak can't be masked.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let survivor = make_vpn_rib_route(peer_addr, 21, 100, 100);
    let omitted = make_vpn_rib_route(peer_addr, 22, 100, 200);
    manager.handle_vpn_routes_received(peer, vec![survivor.clone(), omitted], vec![]);
    assert_eq!(manager.attr_intern.len(), 2);

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });
    // Reannounce only the survivor; the omitted route stays stale and is swept.
    manager.handle_vpn_routes_received(peer, vec![survivor], vec![]);
    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });

    assert_eq!(
        manager.loc_rib.iter_vpn().count(),
        1,
        "EoRR sweeps the omitted VPN route, leaving only the survivor"
    );
    assert_eq!(
        manager.attr_intern.len(),
        1,
        "EoRR sweep must reclaim the swept VPN route's interned attribute set \
         (gc must run after finish_route_refresh's Loc-RIB recompute)"
    );
}

#[test]
fn cross_peer_identical_attrs_share_one_global_intern_entry() {
    // The LAN-336 premise: two RR clients advertising the same route carry
    // byte-identical attribute sets (reflection preserves NEXT_HOP). The
    // global table must collapse both peers' allocations to ONE entry, and
    // both stored routes must share that allocation (Arc pointer equality
    // across Adj-RIB-Ins — per-peer tables could never produce this).
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    manager.ribs.insert(peer1, AdjRibIn::new(peer1));
    manager.ribs.insert(peer2, AdjRibIn::new(peer2));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![PathAttribute::Med(100), PathAttribute::LocalPref(200)];

    let mut r1 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    r1.attributes = Arc::new(attrs.clone());
    let mut r2 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 2));
    r2.attributes = Arc::new(attrs);
    assert!(!Arc::ptr_eq(&r1.attributes, &r2.attributes));

    manager.process_announce_chunk(peer1, vec![r1]);
    manager.process_announce_chunk(peer2, vec![r2]);

    assert_eq!(
        manager.attr_intern.len(),
        1,
        "identical attribute sets from two peers must intern to one entry"
    );
    let a1 = &manager.ribs[&peer1]
        .get(&Prefix::V4(prefix), 0)
        .unwrap()
        .attributes;
    let a2 = &manager.ribs[&peer2]
        .get(&Prefix::V4(prefix), 0)
        .unwrap()
        .attributes;
    assert!(
        Arc::ptr_eq(a1, a2),
        "both peers' stored routes must share one allocation"
    );
    // Referenced by: intern table + peer1 route + peer2 route + the
    // Loc-RIB selected clone. The point: >= 3 proves cross-peer sharing.
    assert!(Arc::strong_count(a1) >= 3);
}

#[test]
fn cross_peer_churn_keeps_global_intern_table_flat_and_teardown_reclaims() {
    // Reclaim proof for the global table (same discipline as the slab
    // slot-reuse test): steady-state replace churn across two peers must
    // hold the table at exactly one entry per live attribute set — a table
    // that only grows is a soak-killer. Afterwards, tearing down one peer
    // keeps the shared entries alive (the other peer still references
    // them); tearing down the last peer drops the table to zero.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    manager.ribs.insert(peer1, AdjRibIn::new(peer1));
    manager.ribs.insert(peer2, AdjRibIn::new(peer2));

    let n = 64u8;
    let cycles = 10u32;
    for cycle in 0..cycles {
        for (peer, nh) in [
            (peer1, Ipv4Addr::new(10, 0, 0, 1)),
            (peer2, Ipv4Addr::new(10, 0, 0, 2)),
        ] {
            let routes: Vec<_> = (0..n)
                .map(|i| {
                    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, i, 0), 24);
                    let mut route = make_route(prefix, nh);
                    // Per-prefix-unique, cross-peer-identical, rotated
                    // every cycle so each cycle replaces every set.
                    route.attributes = Arc::new(vec![
                        PathAttribute::Med(u32::from(i)),
                        PathAttribute::LocalPref(cycle),
                    ]);
                    route
                })
                .collect();
            manager.process_announce_chunk(peer, routes);
        }
        assert_eq!(
            manager.attr_intern.len(),
            usize::from(n),
            "cycle {cycle}: one global entry per live attribute set — \
             replaced sets must be reclaimed, cross-peer duplicates merged"
        );
    }

    manager.handle_peer_deleted(peer2);
    assert_eq!(
        manager.attr_intern.len(),
        usize::from(n),
        "peer2 teardown must NOT reclaim sets peer1's routes still share"
    );
    manager.handle_peer_deleted(peer1);
    assert_eq!(
        manager.attr_intern.len(),
        0,
        "tearing down the last referencing peer must empty the table"
    );
}
