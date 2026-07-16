use super::*;

/// Regression: EVPN routes learned from a peer that goes down must be
/// withdrawn from remaining peers. Before this fix, `handle_peer_down` removed
/// the dead peer's Adj-RIB-In but never called `recompute_and_distribute_evpn`,
/// leaving the Loc-RIB advertising stale MAC/IP reachability.
#[tokio::test]
async fn peer_down_withdraws_evpn_routes_from_remaining_peers() {
    let (tx, rx) = mpsc::channel(64);
    // Cluster-ID is required for iBGP→iBGP reflection (RFC 4456); without it,
    // should_suppress_ibgp_inner falls back to standard split-horizon.
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Register target as RR client for L2VPN/EVPN (iBGP, same AS).
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Register source as an RR client too — the RibManager needs an outbound
    // entry for the source or it skips reflection evaluation entirely; the
    // source's own announces will round-trip to itself but split-horizon
    // suppresses them at the stage step.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // Source advertises a Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target receives the reflected EVPN announce.
    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);
    assert_eq!(announce.evpn_announce[0].key(), imet_key);
    assert!(
        announce.evpn_withdraw.is_empty(),
        "announce phase should have no withdrawals"
    );

    // Source goes down.
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Target should receive a withdrawal for that EVPN key.
    let withdraw = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN withdrawal within 2s")
        .expect("outbound channel still open");
    assert!(
        withdraw.evpn_announce.is_empty(),
        "peer-down should not produce announces"
    );
    assert_eq!(
        withdraw.evpn_withdraw,
        vec![imet_key],
        "target must see the withdrawal for the dead peer's EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: an RR must not reflect an EVPN route back to the peer
/// that originated it (source-peer split horizon). Prior to the fix the
/// distribution path went `loc_rib.get_evpn()` → RR suppression check →
/// stage for all peers including the source. FRR dropped the
/// self-reflection via `ORIGINATOR_ID`, but RFC 4456 hygiene says we
/// shouldn't emit it in the first place.
#[tokio::test]
async fn evpn_is_not_reflected_back_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Source is an RR client.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // A second RR client so reflection has somewhere to go.
    let (other_out_tx, mut other_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: other,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: other_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut other_out_rx).await;

    // Source advertises a Type 3 IMET.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // The "other" client must receive a reflected announce.
    let other_announce = tokio::time::timeout(Duration::from_secs(2), other_out_rx.recv())
        .await
        .expect("other peer should receive reflection within 2s")
        .expect("outbound channel still open");
    assert_eq!(other_announce.evpn_announce.len(), 1);
    assert_eq!(other_announce.evpn_announce[0].key(), imet_key);

    // The source must NOT receive its own route back. A short wait is
    // enough — if the bug exists, the bad announce fires on the same
    // distribute_changes as the reflection to "other".
    match tokio::time::timeout(Duration::from_millis(300), source_out_rx.recv()).await {
        Err(_) => {
            // Timeout — correct behavior. Source saw nothing.
        }
        Ok(Some(msg)) => {
            assert!(
                msg.evpn_announce.is_empty(),
                "source peer must not receive its own EVPN route back (got {:?})",
                msg.evpn_announce,
            );
        }
        Ok(None) => panic!("source outbound channel closed unexpectedly"),
    }

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when an EVPN update fails to send (outbound channel full),
/// the peer is marked dirty; a later `distribute_changes` must resync EVPN
/// routes, not only unicast / `FlowSpec`. Before this fix, dirty resync
/// rebuilt unicast prefixes + `FlowSpec` rules but never gathered EVPN keys
/// or staged EVPN routes, so EVPN deltas could be silently dropped.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "full channel-full → dirty-resync flow in one scenario"
)]
async fn dirty_resync_includes_evpn_routes_after_channel_full() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Target's outbound channel is size 1 — after the EoR, one more slot.
    // We'll fill it, then the EVPN announce will fail and mark target dirty.
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Source as RR client so reflection isn't suppressed.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // Fill the target's outbound channel by NOT draining — send two EVPN
    // announces in a row. The first lands in the channel (queue size 1);
    // the second fails `try_send` and marks target dirty.
    let imet1 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet1_key = imet1.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet1],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Give the RibManager a tick to process and fill the channel.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second EVPN route arrives; target's channel is full → target goes dirty.
    let imet2 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let imet2_key = imet2.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet2],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the first queued update to make room, then drain anything the
    // resync timer delivers.
    let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("first EVPN announce must arrive")
        .expect("channel open");
    assert_eq!(first.evpn_announce.len(), 1);
    assert_eq!(first.evpn_announce[0].key(), imet1_key);

    // Collect EVPN announces until we see imet2_key — the dirty-resync path
    // must eventually deliver it. Time out after 10s (resync timer is faster).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_imet2 = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await {
            Ok(Some(update)) => {
                if update.evpn_announce.iter().any(|r| r.key() == imet2_key) {
                    saw_imet2 = true;
                    break;
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_imet2,
        "dirty resync must eventually deliver the second EVPN announce (imet2) to the target peer"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route should remain in Loc-RIB");
    assert!(best[0].is_stale, "EVPN route should be marked stale");
    assert!(!best[0].is_llgr_stale);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let dropped = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept.clone(), dropped],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 2);
    assert!(best.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    // RFC 4724 §4.1: an EVPN route still marked stale at End-of-RIB was
    // not re-advertised during the restart window and must be removed;
    // the re-advertised route survives with its stale flag cleared.
    let best = query_evpn_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised stale EVPN route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].key(), kept_key);
    assert!(!best[0].is_stale, "EoR should clear stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while EVPN routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn evpn_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_evpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_evpn_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR without LLGR — stale routes should be purged on timer expiry.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "GR timer expiry must sweep stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 7200,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Advance past GR timer — promotes to LLGR-stale
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route retained during LLGR");
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    // LLGR_STALE community injected locally
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted EVPN route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let dropped = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept.clone(), dropped],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 2);
    assert!(best.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_llgr_stale));
    assert!(best.iter().all(|r| {
        r.communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    }));

    // Only `kept` is re-advertised before End-of-RIB. EoR during the LLGR
    // phase removes what was not re-advertised (RFC 4724 §4.1 via RFC 9494
    // §4.2) and clears is_llgr_stale + strips the locally-injected
    // LLGR_STALE community on the retained route.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised LLGR-stale EVPN route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].key(), kept_key);
    assert!(!best[0].is_llgr_stale, "LLGR-stale flag must be cleared");
    assert!(
        !best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "locally-injected LLGR_STALE community must be stripped"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_no_llgr_community_drops_route_on_promotion() {
    use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};

    tokio::time::pause();

    // Build an EVPN route carrying COMMUNITY_NO_LLGR so it must be dropped
    // when the GR timer expires rather than promoted to LLGR-stale.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = EvpnRoute::Imet(EvpnImet {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        ethernet_tag: EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    });
    let imet = EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        link_local_next_hop: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        attributes: Arc::new(vec![PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_NO_LLGR,
        ])]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        is_stale: false,
        is_llgr_stale: false,
    };
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past GR timer — NO_LLGR route must be removed, not promoted.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "NO_LLGR EVPN route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Typed-family LLGR two-phase lifecycle (RFC 9494): VPN, BGP-LS, RTC ---

/// Gate 6: controller-driven EVPN injection. `InjectEvpn` places a
/// `RouteOrigin::Local` EVPN route into the RR's Loc-RIB and reflects
/// it to peers negotiating L2VPN/EVPN — same shape as `InjectFlowSpec`.
#[tokio::test]
async fn inject_evpn_reflects_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Construct an EVPN Type 3 IMET anchored on a synthetic local
    // originator (0.0.0.0, matches LOCAL_PEER in the manager).
    let mut imet = make_evpn_imet(Ipv4Addr::UNSPECIFIED, 100);
    imet.origin_type = crate::route::RouteOrigin::Local;
    let injected_key = imet.key();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectEvpn {
        route: imet,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("inject reply")
        .expect("inject must succeed");

    // Peer must see the reflected local route as an announce.
    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive the injected route within 2s")
        .expect("outbound channel open");
    assert_eq!(msg.evpn_announce.len(), 1);
    assert_eq!(msg.evpn_announce[0].key(), injected_key);

    // Withdraw through the same channel; peer must see the retraction.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: injected_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("withdraw reply")
        .expect("withdraw must succeed");

    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive withdraw within 2s")
        .expect("outbound channel open");
    assert!(msg.evpn_announce.is_empty());
    assert_eq!(msg.evpn_withdraw, vec![injected_key]);

    drop(tx);
    handle.await.unwrap();
}

/// Withdrawing an unknown EVPN key surfaces a user-visible error
/// (controller got a bad route identifier).
#[tokio::test]
async fn withdraw_evpn_unknown_key_returns_error() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let fake_key = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 999).key();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: fake_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.expect("withdraw reply");
    assert!(result.is_err(), "unknown key must return an error");

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a peer that joins AFTER the EVPN Loc-RIB has been
/// populated must receive the existing routes in its initial dump.
/// Prior to the fix, `send_initial_table` never called
/// `stage_evpn_routes` and hardcoded `evpn_announce: vec![]`, so a
/// late-joining VTEP saw an EVPN End-of-RIB with zero routes and
/// cleared any stale state — operating with no EVPN reachability for
/// the existing fabric until unrelated RIB churn forced redistribution.
/// The M30-M33 harnesses miss this because they bring up peers before
/// any EVPN advertisements; production VTEPs reconnect into a
/// converged fabric all the time.
#[tokio::test]
async fn late_joining_peer_receives_existing_evpn_routes_in_initial_dump() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let early = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (early_out_tx, mut early_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: early,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: early_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut early_out_rx).await;

    // Early peer advertises a Type 3 IMET — this populates the RR's
    // EVPN Loc-RIB before the late peer connects.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: early,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain side-effects so the early peer's reflection (if any) is
    // processed before we register the late peer.
    let _ = query_evpn_routes(&tx).await;

    // Now a late-joining peer connects to the same RR.
    let late = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (late_out_tx, mut late_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: late,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: late_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // First message to the late peer must be the initial dump carrying
    // the existing EVPN route. Without the fix this is just an empty
    // EoR and the route is silently absent.
    let msg = tokio::time::timeout(Duration::from_secs(2), late_out_rx.recv())
        .await
        .expect("late peer should receive an outbound update within 2s")
        .expect("outbound channel open");

    assert_eq!(
        msg.evpn_announce.len(),
        1,
        "late-joining peer must see the existing EVPN route in initial dump"
    );
    assert_eq!(msg.evpn_announce[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: RFC 7313 Enhanced Route Refresh on the L2VPN/EVPN family
/// must remove re-advertised keys from the per-peer stale set, otherwise
/// `EoRR` sweeps every reflected EVPN route off the RIB. The unicast and
/// `FlowSpec` chunks already do this; the EVPN chunks were missing the
/// hook entirely.
#[tokio::test]
async fn enhanced_route_refresh_evpn_replacement_preserves_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Stage 1: peer advertises one EVPN Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet.clone()],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stage 2: peer initiates ERR for L2VPN/EVPN. The manager snapshots
    // imet_key into refresh_stale_evpn[peer] at this point.
    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    // Quiesce the manager so the BoRR snapshot lands before the
    // re-advertisement races it.
    let _drain = query_evpn_routes(&tx).await;

    // Stage 3: peer re-advertises the same key — must remove it from
    // the stale set. Without the fix this is a no-op on the stale set.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stage 4: peer ends the refresh window. EoRR sweeps anything left
    // in the stale set; with the fix that set is empty, so the route
    // survives. Without the fix, the route gets withdrawn here.
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "refreshed EVPN route must survive EoRR");
    assert_eq!(best[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: EVPN export-policy `RouteModifications` (community add,
/// `LocalPref` override, etc.) must be applied to the announced route.
/// Before the fix, `evaluate_chain`'s result was checked for Permit/Deny
/// but `result.modifications` was discarded, so RT/community/`LocalPref`
/// rewrite policy silently had no effect on EVPN exports.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "EVPN export-policy regression keeps route setup and modification assertions together"
)]
async fn evpn_export_policy_applies_modifications() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    // Permit-all with a community-add side effect.
    let added_community: u32 = (65000u32 << 16) | 0x3E7;
    let mut mods = RouteModifications::default();
    mods.communities_add.push(added_community);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: mods,
        }],
        default_action: PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        cluster_id,
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);

    let attrs = announce.evpn_announce[0].attributes.as_ref();
    let comms_attr = attrs
        .iter()
        .find_map(|a| {
            if let PathAttribute::Communities(c) = a {
                Some(c)
            } else {
                None
            }
        })
        .expect("export policy must add Communities attribute when modifications include communities_add");
    assert!(
        comms_attr.contains(&added_community),
        "added community {added_community:#x} must appear on the reflected EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: `PendingRoutesReceived::has_more()` previously omitted
/// the EVPN iterators, so a `RoutesReceived` carrying more than
/// `ROUTES_RECEIVED_CHUNK_SIZE` EVPN routes had everything past the
/// first chunk silently dropped at distribution.rs's `if has_more()
/// push_front` re-enqueue site. This test drains a 2-chunk-sized batch
/// of EVPN announces and verifies every route appears in the chunk
/// stream.
#[test]
fn pending_routes_received_drains_full_evpn_announce_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE * 2 + 7;
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let evpn_announced: Vec<EvpnRibRoute> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag))
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        evpn_announced,
        vec![],
    );

    let mut drained: usize = 0;
    let mut last_was_evpn = false;
    while let Some(chunk) = pending.next_chunk() {
        match chunk {
            PendingRouteChunk::EvpnAnnounced(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            PendingRouteChunk::EvpnWithdrawn(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            _ => last_was_evpn = false,
        }
    }
    assert!(last_was_evpn, "final chunk must be EVPN");
    assert_eq!(
        drained, total,
        "every EVPN route must be drained; has_more() must keep the batch alive"
    );
    assert!(
        !pending.has_more(),
        "after full drain, has_more() must report false"
    );
}

/// Regression: same drain check for EVPN withdrawals, since they also
/// flow through the `evpn_withdrawn` iterator and `has_more()`.
#[test]
fn pending_routes_received_drains_full_evpn_withdraw_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE + 1;
    let peer = Ipv4Addr::new(192, 0, 2, 2);
    let withdrawn: Vec<rustbgpd_wire::EvpnRouteKey> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag).key())
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        withdrawn,
    );

    let mut drained: usize = 0;
    while let Some(chunk) = pending.next_chunk() {
        if let PendingRouteChunk::EvpnWithdrawn(keys) = chunk {
            drained += keys.len();
        }
    }
    assert_eq!(drained, total);
    assert!(!pending.has_more());
}

// --- EVPN route event streaming tests (Gate 7c) ---

/// Build a Type 2 (`MacIp`) `EvpnRibRoute` carrying an optional MAC
/// Mobility extended community. Tests use this to simulate received
/// routes with varying mobility sequences.
fn make_evpn_macip(
    peer: Ipv4Addr,
    mac: [u8; 6],
    mobility_seq: Option<u32>,
    sticky: bool,
) -> EvpnRibRoute {
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress::new(mac),
        ip: None,
        label1: MplsLabel::new(100),
        label2: None,
    });

    let mut attrs: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(peer),
    ];
    if let Some(seq) = mobility_seq {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::mac_mobility(sticky, seq),
        ]));
    }

    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(attrs),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

async fn subscribe_evpn_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<crate::event::EvpnRouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_evpn_event_history(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Option<IpAddr>,
    route_type: Option<u8>,
    rd: Option<RouteDistinguisher>,
    event_types: BTreeSet<RouteEventType>,
    limit: usize,
) -> Vec<crate::event::EvpnRouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRouteEventHistory {
        peer,
        route_type,
        rd,
        event_types,
        limit,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

#[tokio::test]
async fn evpn_route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_evpn_events(&tx).await;

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.key, key);
    assert_eq!(event.peer, Some(peer));
    assert!(event.previous_peer.is_none());
    assert!(event.best.is_some(), "Added must carry a best path");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x77],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::Added);
    assert_eq!(history[0].key, key);
    assert_eq!(history[0].peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_filters_peer_rd_type_and_limit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02];
    let peer1_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer2_addr = Ipv4Addr::new(10, 0, 0, 2);
    let peer1 = IpAddr::V4(peer1_addr);
    let peer2 = IpAddr::V4(peer2_addr);
    let route1 = make_evpn_macip(peer1_addr, mac, Some(0), false);
    let rd = crate::event::evpn_key_rd(&route1.key());

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route1],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(peer2_addr, mac, Some(1), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut event_types = BTreeSet::new();
    event_types.insert(RouteEventType::BestChanged);
    let history =
        query_evpn_event_history(&tx, Some(peer1), Some(2), Some(rd), event_types, 1).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::BestChanged);
    assert_eq!(history[0].peer, Some(peer2));
    assert_eq!(history[0].previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_capacity_evicts_oldest_event() {
    let (tx, rx) = mpsc::channel(256);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    for index in 0..=EVPN_ROUTE_EVENT_HISTORY_CAPACITY {
        let index_bytes = u32::try_from(index)
            .expect("test history capacity fits in u32")
            .to_be_bytes();
        let mac = [
            0x02,
            0x00,
            0x00,
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ];
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![make_evpn_macip(peer_addr, mac, Some(0), false)],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 0).await;
    assert_eq!(history.len(), EVPN_ROUTE_EVENT_HISTORY_CAPACITY);
    assert_eq!(history[0].key.route_type(), 2);
    let rustbgpd_wire::EvpnRouteKey::MacIp { mac: first_mac, .. } = history[0].key else {
        panic!("expected Type 2 key");
    };
    assert_eq!(first_mac.octets(), [0x02, 0x00, 0x00, 0, 0, 1]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_best_changed_on_higher_mobility() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
    let original_peer = Ipv4Addr::new(10, 0, 0, 1);
    let new_peer = Ipv4Addr::new(10, 0, 0, 2);

    // First peer originates with seq=0.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(original_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(original_peer, mac, Some(0), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Subscribe after the initial Added event so the next event we
    // observe is the contended best-path move.
    let mut events_rx = subscribe_evpn_events(&tx).await;

    // Second peer originates the same MAC with a higher mobility seq.
    // Best-path tiebreak (RFC 7432 §15.1) prefers the higher seq.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(new_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(new_peer, mac, Some(1), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(IpAddr::V4(new_peer)));
    assert_eq!(event.previous_peer, Some(IpAddr::V4(original_peer)));
    let best = event.best.expect("BestChanged must carry a best path");
    assert_eq!(best.peer, IpAddr::V4(new_peer));
    let prior = event
        .previous_best
        .expect("BestChanged must carry the prior best path");
    assert_eq!(prior.peer, IpAddr::V4(original_peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 3);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
        Some(0),
        false,
    );
    let key = route.key();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_evpn_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![key],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
    assert_eq!(event.key, key);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer));
    assert!(event.best.is_none(), "Withdrawn must not carry a best");
    let prior = event
        .previous_best
        .expect("Withdrawn must carry the prior best so consumers recover VNI");
    assert_eq!(prior.peer, peer);

    drop(tx);
    handle.await.unwrap();
}

// --- FIB install-candidate view (multipath/ECMP) ---
