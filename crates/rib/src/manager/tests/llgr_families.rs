use super::*;

/// Bring up an iBGP route-reflector client negotiating `sendable`, for
/// observing typed-family re-exports.
async fn llgr_target_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    sendable: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: sendable,
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
    out_rx
}

/// GR-timer expiry with LLGR negotiated promotes GR-stale VPN routes to
/// LLGR-stale: flag flip, locally-injected `LLGR_STALE` community, and a
/// DEEPER tiebreak demotion — an LLGR-stale candidate loses to a GR-stale
/// one regardless of `LOCAL_PREF` (RFC 9494 §4.3).
#[tokio::test]
async fn vpn_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same key from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 3), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Past A's GR timer only: A is promoted to LLGR-stale and now ranks
    // BELOW B's GR-stale route despite the higher LOCAL_PREF.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    // Past B's GR timer too: both LLGR-stale, the LOCAL_PREF tiebreak
    // re-applies and the promoted route carries the injected community.
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted VPN route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same key from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 3), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted BGP-LS route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same NLRI from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 3), 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted RTC route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn vpn_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_vpn_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale VPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_bgpls_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale BGP-LS routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_rtc_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale RTC routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// `EoR` during the LLGR phase: re-advertised routes survive with the flag
/// cleared and the locally-injected `LLGR_STALE` community gone; a
/// peer-originated `LLGR_STALE` community is preserved; what was NOT
/// re-advertised is deleted and withdrawn downstream (RFC 4724 §4.1 via
/// RFC 9494 §4.2).
#[tokio::test]
async fn vpn_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, vpn_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let mut kept_tagged = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 62, 100, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 3);

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_vpn_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    // Only the two `kept` routes are re-advertised before End-of-RIB; the
    // tagged one still carries its peer-originated LLGR_STALE community.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_eor = query_vpn_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale VPN route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised VPN route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged VPN route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    // The EoR removal must be withdrawn downstream.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.vpn_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, bgpls_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x60, 100);
    let mut kept_tagged = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x61, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x62, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.bgpls_announce.len(), 3);

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_bgpls_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_eor = query_bgpls_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale BGP-LS route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised BGP-LS route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged BGP-LS route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.bgpls_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.bgpls_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // iBGP RR-client observer: an eBGP target without LLGR would now
    // suppress the pre-tagged route below (RFC 9494 §4.4 export gate,
    // pinned by its own tests); this test is about EoR clearing.
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, false, true).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let mut kept_tagged = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 101, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 102, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 3);

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert!(stale.iter().all(|r| r.nlri.is_default() || r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_rtc_routes(&tx).await;
    assert!(
        promoted
            .iter()
            .all(|r| r.nlri.is_default() || r.is_llgr_stale)
    );

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let after_eor = query_rtc_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale RTC route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised RTC route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged RTC route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.rtc_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.rtc_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.3: a route carrying `NO_LLGR` must not enter the LLGR phase —
/// it is removed at GR-timer expiry instead of being promoted.
#[tokio::test]
async fn vpn_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "NO_LLGR VPN route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "NO_LLGR BGP-LS route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "NO_LLGR RTC route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.3: a promoted LLGR-stale route re-exported to another iBGP
/// peer carries the `LLGR_STALE` community — it must not be removed on
/// re-advertisement.
#[tokio::test]
async fn vpn_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, vpn_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert!(
        !first.vpn_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed, then drain the
    // staged updates. The GR-entry restage may re-announce the still-plain
    // stale route first; the promotion restage must carry the community.
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.vpn_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale VPN route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, bgpls_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100);
    let key = route.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.bgpls_announce.len(), 1);
    assert!(
        !first.bgpls_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(query_bgpls_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed.
    assert!(query_bgpls_routes(&tx).await[0].is_llgr_stale);
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.bgpls_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale BGP-LS route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, false, true).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.rtc_announce.len(), 1);
    assert!(
        !first.rtc_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(
        query_rtc_routes(&tx)
            .await
            .iter()
            .any(|r| r.key() == key && r.is_stale)
    );
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed.
    assert!(
        query_rtc_routes(&tx)
            .await
            .iter()
            .any(|r| r.key() == key && r.is_llgr_stale)
    );
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.rtc_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale RTC route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose LLGR capability covers VPN but NOT BGP-LS splits at GR-timer
/// expiry: the VPN route is promoted to LLGR-stale, the BGP-LS route is
/// purged (RFC 9494 §4.3: only LLGR-negotiated families are retained).
#[tokio::test]
async fn llgr_families_split_promote_vs_purge_for_typed_families() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(gr_with_llgr(
        source,
        2,
        vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::BgpLs, Safi::BgpLs)],
        vec![(Afi::Ipv4, Safi::MplsVpn)],
        3600,
    ))
    .await
    .unwrap();
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    assert!(query_bgpls_routes(&tx).await[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let vpn = query_vpn_routes(&tx).await;
    assert_eq!(vpn.len(), 1, "LLGR-covered VPN route must be retained");
    assert!(vpn[0].is_llgr_stale);
    assert!(
        vpn[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "BGP-LS outside the LLGR capability must purge at GR expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

/// The LLGR-expiry sweep is where a down peer's GR/LLGR-preserved RT
/// interest finally dies: after the sweep, a re-established session's
/// initial dump must withhold VPN routes again (empty membership), whereas
/// during the retention window the preserved membership kept serving them.
#[tokio::test]
async fn rtc_llgr_sweep_drops_preserved_vpn_membership() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route_with_rts(
            Ipv4Addr::new(10, 0, 0, 1),
            60,
            vec![rt(100)],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;
    send_rtc_interest(&tx, target, &[100]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    // GR entry preserving RTC through both retention phases.
    tx.send(gr_with_llgr(
        IpAddr::V4(target),
        2,
        vec![(Afi::Ipv4, Safi::RtConstrain)],
        vec![(Afi::Ipv4, Safi::RtConstrain)],
        10,
    ))
    .await
    .unwrap();

    // Past the GR timer: the interest is promoted, not purged.
    // Force the manager to process PeerGracefulRestart before advancing time.
    let marked = query_rtc_routes(&tx).await;
    assert!(marked.iter().any(|r| !r.nlri.is_default() && r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let retained = query_rtc_routes(&tx).await;
    assert!(
        retained
            .iter()
            .any(|r| !r.nlri.is_default() && r.is_llgr_stale),
        "RT interest must survive the GR→LLGR promotion"
    );

    // Past the LLGR timer: the interest is swept and the membership dies.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    let after_sweep = query_rtc_routes(&tx).await;
    assert!(
        after_sweep.iter().all(|r| r.nlri.is_default()),
        "LLGR expiry must sweep the preserved RT interest"
    );

    // Re-establish: the strict dump helper asserts ZERO VPN routes — the
    // preserved membership is gone, so nothing may be served.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

/// LLGR-stale BGP-LS routes keep feeding the ORR topology (RFC 9107
/// vantages stay resolved) through BOTH retention phases; the LLGR-expiry
/// sweep is where the vantage finally unresolves.
#[tokio::test]
async fn bgpls_llgr_stale_topology_keeps_orr_vantages_resolved_until_llgr_sweep() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;
    let status = query_orr_status(&tx).await;
    assert!(status.vantages[0].resolved);
    assert_eq!(status.topology_nodes, 4);

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(
        IpAddr::V4(feed),
        2,
        family.clone(),
        family,
        10,
    ))
    .await
    .unwrap();
    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "GR-stale BGP-LS routes must keep feeding the topology"
    );

    // Past the GR timer: promotion to LLGR-stale keeps the routes in the
    // Adj-RIB-In, so the topology (and the vantage) must survive.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "LLGR-stale BGP-LS routes must keep feeding the topology"
    );
    assert_eq!(status.topology_nodes, 4);

    // Past the LLGR timer: the sweep empties the topology — NOW the
    // vantage unresolves.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    let status = query_orr_status(&tx).await;
    assert!(
        !status.vantages[0].resolved,
        "the LLGR expiry sweep must rebuild the cache against the emptied topology"
    );
    assert_eq!(status.topology_nodes, 0);

    drop(tx);
    handle.await.unwrap();
}

/// Announce a unicast route from `source`, then drive it GR-stale →
/// LLGR-stale (short GR timer + promotion), with query sync points.
async fn unicast_announce_and_promote_to_llgr(
    tx: &mpsc::Sender<RibUpdate>,
    source: IpAddr,
    prefix: Ipv4Prefix,
) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    // Sync: route present and fresh before GR.
    assert_eq!(query_best_routes(tx).await.len(), 1);

    let family = vec![(Afi::Ipv4, Safi::Unicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_best_routes(tx).await[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_best_routes(tx).await[0].is_llgr_stale);
}

/// RFC 9494 §4.4: an LLGR-stale route is withdrawn from (not announced
/// to) an eBGP peer that did not advertise the LLGR capability for the
/// family.
#[tokio::test]
async fn llgr_stale_suppressed_toward_ebgp_peer_without_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, ipv4_sendable(), true, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    unicast_announce_and_promote_to_llgr(&tx, source, prefix).await;

    let mut withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "LLGR-stale route must not be announced to a non-LLGR eBGP peer"
        );
        if update.withdraw.contains(&(Prefix::V4(prefix), 0)) {
            withdrawn = true;
        }
    }
    assert!(
        withdrawn,
        "previously advertised route must be withdrawn from the non-LLGR eBGP peer at promotion"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that DID advertise LLGR for the family keeps receiving the
/// stale route, community riding (RFC 9494 §4.3 — MUST NOT be removed).
#[tokio::test]
async fn llgr_stale_unchanged_toward_llgr_capable_peer() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        true,
        vec![(Afi::Ipv4, Safi::Unicast)],
        None,
    )
    .await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    unicast_announce_and_promote_to_llgr(&tx, source, prefix).await;

    let mut reannounced = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.withdraw.contains(&(Prefix::V4(prefix), 0)),
            "LLGR-stale route must not be withdrawn from an LLGR-capable peer"
        );
        if update.announce.iter().any(|route| {
            route.prefix == Prefix::V4(prefix)
                && route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        }) {
            reannounced = true;
        }
    }
    assert!(
        reannounced,
        "promotion must re-announce the route with LLGR_STALE to the LLGR-capable peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.6 intra-AS exception: toward a non-LLGR iBGP peer the
/// LLGR-stale route is still advertised at the RIB layer, community
/// intact — transport rewrites it to the `NO_EXPORT` + `LOCAL_PREF`-0 form
/// (pinned by `llgr_stale_to_non_llgr_ibgp_peer_carries_no_export_and_lpref_zero`
/// in the transport crate).
#[tokio::test]
async fn llgr_stale_to_ibgp_peer_without_llgr_still_advertised_with_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, ipv4_sendable(), false, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    unicast_announce_and_promote_to_llgr(&tx, source, prefix).await;

    let mut reannounced = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.withdraw.contains(&(Prefix::V4(prefix), 0)),
            "the §4.6 exception permits advertising to a non-LLGR iBGP peer"
        );
        if update.announce.iter().any(|route| {
            route.prefix == Prefix::V4(prefix)
                && route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        }) {
            reannounced = true;
        }
    }
    assert!(
        reannounced,
        "LLGR-stale route must flow to the iBGP peer with LLGR_STALE intact"
    );

    drop(tx);
    handle.await.unwrap();
}

/// No-behavior-change pin: fresh routes are advertised identically to
/// peers with and without the LLGR capability (the gate only exists for
/// LLGR-stale routes, a state that only occurs during an LLGR phase).
#[tokio::test]
async fn fresh_routes_unaffected_by_peer_llgr_capability() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let plain = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let capable = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut plain_rx = llgr_gate_peer_up(&tx, plain, ipv4_sendable(), true, vec![], None).await;
    let mut capable_rx = llgr_gate_peer_up(
        &tx,
        capable,
        ipv4_sendable(),
        true,
        vec![(Afi::Ipv4, Safi::Unicast)],
        None,
    )
    .await;
    drain_eor(&mut plain_rx).await;
    drain_eor(&mut capable_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    for out_rx in [&mut plain_rx, &mut capable_rx] {
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
        assert!(!update.announce[0].is_llgr_stale);
        assert!(
            !update.announce[0]
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
        assert!(update.withdraw.is_empty());
    }

    drop(tx);
    handle.await.unwrap();
}

/// VPN counterpart of the eBGP suppression: an LLGR-stale VPN route is
/// withdrawn from a non-LLGR eBGP peer at promotion.
#[tokio::test]
async fn vpn_llgr_stale_suppressed_toward_ebgp_peer_without_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, vpn_sendable(), true, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);

    let mut withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.vpn_announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "LLGR-stale VPN route must not be announced to a non-LLGR eBGP peer"
        );
        if update.vpn_withdraw.contains(&key) {
            withdrawn = true;
        }
    }
    assert!(
        withdrawn,
        "previously advertised VPN route must be withdrawn from the non-LLGR eBGP peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// VPN toward an LLGR-capable eBGP peer: unchanged — the promoted route
/// re-announces with the community riding.
#[tokio::test]
async fn vpn_llgr_stale_unchanged_toward_llgr_capable_ebgp_peer() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(
        &tx,
        target,
        vpn_sendable(),
        true,
        vec![(Afi::Ipv4, Safi::MplsVpn)],
        None,
    )
    .await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(out_rx.recv().await.unwrap().vpn_announce.len(), 1);

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);

    let mut reannounced = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.vpn_withdraw.contains(&key),
            "LLGR-stale VPN route must not be withdrawn from an LLGR-capable peer"
        );
        if update.vpn_announce.iter().any(|route| {
            route.key().nlri_key == key.nlri_key
                && route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        }) {
            reannounced = true;
        }
    }
    assert!(reannounced, "community must ride to the LLGR-capable peer");

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.4 in the VPN Add-Path branch: each staged candidate is
/// gated individually — the LLGR-stale path loses its Add-Path rank
/// toward a non-LLGR eBGP peer while the fresh path keeps flowing.
#[tokio::test]
async fn vpn_addpath_llgr_stale_candidates_gated_individually() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(
        &tx,
        target,
        vpn_sendable(),
        true,
        vec![],
        Some(((Afi::Ipv4, Safi::MplsVpn), 4)),
    )
    .await;
    drain_eor(&mut out_rx).await;

    // Same RD+prefix identity from two sources; A wins on LOCAL_PREF.
    let source_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let route_a = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200);
    let route_b = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 3), 31, 100, 100);
    let nlri_key = route_a.nlri.key();
    for (peer, route) in [(source_a, route_a), (source_b, route_b)] {
        tx.send(RibUpdate::VpnRoutesReceived {
            session_id: 0,
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    // Both paths staged with Add-Path ranks 1..=2 before the LLGR phase.
    assert_eq!(query_vpn_routes(&tx).await.len(), 1);
    let mut ranks_seen: HashSet<u32> = HashSet::new();
    while let Ok(update) = out_rx.try_recv() {
        for route in &update.vpn_announce {
            ranks_seen.insert(route.path_id);
        }
    }
    assert!(
        ranks_seen.contains(&1) && ranks_seen.contains(&2),
        "both candidates staged pre-LLGR, got ranks {ranks_seen:?}"
    );

    // B restarts and its path is promoted to LLGR-stale.
    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source_b, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let _ = query_vpn_routes(&tx).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let _ = query_vpn_routes(&tx).await;

    let mut rank2_withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.vpn_announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "the LLGR-stale candidate must not occupy an Add-Path rank"
        );
        if update.vpn_withdraw.contains(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2,
        }) {
            rank2_withdrawn = true;
        }
    }
    assert!(
        rank2_withdrawn,
        "the stale candidate's Add-Path rank must be withdrawn"
    );

    drop(tx);
    handle.await.unwrap();
}

/// EVPN spot-check of the eBGP suppression shape.
#[tokio::test]
async fn evpn_llgr_stale_suppressed_toward_ebgp_peer_without_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, evpn_sendable(), true, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let key = imet.key();
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
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.evpn_announce.len(), 1);

    let family = vec![(Afi::L2Vpn, Safi::Evpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_evpn_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_evpn_routes(&tx).await[0].is_llgr_stale);

    let mut withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.evpn_announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "LLGR-stale EVPN route must not be announced to a non-LLGR eBGP peer"
        );
        if update.evpn_withdraw.contains(&key) {
            withdrawn = true;
        }
    }
    assert!(
        withdrawn,
        "previously advertised EVPN route must be withdrawn from the non-LLGR eBGP peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Plumbing: `PeerUp` carries the peer's advertised LLGR families into
/// the per-peer map; session teardown clears it.
#[tokio::test]
async fn peer_up_registers_llgr_families_and_teardown_clears() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let (out_tx, _out_rx) = mpsc::channel(8);
    manager.handle_peer_up(
        peer,
        1,
        65000,
        Ipv4Addr::UNSPECIFIED,
        out_tx,
        None,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        0,
        Vec::new(),
        vec![(Afi::Ipv4, Safi::Unicast)],
    );
    assert_eq!(
        manager.peer_advertised_llgr_families.get(&peer),
        Some(&vec![(Afi::Ipv4, Safi::Unicast)])
    );

    manager.handle_peer_down(peer, 1);
    assert!(
        !manager.peer_advertised_llgr_families.contains_key(&peer),
        "teardown must clear the per-peer LLGR-family registration"
    );
}
