use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "channel-backpressure scenario needs setup, retry clock, and assertions together"
)]
async fn channel_full_marks_dirty_and_resyncs() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    // Channel capacity 1: fills after one send
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // First route: should succeed (channel empty → fits)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the successful send so we can verify AdjRibOut
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Verify AdjRibOut has the route
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);

    // Send prefix2 — fills the channel (capacity 1)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // DON'T drain — channel is now full. Withdraw prefix1 to trigger
    // another distribute_changes that will fail on try_send.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // After channel-full failure, AdjRibOut preserves last successfully
    // sent state: both prefix1 and prefix2 were sent before the failure.
    // The withdrawal of prefix1 was lost because the channel was full.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        2,
        "AdjRibOut preserves last successfully sent state (prefix1+prefix2)"
    );

    // Now drain the channel to allow resync
    let _ = out_rx.recv().await.unwrap();

    // Advance time to trigger the dirty-peer resync timer — no external
    // route mutation needed; the timer fires independently.
    tokio::time::advance(Duration::from_secs(2)).await;

    // Drain the resync update
    let resync = out_rx.recv().await.unwrap();

    // The resync should withdraw prefix1 (no longer in Loc-RIB). Prefix2
    // was already successfully enqueued before the channel filled, so it
    // does not need to be re-announced unless it diverged.
    assert!(
        resync.withdraw.contains(&(Prefix::V4(prefix1), 0)),
        "resync should withdraw prefix1 (no longer in Loc-RIB)"
    );
    assert!(
        !resync.withdraw.contains(&(Prefix::V4(prefix2), 0)),
        "resync should not withdraw prefix2"
    );

    // After successful resync, AdjRibOut should match Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        1,
        "AdjRibOut matches Loc-RIB after resync (only prefix2)"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_not_starved_by_query_traffic() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Announce prefix1
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap(); // drain

    // Withdraw prefix1 — channel is empty so this fills it
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // That send succeeded (channel was empty). Now announce again to fill.
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Don't drain — channel full. Send another route to trigger a failed
    // distribute_changes, marking the peer dirty.
    let prefix3 = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix3, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Drain the outbound channel to allow resync
    let _ = out_rx.recv().await.unwrap();

    // Advance 500ms — not enough for the 1s timer
    tokio::time::advance(Duration::from_millis(500)).await;

    // Send several queries to exercise the "message churn" path.
    // With the old code (sleep recreated each iteration), each query
    // would reset the 1s countdown, starving the timer.
    for _ in 0..5 {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;
    }

    // Advance the remaining 600ms — total 1100ms, past the 1s deadline
    // that was set before the query churn.
    tokio::time::advance(Duration::from_millis(600)).await;

    // The resync should fire despite the intervening queries.
    let resync = out_rx.recv().await.unwrap();
    assert!(
        !resync.announce.is_empty() || !resync.withdraw.is_empty(),
        "resync should produce updates despite query churn"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn initial_dump_failure_leaves_adjribout_empty() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Pre-populate Loc-RIB
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

    // Use a closed channel (drop rx side immediately) to guarantee send failure
    let (out_tx, out_rx) = mpsc::channel(1);
    drop(out_rx);

    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // AdjRibOut should be empty since initial dump send failed
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert!(
        advertised.is_empty(),
        "AdjRibOut should be empty when initial dump send fails"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn initial_dump_failure_resyncs_via_timer() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Pre-populate Loc-RIB
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

    // Use a full channel (capacity 1, pre-filled) to fail the initial dump
    // but keep the channel recoverable (unlike closed).
    let (out_tx, mut out_rx) = mpsc::channel(1);
    // Fill the channel so send_initial_table's try_send fails
    out_tx
        .send(OutboundRouteUpdate {
            next_hop_override: vec![],
            announce: vec![],
            withdraw: vec![],
            end_of_rib: vec![],
            refresh_markers: vec![],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
            evpn_announce: vec![],
            evpn_withdraw: vec![],
            bgpls_announce: vec![],
            bgpls_withdraw: vec![],
            vpn_announce: vec![],
            labeled_announce: vec![],
            rtc_announce: vec![],
            vpn_withdraw: vec![],
            labeled_withdraw: vec![],
            rtc_withdraw: vec![],
            request_refresh_all_negotiated: false,
        })
        .await
        .unwrap();

    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Force serialization — initial dump should have failed (channel full)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert!(
        advertised.is_empty(),
        "AdjRibOut should be empty after failed initial dump"
    );

    // Drain the channel to make room for the resync
    let _ = out_rx.recv().await.unwrap();

    // Advance time to trigger the resync timer
    tokio::time::advance(Duration::from_secs(2)).await;

    // The resync should deliver the initial table
    let resync = out_rx.recv().await.unwrap();
    assert_eq!(
        resync.announce.len(),
        1,
        "resync should announce the route from Loc-RIB"
    );
    assert_eq!(resync.announce[0].prefix, Prefix::V4(prefix));
    assert!(resync.withdraw.is_empty());
    assert_eq!(resync.end_of_rib, ipv4_sendable());

    // AdjRibOut should now reflect Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        1,
        "AdjRibOut should match Loc-RIB after resync"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Route event streaming tests ---

/// Regression test for the silent advertisement wedge (ROADMAP, observed
/// in an M66 CI run, root-caused in the stale-PeerDown deregistration
/// entry): two sessions for one peer address overlap during the RFC 4271
/// §6.8 collision window, the loser's `PeerDown` is processed AFTER the
/// winner's `PeerUp`, and — before session-identity stamping — it
/// deregistered the surviving session's outbound sender, silently
/// wedging every later advertisement while the session stayed
/// Established (keepalives are writer-owned in transport).
///
/// With the fix, `PeerUp`/`PeerDown` carry the transport session id and
/// the whole `handle_peer_down` teardown is gated on it: the stale
/// collision-loser `PeerDown` is discarded, the winner's Adj-RIB-In
/// survives, and a post-convergence advertisement MUST be delivered on
/// the winner's outbound channel.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "collision regression keeps both session orderings and assertions together"
)]
async fn stale_peer_down_after_replacement_peer_up_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        };

    // Session A (collision loser) reaches Established first and registers.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 1)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // Session B (collision winner) reaches Established while A is still
    // registered — same peer address, fresh outbound channel, new session
    // id. The session task keeps its own sender clone alive (it does in
    // production), so a deregistration in the manager closes nothing.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 2)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // The winner session receives a route from the peer — state a stale
    // PeerDown must NOT destroy (the id check gates the whole teardown,
    // Adj-RIB-In included, not just outbound deregistration).
    let imet_winner = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_winner_key = imet_winner.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_winner],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // The dumped loser's teardown lands last, stamped with ITS session id.
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    })
    .await
    .unwrap();

    // The stale PeerDown must not have cleared the winner session's
    // Adj-RIB-In: the route it received is still in the Loc-RIB.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .unwrap();
    let evpn_routes = reply_rx.await.unwrap();
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_winner_key),
        "stale PeerDown must not clear the surviving session's Adj-RIB-In"
    );

    // A post-convergence advertisement arrives from another RR client —
    // the analogue of pe1's fresh Type 2 origination / drain withdrawals.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
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

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    // Delivery assert: the winner session is still registered, so the new
    // advertisement MUST reach its outbound channel. (Before the fix this
    // never arrived — the stale PeerDown had removed the peer from
    // `outbound_peers`, so distribution skipped it forever.)
    let delivered = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "stale collision-loser PeerDown wedged distribution — no advertisement \
             reached the surviving session's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        delivered.evpn_announce.iter().any(|r| r.key() == imet_key),
        "delivered update must carry the post-convergence EVPN announce"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// GR flavor of the stale collision-loser teardown: a
/// `PeerGracefulRestart` from a superseded session must be discarded by
/// the same session-identity rule. Before stamping, a stale GR-down
/// would mark the surviving session's routes stale AND deregister its
/// outbound sender (`clear_outbound_peer_state` runs on the GR path
/// too) — the same silent wedge. A GR-down whose id matches the
/// registered session keeps its stale-path-retention semantics
/// unchanged.
#[tokio::test]
async fn stale_graceful_restart_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        };

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 1)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 2)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // The dumped loser goes down with GR retention — stamped with ITS id.
    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 1,
        restart_time: 30,
        stale_routes_time: 30,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // The winner session must still be registered: a new advertisement
    // reaches its outbound channel.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
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

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    let delivered = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "stale collision-loser PeerGracefulRestart wedged distribution — no \
             advertisement reached the surviving session's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        delivered.evpn_announce.iter().any(|r| r.key() == imet_key),
        "delivered update must carry the post-convergence EVPN announce"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// The SYMMETRIC collision interleaving to
/// `stale_peer_down_after_replacement_peer_up_is_discarded`: the winner
/// session registers FIRST, the loser's `PeerUp` arrives later (cross-task
/// mpsc interleaving is arbitrary — per-sender FIFO only), and then the
/// loser's `PeerDown` lands. The loser's `PeerUp` is treated as a
/// replacement (clearing the winner's Adj-RIB-In and registering the
/// loser's outbound channel + session id), so the loser's `PeerDown`
/// MATCHES the registered id and runs the full teardown — leaving the
/// winner Established but deregistered with its Adj-RIB-In destroyed.
///
/// The completed design keeps every live session for the peer address in a
/// bounded per-peer map: when the active registration's session goes down
/// while another live session remains, the registration FAILS OVER to the
/// survivor (re-register its channel, re-run the initial table dump,
/// request an inbound ROUTE-REFRESH through its channel) instead of
/// tearing the peer down.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "failover regression keeps session interleaving and recovery assertions together"
)]
async fn peer_down_of_replacement_session_fails_over_to_surviving_session() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        };

    // Session W (collision winner) registers first.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // W's session delivers a route into its Adj-RIB-In.
    let imet_winner = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_winner_key = imet_winner.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_winner],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Session L (collision loser) reaches Established too; its PeerUp is
    // processed AFTER the winner's. The manager treats it as a
    // replacement and registers L's channel + id.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // The loser is torn down by collision resolution; its PeerDown is
    // stamped with ITS session id — which matches the registration.
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();

    // FAILOVER, half 1 — outbound: W's channel must be re-registered and
    // receive the failover initial-table dump (at minimum an EoR for its
    // sendable families).
    let dump = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "PeerDown of the replacement (loser) session tore down the surviving \
             (winner) session's registration — no failover dump reached the \
             winner's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !dump.end_of_rib.is_empty() || dump.request_refresh_all_negotiated,
        "first post-failover update must be the initial dump EoR or the inbound \
         refresh request, got announce={} withdraw={}",
        dump.announce.len(),
        dump.withdraw.len(),
    );

    // FAILOVER, half 2 — inbound: W's Adj-RIB-In was cleared by the
    // loser's replacement reset (and W's routes were discarded by the
    // session-identity gate while superseded). The manager must
    // request an inbound ROUTE-REFRESH through W's channel so the peer
    // re-advertises; family selection is delegated to the session task's
    // negotiated set (the session task also enforces the RFC 2918
    // capability).
    let mut saw_refresh_request = dump.request_refresh_all_negotiated;
    if !saw_refresh_request {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
                Ok(Some(update)) => {
                    if update.request_refresh_all_negotiated {
                        saw_refresh_request = true;
                        break;
                    }
                }
                Ok(None) => panic!("winner outbound channel closed unexpectedly"),
                Err(_) => {}
            }
        }
    }
    assert!(
        saw_refresh_request,
        "failover must request an inbound ROUTE-REFRESH toward the surviving \
         session (its Adj-RIB-In was cleared by the replacement reset; the \
         session task picks the families from its negotiated set)"
    );

    // The peer answers the refresh: W's route lands back in the Loc-RIB.
    let imet_again = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_again],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_winner_key),
        "the surviving session's re-advertised route must land in the Loc-RIB"
    );

    // A post-convergence advertisement from another RR client must still
    // reach W — the registration survived the whole interleaving.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
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

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut delivered = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.evpn_announce.iter().any(|r| r.key() == imet_key) {
                    delivered = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        delivered,
        "post-convergence advertisement must reach the surviving session's \
         outbound channel after failover"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// GR flavor of the registration failover: a `PeerGracefulRestart` from
/// the ACTIVE (replacement) session while another live session remains
/// must fail the registration over to the survivor — NOT enter GR
/// stale-path retention. Retention bridges a session that is gone; here
/// an Established session for the address exists and is refreshed
/// immediately instead.
#[tokio::test]
async fn graceful_restart_of_replacement_session_fails_over_to_surviving_session() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        };

    // Winner registers first, loser's PeerUp replaces the registration.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // The loser goes down WITH GR — stamped with the ACTIVE session id.
    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 2,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Failover, not retention: the winner's channel receives the failover
    // initial dump and the inbound refresh request.
    let mut saw_refresh_request = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.request_refresh_all_negotiated {
                    saw_refresh_request = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_refresh_request,
        "GR-down of the active session with a live survivor must fail over and \
         request an inbound ROUTE-REFRESH toward the survivor"
    );

    // GR retention must NOT have been entered for the peer (no stale
    // phase while an Established session holds the registration).
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        gr_active.abs() < f64::EPSILON,
        "failover must not enter GR stale-path retention, gr_active = {gr_active}"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// The failover inbound refresh must NOT be limited to the sendable
/// (outbound) family subset the manager sees in `PeerUp` — a family
/// negotiated for receive but pruned from the sendable set (e.g. IPv6
/// with no usable local IPv6 next-hop) still needs its Adj-RIB-In
/// repopulated. The manager therefore delegates family selection to the
/// session task via `request_refresh_all_negotiated`. Modeled here as
/// the extreme case: a survivor whose sendable set is EMPTY must still
/// get the refresh request (a sendable-derived selection would request
/// nothing at all).
#[tokio::test]
async fn failover_inbound_refresh_covers_negotiated_but_not_sendable_families() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Both sessions advertise an EMPTY sendable set — every negotiated
    // family is receive-only from the manager's point of view.
    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: vec![],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        };

    // Winner registers first, loser's PeerUp replaces the registration,
    // loser goes down — the registration fails over to the winner. (No
    // EoR drain: with an empty sendable set there is no initial dump.)
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    let (loser_tx, _loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();

    let mut saw_refresh_request = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.request_refresh_all_negotiated {
                    saw_refresh_request = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_refresh_request,
        "failover must request the inbound ROUTE-REFRESH even when the \
         survivor's sendable family set is empty — the refresh covers \
         receive-side families the manager cannot see, so family selection \
         belongs to the session task"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// `RibUpdate::PeerUp` boilerplate for the stale-data-message tests
/// below: an iBGP RR-client peer with the given sendable families.
fn session_peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    sendable_families: Vec<(Afi, Safi)>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

/// `RoutesReceived` queued by a superseded session and processed after
/// the replacement's `PeerUp` must be discarded by session identity —
/// otherwise stale routes from the dumped session land in the
/// replacement session's Adj-RIB-In (an announce/withdraw race can
/// leave entries the new session never sent). The ACTIVE session's
/// routes must still be accepted.
#[tokio::test]
async fn stale_routes_received_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Loser registers, winner's PeerUp replaces the registration.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Stale routes from the superseded session, queued behind the
    // winner's PeerUp.
    let imet_stale = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_stale_key = imet_stale.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_stale],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        !evpn_routes.iter().any(|r| r.key() == imet_stale_key),
        "stale RoutesReceived from a superseded session must not land in the \
         replacement session's Adj-RIB-In"
    );

    // The ACTIVE session's routes still flow.
    let imet_active = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 60);
    let imet_active_key = imet_active.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_active],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_active_key),
        "the active session's RoutesReceived must not be discarded"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A stale `EndOfRib` from a superseded session must not complete the
/// registered session's graceful-restart window for the family — a
/// premature completion ends stale-route retention on the strength of
/// a table dump the surviving session never finished.
#[tokio::test]
async fn stale_end_of_rib_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Session 1 establishes, announces a route, then goes down with GR —
    // the route is retained stale, awaiting the reconnect's End-of-RIB.
    let (s1_tx, mut s1_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, s1_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut s1_rx).await;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 1,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // The peer reconnects as session 2 (re-registers during the GR
    // window; GR completion now waits on SESSION 2's End-of-RIB).
    let (s2_tx, mut s2_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, s2_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut s2_rx).await;

    // A stale EoR from the dumped session must NOT complete the sweep.
    tx.send(RibUpdate::EndOfRib {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    // Barrier: the query is processed after the EoR (same channel).
    let _ = query_received_routes(&tx, peer).await;
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        (gr_active - 1.0).abs() < f64::EPSILON,
        "stale EndOfRib from a superseded session must not complete the \
         registered session's GR window, gr_active = {gr_active}"
    );

    // The ACTIVE session's EoR completes GR normally.
    tx.send(RibUpdate::EndOfRib {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let _ = query_received_routes(&tx, peer).await;
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        gr_active.abs() < f64::EPSILON,
        "the active session's EndOfRib must complete GR, gr_active = {gr_active}"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Stale RFC 7313 demarcation markers (`BoRR`/`EoRR`) from a superseded
/// session must be discarded — a stale `BoRR` would mark the
/// replacement session's Adj-RIB-In refresh-stale and a stale `EoRR`
/// would close the window and sweep routes the new session was about
/// to re-send. The ACTIVE session's markers keep their semantics.
#[tokio::test]
async fn stale_enhanced_refresh_markers_from_superseded_session_are_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // The active session's route sits in the Adj-RIB-In.
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stale BoRR + EoRR from the superseded session: without the gate,
    // this pair opens a refresh window over the active session's
    // Adj-RIB-In and immediately sweeps every route in the family.
    for subtype_is_begin in [true, false] {
        let update = if subtype_is_begin {
            RibUpdate::BeginRouteRefresh {
                peer,
                session_id: 1,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }
        } else {
            RibUpdate::EndRouteRefresh {
                peer,
                session_id: 1,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }
        };
        tx.send(update).await.unwrap();
    }
    let received = query_received_routes(&tx, peer).await;
    assert!(
        received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "stale BoRR/EoRR from a superseded session must not sweep the \
         registered session's Adj-RIB-In"
    );

    // The ACTIVE session's BoRR + EoRR keep their semantics: the route
    // is not re-announced inside the window, so it is swept at EoRR.
    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, peer).await;
    assert!(
        !received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "the active session's BoRR/EoRR must still sweep unreplaced routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A stale `RouteRefreshRequest` from a superseded session must be
/// discarded (it would only trigger a spurious re-advertisement, but
/// the same active-or-drop rule applies to every session-scoped
/// message); the ACTIVE session's request still gets the full
/// refresh response.
#[tokio::test]
async fn stale_route_refresh_request_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Stale request: no refresh response may reach the active session's
    // outbound channel.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    // Barrier: the query reply proves the request was processed.
    let _ = query_received_routes(&tx, peer).await;
    assert!(
        winner_rx.try_recv().is_err(),
        "stale RouteRefreshRequest from a superseded session must not \
         trigger a re-advertisement"
    );

    // The ACTIVE session's request produces the refresh response (EoR +
    // demarcation markers even with an empty table).
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect("the active session's RouteRefreshRequest must get a response")
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !response.refresh_markers.is_empty() || !response.end_of_rib.is_empty(),
        "refresh response must carry the demarcation markers / EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Stale ORF entries from a superseded session must not install or
/// modify the replacement session's outbound filter — ORF state is
/// per-session (RFC 5291). The discard is observable on the reply
/// channel; the ACTIVE session's ORF update still applies.
#[tokio::test]
async fn stale_orf_update_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    let entry = AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Deny,
        sequence: 10,
        min_len: 0,
        max_len: 32,
        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16))),
    };

    // Stale ORF push: rejected on the reply channel, filter not installed.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Defer,
        entries: vec![entry],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_err(),
        "stale PeerOrfUpdate from a superseded session must be rejected, got {result:?}"
    );

    // The ACTIVE session's ORF push is accepted.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Defer,
        entries: vec![entry],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_ok(),
        "the active session's PeerOrfUpdate must be accepted, got {result:?}"
    );

    drop(winner_rx);
    drop(tx);
    handle.await.unwrap();
}

/// No-false-drops guard for the session-identity gate on data messages:
/// every message kind stamped with the ACTIVE session's id (and the
/// legacy id-0 flavor on an id-0 registration) flows exactly as before
/// stamping.
#[tokio::test]
async fn active_session_messages_flow_after_replacement() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Replacement scenario: the gate sees a non-trivial registration.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Routes from the active session land in the Adj-RIB-In.
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, peer).await;
    assert!(
        received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "the active session's routes must be accepted"
    );

    // A refresh request from the active session gets its response.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect("the active session's RouteRefreshRequest must get a response")
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !response.refresh_markers.is_empty() || !response.end_of_rib.is_empty(),
        "refresh response must carry the demarcation markers / EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn unregistered_session_message_keeps_legacy_accept_behavior() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 44, 0, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 77,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let received = query_received_routes(&tx, peer).await;
    assert!(
        received
            .iter()
            .any(|route| route.prefix == Prefix::V4(prefix)),
        "unregistered data messages intentionally retain the legacy accept behavior"
    );

    drop(tx);
    handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// EVPN GR/LLGR tests (Gate 2) — mirror the unicast + FlowSpec GR/LLGR suite.
// Each test spawns a RibManager with a cluster-id so iBGP reflection works,
// registers two peers (source + target, both RR clients), and drives
// RibUpdate events to exercise the stale lifecycle.
// ---------------------------------------------------------------------------
