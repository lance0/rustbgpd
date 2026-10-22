use super::*;
use crate::PeerId;
use crate::test_support::peer_v4;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "channel-backpressure scenario needs setup, retry clock, and assertions together"
)]
async fn channel_full_marks_dirty_and_resyncs() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Pin the PER-PEER path: commit-after-send is a per-peer AdjRibOut
    // discipline (a grouped member's advertised view is synthesized from
    // the group table, which advances at staging time and heals via the
    // dirty resync — covered by the update-group differential tests).
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    // Channel capacity 1: fills after one send
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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
        validated_with: None,
    })
    .await
    .unwrap();

    // Drain the successful send so we can verify AdjRibOut
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Verify AdjRibOut has the route
    let advertised = collect_advertised_routes(&tx, target).await;
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
        validated_with: None,
    })
    .await
    .unwrap();
    // Separate distribution passes: without this barrier the queued
    // messages coalesce into one window.
    let _ = query_best_routes(&tx).await;

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
        validated_with: None,
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // After channel-full failure, AdjRibOut preserves last successfully
    // sent state: both prefix1 and prefix2 were sent before the failure.
    // The withdrawal of prefix1 was lost because the channel was full.
    let advertised = collect_advertised_routes(&tx, target).await;
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
    let advertised = collect_advertised_routes(&tx, target).await;
    assert_eq!(
        advertised.len(),
        1,
        "AdjRibOut matches Loc-RIB after resync (only prefix2)"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario proves resync progress under sustained query load"
)]
async fn dirty_resync_not_starved_by_query_traffic() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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
        validated_with: None,
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
        validated_with: None,
    })
    .await
    .unwrap();
    // Separate distribution passes: without this barrier the queued
    // messages coalesce into one window.
    let _ = query_best_routes(&tx).await;

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
        validated_with: None,
    })
    .await
    .unwrap();
    // Separate distribution passes: without this barrier the queued
    // messages coalesce into one window.
    let _ = query_best_routes(&tx).await;

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
        validated_with: None,
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
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
        tx.send(RibUpdate::QueryBestRoutes {
            deadline: full_snapshot_query_deadline(),
            reply: reply_tx,
        })
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
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Pin the PER-PEER path: commit-after-send is a per-peer AdjRibOut
    // discipline (a grouped member's advertised view is synthesized from
    // the group table, which advances at staging time and heals via the
    // dirty resync — covered by the update-group differential tests).
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
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
        validated_with: None,
    })
    .await
    .unwrap();

    // Use a closed channel (drop rx side immediately) to guarantee send failure
    let (out_tx, out_rx) = mpsc::channel(1);
    drop(out_rx);

    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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
    let advertised = collect_advertised_routes(&tx, target).await;
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
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Pin the PER-PEER path: commit-after-send is a per-peer AdjRibOut
    // discipline (a grouped member's advertised view is synthesized from
    // the group table, which advances at staging time and heals via the
    // dirty resync — covered by the update-group differential tests).
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
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
        validated_with: None,
    })
    .await
    .unwrap();

    // Use a full channel (capacity 1, pre-filled) to fail the initial dump
    // but keep the channel recoverable (unlike closed).
    let (out_tx, mut out_rx) = mpsc::channel(1);
    // Fill the channel so send_initial_table's try_send fails
    out_tx.send(OutboundRouteUpdate::default()).await.unwrap();

    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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
    let advertised = collect_advertised_routes(&tx, target).await;
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
    assert_eq!(resync.withdraw.len(), 0);
    assert_eq!(resync.end_of_rib, ipv4_sendable());

    // AdjRibOut should now reflect Loc-RIB
    let advertised = collect_advertised_routes(&tx, target).await;
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
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
        validated_with: None,
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
    tx.send(RibUpdate::QueryEvpnRoutes {
        filter: None,
        reply: reply_tx,
    })
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
        per_client_best: false,
        interpret_rfc1997: true,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
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
        per_client_best: false,
        interpret_rfc1997: true,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
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
        validated_with: None,
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
        validated_with: None,
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
        per_client_best: false,
        interpret_rfc1997: true,
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
        validated_with: None,
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

/// A full survivor channel must defer the collision-failback refresh without
/// counting permanent loss, then deliver exactly one request after capacity
/// returns through the existing resync timer.
#[tokio::test]
async fn failover_inbound_refresh_retries_once_after_channel_drains() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

    // Capacity one makes the failover initial EoR occupy the only slot, so
    // the immediately-following inbound refresh request must be deferred.
    let (winner_tx, mut winner_rx) = mpsc::channel(1);
    let winner_session_tx = winner_tx.clone();
    tx.send(session_peer_up(peer, 1, winner_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    let (loser_tx, mut loser_rx) = mpsc::channel(1);
    tx.send(session_peer_up(peer, 2, loser_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();

    let failover_dump = winner_rx.recv().await.expect("winner channel stays open");
    assert!(!failover_dump.request_refresh_all_negotiated);
    assert_ne!(failover_dump.end_of_rib.len(), 0);
    assert!(
        counter_metric_value(
            &metrics,
            "bgp_outbound_route_drops_total",
            &[("peer", "10.0.0.2")],
        )
        .abs()
            < f64::EPSILON,
        "temporary saturation is deferred, not counted as permanent loss"
    );

    tokio::time::advance(DIRTY_RESYNC_INTERVAL).await;
    tokio::task::yield_now().await;
    let refresh = winner_rx.recv().await.expect("retry reaches live winner");
    assert!(refresh.request_refresh_all_negotiated);

    tokio::time::advance(DIRTY_RESYNC_INTERVAL).await;
    tokio::task::yield_now().await;
    assert!(
        winner_rx.try_recv().is_err(),
        "successful retry must clear the coalesced request"
    );
    assert!(
        counter_metric_value(
            &metrics,
            "bgp_outbound_route_drops_total",
            &[("peer", "10.0.0.2")],
        )
        .abs()
            < f64::EPSILON,
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

#[test]
fn pending_inbound_refresh_coalesces_and_closed_channel_is_terminal() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(1);
    manager.handle_update(session_peer_up(peer, 11, out_tx, evpn_sendable()));

    // The initial EoR fills the only slot. Repeat requests replace the same
    // peer-generation bit instead of appending attempts.
    manager.request_inbound_refresh(peer);
    manager.request_inbound_refresh(peer);
    assert_eq!(manager.pending_inbound_refresh.len(), 1);
    assert_eq!(manager.pending_inbound_refresh.get(&peer), Some(&11));

    let _ = out_rx.try_recv().expect("initial EoR occupied the channel");
    drop(out_rx);
    manager.retry_pending_inbound_refresh_bounded();
    assert!(manager.pending_inbound_refresh.is_empty());
    assert!(
        (counter_metric_value(
            &metrics,
            "bgp_outbound_route_drops_total",
            &[("peer", "10.0.0.2")],
        ) - 1.0)
            .abs()
            < f64::EPSILON,
        "a closed live-session channel retires and counts terminal loss"
    );
}

#[test]
fn newer_registration_reaps_older_pending_inbound_refresh() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let (old_tx, mut old_rx) = mpsc::channel(1);
    manager.handle_update(session_peer_up(peer, 21, old_tx, evpn_sendable()));
    manager.request_inbound_refresh(peer);
    assert_eq!(manager.pending_inbound_refresh.get(&peer), Some(&21));

    let (new_tx, _new_rx) = mpsc::channel(1);
    manager.handle_update(session_peer_up(peer, 22, new_tx, evpn_sendable()));
    assert!(manager.pending_inbound_refresh.is_empty());
    assert_eq!(manager.outbound_session_ids.get(&peer), Some(&22));

    let _ = old_rx
        .try_recv()
        .expect("old session's initial EoR remains");
    assert!(
        old_rx.try_recv().is_err(),
        "stale refresh must not be delivered to the superseded session"
    );
}

#[test]
fn inbound_refresh_retry_attempts_at_most_one_resync_slice() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_count = super::super::RESYNC_PEERS_PER_TICK + 1;
    let mut receivers = Vec::with_capacity(peer_count);

    for index in 0..peer_count {
        let peer = peer_v4(Ipv4Addr::new(10, 0, 0, u8::try_from(index + 1).unwrap()));
        let (out_tx, out_rx) = mpsc::channel(1);
        manager.handle_update(session_peer_up(
            peer,
            u64::try_from(index + 1).unwrap(),
            out_tx,
            ipv4_sendable(),
        ));
        manager.request_inbound_refresh(peer);
        receivers.push(out_rx);
    }
    assert_eq!(manager.pending_inbound_refresh.len(), peer_count);
    for receiver in &mut receivers {
        let _ = receiver.try_recv().expect("initial EoR fills each channel");
    }

    manager.retry_pending_inbound_refresh_bounded();
    let first_slice_deliveries = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .filter(|update| update.request_refresh_all_negotiated)
        .count();
    assert_eq!(first_slice_deliveries, super::super::RESYNC_PEERS_PER_TICK);
    assert_eq!(manager.pending_inbound_refresh.len(), 1);

    manager.retry_pending_inbound_refresh_bounded();
    let second_slice_deliveries = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .filter(|update| update.request_refresh_all_negotiated)
        .count();
    assert_eq!(second_slice_deliveries, 1);
    assert!(manager.pending_inbound_refresh.is_empty());
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

    // Both sessions advertise an EMPTY sendable set — every negotiated
    // family is receive-only from the manager's point of view.
    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
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
pub(super) fn session_peer_up(
    peer: PeerId,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    sendable_families: Vec<(Afi, Safi)>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

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
        validated_with: None,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

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
        queued: Arc::default(),
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
        queued: Arc::default(),
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let orf_peer_up = |session_id, outbound_tx| {
        let mut update = session_peer_up(peer, session_id, outbound_tx, ipv4_sendable());
        let RibUpdate::PeerUp {
            negotiated_orf_recv,
            ..
        } = &mut update
        else {
            unreachable!("session_peer_up always constructs PeerUp")
        };
        *negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
        update
    };

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(orf_peer_up(1, loser_tx)).await.unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(orf_peer_up(2, winner_tx)).await.unwrap();
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

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
        validated_with: None,
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
        queued: Arc::default(),
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
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
        validated_with: None,
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

// ---------------------------------------------------------------------------
// LAN-475: deferred outbound registration — a mass reconnect must not
// head-of-line block re-announcement delivery to established peers behind
// the reconnecting peers' full-table initial dumps.
// ---------------------------------------------------------------------------

fn test_peer_up(
    peer: PeerId,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

fn test_routes_received(peer: PeerId, announced: Vec<Route>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// With queued actor work, a re-established peer's registration (and its
/// full-table initial dump) is deferred, and the peer's inbound routes
/// distribute to already-established peers BEFORE the dump runs — the
/// LAN-475 property. The deferred dump then completes and reflects the
/// current table. Driven synchronously for determinism.
#[tokio::test]
async fn deferred_registration_lets_queued_imports_distribute_first() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Exercise the deferral without bulk data: treat any table as expensive.
    manager.initial_dump_defer_min_routes = 0;
    // The queued message below must join the restarter's window whatever
    // the host's speed.
    super::distribution_window::untimed_window(&mut manager);

    let survivor = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let third = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let restarter = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let third_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let restarter_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    // Survivor establishes on a quiet actor: registration is synchronous,
    // exactly the pre-LAN-475 behavior.
    let (survivor_tx, mut survivor_rx) = mpsc::channel(16);
    manager.handle_update(test_peer_up(survivor, 1, survivor_tx));
    let eor = survivor_rx
        .try_recv()
        .expect("quiet-actor PeerUp dumps synchronously");
    assert_ne!(eor.end_of_rib.len(), 0);

    // A third peer's route lands in the table (feeds the eventual dump).
    manager.handle_update(test_routes_received(
        third,
        vec![make_route(third_prefix, Ipv4Addr::new(10, 0, 0, 3))],
    ));
    drain_route_chunks(&mut manager);
    let update = survivor_rx
        .try_recv()
        .expect("survivor gets the third peer's route");
    assert_eq!(update.announce.len(), 1);

    // Queue work on the actor channel (a mass-reconnect burst in miniature),
    // then re-establish the restarter: its registration must defer.
    tx.try_send(test_routes_received(third, vec![])).unwrap();
    let (restarter_tx, mut restarter_rx) = mpsc::channel(16);
    manager.handle_update(test_peer_up(restarter, 2, restarter_tx));
    assert!(
        restarter_rx.try_recv().is_err(),
        "busy-actor PeerUp must not dump inline"
    );
    assert_eq!(manager.pending_initial_registrations.len(), 1);
    assert_eq!(manager.peer_outbound_state(restarter).update_group.len(), 0);

    // The restarter's re-announcements import and distribute to the
    // survivor while the restarter's own dump is still pending.
    manager.handle_update(test_routes_received(
        restarter,
        vec![make_route(restarter_prefix, Ipv4Addr::new(10, 0, 0, 2))],
    ));
    drain_route_chunks(&mut manager);
    let update = survivor_rx
        .try_recv()
        .expect("re-announced route reaches the survivor before the deferred dump");
    assert!(
        update
            .announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(restarter_prefix)),
        "survivor receives the re-announced prefix"
    );
    assert!(
        restarter_rx.try_recv().is_err(),
        "the deferred dump has still not run"
    );

    // The deferred registration completes: the restarter receives the
    // current table (the third peer's route, not its own) and an EoR.
    // The queued route message was already waiting when the restarter's
    // batch drained, so it joined that distribution window; draining
    // ready updates never advances the idle-only registration.
    assert_eq!(manager.primary_backlog(), 0);
    assert!(!manager.drain_ready_updates().await);
    assert_eq!(manager.peer_outbound_state(restarter).update_group.len(), 0);
    manager.advance_pending_initial_registration();
    assert_ne!(manager.peer_outbound_state(restarter).update_group.len(), 0);
    assert!(manager.pending_initial_registrations.is_empty());
    let dump = restarter_rx.try_recv().expect("deferred dump delivered");
    assert!(
        dump.announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(third_prefix)),
        "dump reflects the table at completion time"
    );
    let mut saw_eor = !dump.end_of_rib.is_empty();
    while let Ok(update) = restarter_rx.try_recv() {
        saw_eor |= !update.end_of_rib.is_empty();
    }
    assert!(saw_eor, "initial dump still ends with End-of-RIB");
}

/// A peer whose session goes down while its registration is deferred must
/// not be registered by the later advance; a full teardown still applies
/// (no survivor session), matching the pre-deferral invariant.
#[tokio::test]
async fn deferred_registration_dropped_when_session_dies_first() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;

    let restarter = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    tx.try_send(test_routes_received(restarter, vec![]))
        .unwrap();
    let (restarter_tx, mut restarter_rx) = mpsc::channel(16);
    manager.handle_update(test_peer_up(restarter, 7, restarter_tx));
    assert_eq!(manager.pending_initial_registrations.len(), 1);

    manager.handle_update(RibUpdate::PeerDown {
        peer: restarter,
        session_id: 7,
    });
    manager.advance_pending_initial_registration();
    assert!(manager.pending_initial_registrations.is_empty());
    assert!(
        restarter_rx.try_recv().is_err(),
        "no dump for a session that died before its deferred registration"
    );
    assert!(!manager.outbound_peers.contains_key(&restarter));
}

fn policy_chain(action: rustbgpd_policy::PolicyAction) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![],
        default_action: action,
    }])
}

/// Drive a parked clean transition to its terminal reply, as the run loop
/// does between polls.
fn finish_clean_transition(manager: &mut RibManager) {
    use crate::manager::distribution::CleanPolicyTransitionAdvance;
    use crate::update::ExportPolicyCohortOutcome;
    while let Some(pending) = manager.pending_clean_policy_transition.take() {
        match manager.advance_clean_policy_transition(pending) {
            CleanPolicyTransitionAdvance::Continue(next) => {
                manager.pending_clean_policy_transition = Some(next);
            }
            CleanPolicyTransitionAdvance::Committed(mut done) => {
                manager.with_replacement_readiness_age(done.elapsed(), |manager| {
                    done.retire_inputs(manager);
                });
                if let Some(reply) = done.take_reply() {
                    let _ = reply.send(Ok(ExportPolicyCohortOutcome::Committed));
                }
            }
            CleanPolicyTransitionAdvance::Fallback(mut failed) => {
                failed
                    .discard_uncommitted_transition(manager)
                    .expect("fallback cleanup succeeds");
                if let Some(reply) = failed.take_reply() {
                    let _ = reply.send(Ok(
                        ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
                    ));
                }
            }
        }
    }
}

/// Where the reload's export-policy cohort finds the third member.
#[derive(Clone, Copy, Debug)]
enum UnregisteredMember {
    /// Established, its `PeerUp` registration deferred behind queued work.
    DeferredRegistration,
    /// Between `PeerDown` and the next session's `PeerUp`.
    BetweenSessions,
}

/// LAN-2512: a reload changes the export policy of a cohort whose third
/// member is Established at the transport but not registered in the RIB.
/// The cohort commits for the registered members instead of rejecting the
/// whole batch (which forced a rollback that then fenced the daemon), and the
/// unregistered member's registration installs the NEW chain: its initial
/// dump is already filtered by it, so there is no stale-policy window.
///
/// The interleaving is the one the transport guarantees: the session records
/// its accepted chain (`SetPeerSessionExportPolicy` for the live session, or
/// the next `PeerUp` payload) on this channel before the peer manager's
/// cohort command. Driven synchronously, so the deferral is deterministic.
#[expect(
    clippy::too_many_lines,
    reason = "both unregistered-member interleavings share one setup, cohort and registration proof"
)]
async fn cohort_skips_unregistered_member(member: UnregisteredMember) {
    use rustbgpd_policy::PolicyAction;
    let (tx, rx) = mpsc::channel(64);
    let old = policy_chain(PolicyAction::Permit);
    let new = policy_chain(PolicyAction::Deny);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(old.clone()),
        None,
        BgpMetrics::new(),
    );
    manager.initial_dump_defer_min_routes = 0;

    let first = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let second = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let third = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 9));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 9, 0), 24);
    let mut receivers = Vec::new();
    for (session_id, peer) in [(1, first), (2, second)] {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        manager.handle_update(test_peer_up(peer, session_id, outbound_tx));
        receivers.push(outbound_rx);
    }
    manager.handle_update(test_routes_received(
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 9))],
    ));
    drain_route_chunks(&mut manager);

    let (third_tx, mut third_rx) = mpsc::channel(64);
    match member {
        UnregisteredMember::DeferredRegistration => {
            // Queued actor work defers the re-established member's
            // registration (LAN-475); then its session accepts the new chain.
            tx.try_send(test_routes_received(source, vec![])).unwrap();
            manager.handle_update(test_peer_up(third, 3, third_tx.clone()));
            assert_eq!(manager.pending_initial_registrations.len(), 1);
            manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
                peer: third,
                session_id: 3,
                export_policy: Some(new.clone()),
            });
        }
        UnregisteredMember::BetweenSessions => {
            manager.handle_update(test_peer_up(third, 3, third_tx.clone()));
            manager.handle_update(RibUpdate::PeerDown {
                peer: third,
                session_id: 3,
            });
        }
    }
    assert!(!manager.outbound_peers.contains_key(&third));
    while third_rx.try_recv().is_ok() {}
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }

    let (reply, response) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
        replacements: [first, second, third]
            .into_iter()
            .map(|peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(new.clone()),
            })
            .collect(),
        reply,
    });
    finish_clean_transition(&mut manager);
    let outcome = response
        .await
        .expect("the cohort replies")
        .unwrap_or_else(|error| panic!("{member:?}: cohort rejected: {error}"));
    if outcome == crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply {
        manager
            .apply_export_policy_replacements_synchronously(
                [first, second, third]
                    .into_iter()
                    .map(|peer| crate::update::PeerExportPolicyReplacement {
                        peer,
                        export_policy: Some(new.clone()),
                    })
                    .collect(),
            )
            .unwrap();
    }
    for peer in [first, second] {
        assert_eq!(manager.export_chains[&peer], Some(new.clone()));
    }

    match member {
        UnregisteredMember::DeferredRegistration => {
            while manager.drain_ready_updates().await {}
            manager.advance_pending_initial_registration();
        }
        UnregisteredMember::BetweenSessions => {
            // The next session's `PeerUp` carries its accepted chain.
            let mut peer_up = test_peer_up(third, 4, third_tx);
            if let RibUpdate::PeerUp { export_policy, .. } = &mut peer_up {
                *export_policy = Some(new.clone());
            }
            manager.handle_update(peer_up);
        }
    }
    assert!(manager.outbound_peers.contains_key(&third));
    assert_eq!(
        manager.export_chains[&third],
        Some(new.clone()),
        "{member:?}: registration installs the accepted chain"
    );
    let mut saw_eor = false;
    while let Ok(update) = third_rx.try_recv() {
        assert!(
            update.announce.is_empty(),
            "{member:?}: the initial dump is filtered by the new deny chain"
        );
        saw_eor |= !update.end_of_rib.is_empty();
    }
    assert!(saw_eor, "{member:?}: the initial dump completed");
}

#[tokio::test]
async fn export_policy_cohort_skips_member_with_deferred_registration() {
    cohort_skips_unregistered_member(UnregisteredMember::DeferredRegistration).await;
}

#[tokio::test]
async fn export_policy_cohort_skips_member_between_sessions() {
    cohort_skips_unregistered_member(UnregisteredMember::BetweenSessions).await;
}

fn peer_up_with_policy(
    peer: PeerId,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    policy: rustbgpd_policy::PolicyChain,
) -> RibUpdate {
    let mut peer_up = test_peer_up(peer, session_id, outbound_tx);
    if let RibUpdate::PeerUp { export_policy, .. } = &mut peer_up {
        *export_policy = Some(policy);
    }
    peer_up
}

/// LAN-2512: a dataset re-evaluation naming a member whose registration is
/// still deferred re-evaluates the registered member instead of rejecting the
/// batch, and the deferred registration's initial dump reads the CURRENT
/// dataset content.
#[tokio::test]
async fn dataset_reevaluation_skips_member_with_deferred_registration() {
    use super::update_groups_oracle::{dataset_prefix_data, dataset_prefix_policy};
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 7, 0), 24);
    let (dataset, chain) = dataset_prefix_policy(Prefix::V4(prefix), false);
    let registered = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let deferred = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 9));
    let (registered_tx, mut registered_rx) = mpsc::channel(64);
    manager.handle_update(peer_up_with_policy(
        registered,
        1,
        registered_tx,
        chain.clone(),
    ));
    manager.handle_update(test_routes_received(
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 9))],
    ));
    drain_route_chunks(&mut manager);
    tx.try_send(test_routes_received(source, vec![])).unwrap();
    let (deferred_tx, mut deferred_rx) = mpsc::channel(64);
    manager.handle_update(peer_up_with_policy(deferred, 3, deferred_tx, chain));
    assert_eq!(manager.pending_initial_registrations.len(), 1);
    while registered_rx.try_recv().is_ok() {}

    dataset
        .refresh(dataset_prefix_data(Prefix::V4(prefix), true))
        .unwrap();
    let (reply, response) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![registered, deferred],
        swaps: None,
        reply,
    });
    assert_eq!(response.await.expect("the RIB replies"), Ok(()));
    let mut announced = false;
    while let Ok(update) = registered_rx.try_recv() {
        announced |= update
            .announce
            .iter()
            .any(|r| r.prefix == Prefix::V4(prefix));
    }
    assert!(announced, "the registered member is re-evaluated");

    while manager.drain_ready_updates().await {}
    manager.advance_pending_initial_registration();
    assert!(manager.outbound_peers.contains_key(&deferred));
    let mut dumped = false;
    while let Ok(update) = deferred_rx.try_recv() {
        dumped |= update
            .announce
            .iter()
            .any(|r| r.prefix == Prefix::V4(prefix));
    }
    assert!(dumped, "the deferred dump reads the current dataset");
}

/// LAN-2512: a reload during a mass reconnect finds every cohort member's
/// registration deferred after the peer manager prepared the destination
/// group. The all-skipped cohort releases that preparation (nothing will adopt
/// it, and the caller discards only on failure), and each member registers on
/// the new chain.
#[tokio::test]
async fn all_deferred_cohort_releases_prepared_destination() {
    use rustbgpd_policy::PolicyAction;
    let (tx, rx) = mpsc::channel(64);
    let old = policy_chain(PolicyAction::Permit);
    let new = policy_chain(PolicyAction::Deny);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(old.clone()),
        None,
        BgpMetrics::new(),
    );
    manager.initial_dump_defer_min_routes = 0;
    let members = [
        peer_v4(Ipv4Addr::new(10, 0, 0, 1)),
        peer_v4(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 9));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 9, 0), 24);
    let mut first_sessions = Vec::new();
    for (session_id, &peer) in (1..).zip(&members) {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        manager.handle_update(test_peer_up(peer, session_id, outbound_tx));
        first_sessions.push(outbound_rx);
    }
    manager.handle_update(test_routes_received(
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 9))],
    ));
    drain_route_chunks(&mut manager);

    let (reply, prepared) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
        peer: members[0],
        export_policy: Some(new.clone()),
        reply,
    });
    while manager.pending_destination_prestage.is_some() {
        manager.advance_destination_prestage();
    }
    assert_eq!(prepared.await.unwrap(), Ok(()));
    let destination = manager
        .prepared_destination
        .expect("the preparation staged a destination");

    // Mass reconnect: both members drop and re-establish behind queued work,
    // then each session accepts the new chain.
    for (session_id, &peer) in (1..).zip(&members) {
        manager.handle_update(RibUpdate::PeerDown { peer, session_id });
    }
    tx.try_send(test_routes_received(source, vec![])).unwrap();
    let mut receivers = Vec::new();
    for (session_id, &peer) in (3..).zip(&members) {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        manager.handle_update(test_peer_up(peer, session_id, outbound_tx));
        manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
            peer,
            session_id,
            export_policy: Some(new.clone()),
        });
        receivers.push(outbound_rx);
    }
    assert_eq!(manager.pending_initial_registrations.len(), members.len());

    let (reply, response) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
        replacements: members
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(new.clone()),
            })
            .collect(),
        reply,
    });
    assert_eq!(
        response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    assert!(manager.pending_clean_policy_transition.is_none());
    assert_eq!(manager.prepared_destination, None, "no leaked preparation");
    assert!(manager.prestaged_inventory.is_none(), "no leaked inventory");
    assert!(
        !manager.group_ribs.contains_key(&destination),
        "the memberless prepared group is removed"
    );

    while manager.drain_ready_updates().await {}
    while !manager.pending_initial_registrations.is_empty() {
        manager.advance_pending_initial_registration();
    }
    for (&peer, receiver) in members.iter().zip(&mut receivers) {
        assert!(manager.outbound_peers.contains_key(&peer));
        assert_eq!(manager.export_chains[&peer], Some(new.clone()));
        let mut saw_eor = false;
        while let Ok(update) = receiver.try_recv() {
            assert!(
                update.announce.is_empty(),
                "{peer}: dump uses the new chain"
            );
            saw_eor |= !update.end_of_rib.is_empty();
        }
        assert!(saw_eor, "{peer}: initial dump completed");
    }
}

/// End-to-end through the run loop: a reconnect burst (`PeerUp`s and the
/// re-announcements queued behind them) still delivers the re-announced
/// routes to the survivor AND completes every deferred initial dump.
#[tokio::test]
async fn run_loop_advances_deferred_registrations() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let handle = tokio::spawn(manager.run());

    let survivor = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let (survivor_tx, mut survivor_rx) = mpsc::channel(64);
    tx.send(test_peer_up(survivor, 1, survivor_tx))
        .await
        .unwrap();
    drain_eor(&mut survivor_rx).await;

    // Reconnect burst: two peers re-establish and re-announce.
    let r1 = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let r2 = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    let (r1_tx, mut r1_rx) = mpsc::channel(64);
    let (r2_tx, mut r2_rx) = mpsc::channel(64);
    tx.send(test_peer_up(r1, 2, r1_tx)).await.unwrap();
    tx.send(test_peer_up(r2, 3, r2_tx)).await.unwrap();
    tx.send(test_routes_received(
        r1,
        vec![make_route(p1, Ipv4Addr::new(10, 0, 0, 2))],
    ))
    .await
    .unwrap();
    tx.send(test_routes_received(
        r2,
        vec![make_route(p2, Ipv4Addr::new(10, 0, 0, 3))],
    ))
    .await
    .unwrap();

    // The survivor receives both re-announced prefixes...
    let deadline = std::time::Duration::from_secs(5);
    let mut seen = HashSet::new();
    while seen.len() < 2 {
        let update = tokio::time::timeout(deadline, survivor_rx.recv())
            .await
            .expect("survivor delivery must not stall")
            .unwrap();
        for route in update.announce.iter() {
            seen.insert(route.prefix);
        }
    }
    assert!(seen.contains(&Prefix::V4(p1)) && seen.contains(&Prefix::V4(p2)));

    // ...and both reconnecting peers' deferred initial dumps complete
    // (liveness: the run loop advances the queue), ending in EoR.
    for rx in [&mut r1_rx, &mut r2_rx] {
        let mut saw_eor = false;
        while !saw_eor {
            let update = tokio::time::timeout(deadline, rx.recv())
                .await
                .expect("deferred initial dump must complete from the run loop")
                .unwrap();
            saw_eor = !update.end_of_rib.is_empty();
        }
    }

    drop(tx);
    handle.await.unwrap();
}

/// The scope an event or disposition reports is the active registration's
/// (the newest live session), never an older collision session's.
#[test]
fn session_peer_scope_reads_only_the_active_session() {
    use crate::update::PeerSourceContext;
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
    let context = |interface: Option<&str>| {
        Arc::new(PeerSourceContext {
            dampening_admission: None,
            peer_interface: interface.map(str::to_string),
            accepted_dynamic_range: None,
            route_server_client: false,
        })
    };
    let (older_tx, _older_rx) = mpsc::channel(64);
    let (newer_tx, _newer_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 1,
        context: context(Some("eth0")),
    });
    manager.handle_update(session_peer_up(peer, 1, older_tx, ipv4_sendable()));
    assert_eq!(
        manager.session_peer_scope(peer).peer_interface().as_deref(),
        Some("eth0")
    );
    // The installed export chain reports the same scope, so ComparePolicy
    // can refuse a chain that belongs to another interface.
    let installed_interface = |manager: &mut RibManager| {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        manager.handle_update(RibUpdate::QueryInstalledExportChain { peer, reply });
        answer
            .try_recv()
            .unwrap()
            .expect("registered peer")
            .peer_interface
    };
    assert_eq!(installed_interface(&mut manager).as_deref(), Some("eth0"));
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 2,
        context: context(None),
    });
    manager.handle_update(session_peer_up(peer, 2, newer_tx, ipv4_sendable()));
    assert_eq!(manager.live_sessions[&peer].len(), 2);
    assert_eq!(
        manager.session_peer_scope(peer),
        crate::route::AspaContextId::DEFAULT
    );
    assert_eq!(installed_interface(&mut manager), None);
}

#[tokio::test]
async fn accepted_source_context_survives_collision_failback_and_stamps_pending_input() {
    use crate::update::{AcceptedDynamicRange, PeerSourceContext};
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
    let context = Arc::new(PeerSourceContext {
        dampening_admission: None,
        peer_interface: Some("eth1".into()),
        accepted_dynamic_range: Some(AcceptedDynamicRange {
            addr: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            peer_group: "members".into(),
        }),
        route_server_client: true,
    });
    let (winner_tx, _winner_rx) = mpsc::channel(64);
    let (loser_tx, _loser_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 1,
        context: context.clone(),
    });
    manager.handle_update(session_peer_up(peer, 1, winner_tx, ipv4_sendable()));
    let loser_context = Arc::new(PeerSourceContext {
        accepted_dynamic_range: Some(AcceptedDynamicRange {
            addr: "192.0.0.0".parse().unwrap(),
            prefix_len: 16,
            peer_group: "replacement".into(),
        }),
        ..(*context).clone()
    });
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 2,
        context: loser_context,
    });
    manager.handle_update(session_peer_up(peer, 2, loser_tx, ipv4_sendable()));
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    });
    let survivor = &manager.live_sessions[&peer][0];
    assert_eq!(survivor.session_id, 1);
    assert_eq!(survivor.source_context, Some(context.clone()));
    let peer_asn = survivor.peer_asn;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        session_id: 1,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    let admitted = manager.pending_route_batches.back().unwrap().source.clone();
    assert_eq!(admitted.session_id, 1);
    assert_eq!(admitted.peer_asn, Some(peer_asn));
    assert_eq!(admitted.context, Some(context));
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    assert!(!manager.live_sessions.contains_key(&peer));
    assert!(manager.pending_peer_source_context.is_empty());
    assert_eq!(
        admitted.session_id, 1,
        "the captured batch is independent of later teardown"
    );
}

#[tokio::test]
async fn repeated_peer_up_preserves_only_matching_source_context() {
    use crate::update::PeerSourceContext;
    for session_id in [0, 7] {
        for (next_id, replacement) in [
            (session_id, false),
            (session_id, true),
            (session_id + 1, false),
        ] {
            let (_tx, rx) = mpsc::channel(64);
            let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
            let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
            let context = Arc::new(PeerSourceContext {
                dampening_admission: None,
                peer_interface: Some("eth1".into()),
                accepted_dynamic_range: None,
                route_server_client: false,
            });
            manager.handle_update(RibUpdate::SetPeerSourceContext {
                peer,
                session_id,
                context: context.clone(),
            });
            let (initial_tx, _initial_rx) = mpsc::channel(64);
            manager.handle_update(session_peer_up(
                peer,
                session_id,
                initial_tx,
                ipv4_sendable(),
            ));
            let expected = if replacement {
                let replacement = Arc::new(PeerSourceContext {
                    peer_interface: Some("eth2".into()),
                    ..(*context).clone()
                });
                manager.handle_update(RibUpdate::SetPeerSourceContext {
                    peer,
                    session_id: next_id,
                    context: replacement.clone(),
                });
                Some(replacement)
            } else {
                (next_id == session_id).then_some(context)
            };
            let (next_tx, _next_rx) = mpsc::channel(64);
            manager.handle_update(session_peer_up(peer, next_id, next_tx, ipv4_sendable()));
            manager.handle_update(RibUpdate::RoutesReceived {
                peer,
                session_id: next_id,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            });
            let admitted = &manager.pending_route_batches.back().unwrap().source;
            assert_eq!(admitted.session_id, next_id);
            assert_eq!(admitted.context, expected);
            if let Some(expected) = expected {
                assert!(Arc::ptr_eq(admitted.context.as_ref().unwrap(), &expected));
            }
        }
    }
}

#[tokio::test]
async fn ending_session_preserves_newer_staged_registration_context() {
    use crate::update::PeerSourceContext;
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
    let (old_tx, _old_rx) = mpsc::channel(64);
    manager.handle_update(session_peer_up(peer, 1, old_tx, ipv4_sendable()));
    let context = Arc::new(PeerSourceContext {
        dampening_admission: None,
        peer_interface: Some("eth2".into()),
        accepted_dynamic_range: None,
        route_server_client: false,
    });
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 2,
        context: context.clone(),
    });
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 2,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: ipv4_sendable(),
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 30,
    });
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 2,
        rs_control_asn: Some(65001),
    });
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 2,
        local_role: Some(rustbgpd_wire::BgpRole::Provider),
    });
    let encoder: Arc<dyn crate::update::ExactExportEncoder> =
        super::exportability::MockExactExportEncoder::accepting(1);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 2,
        encoder: encoder.clone(),
    });
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 2,
        peer_group: Some("replacement".into()),
    });
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    let (new_tx, _new_rx) = mpsc::channel(64);
    manager.handle_update(session_peer_up(peer, 2, new_tx, ipv4_sendable()));
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("replacement")
    );
    let record = &manager.live_sessions[&peer][0];
    assert_eq!(record.source_context, Some(context));
    assert!(record.gr_context.as_ref().unwrap().peer_enhanced_refresh);
    assert_eq!(record.rs_control_asn, Some(65001));
    assert_eq!(record.local_role, Some(rustbgpd_wire::BgpRole::Provider));
    assert!(Arc::ptr_eq(
        record.exact_export_encoder.as_ref().unwrap(),
        &encoder,
    ));
    assert!(manager.pending_peer_source_context.is_empty());
}

#[tokio::test]
async fn aborted_registration_reaps_only_its_own_staged_source_context() {
    use crate::update::PeerSourceContext;
    for registered in [false, true] {
        for graceful in [false, true] {
            let (_tx, rx) = mpsc::channel(64);
            let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
            let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
            let (active_tx, _active_rx) = mpsc::channel(64);
            if registered {
                manager.handle_update(session_peer_up(peer, 99, active_tx, ipv4_sendable()));
            }
            for session_id in [1, 2] {
                manager.handle_update(RibUpdate::SetPeerSourceContext {
                    peer,
                    session_id,
                    context: Arc::new(PeerSourceContext {
                        dampening_admission: None,
                        peer_interface: None,
                        accepted_dynamic_range: None,
                        route_server_client: false,
                    }),
                });
            }
            for session_id in [1, 2] {
                manager.handle_update(RibUpdate::SetPeerPolicyContext {
                    peer,
                    session_id,
                    peer_group: Some(format!("group-{session_id}")),
                });
            }
            if graceful {
                manager.handle_update(RibUpdate::PeerGracefulRestart {
                    peer,
                    session_id: 1,
                    restart_time: 30,
                    stale_routes_time: 30,
                    gr_families: ipv4_sendable(),
                    peer_llgr_capable: false,
                    peer_llgr_families: vec![],
                    llgr_stale_time: 0,
                });
            } else {
                manager.handle_update(RibUpdate::PeerDown {
                    peer,
                    session_id: 1,
                });
            }
            assert!(!manager.pending_peer_source_context.contains_key(&(peer, 1)));
            assert!(manager.pending_peer_source_context.contains_key(&(peer, 2)));
            assert!(!manager.pending_peer_policy_context.contains_key(&(peer, 1)));
            assert!(manager.pending_peer_policy_context.contains_key(&(peer, 2)));
            if registered {
                assert_eq!(manager.live_sessions[&peer][0].session_id, 99);
            }
            manager.handle_update(RibUpdate::PeerDeleted { peer, label: None });
            assert!(manager.pending_peer_source_context.is_empty());
            assert!(manager.pending_peer_policy_context.is_empty());
        }
    }
}

#[tokio::test]
async fn live_peer_policy_context_follows_failback_without_publishing_standby_updates() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
    let (first_tx, _first_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 1,
        peer_group: Some("first".into()),
    });
    manager.handle_update(session_peer_up(peer, 1, first_tx, ipv4_sendable()));
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 1,
        peer_group: Some("first-current".into()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("first-current")
    );
    let (second_tx, _second_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 2,
        peer_group: Some("second".into()),
    });
    manager.handle_update(session_peer_up(peer, 2, second_tx, ipv4_sendable()));
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("second")
    );
    let before = (
        manager.peer_group_version,
        manager.route_page_advertised_version,
    );
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 1,
        peer_group: Some("first-standby".into()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("second")
    );
    assert_eq!(
        (
            manager.peer_group_version,
            manager.route_page_advertised_version
        ),
        before
    );
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("first-standby")
    );
    let before = (
        manager.peer_group_version,
        manager.route_page_advertised_version,
    );
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 2,
        peer_group: Some("ended".into()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("first-standby")
    );
    assert_eq!(
        (
            manager.peer_group_version,
            manager.route_page_advertised_version
        ),
        before
    );
}
