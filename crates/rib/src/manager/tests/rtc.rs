use super::*;

fn with_rtc_no_advertise(mut route: crate::route::RtcRibRoute) -> crate::route::RtcRibRoute {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
    ]));
    route
}

fn rtc_no_advertise_policy(next_hop: IpAddr, add: bool) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Permit,
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
            match_next_hop: Some(next_hop),
            modifications: rustbgpd_policy::RouteModifications {
                communities_add: add
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                communities_remove: (!add)
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                ..rustbgpd_policy::RouteModifications::default()
            },
        }],
        // The locally originated default RTC NLRI has an unspecified next
        // hop, so this narrow fixture never changes or suppresses it.
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

/// Received RTC routes land in the typed Adj-RIB-In / Loc-RIB and are
/// queryable through `QueryRtcRoutes`.
#[tokio::test]
async fn rtc_routes_received_stored_and_queryable() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].nlri, route.nlri);
    assert_eq!(stored[0].peer, source);
    assert_eq!(stored[0].nlri.prefix_len, 96);

    drop(tx);
    handle.await.unwrap();
}

/// A withdraw for a stored RTC key removes it from the Loc-RIB.
#[tokio::test]
async fn rtc_withdraw_removes_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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
    assert_eq!(query_rtc_routes(&tx).await.len(), 1);

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    assert!(query_rtc_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// A peer-advertised default (zero-length) RTC NLRI is a valid route
/// identity of its own.
#[tokio::test]
async fn rtc_default_nlri_stored() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 0, 100);
    route.nlri = rustbgpd_wire::RtcNlri::DEFAULT;
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].nlri.is_default());
    assert_eq!(stored[0].peer, source);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4684 §3.2: RTC routes reflect between iBGP RR clients through the
/// shared reflection machinery (`ORIGINATOR_ID` / `CLUSTER_LIST` are
/// attached by transport's `prepare_outbound_attributes_rtc`, pinned in
/// the transport tests).
#[tokio::test]
async fn rtc_route_reflects_between_ibgp_clients_with_originator_and_cluster_list() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut a_rx = rtc_peer_up(&tx, client_a, false, true).await;
    drain_rtc_initial_dump(&mut a_rx).await;
    let mut b_rx = rtc_peer_up(&tx, client_b, false, true).await;
    drain_rtc_initial_dump(&mut b_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: client_a,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = b_rx.recv().await.unwrap();
    assert_eq!(reflected.rtc_announce.len(), 1);
    assert_eq!(reflected.rtc_announce[0].key(), key);
    assert_eq!(
        reflected.rtc_announce[0].nlri, route.nlri,
        "membership NLRI must pass through reflection verbatim"
    );
    assert_eq!(
        reflected.rtc_announce[0].peer_router_id,
        route.peer_router_id
    );
    assert_eq!(
        reflected.rtc_announce[0].origin_type,
        crate::route::RouteOrigin::Ibgp,
        "reflected route keeps iBGP origin so transport attaches ORIGINATOR_ID/CLUSTER_LIST"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RT-Constrain enforces RFC 1997 before and after export policy, withdraws
/// the exact prior Adj-RIB-Out identity, and re-announces after either scope is
/// removed without disturbing the locally originated default RTC NLRI.
///
/// Break-to-red: deleting the pre-policy guard lets the removal policy export
/// the source-scoped route; deleting the post-policy guard retains the route
/// when policy adds `NO_ADVERTISE`; deleting either existing-state withdrawal
/// leaves the exact key advertised; making suppression sticky prevents the two
/// recovery announcements.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered state-machine regression proves suppression, withdrawal, and recovery"
)]
async fn rtc_no_advertise_withdraws_exact_prior_and_recovers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source = Ipv4Addr::new(198, 51, 100, 10);
    let source_ip = IpAddr::V4(source);
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(rtc_no_advertise_policy(source_ip, false)),
        sendable_families: rtc_sendable(),
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
    drain_rtc_initial_dump(&mut out_rx).await;

    let route = make_rtc_rib_route(source, 442, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_rtc_routes(&tx).await;
    let initial = out_rx
        .try_recv()
        .expect("plain RTC route must be announced");
    assert_eq!(initial.rtc_announce.len(), 1);
    assert_eq!(initial.rtc_announce[0].key(), key);

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![with_rtc_no_advertise(route.clone())],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_rtc_routes(&tx).await;
    let source_scoped = out_rx
        .try_recv()
        .expect("source NO_ADVERTISE must withdraw the prior RTC route");
    assert!(source_scoped.rtc_announce.is_empty());
    assert_eq!(source_scoped.rtc_withdraw, vec![key.clone()]);

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_rtc_routes(&tx).await;
    let source_recovered = out_rx.try_recv().expect("plain RTC route must recover");
    assert_eq!(source_recovered.rtc_announce.len(), 1);
    assert!(source_recovered.rtc_withdraw.is_empty());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(rtc_no_advertise_policy(source_ip, true)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_rtc_routes(&tx).await;
    let policy_scoped = out_rx
        .try_recv()
        .expect("policy-added NO_ADVERTISE must withdraw the RTC route");
    assert!(policy_scoped.rtc_announce.is_empty());
    assert_eq!(policy_scoped.rtc_withdraw, vec![key]);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(rtc_no_advertise_policy(source_ip, false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_rtc_routes(&tx).await;
    let policy_recovered = out_rx
        .try_recv()
        .expect("removing policy-added NO_ADVERTISE must re-announce RTC");
    assert_eq!(policy_recovered.rtc_announce.len(), 1);
    assert!(policy_recovered.rtc_withdraw.is_empty());
    assert!(out_rx.try_recv().is_err(), "default RTC must not churn");

    drop(tx);
    handle.await.unwrap();
}

/// Split horizon: an RTC route is never echoed back to its source.
#[tokio::test]
async fn rtc_route_not_reflected_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut source_rx = rtc_peer_up(&tx, source, false, true).await;
    drain_rtc_initial_dump(&mut source_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let echo = tokio::time::timeout(Duration::from_millis(50), source_rx.recv()).await;
    assert!(
        echo.is_err(),
        "RTC routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4456: an iBGP route learned from a non-client is reflected to
/// clients only — another non-client must not receive it.
#[tokio::test]
async fn rtc_route_suppressed_nonclient_to_nonclient() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let non_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut source_rx = rtc_peer_up(&tx, source, false, false).await;
    drain_rtc_initial_dump(&mut source_rx).await;
    let mut non_client_rx = rtc_peer_up(&tx, non_client, false, false).await;
    drain_rtc_initial_dump(&mut non_client_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let echo = tokio::time::timeout(Duration::from_millis(50), non_client_rx.recv()).await;
    assert!(
        echo.is_err(),
        "non-client iBGP RTC route must not be reflected to another non-client"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that comes up after RTC state converged must receive the full
/// SAFI-132 table (peer routes + local default) in its initial dump,
/// followed by the SAFI-132 `EoR` — without any GR involvement (RFC 4684
/// §5: RTC `EoR` SHOULD be sent regardless of GR).
#[tokio::test]
async fn send_initial_table_includes_rtc_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(
        update.rtc_announce.iter().any(|r| r.key() == key),
        "initial dump must carry the converged RTC table"
    );
    assert!(
        update.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "initial dump must carry the locally-originated default"
    );
    assert!(update.rtc_withdraw.is_empty());

    // EoR pin: emitted for (IPv4, RtConstrain) with no GR state at all.
    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, rtc_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// The first RTC-capable peer-up lazily originates the local default NLRI
/// (wildcard RT interest) and delivers it in that peer's initial dump.
#[tokio::test]
async fn peer_up_with_rtc_family_originates_default_rtc_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.rtc_announce.len(), 1);
    let default = &update.rtc_announce[0];
    assert!(default.nlri.is_default());
    assert_eq!(default.origin_type, crate::route::RouteOrigin::Local);
    assert!(
        default.next_hop.is_unspecified(),
        "local default stores an unspecified next-hop; transport emits the session-local address"
    );
    // AS_PATH is well-known mandatory even when empty: without it, RFC 7606
    // peers treat-as-withdraw the default-RTC UPDATE and never send the RR
    // their VPN routes (M75 regression).
    assert!(
        default
            .attributes
            .iter()
            .any(|attr| matches!(attr, rustbgpd_wire::PathAttribute::AsPath(_))),
        "locally-originated default RTC NLRI must carry an (empty) AS_PATH"
    );

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, rtc_sendable());

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer without the RTC family must not trigger default origination.
#[tokio::test]
async fn default_rtc_not_originated_to_non_rtc_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
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

    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "default RTC origination is lazy: no RTC peer, no default"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Repeated RTC peer-ups (flap or additional peers) must not duplicate the
/// local default NLRI.
#[tokio::test]
async fn default_rtc_origination_idempotent_across_peer_ups() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    // Same peer returns; a second RTC peer joins too.
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut second_rx = rtc_peer_up(&tx, second, true, false).await;
    drain_rtc_initial_dump(&mut second_rx).await;

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(
        stored.len(),
        1,
        "default origination must be idempotent across peer-ups"
    );
    assert!(stored[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// LAN-190 §B: the locally-originated default RTC NLRI is intentionally
/// retained when the LAST RTC peer drops — it lives in the synthetic
/// `LOCAL_PEER` RIB, which peer teardown never touches — and is
/// re-advertised for free when an RTC peer returns. No withdraw is emitted.
#[tokio::test]
async fn default_rtc_retained_after_last_rtc_peer_drops_and_readvertised_on_return() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // The only RTC peer comes up: default is originated and advertised.
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    // The last (and only) RTC peer drops.
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    // The default RTC NLRI is retained, not withdrawn: still originated with
    // no RTC peer remaining.
    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1, "default RTC NLRI must be retained");
    assert!(stored[0].nlri.is_default());
    assert_eq!(stored[0].origin_type, crate::route::RouteOrigin::Local);

    // An RTC peer returns: the retained default is re-advertised in its
    // initial dump — no re-origination churn, the entry was never dropped.
    let mut return_rx = rtc_peer_up(&tx, peer, true, false).await;
    let dump = return_rx.recv().await.unwrap();
    assert!(
        dump.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "returning RTC peer must receive the retained default NLRI"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Peer teardown removes the departed peer's RTC routes and withdraws them
/// from remaining peers.
#[tokio::test]
async fn peer_down_withdraws_rtc_routes_from_other_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
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
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.rtc_announce.is_empty());
    assert_eq!(withdraw.rtc_withdraw, vec![key]);

    // Only the local default survives (LOCAL_PEER is not a session).
    let remaining = query_rtc_routes(&tx).await;
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (IPv4, `RtConstrain`) must have
/// its RTC routes withdrawn on GR entry — RFC 4724 retains only families in
/// the advertised capability.
#[tokio::test]
async fn rtc_gr_family_not_in_capability_is_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
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
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    // GR entry with only unicast in the capability: SAFI 132 is not
    // covered, so the peer's RTC routes are withdrawn, not marked stale.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert_eq!(
        withdraw.rtc_withdraw,
        vec![key],
        "GR entry must withdraw RTC routes absent from the capability"
    );

    let remaining = query_rtc_routes(&tx).await;
    assert_eq!(
        remaining.len(),
        1,
        "only the local default survives GR entry"
    );
    assert!(remaining[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer entering GR with (IPv4, `RtConstrain`) in its capability keeps its
/// RTC routes as stale: they stay in the Loc-RIB (demoted-rank candidates)
/// and are NOT withdrawn from other RTC peers.
#[tokio::test]
async fn rtc_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
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
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let retained = query_rtc_routes(&tx).await;
    let stale_route = retained
        .iter()
        .find(|r| r.key() == key)
        .expect("GR-covered RTC route must be retained in the Loc-RIB");
    assert!(stale_route.is_stale, "retained RTC route must be stale");

    // No withdraw may reach the other RTC peer during the retention window
    // (a benign re-announce of the unchanged route is tolerated).
    while let Ok(Some(update)) =
        tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await
    {
        assert!(
            update.rtc_withdraw.is_empty(),
            "GR-preserved RTC routes must not be withdrawn from other peers"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// End-of-RIB after re-establishment clears the re-advertised RTC route's
/// stale flag and removes (and withdraws downstream) interest that was not
/// re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn rtc_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let dropped = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 200, 100);
    let kept_key = kept.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 2);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept],
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
        "the non-readvertised stale RTC route must be removed at End-of-RIB"
    );
    let kept_route = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised RTC route survives EoR");
    assert!(!kept_route.is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale RTC routes and withdraws
/// them from other peers.
#[tokio::test]
async fn rtc_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let retained = query_rtc_routes(&tx).await;
    assert!(retained.iter().any(|r| r.key() == key && r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let after_sweep = query_rtc_routes(&tx).await;
    assert!(
        after_sweep.iter().all(|r| r.key() != key),
        "GR timer expiry must sweep stale RTC routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while RTC routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts) and the
/// deletion is withdrawn from other RTC peers.
#[tokio::test]
async fn rtc_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
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
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let retained = query_rtc_routes(&tx).await;
    assert!(retained.iter().any(|r| r.key() == key && r.is_stale));

    tx.send(gr_entry()).await.unwrap();
    let after_second = query_rtc_routes(&tx).await;
    assert!(
        after_second.iter().all(|r| r.key() != key),
        "a route still stale at the next restart must be deleted"
    );
    // Skip any benign re-announce staged by the first GR entry; the
    // deletion itself must surface as a downstream withdraw.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.rtc_withdraw.is_empty() {
            continue;
        }
        assert_eq!(
            update.rtc_withdraw,
            vec![key],
            "the consecutive-restart deletion must be withdrawn downstream"
        );
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// A plain ROUTE-REFRESH request for (IPv4, `RtConstrain`) must replay the
/// staged RTC routes between the BoRR/EoRR markers.
#[tokio::test]
async fn route_refresh_rtc_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        update.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "refresh replay must re-send the local default"
    );
    assert_eq!(update.end_of_rib, rtc_sendable());
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::Ipv4,
                Safi::RtConstrain,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::Ipv4,
                Safi::RtConstrain,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RFC 4684 VPN reflection filter (RT-Constrain membership) ---

/// An RT membership route from `peer` carrying an arbitrary NLRI.
fn make_rtc_rib_route_with_nlri(
    peer: Ipv4Addr,
    nlri: rustbgpd_wire::RtcNlri,
) -> crate::route::RtcRibRoute {
    let mut route = make_rtc_rib_route(peer, 0, 100);
    route.nlri = nlri;
    route
}

/// SAFI 132 negotiated + no RTC interest received ⇒ NO VPN routes advertised
/// (the strict rule) — the initial dump stages zero VPN routes.
#[tokio::test]
async fn vpn_not_advertised_to_rtc_peer_with_empty_membership() {
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

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = vpn_rtc_peer_up(&tx, target).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

/// LAN-190 §E: `rtc_vpn_filter` resolves the RFC 4684 VPN outbound filter
/// directly. Two contracts pinned: (1) an RTC-negotiated peer with no
/// membership recorded resolves to the STRICT EMPTY filter (advertise
/// nothing), never fail-open; (2) the filter keys off the `sendable`
/// ARGUMENT, so a stale `peer_sendable_families` entry is harmless — a
/// sendable set lacking RTC resolves to `None` (unfiltered) even when a
/// membership is still recorded for the peer.
#[test]
fn rtc_vpn_filter_strict_empty_and_argument_driven() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let sendable_rtc = vec![crate::route::RtcRibRouteKey::afi_safi()];
    let sendable_no_rtc = vec![(Afi::Ipv4, Safi::Unicast)];

    // (1) RTC negotiated, no membership recorded → strict empty, not fail-open.
    assert_eq!(
        manager.rtc_vpn_filter(peer, Some(&sendable_rtc)),
        Some(RtcMembership::default()),
        "no membership must resolve to strict empty, not fail-open"
    );

    // A recorded membership is returned verbatim.
    let membership = RtcMembership {
        has_default: true,
        entries: vec![],
    };
    manager.peer_rt_membership.insert(peer, membership.clone());
    assert_eq!(
        manager.rtc_vpn_filter(peer, Some(&sendable_rtc)),
        Some(membership)
    );

    // (2) Argument-driven: a sendable set lacking RTC (or absent) resolves
    // to None even though a membership is still recorded for the peer.
    assert_eq!(manager.rtc_vpn_filter(peer, Some(&sendable_no_rtc)), None);
    assert_eq!(manager.rtc_vpn_filter(peer, None), None);
}

/// When a matching RTC NLRI arrives, the withheld VPN route is announced as a
/// minimal delta — no session reset, and already-correct Adj-RIB-Out state is
/// not re-sent.
#[tokio::test]
async fn vpn_advertised_after_matching_rtc_nlri_arrives_without_reset() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_a = route_a.key();
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert_eq!(first.vpn_announce[0].key(), key_a);
    assert!(first.vpn_withdraw.is_empty());

    // Widening the membership announces ONLY the newly-covered route — the
    // already-advertised one is suppressed by the Adj-RIB-Out equality check.
    send_rtc_interest(&tx, target, &[200]).await;
    let second = out_rx.recv().await.unwrap();
    assert_eq!(second.vpn_announce.len(), 1);
    assert_eq!(second.vpn_announce[0].key(), key_b);
    assert!(second.vpn_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Withdrawing the covering RTC NLRI withdraws the VPN route from that peer.
#[tokio::test]
async fn vpn_withdrawn_when_rtc_nlri_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 62, vec![rt(100)]);
    let vpn_key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
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

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![],
        withdrawn: vec![make_rtc_rib_route(target, 100, 100).key()],
    })
    .await
    .unwrap();
    let withdrawn = out_rx.recv().await.unwrap();
    assert!(withdrawn.vpn_announce.is_empty());
    assert_eq!(withdrawn.vpn_withdraw, vec![vpn_key]);

    drop(tx);
    handle.await.unwrap();
}

/// The zero-length default NLRI is wildcard interest: every VPN route passes,
/// including one with no Route Target extended community at all.
#[tokio::test]
async fn default_rtc_nlri_matches_all_vpn_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]),
            // No extended communities at all — only default interest covers it.
            make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100),
        ],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![make_rtc_rib_route_with_nlri(
            target,
            rustbgpd_wire::RtcNlri::DEFAULT,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.vpn_announce.len(),
        2,
        "default RTC NLRI must admit every VPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A /48 membership NLRI (origin AS + RT type/subtype bytes) admits the whole
/// two-octet-AS RT family regardless of local admin, while an RT of a
/// different type encoding stays filtered — prefix matching is masked, not
/// exact.
#[tokio::test]
async fn rtc_prefix_match_gates_by_masked_bits() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let covered_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let covered_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(999)]);
    // Type 0x01 (IPv4-administrator) Route Target: outside the /48's
    // type/subtype bits, so it must stay filtered.
    let uncovered = make_vpn_rib_route_with_rts(
        Ipv4Addr::new(10, 0, 0, 1),
        62,
        vec![ExtendedCommunity::new(0x0102_0A00_0001_0064)],
    );
    let covered_keys: HashSet<_> = [covered_a.key(), covered_b.key()].into();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![covered_a, covered_b, uncovered],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    // /48 = origin AS 65001 (32 bits) + RT type 0x00 / subtype 0x02 (16 bits).
    let nlri = rustbgpd_wire::RtcNlri::new(65001, 0x0002_0000_0000_0000, 48).unwrap();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![make_rtc_rib_route_with_nlri(target, nlri)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let announced_keys: HashSet<_> = update
        .vpn_announce
        .iter()
        .map(crate::route::VpnRibRoute::key)
        .collect();
    assert_eq!(
        announced_keys, covered_keys,
        "the /48 must admit the whole RT:65001:* family and nothing else"
    );

    drop(tx);
    handle.await.unwrap();
}

/// One membership gates BOTH `VPNv4` and `VPNv6` keys.
#[tokio::test]
async fn rtc_filter_applies_to_both_vpnv4_and_vpnv6() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_covered = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let v6_covered = make_vpn6_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 1, vec![rt(100)]);
    let v4_other = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let v6_other = make_vpn6_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 2, vec![rt(200)]);
    let covered_keys: HashSet<_> = [v4_covered.key(), v6_covered.key()].into();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_covered, v6_covered, v4_other, v6_other],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    let announced_keys: HashSet<_> = update
        .vpn_announce
        .iter()
        .map(crate::route::VpnRibRoute::key)
        .collect();
    assert_eq!(
        announced_keys, covered_keys,
        "the RTC gate must admit the matching VPNv4 AND VPNv6 routes only"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that did NOT negotiate SAFI 132 keeps today's unfiltered VPN
/// reflection — the regression guard for the `None`-filter path.
#[tokio::test]
async fn non_rtc_peer_reflection_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
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

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A VPN route with several Route Targets passes when ANY of them matches
/// the peer's membership.
#[tokio::test]
async fn route_with_any_matching_rt_passes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(555), rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// Membership derives from the peer's OWN Adj-RIB-In — all paths, never the
/// Loc-RIB best: when two peers advertise the same RTC NLRI, the tiebreak
/// loser's interest still opens its VPN filter.
#[tokio::test]
async fn membership_rebuilt_from_all_adjribin_paths_not_locrib_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let winner = Ipv4Addr::new(10, 0, 0, 2);
    let loser = Ipv4Addr::new(10, 0, 0, 3);
    let mut winner_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(winner)).await;
    drain_strict_vpn_rtc_initial_dump(&mut winner_rx).await;
    let mut loser_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(loser)).await;
    drain_strict_vpn_rtc_initial_dump(&mut loser_rx).await;

    // Winner's copy of the NLRI takes the Loc-RIB tiebreak (higher LOCAL_PREF)
    // and gets reflected to the loser.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(winner),
        announced: vec![make_rtc_rib_route(winner, 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let winner_vpn = winner_rx.recv().await.unwrap();
    assert_eq!(winner_vpn.vpn_announce.len(), 1);
    let reflected = loser_rx.recv().await.unwrap();
    assert_eq!(reflected.rtc_announce.len(), 1);

    // The loser advertises the SAME NLRI with a losing LOCAL_PREF: the
    // Loc-RIB best is unchanged, but the loser's own membership must still
    // open — the filter reads the peer's Adj-RIB-In, not the Loc-RIB.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(loser),
        announced: vec![make_rtc_rib_route(loser, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let loser_vpn = loser_rx.recv().await.unwrap();
    assert_eq!(
        loser_vpn.vpn_announce.len(),
        1,
        "tiebreak-losing RTC path must still open the loser's VPN filter"
    );
    assert_eq!(loser_vpn.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// An enhanced-refresh `EoRR` sweep that removes an unreplaced RTC route must
/// shrink the peer's membership and withdraw the now-uncovered VPN route.
#[tokio::test]
async fn rtc_refresh_eorr_sweep_restages_vpn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100, 200]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    tx.send(RibUpdate::BeginRouteRefresh {
        peer: IpAddr::V4(target),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();
    // Only the RT:100 interest is re-announced inside the window; RT:200
    // stays marked stale.
    send_rtc_interest(&tx, target, &[100]).await;
    tx.send(RibUpdate::EndRouteRefresh {
        peer: IpAddr::V4(target),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let swept = out_rx.recv().await.unwrap();
    assert!(swept.vpn_announce.is_empty());
    assert_eq!(
        swept.vpn_withdraw,
        vec![key_b],
        "the EoRR sweep must withdraw the VPN route whose RTC interest was not replayed"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability omits SAFI 132 has its RTC interest withdrawn
/// on GR entry, so it re-establishes with a strict empty membership and only
/// receives VPN routes once its interest re-arrives.
#[tokio::test]
async fn gr_reestablish_without_rtc_in_capability_starts_strict() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
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

    // GR capability covers only VPN — the peer's RTC interest is NOT
    // retained (RFC 4724: only families in the capability are preserved).
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(target),
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish: the strict initial dump proves the membership did not
    // survive the restart — no VPN routes until the interest re-arrives.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let reannounced = out_rx.recv().await.unwrap();
    assert_eq!(reannounced.vpn_announce.len(), 1);
    assert_eq!(reannounced.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability covers SAFI 132 keeps its RT interest as stale
/// through the restart window: the re-establish initial dump serves VPN
/// routes immediately from the preserved membership (no wait for the
/// interest to re-arrive), and the End-of-RIB sweep of interest the peer did
/// NOT re-advertise withdraws the corresponding VPN routes.
#[tokio::test]
async fn rtc_gr_preserves_vpn_membership_through_restart_window() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_a = route_a.key();
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;
    send_rtc_interest(&tx, target, &[100, 200]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    // GR capability covers both VPN and RTC: the peer's RT interest is
    // preserved as stale.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(target),
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish: VPN routes flow in the INITIAL dump, filtered by the
    // stale membership — before any RTC re-advertisement arrives.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    let dump = out_rx.recv().await.unwrap();
    let dumped: Vec<_> = dump.vpn_announce.iter().map(VpnRibRoute::key).collect();
    assert!(
        dumped.contains(&key_a) && dumped.contains(&key_b),
        "the initial dump must serve VPN routes from the GR-preserved membership, got {dumped:?}"
    );

    // The peer re-advertises interest in RT 100 only; RT 200 stays stale.
    send_rtc_interest(&tx, target, &[100]).await;
    // End-of-RIB for SAFI 132 sweeps the non-readvertised interest —
    // membership shrinks and the uncovered VPN route is withdrawn.
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: IpAddr::V4(target),
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(
            update.vpn_withdraw,
            vec![key_b.clone()],
            "the EoR sweep must withdraw the VPN route whose stale interest was not re-advertised"
        );
        assert!(update.vpn_announce.is_empty());
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// The initial table dump to an RTC peer stages zero VPN routes, and the
/// table flows as soon as matching interest arrives — no flap needed.
#[tokio::test]
async fn initial_dump_to_rtc_peer_stages_no_vpn_then_flows_on_interest() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A duplicate RTC announce leaves the rebuilt membership equal to the old
/// one and must NOT trigger a dirty resync — nothing is re-sent.
#[tokio::test]
async fn rtc_membership_unchanged_skips_restage() {
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
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);

    // Duplicate announce: membership rebuild compares equal — no restage.
    send_rtc_interest(&tx, target, &[100]).await;
    let resend = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        resend.is_err(),
        "unchanged RTC membership must skip the dirty resync entirely"
    );

    drop(tx);
    handle.await.unwrap();
}
