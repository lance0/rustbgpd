use super::*;

fn orf_permit(seq: u32, min: u8, max: u8, p: Ipv4Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Permit,
        sequence: seq,
        min_len: min,
        max_len: max,
        prefix: Some(Prefix::V4(p)),
    }
}

fn orf_deny(seq: u32, min: u8, max: u8, p: Ipv4Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Deny,
        sequence: seq,
        min_len: min,
        max_len: max,
        prefix: Some(Prefix::V4(p)),
    }
}

async fn send_peer_orf(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    when: WhenToRefresh,
    entries: Vec<AddressPrefixOrf>,
) {
    let (rtx, rrx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when,
        entries,
        reply: rtx,
    })
    .await
    .unwrap();
    rrx.await.unwrap().unwrap();
}

/// Drain outbound updates until `count` prefixes have been announced.
async fn collect_announced(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    count: usize,
) -> Vec<Prefix> {
    let mut prefixes = Vec::new();
    while prefixes.len() < count {
        let u = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("outbound update should arrive")
            .expect("outbound channel open");
        prefixes.extend(u.announce.iter().map(|r| r.prefix));
    }
    prefixes
}

/// Drain outbound updates until `prefix` has been announced.
async fn collect_until_announced(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>, prefix: Prefix) {
    let deadline = Duration::from_secs(5);
    let result = tokio::time::timeout(deadline, async {
        loop {
            let u = out_rx.recv().await.expect("outbound channel open");
            if u.announce.iter().any(|route| route.prefix == prefix) {
                break;
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "expected {prefix:?} to be announced within {deadline:?}"
    );
}

/// Set up a manager with two routes (10/8, 192.168/16) in the Loc-RIB and a
/// gated ORF-receive target peer; returns the tx, the target peer, and the
/// target's outbound receiver after draining the (route-less) initial `EoR`.
async fn orf_setup() -> (
    mpsc::Sender<RibUpdate>,
    tokio::task::JoinHandle<()>,
    IpAddr,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![(Afi::Ipv4, Safi::Unicast)],
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // RFC 5291 §6 gate: the initial dump must advertise no routes for the
    // gated family — only the EoR marker.
    let initial = out_rx.recv().await.unwrap();
    assert!(
        initial.announce.is_empty(),
        "gated family must not advertise routes initially, got {}",
        initial.announce.len()
    );
    assert!(
        !initial.end_of_rib.is_empty(),
        "EoR still sent for gated family"
    );

    (tx, handle, target, out_rx)
}

#[tokio::test]
async fn orf_gate_lifts_and_floods_filtered_table() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Permit everything (0/0 le 32) ⇒ gate lifts, both routes flood.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 2).await;
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))));
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_filter_constrains_advertised_set() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Permit only 10/8 (le 32); 192.168/16 is not covered ⇒ implicit deny.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 1).await;
    assert_eq!(
        announced,
        vec![Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))]
    );
    // No further announce: 192.168/16 must stay filtered out.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "192.168/16 must not be advertised under a 10/8-only ORF"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_immediate_withdraws_now_denied_prefix() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // Now tighten: permit only 10/8 (IMMEDIATE) → 192.168/16 must be withdrawn.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let mut withdrawn = Vec::new();
    while withdrawn.is_empty() {
        let u = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("withdraw should arrive")
            .unwrap();
        withdrawn.extend(u.withdraw.iter().map(|(p, _)| *p));
    }
    assert!(withdrawn.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_defer_does_not_sweep_existing_routes() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // DEFER deny-all: filter installs, but the existing advertised routes are
    // NOT swept (RFC 5291 When-to-refresh). No outbound update should arrive.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Defer,
        vec![orf_deny(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "DEFER must not sweep already-advertised routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_defer_then_plain_refresh_withdraws_now_denied_prefix() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // Install a deferred filter that keeps 10/8 and denies everything else.
    // DEFER itself must not sweep.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Defer,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "DEFER must not sweep already-advertised routes"
    );

    // A later plain ROUTE-REFRESH is the deferred sweep point: permitted routes
    // are re-advertised and previously-advertised routes denied by the installed
    // ORF must be explicitly withdrawn.
    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let denied = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16));
    let mut withdrawn = Vec::new();
    while withdrawn.is_empty() {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("refresh response should arrive")
            .expect("outbound channel open");
        withdrawn.extend(update.withdraw.iter().map(|(p, _)| *p));
    }
    assert!(
        withdrawn.contains(&denied),
        "plain refresh after deferred ORF must withdraw the denied prefix"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_unknown_when_resets_filter_and_sweeps() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // First install a restrictive ORF that permits only 10/8, proving the
    // 192.168/16 route is currently suppressed.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 1).await;
    assert_eq!(
        announced,
        vec![Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "192.168/16 must be suppressed before the malformed ORF control update"
    );

    // RFC 5291 only defines IMMEDIATE and DEFER. An unknown timing value must
    // not silently install the peer's entries as deferred state; reset the
    // negotiated ORF list and force a safe resync.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Unknown(0x7f),
        vec![orf_deny(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    collect_until_announced(
        &mut out_rx,
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16)),
    )
    .await;

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a graceful-restart flap must clear the RFC 5291 §6
/// initial-advertisement gate. The gate is per-session; previously
/// `handle_peer_graceful_restart` left `peer_orf_pending` populated, so a
/// peer re-establishing WITHOUT ORF inherited the dead session's gate —
/// `send_initial_table` skipped the family and churn stayed suppressed,
/// advertising nothing indefinitely (the new session never negotiated ORF,
/// so it has no reason to send the ROUTE-REFRESH that lifts a gate).
#[tokio::test]
async fn graceful_restart_clears_stale_orf_gate() {
    // orf_setup leaves the target gated (ORF negotiated, no refresh yet).
    let (tx, handle, target, _out_rx) = orf_setup().await;

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish WITHOUT ORF: the initial dump must carry the full table.
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let announced = collect_announced(&mut out_rx, 2).await;
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "post-GR non-ORF session must receive the initial table (stale gate leak)"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a graceful-restart flap must clear the installed ORF filter
/// set. Previously `handle_peer_graceful_restart` left `peer_orf_filters`
/// populated, so a peer re-establishing WITHOUT ORF kept being filtered by
/// the dead session's prefix list — a ghost filter constraining routes the
/// new session never asked to filter.
#[tokio::test]
async fn graceful_restart_clears_orf_filter() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // First session installs a 10/8-only filter (lifts its gate too).
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 1).await;
    assert_eq!(
        announced,
        vec![Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))]
    );

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish WITHOUT ORF: both routes must flood — the dead session's
    // 10/8-only filter must not survive into the new session.
    let (out_tx, mut out_rx2) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let announced = collect_announced(&mut out_rx2, 2).await;
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))));
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(192, 168, 0, 0),
            16
        ))),
        "post-GR initial dump must carry the full table"
    );

    // The ghost filter bites on churn, not the initial dump (the initial
    // dump deliberately bypasses ORF filters): announce a fresh prefix the
    // dead session's 10/8-only filter would deny and assert it floods.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let churned = collect_announced(&mut out_rx2, 1).await;
    assert_eq!(
        churned,
        vec![Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(172, 16, 0, 0),
            12
        ))],
        "post-GR non-ORF session must not inherit the dead session's filter"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Flap `target` into graceful restart (it becomes a GR RESTARTER we are
/// helping) and re-establish it with the given ORF-receive families; returns
/// the new session's outbound receiver.
async fn gr_flap_and_reup(
    tx: &mpsc::Sender<RibUpdate>,
    target: IpAddr,
    gr_families: Vec<(Afi, Safi)>,
    sendable_families: Vec<(Afi, Safi)>,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv,
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

/// Drain outbound updates until one carries an `EoR` for `family`; return
/// every update seen, including the `EoR`-bearing one. Panics if no such
/// `EoR` arrives within 5 s.
async fn drain_until_eor(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    family: (Afi, Safi),
) -> Vec<OutboundRouteUpdate> {
    let mut updates = Vec::new();
    loop {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("EoR-bearing update should arrive")
            .expect("outbound channel open");
        let done = update.end_of_rib.contains(&family);
        updates.push(update);
        if done {
            return updates;
        }
    }
}

/// Prefixes announced across `updates`. Announces inside the `EoR`-bearing
/// update itself count as before-`EoR`: transport encodes a single update's
/// `EoR` markers after its route UPDATEs.
fn prefixes_announced(updates: &[OutboundRouteUpdate]) -> Vec<Prefix> {
    updates
        .iter()
        .flat_map(|u| u.announce.iter().map(|r| r.prefix))
        .collect()
}

/// A GR RESTARTER (RFC 4724) whose family is behind the RFC 5291 §6 ORF
/// initial-advertisement gate must NOT receive the immediate initial-table
/// `EoR`: the restarter takes `EoR` as "this peer's initial update is
/// complete", proceeds with route selection, and sweeps the stale routes it
/// retained from our previous session — before the gated flood has been
/// sent, a self-inflicted blackhole window. The `EoR` must instead follow
/// the gated flood once the gate lifts.
#[tokio::test]
async fn gr_restarter_defers_eor_for_orf_gated_family() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![(Afi::Ipv4, Safi::Unicast)],
    )
    .await;

    // Nothing — neither routes nor EoR — before the gate lifts.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while the family is still ORF-gated"
    );

    // Gate lifts via an IMMEDIATE ORF push: the filtered flood arrives with
    // the EoR ordered behind it.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "gated flood must precede the deferred EoR"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Same deferral when the gate is lifted by a plain ROUTE-REFRESH carrying
/// no ORF payload: the refresh response is the gated flood, and the deferred
/// `EoR` follows it.
#[tokio::test]
async fn gr_restarter_deferred_eor_follows_plain_refresh_flood() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![(Afi::Ipv4, Safi::Unicast)],
    )
    .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while the family is still ORF-gated"
    );

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "gated flood must precede the deferred EoR"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Two independently gated families lift independently: each family's
/// deferred `EoR` follows its OWN gate-lift flood, and a still-gated
/// family's `EoR` does not ride along.
#[tokio::test]
async fn gr_restarter_deferred_eor_lifts_per_family() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let v6_prefix = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![
            make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_v6_route(v6_prefix, "2001:db8::1".parse().unwrap()),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let both = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
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
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: both.clone(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    // First (non-GR) session: both families gated, immediate honest-empty EoR.
    let initial = out_rx.recv().await.unwrap();
    assert!(initial.announce.is_empty());
    assert!(!initial.end_of_rib.is_empty());

    let mut out_rx = gr_flap_and_reup(&tx, target, both.clone(), dual_stack_sendable(), both).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while both families are still gated"
    );

    // Lift IPv4 only: the v4 flood + v4 EoR arrive; the v6 EoR must wait.
    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    assert!(prefixes_announced(&updates).contains(&Prefix::V4(v4_prefix)));
    assert!(
        updates
            .iter()
            .all(|u| !u.end_of_rib.contains(&(Afi::Ipv6, Safi::Unicast))),
        "the still-gated family's EoR must wait for its own gate lift"
    );

    // Lift IPv6: its flood + EoR follow.
    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv6, Safi::Unicast)).await;
    assert!(prefixes_announced(&updates).contains(&Prefix::V6(v6_prefix)));

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a NON-GR ORF peer keeps today's immediate initial-table `EoR`
/// (an honest "empty table so far"). `orf_setup` itself asserts the initial
/// dump carries the `EoR` marker and no routes for the gated family — a
/// client that never sends ROUTE-REFRESH must still see `EoR`.
#[tokio::test]
async fn non_gr_orf_peer_keeps_immediate_initial_eor() {
    let (tx, handle, _target, _out_rx) = orf_setup().await;
    drop(tx);
    handle.await.unwrap();
}

/// Regression: a GR restarter WITHOUT ORF (no gate) keeps the immediate
/// initial dump and `EoR` — no ROUTE-REFRESH is needed.
#[tokio::test]
async fn gr_restarter_without_orf_keeps_immediate_eor() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![],
    )
    .await;

    // The EoR arrives on its own — no refresh is ever sent here — with the
    // full table ahead of it.
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "ungated GR restarter must receive the immediate initial table"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Peer down while an `EoR` deferral is outstanding must clear the deferral
/// (it is per-session state, torn down with the rest of
/// `clear_outbound_peer_state`).
#[tokio::test]
async fn peer_down_clears_gr_deferred_eor() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let family = (Afi::Ipv4, Safi::Unicast);

    // Session 1 (no ORF), then a GR flap.
    let (out_tx, _out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
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
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    });
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![family],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    // Session 2: the restarter comes back with ORF — the deferral arms.
    let (out_tx2, _out_rx2) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx2,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![family],
        negotiated_llgr_families: Vec::new(),
    });
    assert!(
        manager
            .gr_deferred_eor
            .get(&peer)
            .is_some_and(|families| families.contains(&family)),
        "GR restarter with a gated family must have its EoR deferral armed"
    );

    // Peer down mid-deferral: the deferral must not leak into a later session.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.gr_deferred_eor.contains_key(&peer),
        "peer down must clear the outstanding EoR deferral"
    );
}
