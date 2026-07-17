//! RFC 7947 §2.3.2 / RFC 8195 route-server control communities.
//!
//! Per-target announce suppression / announce-only / prepend keyed on
//! the TARGET peer's ASN, enforced for sessions with
//! `rs_control_communities` (staged via `SetPeerRsControl` before
//! `PeerUp`), with the matched control communities scrubbed from the
//! outbound announcement. Sessions without the knob keep full
//! transparency. Enabled sessions stay in shared update-groups
//! (LAN-474): untagged routes ride the shared staged emission, and
//! only routes carrying a control-form community diverge per target at
//! the emit seams. Predicate-level pins live in
//! `distribution::rs_control`; these tests drive the full
//! message-in/announcement-out path.

use rustbgpd_wire::LargeCommunity;

use super::*;

/// The route server's ASN for every session in this module.
const RS_AS: u32 = 65000;

fn large(data1: u32, data2: u32) -> LargeCommunity {
    LargeCommunity {
        global_admin: RS_AS,
        local_data1: data1,
        local_data2: data2,
    }
}

/// Standard community `admin:value` (both halves known to fit 16 bits).
fn std_c(admin: u32, value: u32) -> u32 {
    (admin << 16) | value
}

fn tagged(
    mut route: Route,
    communities: Vec<u32>,
    large_communities: Vec<LargeCommunity>,
) -> Route {
    let attrs = Arc::make_mut(&mut route.attributes);
    if !communities.is_empty() {
        attrs.push(PathAttribute::Communities(communities));
    }
    if !large_communities.is_empty() {
        attrs.push(PathAttribute::LargeCommunities(large_communities));
    }
    route
}

/// `SetPeerRsControl` + `PeerUp` for an eBGP unicast peer, mirroring the
/// transport session registration order (context staged before the
/// initial Adj-RIB-Out build).
async fn rs_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    peer_asn: u32,
    rs_control_asn: Option<u32>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 0,
        rs_control_asn,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        // Route-server-client default: RFC 1997 transparent.
        interpret_rfc1997: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn announce_unicast(tx: &mpsc::Sender<RibUpdate>, source: IpAddr, routes: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
}

async fn query_update_group_label(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> String {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await
        .unwrap();
    response.await.unwrap()
}

fn sequence_asns(route: &Route) -> Vec<u32> {
    route
        .as_path()
        .and_then(|path| {
            path.segments.iter().find_map(|segment| match segment {
                AsPathSegment::AsSequence(asns) => Some(asns.clone()),
                AsPathSegment::AsSet(_) => None,
            })
        })
        .unwrap_or_default()
}

/// One tagged route, three targets: "do not announce to A" suppresses
/// toward A only (with the `rs_control` explain rung), B receives the
/// route with the control communities scrubbed and unrelated
/// communities kept, and a session without the knob receives the
/// control communities untouched (RFC 7947 transparency). All three
/// sessions share ONE update group (LAN-474): the divergence is
/// route-granular at emit, not a session-level disqualifier.
#[tokio::test]
async fn control_communities_steer_per_target_announcement_and_scrub() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a: IpAddr = "192.0.2.201".parse().unwrap();
    let client_b: IpAddr = "192.0.2.202".parse().unwrap();
    let transparent: IpAddr = "192.0.2.203".parse().unwrap();

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;
    let mut t_rx = rs_peer_up(&tx, transparent, 65100, None).await;

    // Update-group posture (LAN-474): the knob no longer disqualifies —
    // enabled and disabled sessions with the same staging fingerprint
    // share one group.
    let group_a = query_update_group_label(&tx, client_a).await;
    let group_b = query_update_group_label(&tx, client_b).await;
    let group_t = query_update_group_label(&tx, transparent).await;
    assert!(group_a.starts_with("group:"), "{group_a}");
    assert_eq!(group_a, group_b, "enabled sessions share the group");
    assert_eq!(
        group_a, group_t,
        "the emit filter is route-granular — the knob is not a group key dimension"
    );

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 119, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40));
    let plain = make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 40), vec![65010]);

    announce_unicast(&tx, source, vec![plain.clone()]).await;
    let _ = query_best_routes(&tx).await;
    for out_rx in [&mut a_rx, &mut b_rx, &mut t_rx] {
        let update = out_rx.try_recv().expect("plain route announced");
        assert_eq!(update.announce.len(), 1);
    }

    // Tag: "do not announce to 65001" (large form) + an unrelated
    // community that must survive the scrub.
    let unrelated = std_c(64999, 42);
    let steered = tagged(plain.clone(), vec![unrelated], vec![large(0, 65001)]);
    announce_unicast(&tx, source, vec![steered]).await;
    let _ = query_best_routes(&tx).await;

    // A: withdrawn, explained by the rs_control rung.
    let update = a_rx
        .try_recv()
        .expect("tagged replacement must withdraw from the steered-away client");
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 0)]);
    let explain = query_explain_advertised_route(&tx, client_a, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = explain
        .gates
        .iter()
        .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
        .unwrap();
    assert_eq!(
        (stop.gate, stop.code),
        ("rs_control", "rs_control_suppressed")
    );

    // B: announced with the control community scrubbed, unrelated kept.
    let update = b_rx.try_recv().expect("other client keeps receiving");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert_eq!(advertised.communities(), [unrelated]);
    assert!(
        advertised.large_communities().is_empty(),
        "control large community must be scrubbed from the wire-bound set"
    );

    // Transparent session: control community delivered untouched.
    let update = t_rx
        .try_recv()
        .expect("transparent session keeps receiving");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert_eq!(advertised.communities(), [unrelated]);
    assert_eq!(advertised.large_communities(), [large(0, 65001)]);

    drop(tx);
    handle.await.unwrap();
}

/// The LAN-474 shared/divergent split in one table: an untagged route
/// flows through the SHARED group emission to enabled rs-clients
/// (grouping stays shared before and after the pass) while a tagged
/// route announced in the same pass diverges per target — suppressed
/// toward the named ASN, scrubbed toward the other enabled member,
/// verbatim toward the transparent session. A member joining late
/// gets the same filtered view from the group-table replay.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario pins the shared path, both divergence shapes, and the join replay end to end"
)]
#[tokio::test]
async fn untagged_routes_share_the_group_path_while_tagged_diverge() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a: IpAddr = "192.0.2.231".parse().unwrap();
    let client_b: IpAddr = "192.0.2.232".parse().unwrap();
    let transparent: IpAddr = "192.0.2.233".parse().unwrap();

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;
    let mut t_rx = rs_peer_up(&tx, transparent, 65100, None).await;

    let group_before = query_update_group_label(&tx, client_a).await;
    assert!(group_before.starts_with("group:"), "{group_before}");
    assert_eq!(group_before, query_update_group_label(&tx, client_b).await);
    assert_eq!(
        group_before,
        query_update_group_label(&tx, transparent).await
    );

    let plain_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 122, 0), 24);
    let tagged_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 123, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 43));
    let unrelated = std_c(64999, 42);
    let plain = make_route_with_as_path(plain_prefix, Ipv4Addr::new(198, 51, 100, 43), vec![65010]);
    let steered = tagged(
        make_route_with_as_path(tagged_prefix, Ipv4Addr::new(198, 51, 100, 43), vec![65010]),
        vec![unrelated],
        vec![large(0, 65001)], // do not announce to 65001
    );
    announce_unicast(&tx, source, vec![plain, steered]).await;
    let _ = query_best_routes(&tx).await;

    // A (the steered-away target): only the untagged route, no
    // withdraw residue for a route it never held.
    let update = a_rx.try_recv().expect("shared route still announced");
    assert_eq!(
        update
            .announce
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>(),
        vec![Prefix::V4(plain_prefix)]
    );
    assert!(update.withdraw.is_empty());

    // B: both routes, the tagged one scrubbed (unrelated kept).
    let update = b_rx.try_recv().expect("other enabled client gets both");
    assert_eq!(update.announce.len(), 2);
    let advertised = update
        .announce
        .iter()
        .find(|route| route.prefix == Prefix::V4(tagged_prefix))
        .expect("tagged route announced to B");
    assert_eq!(advertised.communities(), [unrelated]);
    assert!(advertised.large_communities().is_empty());

    // Transparent session: both routes, control community verbatim.
    let update = t_rx.try_recv().expect("transparent session gets both");
    assert_eq!(update.announce.len(), 2);
    let advertised = update
        .announce
        .iter()
        .find(|route| route.prefix == Prefix::V4(tagged_prefix))
        .expect("tagged route announced to T");
    assert_eq!(advertised.communities(), [unrelated]);
    assert_eq!(advertised.large_communities(), [large(0, 65001)]);

    // Grouping is untouched by the divergent pass.
    assert_eq!(query_update_group_label(&tx, client_a).await, group_before);
    assert_eq!(query_update_group_label(&tx, client_b).await, group_before);

    // Late join with the steered-away ASN: the group-table replay
    // (initial dump) applies the same filter — only the untagged route.
    let late: IpAddr = "192.0.2.234".parse().unwrap();
    tx.send(RibUpdate::SetPeerRsControl {
        peer: late,
        session_id: 0,
        rs_control_asn: Some(RS_AS),
    })
    .await
    .unwrap();
    let (out_tx, mut late_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        peer: late,
        session_id: 0,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    let mut dumped: Vec<Prefix> = Vec::new();
    let mut saw_eor = false;
    while let Ok(update) = late_rx.try_recv() {
        dumped.extend(update.announce.iter().map(|route| route.prefix));
        saw_eor |= !update.end_of_rib.is_empty();
    }
    assert!(saw_eor, "initial dump must end with EoR");
    assert_eq!(
        dumped,
        vec![Prefix::V4(plain_prefix)],
        "join replay must suppress the tagged route toward the steered-away ASN"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Standard-community forms: `0:RS` (announce to none) overridden by
/// `RS:PEER` announces only to that peer, and the fully-scrubbed
/// announcement carries no Communities attribute residue.
#[tokio::test]
async fn announce_to_none_std_form_with_announce_override() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a: IpAddr = "192.0.2.211".parse().unwrap();
    let client_b: IpAddr = "192.0.2.212".parse().unwrap();

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 120, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41));
    let route = tagged(
        make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 41), vec![65010]),
        // 0:RS (announce to none) + RS:65002 (except to 65002).
        vec![std_c(0, RS_AS), std_c(RS_AS, 65002)],
        vec![],
    );
    announce_unicast(&tx, source, vec![route]).await;
    let _ = query_best_routes(&tx).await;

    assert!(
        a_rx.try_recv().is_err(),
        "announce-to-none must suppress the client without an override"
    );
    let update = b_rx.try_recv().expect("override client must receive");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert!(
        advertised.communities().is_empty(),
        "both control communities were scrubbed — no residue"
    );
    assert!(
        !advertised
            .attributes
            .iter()
            .any(|attr| matches!(attr, PathAttribute::Communities(_))),
        "an emptied Communities attribute must be dropped, not sent empty"
    );

    drop(tx);
    handle.await.unwrap();
}

/// `RS:102:PEER` prepends the announcing client's ASN twice toward that
/// target only; the other target receives the unprepended path. Both
/// wire-bound routes have the control community scrubbed.
#[tokio::test]
async fn prepend_toward_target_asn_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a: IpAddr = "192.0.2.221".parse().unwrap();
    let client_b: IpAddr = "192.0.2.222".parse().unwrap();

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 121, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    let route = tagged(
        make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 42), vec![65010, 64510]),
        vec![],
        vec![large(102, 65001)],
    );
    announce_unicast(&tx, source, vec![route]).await;
    let _ = query_best_routes(&tx).await;

    let update = a_rx.try_recv().expect("prepend target still receives");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert_eq!(
        sequence_asns(advertised),
        vec![65010, 65010, 65010, 64510],
        "announcing client's ASN prepended twice toward the steered target"
    );
    assert!(advertised.large_communities().is_empty());

    let update = b_rx.try_recv().expect("other client still receives");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert_eq!(
        sequence_asns(advertised),
        vec![65010, 64510],
        "no prepend toward a non-matching target"
    );
    assert!(advertised.large_communities().is_empty());

    drop(tx);
    handle.await.unwrap();
}
