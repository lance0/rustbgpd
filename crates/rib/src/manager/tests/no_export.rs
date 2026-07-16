//! RFC 1997 `NO_EXPORT` / `NO_EXPORT_SUBCONFED` egress enforcement.
//!
//! The gate is SOURCE-route-only and eBGP-only, keyed by the per-peer
//! `interpret_rfc1997` knob (default on; route-server clients default
//! transparent). Policy-ADDED `NO_EXPORT` is deliberately delivered;
//! policy-REMOVED `NO_EXPORT` cannot bypass the restriction. See
//! `distribution::no_export_export_suppressed`.

use super::*;
use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

fn no_export_chain(add: bool) -> PolicyChain {
    let statement = PolicyStatement {
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
        modifications: RouteModifications {
            communities_add: add
                .then_some(rustbgpd_wire::COMMUNITY_NO_EXPORT)
                .into_iter()
                .collect(),
            communities_remove: (!add)
                .then_some(rustbgpd_wire::COMMUNITY_NO_EXPORT)
                .into_iter()
                .collect(),
            ..RouteModifications::default()
        },
    };
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

fn with_communities(mut route: Route, communities: Vec<u32>) -> Route {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(communities));
    route
}

/// `PeerUp` for a unicast peer with explicit eBGP / RFC 1997 knobs.
async fn unicast_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    is_ebgp: bool,
    interpret_rfc1997: bool,
    export_policy: Option<PolicyChain>,
    add_path_send_max: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: if is_ebgp { 65100 } else { 65000 },
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997,
        add_path_send_families: if add_path_send_max > 0 {
            ipv4_sendable()
        } else {
            vec![]
        },
        add_path_send_max,
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

/// Predicate pins: each community suppresses toward an honor-mode eBGP
/// target only; iBGP and transparent mode never suppress; untagged
/// routes never suppress.
#[test]
fn no_export_predicate_pins() {
    use crate::manager::distribution::no_export_export_suppressed;

    let no_export = [rustbgpd_wire::COMMUNITY_NO_EXPORT];
    let subconfed = [rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED];
    let unrelated = [0x0001_0001, rustbgpd_wire::COMMUNITY_NO_ADVERTISE];

    // Honor-mode eBGP: both RFC 1997 §"NO_EXPORT-shaped" communities
    // suppress (SUBCONFED ≡ NO_EXPORT without confederations).
    assert!(no_export_export_suppressed(&no_export, true, true));
    assert!(no_export_export_suppressed(&subconfed, true, true));
    // iBGP is never suppressed (RFC 1997 permits intra-AS).
    assert!(!no_export_export_suppressed(&no_export, false, true));
    assert!(!no_export_export_suppressed(&subconfed, false, true));
    // Transparent mode (route-server-client default) never suppresses.
    assert!(!no_export_export_suppressed(&no_export, true, false));
    assert!(!no_export_export_suppressed(&subconfed, true, false));
    // Other communities (including NO_ADVERTISE — separate gate) don't.
    assert!(!no_export_export_suppressed(&unrelated, true, true));
    assert!(!no_export_export_suppressed(&[], true, true));
}

/// A `NO_EXPORT` source route is withdrawn from an honor-mode eBGP peer
/// (with the `no_export` explain rung), while a transparent eBGP peer
/// and an iBGP peer keep receiving it; the honor and transparent eBGP
/// peers must land in different update groups (identity isolation) so
/// they can never share a staged winner. The `NO_EXPORT_SUBCONFED`
/// form suppresses identically.
#[tokio::test]
async fn no_export_suppresses_honor_ebgp_only_and_splits_update_groups() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let honor: IpAddr = "192.0.2.60".parse().unwrap();
    let transparent: IpAddr = "192.0.2.61".parse().unwrap();
    let internal: IpAddr = "192.0.2.62".parse().unwrap();

    let mut honor_rx = unicast_peer_up(&tx, honor, true, true, None, 0).await;
    let mut transparent_rx = unicast_peer_up(&tx, transparent, true, false, None, 0).await;
    let mut internal_rx = unicast_peer_up(&tx, internal, false, true, None, 0).await;

    // Update-group identity: the two eBGP peers differ only in
    // `interpret_rfc1997`, so they must be grouped apart.
    let honor_group = query_update_group_label(&tx, honor).await;
    let transparent_group = query_update_group_label(&tx, transparent).await;
    assert!(honor_group.starts_with("group:"), "{honor_group}");
    assert!(
        transparent_group.starts_with("group:"),
        "{transparent_group}"
    );
    assert_ne!(
        honor_group, transparent_group,
        "an honor-mode eBGP peer and a transparent peer must never share \
         an update group (their staged winners differ for NO_EXPORT routes)"
    );

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let plain = make_route(prefix, Ipv4Addr::new(198, 51, 100, 10));
    announce_unicast(&tx, source, vec![plain.clone()]).await;
    let _ = query_best_routes(&tx).await;
    for out_rx in [&mut honor_rx, &mut transparent_rx, &mut internal_rx] {
        let update = out_rx.try_recv().expect("plain route announced");
        assert_eq!(update.announce.len(), 1);
    }

    for community in [
        rustbgpd_wire::COMMUNITY_NO_EXPORT,
        rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED,
    ] {
        announce_unicast(
            &tx,
            source,
            vec![with_communities(plain.clone(), vec![community])],
        )
        .await;
        let _ = query_best_routes(&tx).await;

        // Honor-mode eBGP: withdrawn, explained by the no_export rung,
        // pre-policy (no modifications recorded).
        let update = honor_rx
            .try_recv()
            .expect("tagged replacement must withdraw from the honor peer");
        assert!(update.announce.is_empty());
        assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 0)]);
        let explain = query_explain_advertised_route(&tx, honor, Prefix::V4(prefix)).await;
        assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
        let stop = explain
            .gates
            .iter()
            .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
            .unwrap();
        assert_eq!(
            (stop.gate, stop.code),
            ("no_export", "no_export_suppressed"),
            "community {community:#010x}"
        );

        // Transparent eBGP and iBGP: attribute-only replacement, still
        // advertised (announce refresh, no withdraw).
        for (peer, out_rx) in [
            (transparent, &mut transparent_rx),
            (internal, &mut internal_rx),
        ] {
            let update = out_rx
                .try_recv()
                .expect("tagged replacement re-announced to non-suppressed peers");
            assert_eq!(update.announce.len(), 1, "{peer}");
            assert!(update.withdraw.is_empty(), "{peer}");
            let (reply, response) = oneshot::channel();
            tx.send(RibUpdate::QueryAdvertisedRoutes { peer, reply })
                .await
                .unwrap();
            assert_eq!(response.await.unwrap().len(), 1, "{peer}");
        }

        // Restore the plain route for the next community round.
        announce_unicast(&tx, source, vec![plain.clone()]).await;
        let _ = query_best_routes(&tx).await;
        for out_rx in [&mut honor_rx, &mut transparent_rx, &mut internal_rx] {
            let update = out_rx.try_recv().expect("plain route restored");
            assert_eq!(update.announce.len(), 1);
        }
    }

    drop(tx);
    handle.await.unwrap();
}

/// The deliberate asymmetry against `NO_ADVERTISE`: export policy that
/// ADDS `NO_EXPORT` produces a route that is still delivered (attaching
/// `NO_EXPORT` for the receiver to honor is the standard RS-action idiom,
/// and the RFC 9494 §4.6 LLGR form relies on it), while export policy
/// that REMOVES `NO_EXPORT` cannot bypass the source-route suppression.
#[tokio::test]
async fn policy_added_no_export_is_delivered_and_policy_removed_does_not_bypass() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let adder: IpAddr = "192.0.2.70".parse().unwrap();
    let remover: IpAddr = "192.0.2.71".parse().unwrap();

    let mut adder_rx =
        unicast_peer_up(&tx, adder, true, true, Some(no_export_chain(true)), 0).await;
    let mut remover_rx =
        unicast_peer_up(&tx, remover, true, true, Some(no_export_chain(false)), 0).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));
    let plain = make_route(prefix, Ipv4Addr::new(198, 51, 100, 11));

    // Policy-added NO_EXPORT: the modified route goes out carrying it.
    announce_unicast(&tx, source, vec![plain.clone()]).await;
    let _ = query_best_routes(&tx).await;
    let update = adder_rx
        .try_recv()
        .expect("policy-added NO_EXPORT must still be delivered");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    let communities: Vec<u32> = advertised
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::Communities(communities) => Some(communities.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert!(
        communities.contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT),
        "the wire route must carry the policy-added NO_EXPORT"
    );

    // Policy-removed NO_EXPORT: the SOURCE route carries it, so the
    // suppression fires before the chain can strip it.
    let update = remover_rx
        .try_recv()
        .expect("plain route reaches the remover peer");
    assert_eq!(update.announce.len(), 1);
    announce_unicast(
        &tx,
        source,
        vec![with_communities(
            plain.clone(),
            vec![rustbgpd_wire::COMMUNITY_NO_EXPORT],
        )],
    )
    .await;
    let _ = query_best_routes(&tx).await;
    let update = remover_rx
        .try_recv()
        .expect("source NO_EXPORT withdraws despite the removal policy");
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 0)]);
    let explain = query_explain_advertised_route(&tx, remover, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = explain
        .gates
        .iter()
        .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
        .unwrap();
    assert_eq!(
        (stop.gate, stop.code),
        ("no_export", "no_export_suppressed")
    );
    assert!(
        explain.modifications.communities_remove.is_empty(),
        "the pre-policy stop must occur before the configured removal"
    );

    drop(tx);
    handle.await.unwrap();
}

/// VPN staging applies the same source-route gate: an honor-mode eBGP
/// VPN peer has the tagged route withdrawn, a transparent one keeps it.
#[tokio::test]
async fn vpn_no_export_source_route_suppressed_to_honor_ebgp_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let honor: IpAddr = "192.0.2.80".parse().unwrap();
    let transparent: IpAddr = "192.0.2.81".parse().unwrap();
    let mut receivers = Vec::new();
    for (peer, interpret) in [(honor, true), (transparent, false)] {
        let (out_tx, mut out_rx) = mpsc::channel(32);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vpn_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: interpret,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx));
    }

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let plain = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = plain.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![plain.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (peer, out_rx) in &mut receivers {
        let update = out_rx.try_recv().expect("plain VPN route announced");
        assert_eq!(update.vpn_announce.len(), 1, "{peer}");
    }

    let mut tagged = plain.clone();
    Arc::make_mut(&mut tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_EXPORT,
    ]));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;

    let (_, honor_rx) = &mut receivers[0];
    let update = honor_rx
        .try_recv()
        .expect("tagged VPN route withdrawn from the honor peer");
    assert!(update.vpn_announce.is_empty());
    assert_eq!(update.vpn_withdraw, vec![key]);

    let (_, transparent_rx) = &mut receivers[1];
    let update = transparent_rx
        .try_recv()
        .expect("tagged VPN route re-announced to the transparent peer");
    assert_eq!(update.vpn_announce.len(), 1);
    assert!(update.vpn_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Labeled-unicast staging applies the same source-route gate.
#[tokio::test]
async fn labeled_no_export_source_route_suppressed_to_honor_ebgp_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let honor: IpAddr = "192.0.2.90".parse().unwrap();
    let transparent: IpAddr = "192.0.2.91".parse().unwrap();
    let mut receivers = Vec::new();
    for (peer, interpret) in [(honor, true), (transparent, false)] {
        let (out_tx, mut out_rx) = mpsc::channel(32);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: labeled_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: interpret,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx));
    }

    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let plain = make_labeled_rib_route(Ipv4Addr::new(192, 0, 2, 11), 44, 100, 100);
    let key = plain.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![plain.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (peer, out_rx) in &mut receivers {
        let update = out_rx.try_recv().expect("plain labeled route announced");
        assert_eq!(update.labeled_announce.len(), 1, "{peer}");
    }

    let mut tagged = plain.clone();
    Arc::make_mut(&mut tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED,
    ]));
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;

    let (_, honor_rx) = &mut receivers[0];
    let update = honor_rx
        .try_recv()
        .expect("tagged labeled route withdrawn from the honor peer");
    assert!(update.labeled_announce.is_empty());
    assert_eq!(update.labeled_withdraw, vec![key]);

    let (_, transparent_rx) = &mut receivers[1];
    let update = transparent_rx
        .try_recv()
        .expect("tagged labeled route re-announced to the transparent peer");
    assert_eq!(update.labeled_announce.len(), 1);
    assert!(update.labeled_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Plan-vs-apply equivalence: the `ExplainBestPath` candidate walk
/// applies the same pre-policy `NO_EXPORT` gate as live Add-Path staging
/// — a tagged sibling holds no advertised rank toward an honor-mode
/// eBGP peer, and keeps its rank toward a transparent peer.
#[tokio::test]
async fn explain_best_path_candidate_walk_matches_live_no_export_staging() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let honor: IpAddr = "192.0.2.100".parse().unwrap();
    let transparent: IpAddr = "192.0.2.101".parse().unwrap();
    let mut honor_rx = unicast_peer_up(&tx, honor, true, true, None, 2).await;
    let mut transparent_rx = unicast_peer_up(&tx, transparent, true, false, None, 2).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24);
    let source_a = Ipv4Addr::new(198, 51, 100, 20);
    let source_b = Ipv4Addr::new(198, 51, 100, 21);
    let best = make_route_with_lp(prefix, source_a, 200);
    let sibling = with_communities(
        make_route_with_lp(prefix, source_b, 100),
        vec![rustbgpd_wire::COMMUNITY_NO_EXPORT],
    );
    announce_unicast(&tx, IpAddr::V4(source_a), vec![best]).await;
    announce_unicast(&tx, IpAddr::V4(source_b), vec![sibling]).await;
    let _ = query_best_routes(&tx).await;

    // Live: the honor peer stages only the clean path; the transparent
    // peer stages both ranks.
    let honor_state: Vec<(IpAddr, u32)> = {
        let mut ranks = Vec::new();
        while let Ok(update) = honor_rx.try_recv() {
            ranks.extend(update.announce.iter().map(|r| (r.peer, r.path_id)));
        }
        ranks
    };
    assert_eq!(honor_state, vec![(IpAddr::V4(source_a), 1)]);
    let transparent_state: Vec<IpAddr> = {
        let mut peers = Vec::new();
        while let Ok(update) = transparent_rx.try_recv() {
            peers.extend(update.announce.iter().map(|r| r.peer));
        }
        peers
    };
    assert_eq!(transparent_state.len(), 2);

    // Plan: the candidate walk mirrors both outcomes.
    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), honor)
        .await
        .expect("known peer");
    let tagged = explain
        .candidates
        .iter()
        .find(|candidate| candidate.route.peer == IpAddr::V4(source_b))
        .expect("tagged sibling present in the candidate walk");
    assert_eq!(
        tagged.advertised_path_id, 0,
        "candidate walk must apply pre-policy NO_EXPORT before rank assignment"
    );
    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), transparent)
        .await
        .expect("known peer");
    let tagged = explain
        .candidates
        .iter()
        .find(|candidate| candidate.route.peer == IpAddr::V4(source_b))
        .expect("tagged sibling present in the candidate walk");
    assert_ne!(
        tagged.advertised_path_id, 0,
        "a transparent peer's candidate walk must keep the tagged rank"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 1997 MUST outranks RFC 9494 LLGR export eligibility: a RECEIVED
/// route already carrying `NO_EXPORT` (the upstream §4.6 stale form is
/// exactly `LLGR_STALE` + `NO_EXPORT`) is suppressed toward an eBGP
/// peer even though that peer advertised the LLGR capability for the
/// family. The LLGR-only form (no `NO_EXPORT`) stays deliverable to
/// prove the suppression comes from the new gate, not the LLGR one.
#[tokio::test]
async fn received_llgr_stale_no_export_form_suppressed_despite_llgr_eligibility() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer: IpAddr = "192.0.2.110".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        // LLGR advertised for the family: the RFC 9494 §4.4 gate passes.
        negotiated_llgr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 118, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
    let plain = make_route(prefix, Ipv4Addr::new(198, 51, 100, 30));

    // Carried LLGR_STALE alone: eligible (peer advertised LLGR).
    announce_unicast(
        &tx,
        source,
        vec![with_communities(
            plain.clone(),
            vec![rustbgpd_wire::COMMUNITY_LLGR_STALE],
        )],
    )
    .await;
    let _ = query_best_routes(&tx).await;
    let update = out_rx
        .try_recv()
        .expect("LLGR-stale route deliverable to an LLGR-capable eBGP peer");
    assert_eq!(update.announce.len(), 1);

    // The received §4.6 form (LLGR_STALE + NO_EXPORT): RFC 1997 wins.
    announce_unicast(
        &tx,
        source,
        vec![with_communities(
            plain,
            vec![
                rustbgpd_wire::COMMUNITY_LLGR_STALE,
                rustbgpd_wire::COMMUNITY_NO_EXPORT,
            ],
        )],
    )
    .await;
    let _ = query_best_routes(&tx).await;
    let update = out_rx
        .try_recv()
        .expect("§4.6-form route withdrawn despite LLGR eligibility");
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 0)]);
    let explain = query_explain_advertised_route(&tx, peer, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = explain
        .gates
        .iter()
        .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
        .unwrap();
    assert_eq!(
        (stop.gate, stop.code),
        ("no_export", "no_export_suppressed"),
        "the explain rung must attribute the suppression to RFC 1997, not LLGR"
    );

    drop(tx);
    handle.await.unwrap();
}
