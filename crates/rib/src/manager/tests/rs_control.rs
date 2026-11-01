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

use crate::PeerId;
use crate::test_support::peer_v4;
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
    AttrSet::edit(&mut route.attributes, |attrs| {
        if !communities.is_empty() {
            attrs.push(PathAttribute::Communities(communities));
        }
        if !large_communities.is_empty() {
            attrs.push(PathAttribute::LargeCommunities(large_communities));
        }
    });
    route
}

/// `SetPeerRsControl` + `PeerUp` for an eBGP unicast peer, mirroring the
/// transport session registration order (context staged before the
/// initial Adj-RIB-Out build).
async fn rs_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
    rs_control_asn: Option<u32>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    rs_peer_up_with_policy(tx, peer, peer_asn, rs_control_asn, None).await
}

/// [`rs_peer_up`] with an export policy — the policy-interaction seams
/// (control decisions on the SOURCE route, scrub on the post-policy
/// route) need sessions whose export chain mutates communities.
async fn rs_peer_up_with_policy(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
    rs_control_asn: Option<u32>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
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
        export_policy,
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

async fn announce_unicast(tx: &mpsc::Sender<RibUpdate>, source: PeerId, routes: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
}

async fn query_update_group_label(tx: &mpsc::Sender<RibUpdate>, peer: PeerId) -> String {
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
    let client_a = PeerId::from_addr("192.0.2.201".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.202".parse().unwrap());
    let transparent = PeerId::from_addr("192.0.2.203".parse().unwrap());

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
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 40));
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
    let client_a = PeerId::from_addr("192.0.2.231".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.232".parse().unwrap());
    let transparent = PeerId::from_addr("192.0.2.233".parse().unwrap());

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
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 43));
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
    assert_eq!(update.withdraw.len(), 0);

    // B: both routes, the tagged one scrubbed (unrelated kept).
    let update = b_rx.try_recv().expect("other enabled client gets both");
    assert_eq!(update.announce.len(), 2);
    let advertised = update
        .announce
        .iter()
        .find(|route| route.prefix == Prefix::V4(tagged_prefix))
        .expect("tagged route announced to B");
    assert_eq!(advertised.communities(), [unrelated]);
    assert_eq!(advertised.large_communities().len(), 0);

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
    let late = PeerId::from_addr("192.0.2.234".parse().unwrap());
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
    let client_a = PeerId::from_addr("192.0.2.211".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.212".parse().unwrap());

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 120, 0), 24);
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 41));
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
    let client_a = PeerId::from_addr("192.0.2.221".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.222".parse().unwrap());

    let mut a_rx = rs_peer_up(&tx, client_a, 65001, Some(RS_AS)).await;
    let mut b_rx = rs_peer_up(&tx, client_b, 65002, Some(RS_AS)).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 121, 0), 24);
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 42));
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
    assert_eq!(advertised.large_communities().len(), 0);

    let update = b_rx.try_recv().expect("other client still receives");
    assert_eq!(update.announce.len(), 1);
    let advertised = &update.announce[0];
    assert_eq!(
        sequence_asns(advertised),
        vec![65010, 64510],
        "no prepend toward a non-matching target"
    );
    assert_eq!(advertised.large_communities().len(), 0);

    drop(tx);
    handle.await.unwrap();
}

/// One-statement permit-everything export chain applying `mods` to
/// every route.
fn modifying_export_chain(
    mods: rustbgpd_policy::RouteModifications,
) -> rustbgpd_policy::PolicyChain {
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
            match_next_hop: None,
            modifications: mods,
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

/// The RFC 7947 decision is made on the SOURCE route: an export policy
/// that strips the "do not announce to PEER" community must not make
/// the route leak to that peer — the source member prohibited it, and
/// the ungrouped path's pre-policy gate honors that. Both sessions
/// share one update group (identical chain), so this drives the
/// grouped emit seam.
#[tokio::test]
async fn policy_stripped_suppression_community_still_suppresses_toward_target() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a = PeerId::from_addr("192.0.2.241".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.242".parse().unwrap());

    // Both members strip the control community on export.
    let strip = rustbgpd_policy::RouteModifications {
        large_communities_remove: vec![large(0, 65001)],
        ..rustbgpd_policy::RouteModifications::default()
    };
    let chain = modifying_export_chain(strip);
    let mut a_rx =
        rs_peer_up_with_policy(&tx, client_a, 65001, Some(RS_AS), Some(chain.clone())).await;
    let mut b_rx = rs_peer_up_with_policy(&tx, client_b, 65002, Some(RS_AS), Some(chain)).await;
    assert_eq!(
        query_update_group_label(&tx, client_a).await,
        query_update_group_label(&tx, client_b).await,
        "identical chains must share one update group — this test drives the grouped seam"
    );

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 124, 0), 24);
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 44));
    let steered = tagged(
        make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 44), vec![65010]),
        vec![],
        vec![large(0, 65001)], // source says: do not announce to 65001
    );
    announce_unicast(&tx, source, vec![steered]).await;
    let _ = query_best_routes(&tx).await;

    assert!(
        a_rx.try_recv().is_err(),
        "route must stay suppressed toward the named peer even though the \
         export policy stripped the control community (decision is source-based)"
    );
    let update = b_rx.try_recv().expect("other client still receives");
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].large_communities().len(), 0);

    drop(tx);
    handle.await.unwrap();
}

/// A control community ADDED by export policy is scrubbed from the
/// wire (the scrub runs post-policy) but must not steer: suppression
/// and prepend are decided on the SOURCE route, which carried no tags.
#[tokio::test]
async fn policy_added_control_communities_scrub_but_do_not_steer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let client_a = PeerId::from_addr("192.0.2.243".parse().unwrap());
    let client_b = PeerId::from_addr("192.0.2.244".parse().unwrap());

    // Policy stamps a deny-to-65001 and a prepend-toward-65002 tag onto
    // every route; neither may act.
    let add = rustbgpd_policy::RouteModifications {
        large_communities_add: vec![large(0, 65001), large(102, 65002)],
        ..rustbgpd_policy::RouteModifications::default()
    };
    let chain = modifying_export_chain(add);
    let mut a_rx =
        rs_peer_up_with_policy(&tx, client_a, 65001, Some(RS_AS), Some(chain.clone())).await;
    let mut b_rx = rs_peer_up_with_policy(&tx, client_b, 65002, Some(RS_AS), Some(chain)).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 125, 0), 24);
    let source = peer_v4(Ipv4Addr::new(198, 51, 100, 45));
    let plain = make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 45), vec![65010]);
    announce_unicast(&tx, source, vec![plain]).await;
    let _ = query_best_routes(&tx).await;

    let update = a_rx
        .try_recv()
        .expect("a policy-added deny tag must not suppress — the source carried no tags");
    assert_eq!(update.announce.len(), 1);
    assert!(
        update.announce[0].large_communities().is_empty(),
        "policy-added control communities must still be scrubbed from the wire"
    );
    assert_eq!(sequence_asns(&update.announce[0]), vec![65010]);

    let update = b_rx.try_recv().expect("other client receives");
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].large_communities().len(), 0);
    assert_eq!(
        sequence_asns(&update.announce[0]),
        vec![65010],
        "a policy-added prepend tag must not prepend — the source carried no tags"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Grouped/ungrouped equivalence for the policy-strip interaction: the
/// per-peer path is the group path's correctness oracle, so an
/// identical (tagged route, stripping policy) scenario must produce
/// identical per-member streams with grouping on and off.
#[tokio::test]
async fn grouped_matches_ungrouped_for_stripped_suppression_tag() {
    async fn run(
        force_ungrouped: bool,
    ) -> Vec<(Vec<(Prefix, Vec<LargeCommunity>)>, Vec<(Prefix, u32)>)> {
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_a = PeerId::from_addr("192.0.2.245".parse().unwrap());
        let client_b = PeerId::from_addr("192.0.2.246".parse().unwrap());

        let strip = rustbgpd_policy::RouteModifications {
            large_communities_remove: vec![large(0, 65001)],
            ..rustbgpd_policy::RouteModifications::default()
        };
        let chain = modifying_export_chain(strip);
        let mut a_rx =
            rs_peer_up_with_policy(&tx, client_a, 65001, Some(RS_AS), Some(chain.clone())).await;
        let mut b_rx = rs_peer_up_with_policy(&tx, client_b, 65002, Some(RS_AS), Some(chain)).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 126, 0), 24);
        let source = peer_v4(Ipv4Addr::new(198, 51, 100, 46));
        let plain = make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 46), vec![65010]);
        // Pass 1: untagged — everyone receives. Pass 2: the source
        // re-announces with a deny-to-65001 tag the policy strips —
        // the named member must see a withdraw, the other an update.
        announce_unicast(&tx, source, vec![plain.clone()]).await;
        let _ = query_best_routes(&tx).await;
        let steered = tagged(plain, vec![], vec![large(0, 65001)]);
        announce_unicast(&tx, source, vec![steered]).await;
        let _ = query_best_routes(&tx).await;

        let mut streams = Vec::new();
        for out_rx in [&mut a_rx, &mut b_rx] {
            let mut announced = Vec::new();
            let mut withdrawn = Vec::new();
            while let Ok(update) = out_rx.try_recv() {
                announced.extend(
                    update
                        .announce
                        .iter()
                        .map(|route| (route.prefix, route.large_communities().to_vec())),
                );
                withdrawn.extend(update.withdraw.iter().copied());
            }
            streams.push((announced, withdrawn));
        }
        drop(tx);
        handle.await.unwrap();
        streams
    }

    assert_eq!(
        run(false).await,
        run(true).await,
        "grouped and ungrouped paths must agree on source-based RFC 7947 decisions"
    );
}

/// `SetPeerRsControl` + `PeerUp` on a synchronous manager, so a test can
/// install its readiness observer between the two halves of a scenario.
fn rs_member_up(
    manager: &mut RibManager,
    peer: PeerId,
    peer_asn: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(RS_AS),
    });
    let (out_tx, mut out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 1,
        peer_asn,
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
    });
    while out_rx.try_recv().is_ok() {}
    out_rx
}

fn drain_withdrawn(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> BTreeSet<Prefix> {
    let mut withdrawn = BTreeSet::new();
    while let Ok(update) = out_rx.try_recv() {
        withdrawn.extend(update.withdraw.iter().map(|(prefix, _)| *prefix));
    }
    withdrawn
}

/// A burst of route-server client downs costs each departing source its
/// own withdrawals, not members x withdrawals: on a pass whose prior
/// sources carry no control community, an rs-control member takes the
/// plain shared withdrawal with no per-member admitted-prior set. A
/// control-tagged prior still builds that set, so the member the route
/// was suppressed toward is not sent a withdrawal for it.
#[test]
fn rs_member_down_skips_per_member_priors_unless_a_prior_is_tagged() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let members: Vec<(PeerId, Ipv4Addr, u32)> = (1..=6u8)
        .map(|index| {
            let addr = Ipv4Addr::new(192, 0, 2, 200 + index);
            (peer_v4(addr), addr, 65_000 + u32::from(index))
        })
        .collect();
    let mut receivers: Vec<_> = members
        .iter()
        .map(|&(peer, _, asn)| rs_member_up(&mut manager, peer, asn))
        .collect();
    let gid = manager.grouped_member_of(members[0].0).unwrap();
    assert!(
        members
            .iter()
            .all(|&(peer, ..)| manager.grouped_member_of(peer) == Some(gid))
    );

    let untagged: Vec<Ipv4Prefix> = (0..3u8)
        .map(|index| Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, index), 32))
        .collect();
    let routes = untagged
        .iter()
        .map(|&prefix| make_route(prefix, members[0].1))
        .collect();
    let tagged_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let steered = tagged(
        make_route(tagged_prefix, members[1].1),
        vec![],
        vec![large(0, members[2].2)],
    );
    for (source, announced) in [(members[0].0, routes), (members[1].0, vec![steered])] {
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 1,
            peer: source,
            announced,
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
    }
    for out_rx in &mut receivers {
        while out_rx.try_recv().is_ok() {}
    }

    let prior_visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let prior_visits = Arc::clone(&prior_visits);
        move |stage| {
            if stage == "group_prior_materialization" {
                prior_visits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }));
    let visits = || prior_visits.load(Ordering::Relaxed);

    manager.handle_update(RibUpdate::PeerDown {
        peer: members[0].0,
        session_id: 1,
    });
    assert_eq!(
        visits(),
        0,
        "an untagged withdrawal pass must not build a prior set per rs-control member"
    );
    let untagged: BTreeSet<Prefix> = untagged.into_iter().map(Prefix::V4).collect();
    for out_rx in &mut receivers[1..] {
        assert_eq!(drain_withdrawn(out_rx), untagged);
    }

    manager.handle_update(RibUpdate::PeerDown {
        peer: members[1].0,
        session_id: 1,
    });
    for (index, out_rx) in receivers.iter_mut().enumerate().skip(2) {
        let expected = if index == 2 {
            BTreeSet::new()
        } else {
            BTreeSet::from([Prefix::V4(tagged_prefix)])
        };
        assert_eq!(
            drain_withdrawn(out_rx),
            expected,
            "member {index}: only members the route reached are sent its withdrawal"
        );
    }
    assert!(
        visits() > 0,
        "a tagged prior keeps the per-member admission check"
    );
}

/// Peer-scoped `ExplainBestPath` applies the RFC 7947 §2.3.2 control gate
/// live Add-Path staging applies: a sibling tagged "do not announce to the
/// target's ASN" holds no advertised path ID, exactly like the target's
/// Adj-RIB-Out, and a session without the knob still ranks it.
#[test]
fn explain_best_path_add_path_ranks_match_live_rs_control_staging() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let steered = PeerId::from_addr("192.0.2.211".parse().unwrap());
    let transparent = PeerId::from_addr("192.0.2.212".parse().unwrap());
    let mut receivers = Vec::new();
    for (peer, rs_control_asn) in [(steered, Some(RS_AS)), (transparent, None)] {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 0,
            rs_control_asn,
        });
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        receivers.push(outbound_rx);
        manager.handle_update(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65001,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 4,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
    }

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 119, 0), 24);
    let best_source = Ipv4Addr::new(198, 51, 100, 41);
    let tagged_source = Ipv4Addr::new(198, 51, 100, 42);
    let best = make_multipath_route(prefix, best_source, vec![65010], 200);
    let sibling = tagged(
        make_multipath_route(prefix, tagged_source, vec![65020], 100),
        vec![],
        vec![large(0, 65001)],
    );
    for route in [best, sibling] {
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
    }

    let prefix = Prefix::V4(prefix);
    let (explained, held) = explain_ranks_and_adj_rib_out(&mut manager, steered, prefix);
    assert!(
        held.is_empty(),
        "live staging suppresses the tagged sibling"
    );
    assert_eq!(explained, held);
    let (explained, held) = explain_ranks_and_adj_rib_out(&mut manager, transparent, prefix);
    assert!(held.contains_key(&peer_v4(tagged_source)), "{held:?}");
    assert_eq!(explained, held);
}

/// `SetPeerExportContext` + `SetPeerRsControl` + `PeerUp` for a
/// per-client-best route-server client whose local RFC 9234 role is
/// Customer, so routes carrying OTC are blocked toward it.
async fn pcb_customer_rs_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 0,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    })
    .await
    .unwrap();
    tx.send(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 0,
        rs_control_asn: Some(RS_AS),
    })
    .await
    .unwrap();
    let (out_tx, out_rx) = mpsc::channel(32);
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
        per_client_best: true,
        interpret_rfc1997: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    out_rx
}

/// A client whose best path is suppressed toward it and whose fallback
/// carries OTC: the RFC 9234 backstop blocks the fallback, and the client's
/// update reports exactly that blocked route, as the per-peer path does.
/// The other client receives the best path and reports nothing.
#[tokio::test]
async fn otc_blocked_fallback_is_reported_for_the_suppressed_client() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 121, 0), 24);
    let best = peer_v4(Ipv4Addr::new(198, 51, 100, 41));
    let fallback = peer_v4(Ipv4Addr::new(198, 51, 100, 42));
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_a = PeerId::from_addr("192.0.2.211".parse().unwrap());
        let client_b = PeerId::from_addr("192.0.2.212".parse().unwrap());
        let mut a_rx = pcb_customer_rs_peer_up(&tx, client_a, 65001).await;
        drain_eor(&mut a_rx).await;
        let mut b_rx = pcb_customer_rs_peer_up(&tx, client_b, 65002).await;
        drain_eor(&mut b_rx).await;
        assert_eq!(
            query_update_group_label(&tx, client_a)
                .await
                .starts_with("group:"),
            !force_ungrouped
        );
        let winner = tagged(
            make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 41), vec![64601]),
            vec![std_c(0, 65001)],
            vec![],
        );
        announce_unicast(&tx, best, vec![winner]).await;
        let mut runner_up =
            make_route_with_as_path(prefix, Ipv4Addr::new(198, 51, 100, 42), vec![64602, 64602]);
        AttrSet::edit(&mut runner_up.attributes, |attrs| {
            attrs.push(PathAttribute::OnlyToCustomer(64602));
        });
        announce_unicast(&tx, fallback, vec![runner_up]).await;
        let _ = query_best_routes(&tx).await;
        let report = |rx: &mut mpsc::Receiver<OutboundRouteUpdate>| {
            let mut announced = Vec::new();
            let mut blocked = Vec::new();
            while let Ok(update) = rx.try_recv() {
                announced.extend(update.announce.iter().map(|route| route.peer));
                blocked.extend(update.otc_blocked.iter().map(|route| route.peer));
            }
            (announced, blocked)
        };
        let a = report(&mut a_rx);
        let b = report(&mut b_rx);
        assert_eq!(
            a,
            (vec![], vec![fallback]),
            "force_ungrouped={force_ungrouped}: client A's fallback is blocked and reported"
        );
        assert_eq!(b.1, Vec::<PeerId>::new(), "client B gets the best path");
        reports.push((a, b));
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(reports[0], reports[1]);
}

/// The suppressed best path and the OTC-bearing fallback come from one
/// source, so no lane exists. A client joining afterwards, and the same
/// client's route refresh, report the blocked fallback exactly as the
/// per-peer path does.
#[tokio::test]
async fn otc_blocked_same_source_fallback_is_reported_on_join_and_refresh() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 122, 0), 24);
    let source_addr = Ipv4Addr::new(198, 51, 100, 43);
    let source = peer_v4(source_addr);
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_a = PeerId::from_addr("192.0.2.213".parse().unwrap());
        let client_b = PeerId::from_addr("192.0.2.214".parse().unwrap());
        let mut b_rx = pcb_customer_rs_peer_up(&tx, client_b, 65002).await;
        drain_eor(&mut b_rx).await;
        let mut best = tagged(
            make_route_with_as_path(prefix, source_addr, vec![64603]),
            vec![std_c(0, 65001)],
            vec![],
        );
        best.path_id = 1;
        let mut fallback = make_route_with_as_path(prefix, source_addr, vec![64603, 64603]);
        fallback.path_id = 2;
        AttrSet::edit(&mut fallback.attributes, |attrs| {
            attrs.push(PathAttribute::OnlyToCustomer(64603));
        });
        announce_unicast(&tx, source, vec![best, fallback]).await;
        let _ = query_best_routes(&tx).await;
        let collect = |rx: &mut mpsc::Receiver<OutboundRouteUpdate>| {
            let mut announced = Vec::new();
            let mut blocked = Vec::new();
            while let Ok(update) = rx.try_recv() {
                announced.extend(update.announce.iter().map(|route| route.peer));
                blocked.extend(update.otc_blocked.iter().map(|route| route.peer));
            }
            (announced, blocked)
        };
        let mut a_rx = pcb_customer_rs_peer_up(&tx, client_a, 65001).await;
        let _ = query_best_routes(&tx).await;
        let joined = collect(&mut a_rx);
        assert_eq!(
            joined,
            (vec![], vec![source]),
            "force_ungrouped={force_ungrouped}: the joining client's blocked fallback is reported"
        );
        tx.send(RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            peer: client_a,
            session_id: 0,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        let _ = query_best_routes(&tx).await;
        let refreshed = collect(&mut a_rx);
        reports.push((joined, refreshed));
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(
        reports[0], reports[1],
        "grouped join and refresh reports match the per-peer path"
    );
}

/// An OTC-bearing best path that a control community also suppresses
/// toward client A never reaches A's backstop, so A reports nothing, while
/// client B reports it blocked. Both match the per-peer path.
#[tokio::test]
async fn suppressed_otc_winner_is_not_reported_for_the_suppressed_client() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 123, 0), 24);
    let source_addr = Ipv4Addr::new(198, 51, 100, 44);
    let source = peer_v4(source_addr);
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_a = PeerId::from_addr("192.0.2.215".parse().unwrap());
        let client_b = PeerId::from_addr("192.0.2.216".parse().unwrap());
        let mut a_rx = pcb_customer_rs_peer_up(&tx, client_a, 65001).await;
        drain_eor(&mut a_rx).await;
        let mut b_rx = pcb_customer_rs_peer_up(&tx, client_b, 65002).await;
        drain_eor(&mut b_rx).await;
        let mut winner = tagged(
            make_route_with_as_path(prefix, source_addr, vec![64604]),
            vec![std_c(0, 65001)],
            vec![],
        );
        AttrSet::edit(&mut winner.attributes, |attrs| {
            attrs.push(PathAttribute::OnlyToCustomer(64604));
        });
        announce_unicast(&tx, source, vec![winner]).await;
        let _ = query_best_routes(&tx).await;
        let blocked = |rx: &mut mpsc::Receiver<OutboundRouteUpdate>| {
            let mut blocked = Vec::new();
            while let Ok(update) = rx.try_recv() {
                assert!(update.announce.is_empty());
                blocked.extend(update.otc_blocked.iter().map(|route| route.peer));
            }
            blocked
        };
        let a = blocked(&mut a_rx);
        let b = blocked(&mut b_rx);
        assert_eq!(a, Vec::<PeerId>::new(), "force_ungrouped={force_ungrouped}");
        assert_eq!(b, vec![source], "force_ungrouped={force_ungrouped}");
        reports.push((a, b));
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(reports[0], reports[1]);
}

/// `SetPeerRsControl` + `PeerUp` for a route-server client, per-client-best
/// when `per_client_best`.
async fn rs_client_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
    per_client_best: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    rs_client_up_with_policy(tx, peer, peer_asn, per_client_best, None).await
}

/// [`rs_client_up`] with an export policy.
async fn rs_client_up_with_policy(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
    per_client_best: bool,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    rs_client_up_full(tx, peer, peer_asn, RS_AS, per_client_best, export_policy).await
}

/// [`rs_client_up_with_policy`] under a chosen route-server ASN.
async fn rs_client_up_full(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    peer_asn: u32,
    rs_asn: u32,
    per_client_best: bool,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 0,
        rs_control_asn: Some(rs_asn),
    })
    .await
    .unwrap();
    let (out_tx, out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best,
        interpret_rfc1997: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    out_rx
}

/// What a client's operator surfaces report: the advertised listing
/// (prefix and source; unfiltered and through a filtered scan), the
/// advertised count, the IPv4 unicast Adj-RIB-Out gauge and the BMP stat
/// 17 family counts.
#[derive(Debug, PartialEq)]
struct AdvertisedSurfaces {
    listing: BTreeSet<(String, PeerId, String)>,
    filtered: BTreeSet<(String, PeerId, String)>,
    count: usize,
    gauge: f64,
    bmp: Vec<((Afi, Safi), u64)>,
}

/// The `(prefix, source)` keys of a listing.
fn keys(listing: &BTreeSet<(String, PeerId, String)>) -> BTreeSet<(String, PeerId)> {
    listing
        .iter()
        .map(|(prefix, source, _)| (prefix.clone(), *source))
        .collect()
}

async fn advertised_surfaces(
    tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    peer: PeerId,
) -> AdvertisedSurfaces {
    let listing = collect_advertised_routes(tx, peer)
        .await
        .into_iter()
        .map(|route| {
            (
                route.prefix.to_string(),
                route.peer,
                format!("{:?}", route.attributes.to_vec()),
            )
        })
        .collect();
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope: RouteQueryScope::Advertised { peer },
        filter: Some(Box::new(|_: &Route| true)),
        after: None,
        expected_version: None,
        page_size: 64,
        reply,
    })
    .await
    .unwrap();
    let filtered = response
        .await
        .unwrap()
        .unwrap()
        .routes
        .into_iter()
        .map(|route| {
            (
                route.prefix.to_string(),
                route.peer,
                format!("{:?}", route.attributes.to_vec()),
            )
        })
        .collect();
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount { peer, reply })
        .await
        .unwrap();
    let count = response.await.unwrap();
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryBmpPeerStats { reply })
        .await
        .unwrap();
    let mut bmp = response
        .await
        .unwrap()
        .adj_rib_out_post
        .remove(&peer)
        .unwrap_or_default();
    bmp.retain(|(_, count)| *count != 0);
    let gauge = metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        .and_then(|family| {
            family.get_metric().iter().find(|metric| {
                let labels = metric.get_label();
                labels
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer.to_string())
                    && labels
                        .iter()
                        .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
            })
        })
        .map_or(0.0, |metric| metric.get_gauge().get_value());
    AdvertisedSurfaces {
        listing,
        filtered,
        count,
        gauge,
        bmp,
    }
}

/// A route-server client's advertised listing, count, Adj-RIB-Out gauge
/// and BMP stat 17 report what it was actually sent: not a best path that
/// RFC 7947 control communities suppress toward it, and, with
/// `per_client_best`, the fallback it gets instead. Grouped and ungrouped
/// clients report the same, in a plain and a per-client-best group.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture per group shape, asserted surface by surface"
)]
async fn grouped_advertised_surfaces_follow_rs_control() {
    let tagged_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 124, 0), 24);
    let fallback_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 125, 0), 24);
    let plain_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 126, 0), 24);
    let prepend_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 127, 0), 24);
    let first = Ipv4Addr::new(198, 51, 100, 45);
    let second = Ipv4Addr::new(198, 51, 100, 46);
    for per_client_best in [false, true] {
        let mut reports = Vec::new();
        for force_ungrouped in [false, true] {
            let metrics = BgpMetrics::new();
            let (tx, rx) = mpsc::channel(64);
            let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
            manager.test_force_ungrouped = force_ungrouped;
            let handle = tokio::spawn(manager.run());
            let client_a = PeerId::from_addr("192.0.2.217".parse().unwrap());
            let client_b = PeerId::from_addr("192.0.2.218".parse().unwrap());
            let mut a_rx = rs_client_up(&tx, client_a, 65001, per_client_best).await;
            drain_eor(&mut a_rx).await;
            let mut b_rx = rs_client_up(&tx, client_b, 65002, per_client_best).await;
            drain_eor(&mut b_rx).await;
            assert_eq!(
                query_update_group_label(&tx, client_a)
                    .await
                    .starts_with("group:"),
                !force_ungrouped
            );
            announce_unicast(
                &tx,
                peer_v4(first),
                vec![
                    tagged(
                        make_route_with_as_path(tagged_prefix, first, vec![64605]),
                        vec![],
                        vec![large(0, 65001)],
                    ),
                    tagged(
                        make_route_with_as_path(fallback_prefix, first, vec![64605]),
                        vec![std_c(0, 65001)],
                        vec![],
                    ),
                    make_route_with_as_path(plain_prefix, first, vec![64605]),
                    // Two prepends toward B; scrubbed toward A.
                    tagged(
                        make_route_with_as_path(prepend_prefix, first, vec![64605]),
                        vec![],
                        vec![large(102, 65002)],
                    ),
                ],
            )
            .await;
            announce_unicast(
                &tx,
                peer_v4(second),
                vec![make_route_with_as_path(
                    fallback_prefix,
                    second,
                    vec![64606, 64606],
                )],
            )
            .await;
            let _ = query_best_routes(&tx).await;
            // A third client of AS65001 joins after the routes.
            let client_c = PeerId::from_addr("192.0.2.219".parse().unwrap());
            let _c_rx = rs_client_up(&tx, client_c, 65001, per_client_best).await;
            let a = advertised_surfaces(&tx, &metrics, client_a).await;
            let b = advertised_surfaces(&tx, &metrics, client_b).await;
            let c = advertised_surfaces(&tx, &metrics, client_c).await;
            let mut expected: BTreeSet<_> = BTreeSet::from([
                (Prefix::V4(plain_prefix).to_string(), peer_v4(first)),
                (Prefix::V4(prepend_prefix).to_string(), peer_v4(first)),
            ]);
            if per_client_best {
                expected.insert((Prefix::V4(fallback_prefix).to_string(), peer_v4(second)));
            }
            assert_eq!(
                keys(&a.listing),
                expected,
                "per_client_best={per_client_best} force_ungrouped={force_ungrouped}"
            );
            assert_eq!(a.filtered, a.listing, "{a:?}");
            assert_eq!(a.count, expected.len(), "{a:?}");
            assert_eq!(
                a.gauge,
                f64::from(u32::try_from(expected.len()).unwrap()),
                "{a:?}"
            );
            assert_eq!(
                a.bmp,
                vec![((Afi::Ipv4, Safi::Unicast), expected.len() as u64)],
                "{a:?}"
            );
            assert_eq!(b.count, 4, "{b:?}");
            assert_eq!(
                c.listing, a.listing,
                "the late joiner reports what A reports"
            );
            assert_eq!(c.filtered, a.filtered, "{c:?}");
            assert_eq!(c.count, a.count, "{c:?}");
            assert_eq!(c.bmp, a.bmp, "{c:?}");
            reports.push((a, b, c.listing, c.count, c.bmp));
            drop(tx);
            handle.await.unwrap();
        }
        assert_eq!(
            reports[0], reports[1],
            "per_client_best={per_client_best}: grouped surfaces match the per-peer path"
        );
    }
}

/// In a plain group whose chain strips the control communities, the best
/// path's tag moving from `0:65004` to `0:65005` is a tag-only transition:
/// the shared row is unchanged while D gains the route and E loses it.
/// Their counts, gauges and BMP stat 17 follow, as on the per-peer path.
#[tokio::test]
async fn grouped_counts_follow_a_tag_only_transition() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 128, 0), 24);
    let source = Ipv4Addr::new(198, 51, 100, 48);
    let strip = modifying_export_chain(rustbgpd_policy::RouteModifications {
        communities_remove: vec![std_c(0, 65004), std_c(0, 65005)],
        ..rustbgpd_policy::RouteModifications::default()
    });
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_d = PeerId::from_addr("192.0.2.223".parse().unwrap());
        let client_e = PeerId::from_addr("192.0.2.224".parse().unwrap());
        let mut d_rx =
            rs_client_up_with_policy(&tx, client_d, 65004, false, Some(strip.clone())).await;
        drain_eor(&mut d_rx).await;
        let mut e_rx =
            rs_client_up_with_policy(&tx, client_e, 65005, false, Some(strip.clone())).await;
        drain_eor(&mut e_rx).await;
        assert_eq!(
            query_update_group_label(&tx, client_d)
                .await
                .starts_with("group:"),
            !force_ungrouped
        );
        let mut snapshots = Vec::new();
        for tag in [std_c(0, 65004), std_c(0, 65005)] {
            announce_unicast(
                &tx,
                peer_v4(source),
                vec![tagged(
                    make_route_with_as_path(prefix, source, vec![64608]),
                    vec![tag],
                    vec![],
                )],
            )
            .await;
            let _ = query_best_routes(&tx).await;
            let d = advertised_surfaces(&tx, &metrics, client_d).await;
            let e = advertised_surfaces(&tx, &metrics, client_e).await;
            snapshots.push((d.count, d.gauge, d.bmp, e.count, e.gauge, e.bmp));
        }
        let one = vec![((Afi::Ipv4, Safi::Unicast), 1)];
        assert_eq!(
            snapshots,
            vec![
                (0, 0.0, vec![], 1, 1.0, one.clone()),
                (1, 1.0, one, 0, 0.0, vec![]),
            ],
            "force_ungrouped={force_ungrouped}"
        );
        reports.push(snapshots);
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(reports[0], reports[1]);
}

/// The count, IPv4 gauge and BMP stat 17 of each listed client.
async fn client_counts(
    tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    clients: &[PeerId],
) -> Vec<(PeerId, usize, f64, Vec<((Afi, Safi), u64)>)> {
    let mut out = Vec::new();
    for &client in clients {
        let surfaces = advertised_surfaces(tx, metrics, client).await;
        out.push((client, surfaces.count, surfaces.gauge, surfaces.bmp));
    }
    out
}

/// Every control form a grouped count correction keys on, against the
/// per-peer path: `0:RS` (named by the route server's ASN), the
/// announce-to-none large form of a second route-server ASN, a lane entry
/// suppressed toward the winner's source (recorded only from the lane and
/// the fallback list), a lane-only change, and, for a client that joins
/// after the routes, an announce-to-none large key and a key that is both
/// announce-to-none and names the client.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario per control form, asserted together"
)]
async fn grouped_counts_follow_every_control_form() {
    let source_a = Ipv4Addr::new(198, 51, 100, 51);
    let source_b = Ipv4Addr::new(198, 51, 100, 52);
    let source_c = Ipv4Addr::new(198, 51, 100, 53);
    let prefix = |n: u8| Ipv4Prefix::new(Ipv4Addr::new(203, 0, 130 + n, 0), 24);
    let route = |n: u8, source: Ipv4Addr, len: usize, std: Vec<u32>, lrg: Vec<LargeCommunity>| {
        tagged(
            make_route_with_as_path(prefix(n), source, vec![64609; len]),
            std,
            lrg,
        )
    };
    let large_as = |admin: u32, data1: u32, data2: u32| LargeCommunity {
        global_admin: admin,
        local_data1: data1,
        local_data2: data2,
    };
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_d = PeerId::from_addr("192.0.2.231".parse().unwrap());
        let client_e = PeerId::from_addr("192.0.2.232".parse().unwrap());
        // J enforces control communities for route-server ASN 65100.
        let client_j = PeerId::from_addr("192.0.2.233".parse().unwrap());
        let client_g = PeerId::from_addr("192.0.2.234".parse().unwrap());
        let mut client_rxs = Vec::new();
        for (client, asn, rs_asn) in [
            (client_d, 65004, RS_AS),
            (client_e, 65005, RS_AS),
            (client_j, 65007, 65100),
        ] {
            let mut rx = rs_client_up_full(&tx, client, asn, rs_asn, true, None).await;
            drain_eor(&mut rx).await;
            client_rxs.push(rx);
        }
        // p1: `0:RS` suppresses toward D and E, not toward J.
        announce_unicast(
            &tx,
            peer_v4(source_b),
            vec![route(1, source_b, 1, vec![std_c(0, RS_AS)], vec![])],
        )
        .await;
        // p2: announce-to-none for route-server ASN 65100 suppresses toward J only.
        announce_unicast(
            &tx,
            peer_v4(source_a),
            vec![route(2, source_a, 1, vec![], vec![large_as(65100, 0, 0)])],
        )
        .await;
        // p3: D wins; its lane entry C is suppressed toward D, so D gets nothing.
        announce_unicast(
            &tx,
            client_d,
            vec![route(3, Ipv4Addr::new(192, 0, 2, 231), 1, vec![], vec![])],
        )
        .await;
        announce_unicast(
            &tx,
            peer_v4(source_c),
            vec![route(
                3,
                source_c,
                2,
                vec![std_c(0, 65004)],
                vec![large(0, 65004)],
            )],
        )
        .await;
        // p4: as p3, then a clean B below C: only the fallback list moves
        // (a lane-only change), and D gets B.
        announce_unicast(
            &tx,
            client_d,
            vec![route(4, Ipv4Addr::new(192, 0, 2, 231), 1, vec![], vec![])],
        )
        .await;
        announce_unicast(
            &tx,
            peer_v4(source_c),
            vec![route(4, source_c, 2, vec![std_c(0, 65004)], vec![])],
        )
        .await;
        announce_unicast(
            &tx,
            peer_v4(source_b),
            vec![route(4, source_b, 3, vec![], vec![])],
        )
        .await;
        // p5: announce-to-none (`RS:0:0`) suppresses toward every RS 65000 client.
        announce_unicast(
            &tx,
            peer_v4(source_a),
            vec![route(5, source_a, 1, vec![], vec![large(0, 0)])],
        )
        .await;
        // p6: announce-to-none and also naming AS65004.
        announce_unicast(
            &tx,
            peer_v4(source_a),
            vec![route(
                6,
                source_a,
                1,
                vec![std_c(0, 65004)],
                vec![large(0, 0)],
            )],
        )
        .await;
        // p8: D's own route, the only candidate, carries `0:RS`: D's raw
        // slot is empty (it sourced the winner and there is no lane), so
        // the suppression moves nothing for D.
        announce_unicast(
            &tx,
            client_d,
            vec![route(
                8,
                Ipv4Addr::new(192, 0, 2, 231),
                1,
                vec![std_c(0, RS_AS)],
                vec![],
            )],
        )
        .await;
        // p7: D wins with a clean C behind it, so D gets C; C's re-announce
        // naming AS65004 is a lane-only change that takes p7 from D.
        announce_unicast(
            &tx,
            client_d,
            vec![route(7, Ipv4Addr::new(192, 0, 2, 231), 1, vec![], vec![])],
        )
        .await;
        announce_unicast(
            &tx,
            peer_v4(source_c),
            vec![route(7, source_c, 2, vec![], vec![])],
        )
        .await;
        let _ = query_best_routes(&tx).await;
        announce_unicast(
            &tx,
            peer_v4(source_c),
            vec![route(7, source_c, 2, vec![std_c(0, 65004)], vec![])],
        )
        .await;
        let _ = query_best_routes(&tx).await;
        // G (AS65004) joins after every route: its correction is seeded.
        let mut g_rx = rs_client_up_full(&tx, client_g, 65004, RS_AS, true, None).await;
        let _ = query_best_routes(&tx).await;
        while g_rx.try_recv().is_ok() {}
        let counts = client_counts(&tx, &metrics, &[client_d, client_e, client_j, client_g]).await;
        reports.push(counts);
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(
        reports[0], reports[1],
        "grouped counts, gauges and BMP stat 17 match the per-peer path"
    );
    let d = &reports[0][0];
    // D: p2 (RS 65000 is unaffected by RS 65100 forms) and p4 (B), not p7.
    assert_eq!(d.1, 2, "{d:?}");
}

/// A group whose routes exist before its first rs-control client joins
/// builds the control index on that join, so the client's count already
/// excludes the route suppressed toward it.
#[tokio::test]
async fn grouped_counts_seed_when_routes_precede_the_first_rs_client() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 140, 0), 24);
    let source = Ipv4Addr::new(198, 51, 100, 54);
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let observer = PeerId::from_addr("192.0.2.235".parse().unwrap());
        let mut o_rx = rs_peer_up(&tx, observer, 65009, None).await;
        announce_unicast(
            &tx,
            peer_v4(source),
            vec![tagged(
                make_route_with_as_path(prefix, source, vec![64610]),
                vec![std_c(0, 65004)],
                vec![],
            )],
        )
        .await;
        let _ = query_best_routes(&tx).await;
        while o_rx.try_recv().is_ok() {}
        let client_d = PeerId::from_addr("192.0.2.236".parse().unwrap());
        let mut d_rx = rs_client_up_full(&tx, client_d, 65004, RS_AS, false, None).await;
        let _ = query_best_routes(&tx).await;
        while d_rx.try_recv().is_ok() {}
        reports.push(client_counts(&tx, &metrics, &[client_d]).await);
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[0][0].1, 0, "{:?}", reports[0]);
}

/// A filtered advertised page and its total for `peer`.
async fn filtered_page(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    filter: fn(&Route) -> bool,
) -> (Vec<(String, String)>, u64) {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope: RouteQueryScope::Advertised { peer },
        filter: Some(Box::new(filter)),
        after: None,
        expected_version: None,
        page_size: 64,
        reply,
    })
    .await
    .unwrap();
    let page = response.await.unwrap().unwrap();
    let rows = page
        .routes
        .into_iter()
        .map(|route| {
            (
                route.prefix.to_string(),
                format!("{:?}", route.attributes.to_vec()),
            )
        })
        .collect();
    (rows, page.total)
}

/// A filtered advertised listing of a grouped rs-control client evaluates
/// the filter on the client's wire form, as on an ungrouped client: a
/// community filter does not match a row whose control communities are
/// scrubbed, and an AS-path-length filter matches the prepended row.
#[tokio::test]
async fn grouped_filtered_listing_filters_the_rewritten_row() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 141, 0), 24);
    let source = Ipv4Addr::new(198, 51, 100, 55);
    let mut reports = Vec::new();
    for force_ungrouped in [false, true] {
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        let client_a = PeerId::from_addr("192.0.2.237".parse().unwrap());
        let client_b = PeerId::from_addr("192.0.2.238".parse().unwrap());
        let mut a_rx = rs_client_up(&tx, client_a, 65001, false).await;
        drain_eor(&mut a_rx).await;
        let mut b_rx = rs_client_up(&tx, client_b, 65002, false).await;
        drain_eor(&mut b_rx).await;
        assert_eq!(
            query_update_group_label(&tx, client_b)
                .await
                .starts_with("group:"),
            !force_ungrouped
        );
        // Two prepends toward B; `0:65009` names no client and is scrubbed.
        announce_unicast(
            &tx,
            peer_v4(source),
            vec![tagged(
                make_route_with_as_path(prefix, source, vec![64611]),
                vec![std_c(0, 65009)],
                vec![large(102, 65002)],
            )],
        )
        .await;
        let _ = query_best_routes(&tx).await;
        let with_communities =
            filtered_page(&tx, client_b, |route| !route.communities().is_empty()).await;
        let long_path = filtered_page(&tx, client_b, |route| {
            route.as_path().is_some_and(|path| path.len() >= 3)
        })
        .await;
        assert_eq!(with_communities.1, 0, "force_ungrouped={force_ungrouped}");
        assert_eq!(long_path.1, 1, "force_ungrouped={force_ungrouped}");
        reports.push((with_communities, long_path));
        drop(tx);
        handle.await.unwrap();
    }
    assert_eq!(reports[0], reports[1]);
}
