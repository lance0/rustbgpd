//! Per-peer export disposition of a locally injected unicast route
//! (`QueryLocalRouteExport`): committed only for this exact local source,
//! withheld with a bounded reason, or pending, one row per registered peer.

use super::*;
use crate::update::{PeerRouteExport, RouteExportDisposition, RouteExportPage};

fn manager() -> (RibManager, mpsc::Sender<RibUpdate>) {
    let (tx, rx) = mpsc::channel(8);
    (
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()),
        tx,
    )
}

fn peer_up(
    manager: &mut RibManager,
    peer: IpAddr,
    sendable_families: Vec<(Afi, Safi)>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
    add_path_send_max: u32,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    peer_up_with(
        manager,
        peer,
        sendable_families,
        export_policy,
        add_path_send_max,
        capacity,
        false,
    )
}

fn peer_up_with(
    manager: &mut RibManager,
    peer: IpAddr,
    sendable_families: Vec<(Afi, Safi)>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
    add_path_send_max: u32,
    capacity: usize,
    per_client_best: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    let add_path_send_families = if add_path_send_max > 0 {
        sendable_families.clone()
    } else {
        vec![]
    };
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_010,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best,
        interpret_rfc1997: true,
        add_path_send_families,
        add_path_send_max,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

/// A local route as `AddPath` builds it: next-hop self, empty `AS_PATH`.
fn local_route(prefix: Prefix, path_id: u32) -> Route {
    let mut route = match prefix {
        Prefix::V4(v4) => make_route(v4, Ipv4Addr::UNSPECIFIED),
        Prefix::V6(v6) => make_v6_route(v6, Ipv6Addr::UNSPECIFIED),
    };
    set_peer(&mut route, LOCAL_PEER);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.path_id = path_id;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ]);
    route
}

fn inject(manager: &mut RibManager, route: Route) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    rx.try_recv().unwrap().unwrap();
}

fn query(
    manager: &mut RibManager,
    prefix: Prefix,
    path_id: u32,
    after: Option<IpAddr>,
    page_size: usize,
) -> Option<RouteExportPage> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLocalRouteExport {
        prefix,
        path_id,
        after,
        page_size,
        reply,
    });
    rx.try_recv().unwrap()
}

fn row(page: &RouteExportPage, peer: IpAddr) -> &PeerRouteExport {
    page.peers.iter().find(|row| row.peer == peer).unwrap()
}

fn v4(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

fn v4_prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 7), 32))
}

/// The prefixd shape: an IPv6 RTBH route toward an IPv4-transport eBGP
/// session that withheld IPv6 unicast for lack of a next hop, beside a
/// session that exports it.
#[test]
fn withheld_family_is_reported_beside_a_committed_peer() {
    let (mut manager, _tx) = manager();
    let withheld = v4(1);
    let normal = v4(2);
    manager.handle_update(RibUpdate::SetPeerWithheldFamilies {
        peer: withheld,
        session_id: 0,
        families: vec![(
            (Afi::Ipv6, Safi::Unicast),
            crate::update::ExactExportErrorCode::MissingIpv6NextHop,
        )],
    });
    let _withheld_rx = peer_up(&mut manager, withheld, ipv4_sendable(), None, 0, 64);
    let _normal_rx = peer_up(&mut manager, normal, dual_stack_sendable(), None, 0, 64);

    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::7".parse().unwrap(), 128));
    inject(&mut manager, local_route(prefix, 0));

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    assert_eq!(page.peers.len(), 2);
    assert!(!page.more);
    let suppressed = row(&page, withheld);
    assert_eq!(suppressed.disposition, RouteExportDisposition::Withheld);
    assert_eq!(suppressed.reason, "family_suppressed:missing_ipv6_next_hop");
    let committed = row(&page, normal);
    assert_eq!(committed.disposition, RouteExportDisposition::Committed);
    assert_eq!(committed.reason, "");

    // A family the session never negotiated is a different reason.
    let v4_only = v4(3);
    let _v4_rx = peer_up(&mut manager, v4_only, ipv4_sendable(), None, 0, 64);
    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    assert_eq!(row(&page, v4_only).reason, "family_not_negotiated");
}

/// Another source winning best path for the same prefix is never this
/// route's export, even though the peer's Adj-RIB-Out holds a route for
/// the prefix that is in sync with the winner.
#[test]
fn another_source_for_the_same_prefix_is_not_committed() {
    let (mut manager, _tx) = manager();
    let target = v4(2);
    let source = Ipv4Addr::new(10, 0, 0, 9);
    let _target_rx = peer_up(&mut manager, target, ipv4_sendable(), None, 0, 64);
    let _source_rx = peer_up(
        &mut manager,
        IpAddr::V4(source),
        ipv4_sendable(),
        None,
        0,
        64,
    );
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 0));
    let Prefix::V4(v4_prefix) = prefix else {
        unreachable!()
    };
    // An iBGP-learned route with a higher LOCAL_PREF out-selects it.
    let mut better = make_route_with_lp(v4_prefix, source, 200);
    better.origin_type = crate::route::RouteOrigin::Ibgp;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(source),
        session_id: 0,
        announced: vec![better],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(
        manager.loc_rib.get(&prefix).unwrap().peer,
        IpAddr::V4(source)
    );
    // The target's advertised state holds the winner, in sync.
    let (reply, mut explained) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
        peer: target,
        prefix,
        rd: None,
        labeled: false,
        source: None,
        reply,
    });
    let winner = explained.try_recv().unwrap().unwrap();
    assert_eq!(winner.route_peer, Some(IpAddr::V4(source)));
    assert!(winner.already_advertised);

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "not_selected");
}

/// Two local paths for one prefix with identical content: the peer's
/// Adj-RIB-Out entry is byte-identical for either, so only the source
/// identity check tells the selected path from the other one.
#[test]
fn another_local_path_id_is_not_committed() {
    let (mut manager, _tx) = manager();
    let target = v4(2);
    let _target_rx = peer_up(&mut manager, target, ipv4_sendable(), None, 0, 64);
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 1));
    inject(&mut manager, local_route(prefix, 2));
    let selected = manager.loc_rib.get(&prefix).unwrap().path_id;
    let other = if selected == 1 { 2 } else { 1 };

    let page = query(&mut manager, prefix, selected, None, 10).unwrap();
    assert_eq!(
        row(&page, target).disposition,
        RouteExportDisposition::Committed
    );
    let page = query(&mut manager, prefix, other, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "not_selected");
}

/// An Add-Path send peer is explained for this exact source and reports
/// its outbound rank; export policy is a withheld reason of its own.
#[test]
fn add_path_rank_and_export_policy() {
    let (mut manager, _tx) = manager();
    let add_path = v4(4);
    let denied = v4(5);
    let prefix = v4_prefix();
    let _add_path_rx = peer_up(&mut manager, add_path, ipv4_sendable(), None, 2, 64);
    let _denied_rx = peer_up(
        &mut manager,
        denied,
        ipv4_sendable(),
        Some(deny_prefixes_chain(&[prefix])),
        0,
        64,
    );
    inject(&mut manager, local_route(prefix, 0));

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let ranked = row(&page, add_path);
    assert_eq!(ranked.disposition, RouteExportDisposition::Committed);
    assert_eq!(ranked.advertised_path_id, 1);
    let export = row(&page, denied);
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "export_policy");
    assert_eq!(export.explain_code, "policy_denied");
    // A prefix-only deny tests no validation state.
    assert_eq!(export.deny_validation, Vec::<String>::new());
}

/// `deny_prefixes_chain` with the RPKI condition added to each statement.
fn deny_prefixes_if_rpki(prefixes: &[Prefix], state: RpkiValidation) -> PolicyChain {
    let mut chain = deny_prefixes_chain(prefixes);
    for statement in &mut chain.policies[0].policy.entries {
        statement.match_rpki_validation = Some(state);
    }
    PolicyChain::from_named(chain.policies)
}

fn rpol_chain(source: &str, name: &str) -> PolicyChain {
    let compiled = rustbgpd_policy::rpol::RpolFile::parse(source)
        .expect("clean rpol")
        .compile_policy(name, &[], &mut rustbgpd_policy::sets::SetStore::new())
        .expect("policy exists");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        name.to_string(),
        Arc::new(compiled),
    )])
}

/// An ROV deny names the validation state its deciding statement tests,
/// on the single-best and the Add-Path explain arms, whether the policy is
/// TOML (prefix AND RPKI) or rpol.
#[test]
fn rpki_invalid_deny_names_the_validation_state() {
    let (mut manager, _tx) = manager();
    let prefix = v4_prefix();
    let toml = v4(1);
    let toml_add_path = v4(2);
    let rpol = v4(3);
    let rov = || deny_prefixes_if_rpki(&[prefix], RpkiValidation::Invalid);
    let _toml_rx = peer_up(&mut manager, toml, ipv4_sendable(), Some(rov()), 0, 64);
    let _add_path_rx = peer_up(
        &mut manager,
        toml_add_path,
        ipv4_sendable(),
        Some(rov()),
        2,
        64,
    );
    let _rpol_rx = peer_up(
        &mut manager,
        rpol,
        ipv4_sendable(),
        Some(rpol_chain(
            "policy rov { term invalid { if route.rpki == invalid { reject } } \
             term rest { accept } }",
            "rov",
        )),
        0,
        64,
    );
    let mut route = local_route(prefix, 0);
    route.validation_state = RpkiValidation::Invalid;
    inject(&mut manager, route);

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    for peer in [toml, toml_add_path, rpol] {
        let export = row(&page, peer);
        assert_eq!(export.disposition, RouteExportDisposition::Withheld);
        assert_eq!(export.reason, "export_policy");
        assert_eq!(export.explain_code, "policy_denied");
        assert_eq!(export.deny_validation, ["rpki_invalid"], "peer {peer}");
    }
}

/// An RPKI-valid route that an earlier RPKI statement permits and a later
/// policy's prefix statement denies: the deciding statement tests no
/// validation state, so the deny is a plain policy deny.
#[test]
fn deny_after_an_rpki_permit_names_no_validation_state() {
    let (mut manager, _tx) = manager();
    let prefix = v4_prefix();
    let target = v4(1);
    let mut permit_valid = deny_prefixes_if_rpki(&[prefix], RpkiValidation::Valid);
    permit_valid.policies[0].policy.entries[0].action = rustbgpd_policy::PolicyAction::Permit;
    let mut policies = permit_valid.policies;
    policies.extend(deny_prefixes_chain(&[prefix]).policies);
    let _rx = peer_up(
        &mut manager,
        target,
        ipv4_sendable(),
        Some(PolicyChain::from_named(policies)),
        0,
        64,
    );
    let mut route = local_route(prefix, 0);
    route.validation_state = RpkiValidation::Valid;
    inject(&mut manager, route);

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.reason, "export_policy");
    assert_eq!(export.explain_code, "policy_denied");
    assert_eq!(export.deny_validation, Vec::<String>::new());
}

/// A per-client-best peer whose export policy denies every candidate,
/// including the lone injected route, reports the policy reason.
#[test]
fn per_client_best_policy_deny_is_export_policy() {
    let (mut manager, _tx) = manager();
    let target = v4(6);
    let prefix = v4_prefix();
    let _rx = peer_up_with(
        &mut manager,
        target,
        ipv4_sendable(),
        Some(deny_prefixes_chain(&[prefix])),
        0,
        64,
        true,
    );
    inject(&mut manager, local_route(prefix, 0));

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "export_policy");
    assert_eq!(export.explain_code, "per_client_all_denied");
}

/// A family the session did not negotiate stays withheld while that peer
/// resynchronizes another family: no resync can export it.
#[test]
fn unnegotiated_family_is_withheld_not_pending() {
    let (mut manager, _tx) = manager();
    let v4_only = v4(3);
    let _rx = peer_up(&mut manager, v4_only, ipv4_sendable(), None, 0, 64);
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::7".parse().unwrap(), 128));
    inject(&mut manager, local_route(prefix, 0));
    manager.dirty_peers.insert(v4_only);

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let export = row(&page, v4_only);
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "family_not_negotiated");
}

/// A peer whose outbound delivery failed is pending, not committed or
/// withheld: its wire state is still settling.
#[test]
fn undelivered_peer_is_pending() {
    let (mut manager, _tx) = manager();
    let target = v4(2);
    // The initial End-of-RIB fills the one slot, so the route's send fails.
    let _full_rx = peer_up(&mut manager, target, ipv4_sendable(), None, 0, 1);
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 0));
    assert!(manager.dirty_peers.contains(&target));

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Pending);
    assert_eq!(export.reason, "outbound_resync");
}

#[test]
fn peers_page_in_address_order_within_the_bound() {
    let (mut manager, _tx) = manager();
    let receivers: Vec<_> = [3, 1, 2]
        .into_iter()
        .map(|octet| peer_up(&mut manager, v4(octet), ipv4_sendable(), None, 0, 64))
        .collect();
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 0));

    let first = query(&mut manager, prefix, 0, None, 2).unwrap();
    assert_eq!(
        first.peers.iter().map(|row| row.peer).collect::<Vec<_>>(),
        vec![v4(1), v4(2)]
    );
    assert!(first.more);
    let rest = query(&mut manager, prefix, 0, Some(v4(2)), 2).unwrap();
    assert_eq!(
        rest.peers.iter().map(|row| row.peer).collect::<Vec<_>>(),
        vec![v4(3)]
    );
    assert!(!rest.more);
    // Zero still returns a row; the cap bounds an oversized request.
    assert_eq!(
        query(&mut manager, prefix, 0, None, 0).unwrap().peers.len(),
        1
    );
    assert_eq!(
        query(&mut manager, prefix, 0, None, usize::MAX)
            .unwrap()
            .peers
            .len(),
        3
    );
    drop(receivers);
}

#[test]
fn unknown_local_route_is_not_found() {
    let (mut manager, _tx) = manager();
    let _rx = peer_up(&mut manager, v4(1), ipv4_sendable(), None, 0, 64);
    let prefix = v4_prefix();
    assert!(query(&mut manager, prefix, 0, None, 10).is_none());
    inject(&mut manager, local_route(prefix, 0));
    assert!(query(&mut manager, prefix, 3, None, 10).is_none());
}

/// Each row reports its destination's scope from the registered session's
/// accepted context: a scoped neighbor's interface, none for a numbered one.
/// Red proof: building rows with no interface fails the scoped row.
#[test]
fn rows_report_the_destination_scope() {
    let (mut manager, _tx) = manager();
    let scoped = v4(1);
    let numbered = v4(2);
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer: scoped,
        session_id: 0,
        context: Arc::new(crate::update::PeerSourceContext {
            dampening_admission: None,
            peer_interface: Some("eth0".into()),
            accepted_dynamic_range: None,
            route_server_client: false,
        }),
    });
    let _scoped_rx = peer_up(&mut manager, scoped, ipv4_sendable(), None, 0, 64);
    let _numbered_rx = peer_up(&mut manager, numbered, ipv4_sendable(), None, 0, 64);
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 0));

    let page = query(&mut manager, prefix, 0, None, 10).unwrap();
    assert_eq!(row(&page, scoped).peer_interface.as_deref(), Some("eth0"));
    assert_eq!(row(&page, numbered).peer_interface, None);
}
