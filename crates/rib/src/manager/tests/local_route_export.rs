//! Per-peer export disposition of a locally injected unicast route
//! (`QueryLocalRouteExport`): committed only for this exact local source,
//! withheld with a bounded reason, or pending, one row per registered peer.

use super::*;
use crate::update::{
    ExportDestination, LocalRouteExports, PeerRouteExport, RouteExportCursor,
    RouteExportDisposition, RouteExportPage, RouteExportPageError, RouteExportVersion,
};

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

type Resume = Option<(RouteExportCursor, RouteExportVersion)>;

fn query_keys(
    manager: &mut RibManager,
    keys: &[(Prefix, u32)],
    named: Option<Vec<ExportDestination>>,
    resume: Resume,
    page_size: usize,
) -> Result<RouteExportPage, RouteExportPageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLocalRouteExport {
        keys: keys.to_vec(),
        managed: named,
        resume,
        page_size,
        reply,
    });
    rx.try_recv().unwrap()
}

fn query(
    manager: &mut RibManager,
    prefix: Prefix,
    path_id: u32,
    resume: Resume,
    page_size: usize,
) -> Result<RouteExportPage, RouteExportPageError> {
    query_keys(manager, &[(prefix, path_id)], None, resume, page_size)
}

/// Where the walk `page` belongs to resumes.
fn resume_of(page: &RouteExportPage) -> Resume {
    page.next.clone().map(|cursor| (cursor, page.version))
}

/// A page that lists one key and finds no local route for it.
fn not_found(key: usize) -> Vec<LocalRouteExports> {
    vec![LocalRouteExports {
        key,
        found: false,
        peers: vec![],
    }]
}

fn row(page: &RouteExportPage, peer: IpAddr) -> &PeerRouteExport {
    page.routes
        .iter()
        .flat_map(|route| &route.peers)
        .find(|row| row.peer == peer)
        .unwrap()
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
    assert_eq!(peers_of(&page).len(), 2);
    assert!(page.next.is_none());
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
    assert_eq!(peers_of(&first), vec![v4(1), v4(2)]);
    assert!(first.next.is_some());
    let rest = query(&mut manager, prefix, 0, resume_of(&first), 2).unwrap();
    assert_eq!(peers_of(&rest), vec![v4(3)]);
    assert!(rest.next.is_none());
    // Zero still returns a row; the cap bounds an oversized request.
    assert_eq!(
        peers_of(&query(&mut manager, prefix, 0, None, 0).unwrap()).len(),
        1
    );
    assert_eq!(
        peers_of(&query(&mut manager, prefix, 0, None, usize::MAX).unwrap()).len(),
        3
    );
    drop(receivers);
}

#[test]
fn unknown_local_route_is_not_found() {
    let (mut manager, _tx) = manager();
    let _rx = peer_up(&mut manager, v4(1), ipv4_sendable(), None, 0, 64);
    let prefix = v4_prefix();
    assert_eq!(
        query(&mut manager, prefix, 0, None, 10).unwrap().routes,
        not_found(0)
    );
    inject(&mut manager, local_route(prefix, 0));
    assert_eq!(
        query(&mut manager, prefix, 3, None, 10).unwrap().routes,
        not_found(0)
    );
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

fn peers_of(page: &RouteExportPage) -> Vec<IpAddr> {
    page.routes
        .iter()
        .flat_map(|route| &route.peers)
        .map(|row| row.peer)
        .collect()
}

/// Peers 10.0.0.2..=4 and the local route, with a first page of two peers.
fn walk_started() -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    RouteExportPage,
) {
    let (mut manager, _tx) = manager();
    let receivers = [2, 3, 4]
        .into_iter()
        .map(|octet| peer_up(&mut manager, v4(octet), ipv4_sendable(), None, 0, 64))
        .collect();
    inject(&mut manager, local_route(v4_prefix(), 0));
    let first = query(&mut manager, v4_prefix(), 0, None, 2).unwrap();
    assert_eq!(peers_of(&first), vec![v4(2), v4(3)]);
    assert!(first.next.is_some());
    (manager, receivers, first)
}

fn resume(
    manager: &mut RibManager,
    first: &RouteExportPage,
) -> Result<RouteExportPage, RouteExportPageError> {
    query(manager, v4_prefix(), 0, resume_of(first), 2)
}

fn withdraw(manager: &mut RibManager, prefix: Prefix, path_id: u32) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix,
        path_id,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    rx.try_recv().unwrap().unwrap();
}

/// A route removed between pages invalidates the resumed walk instead of
/// answering as if the key never existed; a fresh walk then reports no
/// route. Red proof: leaving the routes out of the walk version fails the
/// first assertion.
#[test]
fn route_removed_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    withdraw(&mut manager, v4_prefix(), 0);
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
    assert_eq!(
        query(&mut manager, v4_prefix(), 0, None, 2).unwrap().routes,
        not_found(0)
    );
}

/// Replacing the route under the same key between pages also invalidates
/// the walk: the first page described different route state.
#[test]
fn route_replaced_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    let mut replacement = local_route(v4_prefix(), 0);
    replacement.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Incomplete),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ]);
    inject(&mut manager, replacement);
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
}

/// A peer that joins before the cursor between pages would be skipped by
/// an address-ordered resume; the walk is invalidated instead. Red proof:
/// not advancing the roster generation on registration fails this test.
#[test]
fn peer_joining_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, mut receivers, first) = walk_started();
    receivers.push(peer_up(&mut manager, v4(1), ipv4_sendable(), None, 0, 64));
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
    // A restarted walk lists the new peer.
    let restarted = query(&mut manager, v4_prefix(), 0, None, 10).unwrap();
    assert_eq!(peers_of(&restarted), vec![v4(1), v4(2), v4(3), v4(4)]);
}

/// A listed peer that leaves between pages invalidates the walk, and so does
/// a flap that leaves the roster's membership unchanged: the first page's
/// row described the previous session. Red proof: not advancing the roster
/// generation on deregistration fails both halves.
#[test]
fn peer_leaving_or_flapping_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    manager.handle_update(RibUpdate::PeerDown {
        peer: v4(2),
        session_id: 0,
    });
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );

    let (mut manager, mut receivers, first) = walk_started();
    manager.handle_update(RibUpdate::PeerDown {
        peer: v4(2),
        session_id: 0,
    });
    receivers.push(peer_up(&mut manager, v4(2), ipv4_sendable(), None, 0, 64));
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
}

/// The fence is scoped to this walk: another local route's churn and a
/// stale `PeerDown` for an unregistered address leave the walk resumable,
/// and it completes with the remaining peer. A single-page walk reports no
/// more peers.
#[test]
fn unrelated_changes_leave_the_walk_resumable() {
    let (mut manager, _receivers, first) = walk_started();
    let other = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 8), 32));
    inject(&mut manager, local_route(other, 0));
    withdraw(&mut manager, other, 0);
    manager.handle_update(RibUpdate::PeerDown {
        peer: v4(9),
        session_id: 0,
    });
    let rest = resume(&mut manager, &first).unwrap();
    assert_eq!(peers_of(&rest), vec![v4(4)]);
    assert!(rest.next.is_none());
    assert_eq!(rest.version, first.version);

    let single = query(&mut manager, v4_prefix(), 0, None, 10).unwrap();
    assert_eq!(peers_of(&single), vec![v4(2), v4(3), v4(4)]);
    assert!(single.next.is_none());
}

/// The route fence is content, not identity, by design: removing the route
/// and restoring identical content between pages leaves the walk valid,
/// because every disposition is a function of that content.
#[test]
fn identical_route_restored_mid_walk_leaves_the_walk_resumable() {
    let (mut manager, _receivers, first) = walk_started();
    withdraw(&mut manager, v4_prefix(), 0);
    inject(&mut manager, local_route(v4_prefix(), 0));
    let rest = resume(&mut manager, &first).unwrap();
    assert_eq!(peers_of(&rest), vec![v4(4)]);
    assert!(rest.next.is_none());
}

/// Replacing a listed peer's export policy between pages, as a reload does
/// without resetting the session, invalidates the walk. Red proof: leaving
/// the chains' change version out of the policy version fails this test.
#[test]
fn export_policy_replaced_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: v4(2),
        export_policy: Some(deny_prefixes_chain(&[v4_prefix()])),
        reply,
    });
    rx.try_recv().unwrap().unwrap();
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
}

fn allowed_dataset(listed: bool) -> rustbgpd_policy::datasets::DatasetData {
    use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry};
    rustbgpd_policy::datasets::DatasetData::Prefix(PrefixSet::new(listed.then_some(
        PrefixSetEntry {
            prefix: v4_prefix(),
            ge: None,
            le: None,
        },
    )))
}

/// Peers 10.0.0.2..=4 whose export chain accepts the local route only while
/// it is listed in the returned dataset, and the route itself.
fn dataset_walk_setup() -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    Arc<rustbgpd_policy::datasets::DatasetHandle>,
) {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetHandle, DatasetKind};
    use rustbgpd_policy::sets::SetStore;

    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        allowed_dataset(true),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled = rustbgpd_policy::rpol::RpolFile::parse(
        "dataset prefix-set allowed\npolicy p { term t { if route.prefix in allowed { accept } reject } }",
    )
    .unwrap()
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .unwrap()
    .unwrap();
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);

    let (mut manager, _tx) = manager();
    let receivers = [2, 3, 4]
        .into_iter()
        .map(|octet| {
            peer_up(
                &mut manager,
                v4(octet),
                ipv4_sendable(),
                Some(chain.clone()),
                0,
                64,
            )
        })
        .collect();
    inject(&mut manager, local_route(v4_prefix(), 0));
    (manager, receivers, handle)
}

/// A dataset swap is visible to the next explain before any RIB message
/// arrives, so a swap of a dataset a listed peer's export chain reads
/// invalidates the walk with no RIB update in between. Red proof: leaving
/// the dataset generations out of the policy version fails this test.
#[test]
fn export_dataset_swapped_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, handle) = dataset_walk_setup();
    let first = query(&mut manager, v4_prefix(), 0, None, 2).unwrap();
    assert!(first.next.is_some());

    handle.refresh(allowed_dataset(false));
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );
}

/// A dataset refresh runs outside the RIB actor, so it can land after a
/// page's version check while its rows evaluate. The final page has no
/// continuation token, so the page itself is refused; a first page is
/// refused too rather than issuing a token its rows were not read under.
/// The hook lands the refresh in exactly that window. Red proof: removing
/// the post-collection recheck returns both pages.
#[test]
fn export_dataset_swapped_while_a_page_evaluates_invalidates_the_page() {
    use crate::manager::queries::BEFORE_EXPORT_ROWS;

    let (mut manager, _receivers, handle) = dataset_walk_setup();
    let first = query(&mut manager, v4_prefix(), 0, None, 2).unwrap();
    assert!(first.next.is_some());
    let refresh = Arc::clone(&handle);
    BEFORE_EXPORT_ROWS.set(Some(Box::new(move || {
        refresh.refresh(allowed_dataset(false));
    })));
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );

    let refresh = Arc::clone(&handle);
    BEFORE_EXPORT_ROWS.set(Some(Box::new(move || {
        refresh.refresh(allowed_dataset(true));
    })));
    assert_eq!(
        query(&mut manager, v4_prefix(), 0, None, 2),
        Err(RouteExportPageError::Invalidated)
    );
    // Without a refresh in the window, a restarted walk is served.
    assert!(query(&mut manager, v4_prefix(), 0, None, 2).is_ok());
}

fn prefix_at(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

/// Per key on a page: its index, whether it was found and its row peers.
fn listed(page: &RouteExportPage) -> Vec<(usize, bool, Vec<IpAddr>)> {
    page.routes
        .iter()
        .map(|route| {
            (
                route.key,
                route.found,
                route.peers.iter().map(|row| row.peer).collect(),
            )
        })
        .collect()
}

/// Peers 10.0.0.1..=3 and local routes for keys 0 and 2 of [`batch_keys`];
/// key 1 never exists.
fn batch_setup() -> (RibManager, Vec<mpsc::Receiver<OutboundRouteUpdate>>) {
    let (mut manager, _tx) = manager();
    let receivers = [1, 2, 3]
        .into_iter()
        .map(|octet| peer_up(&mut manager, v4(octet), ipv4_sendable(), None, 0, 64))
        .collect();
    inject(&mut manager, local_route(prefix_at(1), 0));
    inject(&mut manager, local_route(prefix_at(3), 0));
    (manager, receivers)
}

fn batch_keys() -> Vec<(Prefix, u32)> {
    vec![(prefix_at(1), 0), (prefix_at(2), 0), (prefix_at(3), 0)]
}

/// A batch lists keys in query order, each with every peer, and a key with
/// no local route as one not-found entry rather than failing the call.
#[test]
fn batch_lists_keys_in_order_with_a_not_found_entry() {
    let (mut manager, _receivers) = batch_setup();
    let page = query_keys(&mut manager, &batch_keys(), None, None, 100).unwrap();
    let all = vec![v4(1), v4(2), v4(3)];
    assert_eq!(
        listed(&page),
        vec![(0, true, all.clone()), (1, false, vec![]), (2, true, all)]
    );
    assert!(page.next.is_none());
    assert_eq!(
        row(&page, v4(1)).disposition,
        RouteExportDisposition::Committed
    );
}

/// The page size bounds entries across keys: a row is one, and so is a key
/// listed with no rows. A key split across pages continues with its
/// remaining peers and no empty continuation entry. Red proof: charging
/// nothing for a not-found key lists key 2's first row on the first page.
#[test]
fn batch_pages_split_keys_and_resume_where_they_stopped() {
    let (mut manager, _receivers) = batch_setup();
    let keys = batch_keys();
    let first = query_keys(&mut manager, &keys, None, None, 4).unwrap();
    assert_eq!(
        listed(&first),
        vec![(0, true, vec![v4(1), v4(2), v4(3)]), (1, false, vec![])]
    );
    assert_eq!(
        first.next,
        Some(RouteExportCursor {
            key: 2,
            after: None
        })
    );
    let rest = query_keys(&mut manager, &keys, None, resume_of(&first), 4).unwrap();
    assert_eq!(listed(&rest), vec![(2, true, vec![v4(1), v4(2), v4(3)])]);
    assert!(rest.next.is_none());

    // Two rows per page: key 0 splits after its second peer.
    let first = query_keys(&mut manager, &keys, None, None, 2).unwrap();
    assert_eq!(listed(&first), vec![(0, true, vec![v4(1), v4(2)])]);
    let second = query_keys(&mut manager, &keys, None, resume_of(&first), 2).unwrap();
    assert_eq!(
        listed(&second),
        vec![(0, true, vec![v4(3)]), (1, false, vec![])]
    );
    let third = query_keys(&mut manager, &keys, None, resume_of(&second), 2).unwrap();
    assert_eq!(listed(&third), vec![(2, true, vec![v4(1), v4(2)])]);
    let last = query_keys(&mut manager, &keys, None, resume_of(&third), 2).unwrap();
    assert_eq!(listed(&last), vec![(2, true, vec![v4(3)])]);
    assert!(last.next.is_none());
}

/// With no peers at all, each found key is still one entry, so a walk over
/// many keys pages instead of returning them all at once.
#[test]
fn batch_found_key_without_peers_is_one_entry() {
    let (mut manager, _tx) = manager();
    inject(&mut manager, local_route(prefix_at(1), 0));
    inject(&mut manager, local_route(prefix_at(3), 0));
    let keys = batch_keys();
    let first = query_keys(&mut manager, &keys, None, None, 2).unwrap();
    assert_eq!(listed(&first), vec![(0, true, vec![]), (1, false, vec![])]);
    let rest = query_keys(&mut manager, &keys, None, resume_of(&first), 2).unwrap();
    assert_eq!(listed(&rest), vec![(2, true, vec![])]);
    assert!(rest.next.is_none());
}

/// The route fence covers every key of the batch, not only the one being
/// listed: a key not yet reached that is removed, or a not-found key that
/// appears, invalidates the walk. Red proof: fingerprinting only the first
/// key's route fails this test.
#[test]
fn batch_walk_aborts_when_any_key_changes() {
    let (mut manager, _receivers) = batch_setup();
    let keys = batch_keys();
    let first = query_keys(&mut manager, &keys, None, None, 2).unwrap();
    withdraw(&mut manager, prefix_at(3), 0);
    assert_eq!(
        query_keys(&mut manager, &keys, None, resume_of(&first), 2),
        Err(RouteExportPageError::Invalidated)
    );

    let (mut manager, _receivers) = batch_setup();
    let first = query_keys(&mut manager, &keys, None, None, 2).unwrap();
    inject(&mut manager, local_route(prefix_at(2), 0));
    assert_eq!(
        query_keys(&mut manager, &keys, None, resume_of(&first), 2),
        Err(RouteExportPageError::Invalidated)
    );
}

fn numbered(peers: &[IpAddr]) -> Vec<ExportDestination> {
    peers.iter().map(|&peer| (peer, None)).collect()
}

/// Named managed peers without a registered session are listed as not
/// Established, in destination order beside the registered ones, with no
/// explain behind them; without names, only registered peers are listed.
#[test]
fn managed_peers_without_a_session_are_listed_only_when_named() {
    let (mut manager, _tx) = manager();
    let _rx = peer_up(&mut manager, v4(2), ipv4_sendable(), None, 0, 64);
    inject(&mut manager, local_route(v4_prefix(), 0));

    let page = query_keys(
        &mut manager,
        &[(v4_prefix(), 0)],
        Some(numbered(&[v4(1), v4(2), v4(3)])),
        None,
        10,
    )
    .unwrap();
    assert_eq!(peers_of(&page), vec![v4(1), v4(2), v4(3)]);
    assert_eq!(
        row(&page, v4(2)).disposition,
        RouteExportDisposition::Committed
    );
    for peer in [v4(1), v4(3)] {
        let row = row(&page, peer);
        assert_eq!(row.disposition, RouteExportDisposition::NotEstablished);
        assert_eq!(row.reason, "not_established");
        assert_eq!(row.explain_code, "");
    }

    let page = query(&mut manager, v4_prefix(), 0, None, 10).unwrap();
    assert_eq!(peers_of(&page), vec![v4(2)]);
}

/// A managed link-local peer matches a registered session only on the same
/// interface. This pins the matching rule for the roster the RIB is handed;
/// it is not a supported configuration, since the daemon refuses one
/// link-local address on two interfaces. A same-address entry on another
/// interface stays a separate, not-Established destination, and a walk pages
/// between the two by scope.
#[test]
fn managed_peers_match_registered_sessions_by_scope() {
    let (mut manager, _tx) = manager();
    let link_local: IpAddr = "fe80::1".parse().unwrap();
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer: link_local,
        session_id: 0,
        context: Arc::new(crate::update::PeerSourceContext {
            dampening_admission: None,
            peer_interface: Some("eth0".into()),
            accepted_dynamic_range: None,
            route_server_client: false,
        }),
    });
    let _rx = peer_up(&mut manager, link_local, ipv4_sendable(), None, 0, 64);
    inject(&mut manager, local_route(v4_prefix(), 0));
    let named = Some(vec![
        (link_local, Some(Arc::from("eth0"))),
        (link_local, Some(Arc::from("eth1"))),
    ]);
    let keys = [(v4_prefix(), 0)];

    let first = query_keys(&mut manager, &keys, named.clone(), None, 1).unwrap();
    let rows = &first.routes[0].peers;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_interface.as_deref(), Some("eth0"));
    assert_eq!(rows[0].disposition, RouteExportDisposition::Committed);
    assert_eq!(
        first.next.as_ref().and_then(|cursor| cursor.after.clone()),
        Some((link_local, Some(Arc::from("eth0"))))
    );

    let rest = query_keys(&mut manager, &keys, named, resume_of(&first), 1).unwrap();
    let rows = &rest.routes[0].peers;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_interface.as_deref(), Some("eth1"));
    assert_eq!(rows[0].disposition, RouteExportDisposition::NotEstablished);
    assert!(rest.next.is_none());
}

/// A managed peer that becomes Established between pages moves from a
/// not-Established row to a registered one, so the walk is invalidated
/// rather than listing it twice or with a stale disposition. Registration
/// moves both the roster generation and the export chains' version. Red
/// proof: dropping both fails this test; dropping either alone does not.
#[test]
fn managed_peer_becoming_established_mid_walk_invalidates_the_walk() {
    let (mut manager, _tx) = manager();
    let _rx = peer_up(&mut manager, v4(2), ipv4_sendable(), None, 0, 64);
    inject(&mut manager, local_route(v4_prefix(), 0));
    let named = Some(numbered(&[v4(1), v4(2), v4(3)]));
    let keys = [(v4_prefix(), 0)];
    let first = query_keys(&mut manager, &keys, named.clone(), None, 1).unwrap();
    assert_eq!(peers_of(&first), vec![v4(1)]);

    let _joined = peer_up(&mut manager, v4(3), ipv4_sendable(), None, 0, 64);
    assert_eq!(
        query_keys(&mut manager, &keys, named, resume_of(&first), 1),
        Err(RouteExportPageError::Invalidated)
    );
}

/// A change to the managed peer set between pages, such as a neighbor added
/// by a reload, invalidates the walk even though no session registered.
/// Red proof: leaving the managed peers out of the version fails this test.
#[test]
fn managed_peer_set_change_mid_walk_invalidates_the_walk() {
    let (mut manager, _tx) = manager();
    inject(&mut manager, local_route(v4_prefix(), 0));
    let keys = [(v4_prefix(), 0)];
    let first = query_keys(
        &mut manager,
        &keys,
        Some(numbered(&[v4(1), v4(3)])),
        None,
        1,
    )
    .unwrap();
    assert_eq!(peers_of(&first), vec![v4(1)]);
    assert_eq!(
        query_keys(
            &mut manager,
            &keys,
            Some(numbered(&[v4(1), v4(2), v4(3)])),
            resume_of(&first),
            1
        ),
        Err(RouteExportPageError::Invalidated)
    );
    // The same set resumes.
    let rest = query_keys(
        &mut manager,
        &keys,
        Some(numbered(&[v4(1), v4(3)])),
        resume_of(&first),
        1,
    )
    .unwrap();
    assert_eq!(peers_of(&rest), vec![v4(3)]);
}

/// A page selects destinations with a bounded heap: it never holds more than
/// `page_size + 1` of them, however many peers are registered or named, and
/// the walk still lists every destination once, in order, across pages and
/// keys. Red proof: collecting and sorting every destination per page fails
/// the bound.
#[test]
fn page_selection_holds_at_most_page_size_plus_one_destinations() {
    use crate::manager::queries::EXPORT_SELECTION_HIGH_WATER;

    let (mut manager, _tx) = manager();
    let _receivers: Vec<_> = (1..=40)
        .map(|octet| peer_up(&mut manager, v4(octet), ipv4_sendable(), None, 0, 64))
        .collect();
    inject(&mut manager, local_route(prefix_at(1), 0));
    inject(&mut manager, local_route(prefix_at(3), 0));
    let named = Some(numbered(&(1..=80).map(v4).collect::<Vec<_>>()));
    let keys = batch_keys();
    let expected: Vec<IpAddr> = (1..=80).map(v4).collect();

    for page_size in [1, 2, 7] {
        let mut listed_rows: Vec<(usize, IpAddr)> = Vec::new();
        let mut resume = None;
        loop {
            EXPORT_SELECTION_HIGH_WATER.set(0);
            let page = query_keys(&mut manager, &keys, named.clone(), resume, page_size).unwrap();
            assert!(
                EXPORT_SELECTION_HIGH_WATER.get() <= page_size + 1,
                "page_size {page_size} held {}",
                EXPORT_SELECTION_HIGH_WATER.get()
            );
            for route in &page.routes {
                listed_rows.extend(route.peers.iter().map(|row| (route.key, row.peer)));
            }
            resume = resume_of(&page);
            if resume.is_none() {
                break;
            }
        }
        for key in [0, 2] {
            let peers: Vec<IpAddr> = listed_rows
                .iter()
                .filter(|(listed, _)| *listed == key)
                .map(|(_, peer)| *peer)
                .collect();
            assert_eq!(peers, expected, "page_size {page_size}, key {key}");
        }
    }
}
