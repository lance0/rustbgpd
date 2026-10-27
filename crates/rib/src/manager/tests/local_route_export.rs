//! Per-peer export disposition of a locally injected unicast route
//! (`QueryLocalRouteExport`): committed only for this exact local source,
//! withheld with a bounded reason, or pending, one row per registered peer.

use super::*;
use crate::PeerId;
use crate::test_support::peer_v4;
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
    peer: PeerId,
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
    peer: PeerId,
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

fn row(page: &RouteExportPage, peer: PeerId) -> &PeerRouteExport {
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
    let withheld = PeerId::from_addr(v4(1));
    let normal = PeerId::from_addr(v4(2));
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
    let v4_only = PeerId::from_addr(v4(3));
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
    let target = PeerId::from_addr(v4(2));
    let source = Ipv4Addr::new(10, 0, 0, 9);
    let _target_rx = peer_up(&mut manager, target, ipv4_sendable(), None, 0, 64);
    let _source_rx = peer_up(&mut manager, peer_v4(source), ipv4_sendable(), None, 0, 64);
    let prefix = v4_prefix();
    inject(&mut manager, local_route(prefix, 0));
    let Prefix::V4(v4_prefix) = prefix else {
        unreachable!()
    };
    // An iBGP-learned route with a higher LOCAL_PREF out-selects it.
    let mut better = make_route_with_lp(v4_prefix, source, 200);
    better.origin_type = crate::route::RouteOrigin::Ibgp;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(source),
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
    assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, peer_v4(source));
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
    assert_eq!(winner.route_peer, Some(peer_v4(source)));
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
    let target = PeerId::from_addr(v4(2));
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
    let add_path = PeerId::from_addr(v4(4));
    let denied = PeerId::from_addr(v4(5));
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
    let toml = PeerId::from_addr(v4(1));
    let toml_add_path = PeerId::from_addr(v4(2));
    let rpol = PeerId::from_addr(v4(3));
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
    let target = PeerId::from_addr(v4(1));
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
    let target = PeerId::from_addr(v4(6));
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
    let v4_only = PeerId::from_addr(v4(3));
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
    let target = PeerId::from_addr(v4(2));
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
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_sendable(),
                None,
                0,
                64,
            )
        })
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
    let _rx = peer_up(
        &mut manager,
        PeerId::from_addr(v4(1)),
        ipv4_sendable(),
        None,
        0,
        64,
    );
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
    let scoped = PeerId::from_addr(v4(1));
    let numbered = PeerId::from_addr(v4(2));
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
        .map(|row| row.peer.addr())
        .collect()
}

/// Peers 10.0.0.2..=4 and the local route, with a first page of two peers.
fn walk_started() -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    RouteExportPage,
) {
    walk_started_with(0, |_| {})
}

/// [`walk_started`] with the peers' Add-Path `send_max`, and `setup` run
/// once they are registered, before the route is injected.
fn walk_started_with(
    add_path_send_max: u32,
    setup: impl FnOnce(&mut RibManager),
) -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    RouteExportPage,
) {
    let (mut manager, _tx) = manager();
    let receivers = [2, 3, 4]
        .into_iter()
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_sendable(),
                None,
                add_path_send_max,
                64,
            )
        })
        .collect();
    setup(&mut manager);
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
    receivers.push(peer_up(
        &mut manager,
        PeerId::from_addr(v4(1)),
        ipv4_sendable(),
        None,
        0,
        64,
    ));
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
        peer: PeerId::from_addr(v4(2)),
        session_id: 0,
    });
    assert_eq!(
        resume(&mut manager, &first),
        Err(RouteExportPageError::Invalidated)
    );

    let (mut manager, mut receivers, first) = walk_started();
    manager.handle_update(RibUpdate::PeerDown {
        peer: PeerId::from_addr(v4(2)),
        session_id: 0,
    });
    receivers.push(peer_up(
        &mut manager,
        PeerId::from_addr(v4(2)),
        ipv4_sendable(),
        None,
        0,
        64,
    ));
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
        peer: PeerId::from_addr(v4(9)),
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
        peer: PeerId::from_addr(v4(2)),
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

/// rpol policy `p` from `policy`, bound to a prefix dataset `allowed` that
/// lists the local route's prefix when `listed`.
fn allowed_dataset_chain(
    policy: &str,
    listed: bool,
) -> (PolicyChain, Arc<rustbgpd_policy::datasets::DatasetHandle>) {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetHandle, DatasetKind};
    use rustbgpd_policy::sets::SetStore;

    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        allowed_dataset(listed),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled =
        rustbgpd_policy::rpol::RpolFile::parse(&format!("dataset prefix-set allowed\n{policy}"))
            .unwrap()
            .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
            .unwrap()
            .unwrap();
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);
    (chain, handle)
}

/// Peers 10.0.0.2..=4 whose export chain accepts the local route only while
/// it is listed in the returned dataset, and the route itself.
fn dataset_walk_setup() -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    Arc<rustbgpd_policy::datasets::DatasetHandle>,
) {
    let (chain, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { accept } reject } }",
        true,
    );
    let (mut manager, _tx) = manager();
    let receivers = [2, 3, 4]
        .into_iter()
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
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

/// An explain's deny label and its deny-validation codes come from the one
/// walk that decided, so a dataset refresh landing after that walk cannot
/// make the label name another term. The RPKI term decides; the hook then
/// lists the prefix, which would make the earlier `listed` term decide a
/// second walk. Both the single-best and the Add-Path explain arms are
/// covered. Red proof: deriving the label from a separate statement-trace
/// walk names `p:listed` beside the `rov` term's `rpki_invalid`.
#[test]
fn explain_deny_label_names_the_deciding_term_across_a_dataset_refresh() {
    use crate::manager::distribution::AFTER_EXPORT_EXPLAIN_WALK;
    use crate::update::ExportGateVerdict;

    let (chain, handle) = allowed_dataset_chain(
        "policy p { term listed { if route.prefix in allowed { reject } } \
         term rov { if route.rpki == invalid { reject } } term rest { accept } }",
        false,
    );
    let (mut manager, _tx) = manager();
    let single_best = PeerId::from_addr(v4(1));
    let add_path = PeerId::from_addr(v4(2));
    let _single_rx = peer_up(
        &mut manager,
        single_best,
        ipv4_sendable(),
        Some(chain.clone()),
        0,
        64,
    );
    let _add_path_rx = peer_up(&mut manager, add_path, ipv4_sendable(), Some(chain), 2, 64);
    let mut route = local_route(v4_prefix(), 0);
    route.validation_state = RpkiValidation::Invalid;
    inject(&mut manager, route);

    for peer in [single_best, add_path] {
        handle.refresh(allowed_dataset(false));
        let refresh = Arc::clone(&handle);
        AFTER_EXPORT_EXPLAIN_WALK.set(Some(Box::new(move || {
            refresh.refresh(allowed_dataset(true));
        })));
        let (reply, mut explained) = oneshot::channel();
        manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
            peer,
            prefix: v4_prefix(),
            rd: None,
            labeled: false,
            source: None,
            reply,
        });
        let explain = explained.try_recv().unwrap().unwrap();
        assert!(
            AFTER_EXPORT_EXPLAIN_WALK.take().is_none(),
            "the refresh must land after the walk for peer {peer}"
        );
        let stop = explain
            .gates
            .iter()
            .find(|step| step.verdict == ExportGateVerdict::Stop)
            .expect("export policy stops the route");
        assert_eq!(
            (stop.code, stop.detail.as_str()),
            ("policy_denied", "export policy \"p:rov\" denied this route"),
            "peer {peer}"
        );
        assert_eq!(explain.deny_validation, ["rpki_invalid"], "peer {peer}");
    }
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
                route.peers.iter().map(|row| row.peer.addr()).collect(),
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
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_sendable(),
                None,
                0,
                64,
            )
        })
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
        row(&page, PeerId::from_addr(v4(1))).disposition,
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
    let _rx = peer_up(
        &mut manager,
        PeerId::from_addr(v4(2)),
        ipv4_sendable(),
        None,
        0,
        64,
    );
    inject(&mut manager, local_route(v4_prefix(), 0));

    let page = query_keys(
        &mut manager,
        &[(v4_prefix(), 0)],
        Some(numbered(&[
            (PeerId::from_addr(v4(1))).addr(),
            (PeerId::from_addr(v4(2))).addr(),
            (PeerId::from_addr(v4(3))).addr(),
        ])),
        None,
        10,
    )
    .unwrap();
    assert_eq!(peers_of(&page), vec![v4(1), v4(2), v4(3)]);
    assert_eq!(
        row(&page, PeerId::from_addr(v4(2))).disposition,
        RouteExportDisposition::Committed
    );
    for peer in [v4(1), v4(3)] {
        let row = row(&page, PeerId::from_addr(peer));
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
    let link_local = PeerId::from_addr("fe80::1".parse().unwrap());
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
        (link_local.addr(), Some(Arc::from("eth0"))),
        (link_local.addr(), Some(Arc::from("eth1"))),
    ]);
    let keys = [(v4_prefix(), 0)];

    let first = query_keys(&mut manager, &keys, named.clone(), None, 1).unwrap();
    let rows = &first.routes[0].peers;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_interface.as_deref(), Some("eth0"));
    assert_eq!(rows[0].disposition, RouteExportDisposition::Committed);
    assert_eq!(
        first.next.as_ref().and_then(|cursor| cursor.after.clone()),
        Some((link_local.addr(), Some(Arc::from("eth0"))))
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
    let _rx = peer_up(
        &mut manager,
        PeerId::from_addr(v4(2)),
        ipv4_sendable(),
        None,
        0,
        64,
    );
    inject(&mut manager, local_route(v4_prefix(), 0));
    let named = Some(numbered(&[
        (PeerId::from_addr(v4(1))).addr(),
        (PeerId::from_addr(v4(2))).addr(),
        (PeerId::from_addr(v4(3))).addr(),
    ]));
    let keys = [(v4_prefix(), 0)];
    let first = query_keys(&mut manager, &keys, named.clone(), None, 1).unwrap();
    assert_eq!(peers_of(&first), vec![v4(1)]);

    let _joined = peer_up(
        &mut manager,
        PeerId::from_addr(v4(3)),
        ipv4_sendable(),
        None,
        0,
        64,
    );
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
        Some(numbered(&[
            (PeerId::from_addr(v4(1))).addr(),
            (PeerId::from_addr(v4(3))).addr(),
        ])),
        None,
        1,
    )
    .unwrap();
    assert_eq!(peers_of(&first), vec![v4(1)]);
    assert_eq!(
        query_keys(
            &mut manager,
            &keys,
            Some(numbered(&[
                (PeerId::from_addr(v4(1))).addr(),
                (PeerId::from_addr(v4(2))).addr(),
                (PeerId::from_addr(v4(3))).addr()
            ])),
            resume_of(&first),
            1
        ),
        Err(RouteExportPageError::Invalidated)
    );
    // The same set resumes.
    let rest = query_keys(
        &mut manager,
        &keys,
        Some(numbered(&[
            (PeerId::from_addr(v4(1))).addr(),
            (PeerId::from_addr(v4(3))).addr(),
        ])),
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
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_sendable(),
                None,
                0,
                64,
            )
        })
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
                listed_rows.extend(route.peers.iter().map(|row| (route.key, row.peer.addr())));
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

// --- FlowSpec (`QueryLocalFlowSpecExport`) --------------------------------

/// A local rule as `AddFlowSpec` builds it, with `communities`.
fn local_rule(communities: &[u32]) -> FlowSpecRoute {
    let mut rule = crate::test_support::make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    rule.peer = LOCAL_PEER;
    rule.origin_type = crate::route::RouteOrigin::Local;
    rule.peer_router_id = Ipv4Addr::UNSPECIFIED;
    rule.attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ];
    if !communities.is_empty() {
        rule.attributes
            .push(PathAttribute::Communities(communities.to_vec()));
    }
    rule
}

fn inject_rule(manager: &mut RibManager, rule: FlowSpecRoute) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectFlowSpec { route: rule, reply });
    rx.try_recv().unwrap().unwrap();
}

fn query_rule(
    manager: &mut RibManager,
    key: &crate::route::FlowSpecKey,
    named: Option<Vec<ExportDestination>>,
    resume: Resume,
    page_size: usize,
) -> Result<RouteExportPage, RouteExportPageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLocalFlowSpecExport {
        key: key.clone(),
        managed: named,
        resume,
        page_size,
        reply,
    });
    rx.try_recv().unwrap()
}

/// The `FlowSpec` rule's destination prefix, for a prefix deny.
fn rule_prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24))
}

/// One row per registered peer, each with the reason its own export gate
/// gives: committed, family not negotiated, export policy, and a
/// pre-policy community gate.
#[test]
fn flowspec_dispositions_name_each_peers_gate() {
    let (mut manager, _tx) = manager();
    let committed = v4(1);
    let unicast_only = v4(2);
    let denied = v4(3);
    let _committed_rx = peer_up(
        &mut manager,
        PeerId::from_addr(committed),
        ipv4_flowspec_sendable(),
        None,
        0,
        64,
    );
    let _unicast_rx = peer_up(
        &mut manager,
        PeerId::from_addr(unicast_only),
        ipv4_sendable(),
        None,
        0,
        64,
    );
    let _denied_rx = peer_up(
        &mut manager,
        PeerId::from_addr(denied),
        ipv4_flowspec_sendable(),
        Some(deny_prefixes_chain(&[rule_prefix()])),
        0,
        64,
    );
    let rule = local_rule(&[]);
    let key = rule.selection_key();
    inject_rule(&mut manager, rule);

    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    assert_eq!(peers_of(&page), vec![committed, unicast_only, denied]);
    assert!(page.next.is_none());
    let export = row(&page, PeerId::from_addr(committed));
    assert_eq!(export.disposition, RouteExportDisposition::Committed);
    assert_eq!(export.reason, "");
    let export = row(&page, PeerId::from_addr(unicast_only));
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "family_not_negotiated");
    assert_eq!(export.explain_code, "family_not_sendable");
    let export = row(&page, PeerId::from_addr(denied));
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "export_policy");
    assert_eq!(export.explain_code, "policy_denied");
    assert_eq!(export.deny_validation, Vec::<String>::new());

    // NO_ADVERTISE stops the rule before policy, for every peer.
    inject_rule(
        &mut manager,
        local_rule(&[rustbgpd_wire::COMMUNITY_NO_ADVERTISE]),
    );
    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    for peer in [committed, denied] {
        let export = row(&page, PeerId::from_addr(peer));
        assert_eq!(export.disposition, RouteExportDisposition::Withheld);
        assert_eq!(export.reason, "export_rule");
        assert_eq!(export.explain_code, "no_advertise_suppressed");
    }
}

/// A received rule with the same key that out-selects the local one is
/// never this rule's export, although the peer's Adj-RIB-Out holds the key.
/// Red proof: dropping the source check reports it committed.
#[test]
fn received_flowspec_rule_out_selecting_the_local_one_is_not_selected() {
    let (mut manager, _tx) = manager();
    let target = v4(2);
    let source = Ipv4Addr::new(10, 0, 0, 9);
    let _target_rx = peer_up(
        &mut manager,
        PeerId::from_addr(target),
        ipv4_flowspec_sendable(),
        None,
        0,
        64,
    );
    let _source_rx = peer_up(
        &mut manager,
        peer_v4(source),
        ipv4_flowspec_sendable(),
        None,
        0,
        64,
    );
    let rule = local_rule(&[]);
    let key = rule.selection_key();
    inject_rule(&mut manager, rule);
    let mut received = crate::test_support::make_flowspec_route(source);
    received.origin_type = crate::route::RouteOrigin::Ibgp;
    received.attributes.push(PathAttribute::LocalPref(200));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(source),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![received],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(
        manager.loc_rib.get_flowspec(&key).unwrap().peer,
        peer_v4(source)
    );
    assert!(
        manager
            .adj_ribs_out
            .get(&PeerId::from_addr(target))
            .and_then(|out| out.get_flowspec(&key))
            .is_some()
    );

    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    let export = row(&page, PeerId::from_addr(target));
    assert_eq!(export.disposition, RouteExportDisposition::Withheld);
    assert_eq!(export.reason, "not_selected");
}

/// Selection flag of each candidate in `peer`'s Adj-RIB-In, by key.
fn received_flowspec_selected(
    manager: &mut RibManager,
    peer: PeerId,
) -> HashMap<crate::route::FlowSpecKey, bool> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryReceivedFlowSpecRoutes {
        peer,
        filter: None,
        reply,
    });
    rx.try_recv()
        .unwrap()
        .into_iter()
        .map(|row| (row.route.selection_key(), row.selected))
        .collect()
}

/// ADR-0141 amendment (2026-10-26): after a planned restart, a static GR
/// waiter that never comes up holds RFC 4724 selection deferral. An injected
/// `FlowSpec` rule is still selected and committed to an Established peer at
/// once. Received rules wait, including one with the injected rule's key
/// that out-selects it only at release; our `FlowSpec` `EoR` waits for the
/// release; injected RTBH unicast has its own exemption. Red proof:
/// dropping the injected-rule exemption from `FlowSpec` selection leaves the rule
/// unselected and its export pending.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart transcript pins the window and its release in order"
)]
fn injected_flowspec_is_exported_during_selection_deferral() {
    const FLOWSPEC: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);
    const UNICAST: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: std::time::Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
                families: vec![FLOWSPEC, UNICAST],
            }],
        });
    let target = PeerId::from_addr(v4(2));
    let source_addr = Ipv4Addr::new(10, 0, 0, 9);
    let source = peer_v4(source_addr);
    let mut target_rx = peer_up(&mut manager, target, vec![FLOWSPEC, UNICAST], None, 0, 64);
    let _source_rx = peer_up(&mut manager, source, ipv4_flowspec_sendable(), None, 0, 64);

    let rule = local_rule(&[]);
    let key = rule.selection_key();
    inject_rule(&mut manager, rule);
    let unicast = v4_prefix();
    inject(&mut manager, local_route(unicast, 0));
    // A received rule with the injected key that wins best path, and one
    // with a key of its own.
    let mut same = crate::test_support::make_flowspec_route(source_addr);
    same.origin_type = crate::route::RouteOrigin::Ibgp;
    same.attributes.push(PathAttribute::LocalPref(200));
    let mut other = crate::test_support::make_flowspec_route(source_addr);
    other.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
    )];
    let other_key = other.selection_key();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![same, other],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);

    // The window: the injected rule is selected and committed.
    assert!(manager.selection_deferred(FLOWSPEC));
    assert_eq!(
        received_flowspec_selected(&mut manager, LOCAL_PEER),
        HashMap::from([(key.clone(), true)])
    );
    assert_eq!(
        received_flowspec_selected(&mut manager, source),
        HashMap::from([(key.clone(), false), (other_key.clone(), false)])
    );
    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Committed);
    assert_eq!(export.reason, "");
    let window: Vec<_> = std::iter::from_fn(|| target_rx.try_recv().ok()).collect();
    let announced: Vec<_> = window
        .iter()
        .flat_map(|update| &update.flowspec_announce)
        .map(|route| (route.selection_key(), route.peer))
        .collect();
    assert_eq!(announced, vec![(key.clone(), LOCAL_PEER)]);
    assert_eq!(
        window
            .iter()
            .flat_map(|update| update.announce.iter())
            .map(|route| (route.prefix, route.peer))
            .collect::<Vec<_>>(),
        vec![(unicast, LOCAL_PEER)]
    );
    assert!(
        window.iter().all(|update| update.end_of_rib.is_empty()),
        "no EoR may leave before release"
    );
    // A peer established inside the window gets the rule in its initial
    // table, and a dirty resync re-sends it; neither withdraws it or sends
    // our FlowSpec EoR. Each path is drained and checked on its own.
    let late = PeerId::from_addr(v4(3));
    let mut late_rx = peer_up(&mut manager, late, ipv4_flowspec_sendable(), None, 0, 64);
    let assert_window_sends_rule = |late_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
                                    path: &str| {
        let sent: Vec<_> = std::iter::from_fn(|| late_rx.try_recv().ok()).collect();
        let announced: Vec<_> = sent
            .iter()
            .flat_map(|update| &update.flowspec_announce)
            .map(|route| (route.selection_key(), route.peer))
            .collect();
        assert_eq!(
            announced,
            vec![(key.clone(), LOCAL_PEER)],
            "{path} must send the injected rule"
        );
        assert!(
            sent.iter().all(|update| update.flowspec_withdraw.is_empty()
                && !update.end_of_rib.contains(&FLOWSPEC)),
            "{path}: no withdrawal and no FlowSpec EoR inside the window"
        );
    };
    assert_window_sends_rule(&mut late_rx, "the initial table");
    manager.mark_outbound_dirty(late);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert_window_sends_rule(&mut late_rx, "the dirty resync");
    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    assert_eq!(
        row(&page, late).disposition,
        RouteExportDisposition::Committed
    );
    // The local-unicast exemption shares the held End-of-RIB boundary.
    let page = query(&mut manager, unicast, 0, None, 10).unwrap();
    let export = row(&page, target);
    assert_eq!(export.disposition, RouteExportDisposition::Committed);
    assert_eq!(export.reason, "");

    // Release: best path decides the shared key, and each EoR follows its
    // family's payload. The timer releases both families together; pin the
    // order in which their completions run so unicast's EoR flush runs
    // before the FlowSpec release selection.
    let metrics = manager.metrics.clone();
    let mut released = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .expire(&metrics);
    released.sort_by_key(|family| *family != UNICAST);
    assert_eq!(released, vec![UNICAST, FLOWSPEC]);
    manager.release_selection_families(&released, "Selection_Deferral_Timer expired");
    assert!(!manager.selection_deferred(FLOWSPEC));
    assert_eq!(
        received_flowspec_selected(&mut manager, source),
        HashMap::from([(key.clone(), true), (other_key.clone(), true)])
    );
    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    assert_eq!(row(&page, target).reason, "not_selected");
    let page = query(&mut manager, unicast, 0, None, 10).unwrap();
    assert_eq!(
        row(&page, target).disposition,
        RouteExportDisposition::Committed
    );
    let release: Vec<_> = std::iter::from_fn(|| target_rx.try_recv().ok()).collect();
    let mut announced = HashSet::new();
    let mut eor = Vec::new();
    for update in &release {
        for route in &update.flowspec_announce {
            assert!(
                !eor.contains(&FLOWSPEC),
                "a FlowSpec announce followed the FlowSpec EoR"
            );
            announced.insert((route.selection_key(), route.peer));
        }
        eor.extend(update.end_of_rib.iter().copied());
    }
    assert_eq!(
        announced,
        HashSet::from([(key, source), (other_key, source)])
    );
    assert_eq!(eor.len(), 2, "one EoR per family: {eor:?}");
    assert_eq!(
        eor.into_iter().collect::<HashSet<_>>(),
        HashSet::from([UNICAST, FLOWSPEC])
    );
    let release: Vec<_> = std::iter::from_fn(|| late_rx.try_recv().ok()).collect();
    let eor_at = release
        .iter()
        .position(|update| update.end_of_rib.contains(&FLOWSPEC))
        .expect("the late peer gets its FlowSpec EoR at release");
    assert!(
        release[eor_at..]
            .iter()
            .all(|update| update.flowspec_announce.is_empty()),
        "a FlowSpec announce followed the late peer's FlowSpec EoR"
    );
}

#[derive(Clone, Copy, Debug)]
enum DeferredUnicastMode {
    Single,
    AddPath,
    Orr,
    GroupedPerClient,
    PrivatePerClient,
}

const DEFERRED_UNICAST_MODES: [DeferredUnicastMode; 5] = [
    DeferredUnicastMode::Single,
    DeferredUnicastMode::AddPath,
    DeferredUnicastMode::Orr,
    DeferredUnicastMode::GroupedPerClient,
    DeferredUnicastMode::PrivatePerClient,
];
const DEFERRED_BLACKHOLE: u32 = 0xffff_029a;

fn deferred_unicast_families() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
}

fn deferred_unicast_hosts() -> [Prefix; 2] {
    [
        v4_prefix(),
        Prefix::V6(Ipv6Prefix::new("2001:db8::7".parse().unwrap(), 128)),
    ]
}

fn deferred_unicast_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 0, 1)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_mins(2),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
            families: deferred_unicast_families(),
        }],
    })
    .with_eor_grace(crate::EorGraceConfig {
        peers: [2, 3]
            .map(|octet| crate::EorGracePeerConfig {
                peer: PeerId::from_addr(v4(octet)).into(),
                deadline,
                families: deferred_unicast_families(),
            })
            .into(),
        replay_owners: vec!["deferral-test".to_string()],
    });
    let source = Ipv4Addr::new(198, 51, 100, 250);
    manager.handle_update(RibUpdate::BgpLsRoutesReceived {
        peer: peer_v4(source),
        session_id: 0,
        announced: crate::orr::fixtures::square_topology(source),
        withdrawn: vec![],
    });
    manager
}

fn deferred_unicast_policy(private: bool, deny_local: bool) -> Option<PolicyChain> {
    if !private && !deny_local {
        return None;
    }
    let mut chain = deny_prefixes_chain(&[v4_prefix()]);
    let mut statement = chain.policies[0].policy.entries[0].clone();
    statement.prefix = None;
    let mut entries = Vec::new();
    if deny_local {
        let mut deny = statement.clone();
        deny.match_community = vec![rustbgpd_policy::CommunityMatch::Standard {
            value: DEFERRED_BLACKHOLE,
        }];
        entries.push(deny);
    }
    if private {
        // A real peer-context criterion disqualifies grouping without changing
        // this fixture's export decisions.
        statement.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![u32::MAX],
            peer_groups: vec![],
        });
        entries.push(statement);
    }
    chain.policies[0].policy.entries = entries;
    Some(PolicyChain::from_named(chain.policies))
}

fn deferred_unicast_peer(
    manager: &mut RibManager,
    peer: PeerId,
    mode: DeferredUnicastMode,
    deny_local: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let add_path = matches!(mode, DeferredUnicastMode::AddPath);
    let orr = matches!(mode, DeferredUnicastMode::Orr);
    let per_client = matches!(
        mode,
        DeferredUnicastMode::GroupedPerClient | DeferredUnicastMode::PrivatePerClient
    );
    let vantage = IpAddr::V4(Ipv4Addr::new(
        10,
        0,
        crate::orr::fixtures::B,
        crate::orr::fixtures::X,
    ));
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 0,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_010,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: deferred_unicast_policy(
            matches!(mode, DeferredUnicastMode::PrivatePerClient),
            deny_local,
        ),
        sendable_families: deferred_unicast_families(),
        is_ebgp: !orr,
        route_reflector_client: orr,
        orr_vantage: orr.then_some(vantage),
        per_client_best: per_client,
        interpret_rfc1997: true,
        add_path_send_families: if add_path {
            deferred_unicast_families()
        } else {
            vec![]
        },
        add_path_send_max: if add_path { 4 } else { 0 },
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    if orr {
        assert!(
            manager.orr.spf.contains_key(&vantage),
            "exercise resolved ORR"
        );
    }
    if per_client {
        assert_eq!(
            manager.grouped_member_of(peer).is_some(),
            matches!(mode, DeferredUnicastMode::GroupedPerClient),
            "exercise the requested per-client path"
        );
    }
    outbound_rx
}

fn deferred_unicast_local(prefix: Prefix, path_id: u32, preference: u32) -> Route {
    let mut route = local_route(prefix, path_id);
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::LocalPref(preference));
        attrs.push(PathAttribute::Communities(vec![DEFERRED_BLACKHOLE]));
    });
    route
}

fn deferred_unicast_lease(
    manager: &mut RibManager,
    route: Route,
) -> crate::injection_lease::LeaseGeneration {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectLeasedRoute {
        route,
        owner: "deferral-test".to_string(),
        lease_seconds: 5,
        reply,
    });
    response.try_recv().unwrap().unwrap().1
}

fn deferred_unicast_received(manager: &mut RibManager, prefixes: &[Prefix]) -> PeerId {
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 9));
    let announced = prefixes
        .iter()
        .map(|prefix| {
            let mut route = local_route(*prefix, 91);
            set_peer(&mut route, source);
            route.origin_type = crate::route::RouteOrigin::Ebgp;
            route.next_hop = match prefix {
                Prefix::V4(_) => IpAddr::V4(Ipv4Addr::new(
                    10,
                    0,
                    crate::orr::fixtures::Y,
                    crate::orr::fixtures::A,
                )),
                Prefix::V6(_) => IpAddr::V6("2001:db8::9".parse().unwrap()),
            };
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.retain(|attr| !matches!(attr, PathAttribute::AsPath(_)));
                attrs.push(PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65_009])],
                }));
                attrs.push(PathAttribute::LocalPref(300));
            });
            route
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
    source
}

fn deferred_unicast_drain(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

#[track_caller]
fn assert_deferred_unicast_replay(
    updates: &[OutboundRouteUpdate],
    mode: DeferredUnicastMode,
    prefixes: &[Prefix],
    multiple: bool,
) {
    assert!(updates.iter().all(|update| update.end_of_rib.is_empty()));
    assert!(updates.iter().all(|update| update.withdraw.is_empty()));
    let announced: BTreeSet<_> = updates
        .iter()
        .flat_map(|update| update.announce.iter())
        .map(|route| {
            assert_eq!(route.peer, LOCAL_PEER, "{mode:?}: received route escaped");
            assert!(route.next_hop.is_unspecified(), "keep next-hop self");
            (route.prefix, route.path_id)
        })
        .collect();
    let expected: BTreeSet<_> = prefixes
        .iter()
        .flat_map(|prefix| {
            let ids = if matches!(mode, DeferredUnicastMode::AddPath) {
                if multiple { vec![1, 2] } else { vec![1] }
            } else {
                vec![0]
            };
            ids.into_iter().map(|path_id| (*prefix, path_id))
        })
        .collect();
    assert_eq!(announced, expected, "{mode:?}: exact local replay");
    assert_eq!(
        updates
            .iter()
            .map(|update| update.announce.len())
            .sum::<usize>(),
        announced.len(),
        "a path must not be announced twice in one replay"
    );
}

fn deferred_unicast_explain(
    manager: &mut RibManager,
    target: PeerId,
    prefix: Prefix,
    mode: DeferredUnicastMode,
    source: (PeerId, u32),
) -> crate::update::ExplainAdvertisedRoute {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
        peer: target,
        prefix,
        rd: None,
        labeled: false,
        source: matches!(mode, DeferredUnicastMode::AddPath).then_some(
            crate::update::RouteSourceIdentity {
                peer: source.0,
                path_id: source.1,
            },
        ),
        reply,
    });
    response.try_recv().unwrap().unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restart transcript checks every selection mode and each export phase"
)]
fn injected_unicast_is_exported_during_selection_deferral() {
    for mode in DEFERRED_UNICAST_MODES {
        let mut manager = deferred_unicast_manager();
        let target = PeerId::from_addr(v4(2));
        let mut target_rx = deferred_unicast_peer(&mut manager, target, mode, false);
        assert!(deferred_unicast_drain(&mut target_rx).is_empty());
        let hosts = deferred_unicast_hosts();
        inject(&mut manager, deferred_unicast_local(hosts[0], 17, 150));
        let generation =
            deferred_unicast_lease(&mut manager, deferred_unicast_local(hosts[1], 17, 150));
        for prefix in hosts {
            inject(&mut manager, deferred_unicast_local(prefix, 23, 100));
        }
        let source = deferred_unicast_received(&mut manager, &hosts);
        for prefix in hosts {
            let best = manager.loc_rib.get(&prefix).expect("local path selected");
            assert_eq!((best.peer, best.path_id), (LOCAL_PEER, 17), "{mode:?}");
            assert!(best.communities().contains(&DEFERRED_BLACKHOLE));
            let page = query(&mut manager, prefix, 17, None, 10).unwrap();
            assert_eq!(
                row(&page, target).disposition,
                RouteExportDisposition::Committed
            );
            let explanation =
                deferred_unicast_explain(&mut manager, target, prefix, mode, (LOCAL_PEER, 17));
            assert_eq!(
                explanation.decision,
                crate::update::ExplainDecision::Advertise
            );
            assert!(explanation.already_advertised);
            assert_eq!(
                (explanation.route_peer, explanation.route_path_id),
                (Some(LOCAL_PEER), Some(17))
            );
            assert!(
                explanation
                    .orr_candidates
                    .iter()
                    .all(|route| route.peer == LOCAL_PEER)
            );
            let page = query(&mut manager, prefix, 23, None, 10).unwrap();
            let export = row(&page, target);
            assert_eq!(
                export.disposition,
                if matches!(mode, DeferredUnicastMode::AddPath) {
                    RouteExportDisposition::Committed
                } else {
                    RouteExportDisposition::Withheld
                }
            );
            if matches!(mode, DeferredUnicastMode::AddPath) {
                assert_eq!(export.advertised_path_id, 2);
                let held =
                    deferred_unicast_explain(&mut manager, target, prefix, mode, (source, 91));
                assert_eq!(held.decision, crate::update::ExplainDecision::NoBestRoute);
                assert!(!held.already_advertised);
                assert!(
                    held.reasons
                        .iter()
                        .any(|reason| reason.code == "no_best_route")
                );
            } else {
                assert_eq!(export.reason, "not_selected");
            }
        }
        let retained = manager.ribs.get(&source).unwrap();
        assert_eq!(retained.len(), 2);
        assert!(
            retained
                .iter()
                .all(|route| !route.is_stale && !route.is_llgr_stale)
        );
        assert_eq!(
            manager
                .injection_leases()
                .live_generation("deferral-test")
                .0,
            Some(generation)
        );
        assert_deferred_unicast_replay(&deferred_unicast_drain(&mut target_rx), mode, &hosts, true);

        let late = PeerId::from_addr(v4(3));
        let mut late_rx = deferred_unicast_peer(&mut manager, late, mode, false);
        assert_deferred_unicast_replay(&deferred_unicast_drain(&mut late_rx), mode, &hosts, true);
        // Hold every channel permit so a real local replacement fails
        // admission. Resync must deliver that change, not just inspect an
        // already-current private Adj-RIB-Out and legitimately emit nothing.
        let mut permits = Vec::new();
        while let Ok(permit) = manager.outbound_peers[&late].clone().try_reserve_owned() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());
        let mut changed_local = deferred_unicast_local(hosts[0], 17, 150);
        AttrSet::edit(&mut changed_local.attributes, |attrs| {
            attrs.push(PathAttribute::Med(99));
        });
        inject(&mut manager, changed_local);
        assert_deferred_unicast_replay(
            &deferred_unicast_drain(&mut target_rx),
            mode,
            &[hosts[0]],
            false,
        );
        assert!(manager.dirty_peers.contains(&late));
        assert_eq!(
            row(&query(&mut manager, hosts[0], 17, None, 10).unwrap(), late).reason,
            "outbound_resync"
        );
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());
        drop(permits);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        let resync = deferred_unicast_drain(&mut late_rx);
        let replayed = if manager.grouped_member_of(late).is_some() {
            hosts.as_slice()
        } else {
            &hosts[..1]
        };
        assert_deferred_unicast_replay(&resync, mode, replayed, false);
        assert!(
            resync
                .iter()
                .flat_map(|update| update.announce.iter())
                .any(|route| route.prefix == hosts[0] && route.med_attr() == Some(99))
        );
        for prefix in hosts {
            assert_eq!(
                row(&query(&mut manager, prefix, 17, None, 10).unwrap(), late).disposition,
                RouteExportDisposition::Committed
            );
        }

        // Removing the preferred local path promotes the other local path,
        // even though the retained received competitor has higher LOCAL_PREF.
        withdraw(&mut manager, hosts[0], 17);
        assert_eq!(manager.loc_rib.get(&hosts[0]).unwrap().path_id, 23);
        let page = query(&mut manager, hosts[0], 23, None, 10).unwrap();
        assert_eq!(
            row(&page, target).disposition,
            RouteExportDisposition::Committed
        );
        for rx in [&mut target_rx, &mut late_rx] {
            let updates = deferred_unicast_drain(rx);
            assert!(updates.iter().all(|update| update.end_of_rib.is_empty()));
            let announced: Vec<_> = updates
                .iter()
                .flat_map(|update| update.announce.iter())
                .collect();
            assert_eq!(announced.len(), 1);
            assert_eq!(
                (announced[0].prefix, announced[0].peer),
                (hosts[0], LOCAL_PEER)
            );
            assert_eq!(announced[0].local_pref(), 100);
            let expected = if matches!(mode, DeferredUnicastMode::AddPath) {
                vec![(hosts[0], 2)]
            } else {
                vec![]
            };
            assert_eq!(
                updates
                    .iter()
                    .flat_map(|update| update.withdraw.iter().copied())
                    .collect::<Vec<_>>(),
                expected
            );
        }

        // An ordinary untagged aggregate waits alongside received routes.
        let plain = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24));
        inject(&mut manager, local_route(plain, 71));
        assert!(manager.loc_rib.get(&plain).is_none());
        assert!(deferred_unicast_drain(&mut target_rx).is_empty());
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());
        assert_eq!(
            row(&query(&mut manager, plain, 71, None, 10).unwrap(), target).reason,
            "selection_deferred"
        );

        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::MarkReplayComplete {
            owner: "deferral-test".to_string(),
            incarnation: manager.injection_leases().incarnation(),
            reply,
        });
        assert_eq!(
            response.try_recv().unwrap().unwrap(),
            super::super::ReplayComplete::Released
        );
        for family in deferred_unicast_families() {
            assert!(manager.selection_deferred(family));
        }
        assert!(deferred_unicast_drain(&mut target_rx).is_empty());
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());

        let metrics = manager.metrics.clone();
        let mut families = manager
            .selection_deferral
            .as_mut()
            .unwrap()
            .expire(&metrics);
        families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
        assert_eq!(families, deferred_unicast_families());
        manager.release_selection_families(&families, "Selection_Deferral_Timer expired");
        for prefix in hosts {
            assert_eq!(
                manager.loc_rib.get(&prefix).unwrap().peer,
                source,
                "received index survives the window"
            );
        }
        for rx in [&mut target_rx, &mut late_rx] {
            let updates = deferred_unicast_drain(rx);
            for family in deferred_unicast_families() {
                let mut terminal = false;
                let mut count = 0;
                let mut announced = false;
                for update in &updates {
                    for route in update
                        .announce
                        .iter()
                        .filter(|route| prefix_family(&route.prefix) == family)
                    {
                        assert!(!terminal, "{mode:?}: release data follows EoR");
                        announced |= route.peer == source;
                    }
                    if update.end_of_rib.contains(&family) {
                        terminal = true;
                        count += 1;
                    }
                }
                assert!(announced, "{mode:?}: released received path is exported");
                assert_eq!(count, 1, "{mode:?}: exactly one EoR per family");
            }
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one dual-stack transcript pins the RTBH boundary across every export mode"
)]
fn unicast_deferral_exempts_only_local_rtbh_candidates() {
    let defaults = [
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)),
        Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0)),
    ];
    let aggregates = [
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24)),
        Prefix::V6(Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 64)),
    ];
    for mode in DEFERRED_UNICAST_MODES {
        let mut manager = deferred_unicast_manager();
        let target = PeerId::from_addr(v4(2));
        let mut rx = deferred_unicast_peer(&mut manager, target, mode, false);
        assert!(deferred_unicast_drain(&mut rx).is_empty());
        let hosts = deferred_unicast_hosts();
        for prefix in defaults.into_iter().chain(aggregates) {
            inject(&mut manager, local_route(prefix, 23));
            assert!(
                manager.loc_rib.get(&prefix).is_none(),
                "{mode:?}: non-RTBH held"
            );
            let page = query(&mut manager, prefix, 23, None, 10).unwrap();
            assert_eq!(
                row(&page, target).disposition,
                RouteExportDisposition::Pending
            );
            assert_eq!(row(&page, target).reason, "selection_deferred");
            let explain =
                deferred_unicast_explain(&mut manager, target, prefix, mode, (LOCAL_PEER, 23));
            assert_eq!(
                explain.decision,
                crate::update::ExplainDecision::NoBestRoute
            );
        }
        assert!(deferred_unicast_drain(&mut rx).is_empty());
        // Host shape is sufficient without BLACKHOLE; the leased API follows
        // the same rule as the unleased API and preserves arbitrary path IDs.
        inject(&mut manager, local_route(hosts[0], 17));
        deferred_unicast_lease(&mut manager, local_route(hosts[1], 17));
        for prefix in aggregates {
            // The same prefix has an untagged local path with a lower path ID.
            // Eligibility is per candidate, not a prefix-wide exemption.
            inject(&mut manager, deferred_unicast_local(prefix, 71, 50));
            assert_eq!(manager.loc_rib.get(&prefix).unwrap().path_id, 71);
            assert_eq!(
                row(&query(&mut manager, prefix, 23, None, 10).unwrap(), target).reason,
                "selection_deferred"
            );
        }
        let immediate: Vec<_> = hosts.into_iter().chain(aggregates).collect();
        assert_deferred_unicast_replay(&deferred_unicast_drain(&mut rx), mode, &immediate, false);
        let all: Vec<_> = immediate.iter().copied().chain(defaults).collect();
        let source = deferred_unicast_received(&mut manager, &all);
        assert!(deferred_unicast_drain(&mut rx).is_empty());
        assert_eq!(manager.ribs[&source].len(), 6);
        assert!(
            manager.ribs[&source]
                .iter()
                .all(|route| !route.is_stale && !route.is_llgr_stale)
        );
        for prefix in &immediate {
            let selected = manager.loc_rib.get(prefix).unwrap();
            assert_eq!(
                selected.peer, LOCAL_PEER,
                "{mode:?}: received candidate held"
            );
            let id = if hosts.contains(prefix) { 17 } else { 71 };
            assert_eq!(selected.path_id, id);
            assert_eq!(
                row(&query(&mut manager, *prefix, id, None, 10).unwrap(), target).disposition,
                RouteExportDisposition::Committed
            );
        }
        let late = PeerId::from_addr(v4(3));
        let mut late_rx = deferred_unicast_peer(&mut manager, late, mode, false);
        assert_deferred_unicast_replay(
            &deferred_unicast_drain(&mut late_rx),
            mode,
            &immediate,
            false,
        );
        // A real failed admission makes dirty recovery restage the exact tagged
        // aggregate, including when its untagged sibling has a better rank.
        let mut permits = Vec::new();
        while let Ok(permit) = manager.outbound_peers[&late].clone().try_reserve_owned() {
            permits.push(permit);
        }
        let mut changed = deferred_unicast_local(aggregates[0], 71, 50);
        AttrSet::edit(&mut changed.attributes, |attrs| {
            attrs.push(PathAttribute::Med(99));
        });
        inject(&mut manager, changed);
        assert!(manager.dirty_peers.contains(&late));
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());
        let _ = deferred_unicast_drain(&mut rx);
        drop(permits);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        let recovery = deferred_unicast_drain(&mut late_rx);
        assert!(
            recovery
                .iter()
                .flat_map(|update| update.announce.iter())
                .any(|route| route.prefix == aggregates[0] && route.med_attr() == Some(99))
        );
        assert!(
            recovery
                .iter()
                .flat_map(|update| update.announce.iter())
                .all(|route| immediate.contains(&route.prefix) && route.peer == LOCAL_PEER)
        );
        for prefix in hosts.into_iter().chain(aggregates) {
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::WithdrawInjected {
                prefix,
                path_id: if hosts.contains(&prefix) { 17 } else { 71 },
                allow_missing: false,
                owner: if prefix == hosts[1] {
                    "deferral-test"
                } else {
                    ""
                }
                .to_string(),
                override_owner: false,
                reply,
            });
            response.try_recv().unwrap().unwrap();
            assert!(
                manager.loc_rib.get(&prefix).is_none(),
                "{mode:?}: fallback still held"
            );
        }
        for outbound in [&mut rx, &mut late_rx] {
            let updates = deferred_unicast_drain(outbound);
            assert!(
                updates
                    .iter()
                    .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
            );
            assert_eq!(
                updates
                    .iter()
                    .map(|update| update.withdraw.len())
                    .sum::<usize>(),
                4
            );
        }
        // After release the retained received fallback wins all six prefixes,
        // including the defaults and aggregates that never bypassed deferral.
        manager.expire_selection_deferral();
        for prefix in all {
            assert_eq!(
                manager.loc_rib.get(&prefix).unwrap().peer,
                source,
                "{mode:?}: received fallback"
            );
        }
    }
}

#[test]
fn tagged_aggregate_keeps_deferral_exemption_after_export_policy_removes_blackhole() {
    for mode in [DeferredUnicastMode::Single, DeferredUnicastMode::AddPath] {
        let mut manager = deferred_unicast_manager();
        let target = PeerId::from_addr(v4(2));
        let mut rx = deferred_unicast_peer(&mut manager, target, mode, false);
        let mut policy = deny_prefixes_chain(&[v4_prefix()]);
        let entry = &mut policy.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.action = rustbgpd_policy::PolicyAction::Permit;
        entry.modifications.communities_remove = vec![DEFERRED_BLACKHOLE];
        let policy = PolicyChain::from_named(policy.policies);
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
            peer: target,
            export_policy: Some(policy),
            reply,
        });
        response.try_recv().unwrap().unwrap();
        let _ = deferred_unicast_drain(&mut rx);
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24));
        inject(&mut manager, deferred_unicast_local(prefix, 71, 50));
        let updates = deferred_unicast_drain(&mut rx);
        let announced: Vec<_> = updates
            .iter()
            .flat_map(|update| update.announce.iter())
            .collect();
        assert_eq!(
            announced.len(),
            1,
            "{mode:?}: source tag determines eligibility"
        );
        assert_eq!(announced[0].communities(), [] as [u32; 0]);
        assert_eq!(
            row(&query(&mut manager, prefix, 71, None, 10).unwrap(), target).disposition,
            RouteExportDisposition::Committed
        );
        let late = PeerId::from_addr(v4(3));
        let export_policy = manager.export_chains.for_peer(target).cloned();
        let mut late_rx = peer_up(
            &mut manager,
            late,
            deferred_unicast_families(),
            export_policy,
            0,
            64,
        );
        assert_eq!(
            deferred_unicast_drain(&mut late_rx)
                .iter()
                .map(|update| update.announce.len())
                .sum::<usize>(),
            1
        );
    }
}

#[test]
fn injected_unicast_replaces_frozen_received_selection_without_fallback() {
    for mode in DEFERRED_UNICAST_MODES {
        let mut manager = deferred_unicast_manager();
        let gate = manager.selection_deferral.take();
        let hosts = deferred_unicast_hosts();
        let source = deferred_unicast_received(&mut manager, &hosts);
        assert_eq!(manager.loc_rib.len(), 2);
        manager.selection_deferral = gate;

        let target = PeerId::from_addr(v4(2));
        let mut rx = deferred_unicast_peer(&mut manager, target, mode, false);
        assert!(
            deferred_unicast_drain(&mut rx).is_empty(),
            "{mode:?}: restored received selections remain withheld"
        );
        inject(&mut manager, deferred_unicast_local(hosts[0], 17, 150));
        assert_eq!(manager.loc_rib.get(&hosts[0]).unwrap().peer, LOCAL_PEER);
        assert_eq!(manager.loc_rib.get(&hosts[1]).unwrap().peer, source);
        assert_deferred_unicast_replay(&deferred_unicast_drain(&mut rx), mode, &hosts[..1], false);
        assert_eq!(
            row(
                &query(&mut manager, hosts[0], 17, None, 10).unwrap(),
                target
            )
            .disposition,
            RouteExportDisposition::Committed,
            "a frozen received prefix must not block an unrelated local commit"
        );

        withdraw(&mut manager, hosts[0], 17);
        assert!(manager.loc_rib.get(&hosts[0]).is_none());
        assert_eq!(manager.loc_rib.get(&hosts[1]).unwrap().peer, source);
        let withdrawn = deferred_unicast_drain(&mut rx);
        assert!(
            withdrawn
                .iter()
                .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(
            withdrawn
                .iter()
                .flat_map(|update| update.withdraw.iter().map(|(prefix, _)| *prefix))
                .collect::<Vec<_>>(),
            vec![hosts[0]],
            "{mode:?}: last-local removal must not fall back to the frozen source"
        );

        let metrics = manager.metrics.clone();
        let released = manager
            .selection_deferral
            .as_mut()
            .unwrap()
            .expire(&metrics);
        manager.release_selection_families(&released, "Selection_Deferral_Timer expired");
        for prefix in hosts {
            assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, source);
        }
        let released = deferred_unicast_drain(&mut rx);
        assert_eq!(
            released
                .iter()
                .flat_map(|update| update.announce.iter().map(|route| route.prefix))
                .collect::<HashSet<_>>(),
            HashSet::from(hosts)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn injected_unicast_delete_and_expiry_withdraw_during_selection_deferral() {
    for mode in DEFERRED_UNICAST_MODES {
        let mut manager = deferred_unicast_manager();
        let target = PeerId::from_addr(v4(2));
        let mut rx = deferred_unicast_peer(&mut manager, target, mode, false);
        let hosts = deferred_unicast_hosts();
        inject(&mut manager, deferred_unicast_local(hosts[0], 17, 150));
        let generation =
            deferred_unicast_lease(&mut manager, deferred_unicast_local(hosts[1], 23, 150));
        let source = deferred_unicast_received(&mut manager, &hosts);
        assert_deferred_unicast_replay(&deferred_unicast_drain(&mut rx), mode, &hosts, false);
        withdraw(&mut manager, hosts[0], 17);
        let updates = deferred_unicast_drain(&mut rx);
        assert!(
            updates
                .iter()
                .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(
            updates
                .iter()
                .flat_map(|update| update.withdraw.iter().copied())
                .collect::<Vec<_>>(),
            vec![(
                hosts[0],
                u32::from(matches!(mode, DeferredUnicastMode::AddPath))
            )]
        );
        assert!(manager.loc_rib.get(&hosts[0]).is_none());
        assert_eq!(manager.ribs.get(&source).unwrap().len(), 2);

        tokio::time::advance(Duration::from_secs(5)).await;
        let (expired, _) = manager.injection_leases().take_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].generation, generation);
        manager.handle_update(RibUpdate::ExpireInjectionLeases { leases: expired });
        let updates = deferred_unicast_drain(&mut rx);
        assert!(
            updates
                .iter()
                .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(
            updates
                .iter()
                .flat_map(|update| update.withdraw.iter().copied())
                .collect::<Vec<_>>(),
            vec![(
                hosts[1],
                u32::from(matches!(mode, DeferredUnicastMode::AddPath))
            )]
        );
        assert!(manager.loc_rib.get(&hosts[1]).is_none());
        assert_eq!(manager.ribs.get(&source).unwrap().len(), 2);
        assert!(
            manager
                .injection_leases()
                .live_generation("deferral-test")
                .0
                .is_none()
        );
        for family in deferred_unicast_families() {
            assert!(manager.selection_deferred(family));
        }
    }
}

#[test]
fn injected_unicast_policy_deny_does_not_reveal_received_during_deferral() {
    for mode in DEFERRED_UNICAST_MODES {
        let mut manager = deferred_unicast_manager();
        let target = PeerId::from_addr(v4(2));
        let mut rx = deferred_unicast_peer(&mut manager, target, mode, true);
        let hosts = deferred_unicast_hosts();
        for prefix in hosts {
            inject(&mut manager, deferred_unicast_local(prefix, 17, 150));
        }
        let source = deferred_unicast_received(&mut manager, &hosts);
        for prefix in hosts {
            assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, LOCAL_PEER);
            let page = query(&mut manager, prefix, 17, None, 10).unwrap();
            assert_eq!(
                row(&page, target).disposition,
                RouteExportDisposition::Withheld
            );
            assert_eq!(row(&page, target).reason, "export_policy");
            let explanation =
                deferred_unicast_explain(&mut manager, target, prefix, mode, (LOCAL_PEER, 17));
            assert_eq!(explanation.decision, crate::update::ExplainDecision::Deny);
            assert!(!explanation.already_advertised);
        }
        assert_eq!(manager.ribs.get(&source).unwrap().len(), 2);
        assert!(deferred_unicast_drain(&mut rx).is_empty());
        let late = PeerId::from_addr(v4(3));
        let mut late_rx = deferred_unicast_peer(&mut manager, late, mode, true);
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());
        manager.mark_outbound_dirty(late);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        assert!(deferred_unicast_drain(&mut late_rx).is_empty());
    }
}

/// A dirty outbound peer is pending, not committed or withheld; a key with
/// no local rule is listed as not found, with no rows.
#[test]
fn flowspec_pending_resync_and_missing_rule() {
    let (mut manager, _tx) = manager();
    let peer = v4(1);
    let _rx = peer_up(
        &mut manager,
        PeerId::from_addr(peer),
        ipv4_flowspec_sendable(),
        None,
        0,
        64,
    );
    let rule = local_rule(&[]);
    let key = rule.selection_key();

    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    assert_eq!(page.routes, not_found(0));

    inject_rule(&mut manager, rule);
    manager.dirty_peers.insert(PeerId::from_addr(peer));
    let page = query_rule(&mut manager, &key, None, None, 10).unwrap();
    let export = row(&page, PeerId::from_addr(peer));
    assert_eq!(export.disposition, RouteExportDisposition::Pending);
    assert_eq!(export.reason, "outbound_resync");
}

/// The `FlowSpec` walk pages, lists named managed peers without a session as
/// not Established, and is fenced like the unicast walk: replacing the rule
/// between pages invalidates the resumed walk.
#[test]
fn flowspec_walk_pages_and_aborts_on_a_replaced_rule() {
    let (mut manager, _tx) = manager();
    let _receivers: Vec<_> = [2, 3]
        .into_iter()
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_flowspec_sendable(),
                None,
                0,
                64,
            )
        })
        .collect();
    let rule = local_rule(&[]);
    let key = rule.selection_key();
    inject_rule(&mut manager, rule);
    let named = Some(vec![(v4(1), None), (v4(2), None)]);

    let first = query_rule(&mut manager, &key, named.clone(), None, 2).unwrap();
    assert_eq!(peers_of(&first), vec![v4(1), v4(2)]);
    assert_eq!(
        row(&first, PeerId::from_addr(v4(1))).disposition,
        RouteExportDisposition::NotEstablished
    );
    let last = query_rule(&mut manager, &key, named.clone(), resume_of(&first), 2).unwrap();
    assert_eq!(peers_of(&last), vec![v4(3)]);
    assert!(last.next.is_none());

    inject_rule(&mut manager, local_rule(&[65_000 << 16 | 1]));
    assert_eq!(
        query_rule(&mut manager, &key, named, resume_of(&first), 2),
        Err(RouteExportPageError::Invalidated)
    );
}

// --- export settings a reload changes without resetting the session ---

/// The second page of a [`walk_started`] walk is refused.
fn assert_walk_invalidated(manager: &mut RibManager, first: &RouteExportPage) {
    assert_eq!(
        resume(manager, first),
        Err(RouteExportPageError::Invalidated)
    );
}

/// The second page of a [`walk_started`] walk is served under the first
/// page's version and completes the walk.
fn assert_walk_resumes(manager: &mut RibManager, first: &RouteExportPage) {
    let rest = resume(manager, first).unwrap();
    assert_eq!(peers_of(&rest), vec![v4(4)]);
    assert!(rest.next.is_none());
    assert_eq!(rest.version, first.version);
}

fn install_prefix_limits(manager: &mut RibManager, txn: u64, peer: PeerId, ipv4: u32) {
    let config = crate::update::OutboundPrefixLimitConfig {
        neighbors: [(
            peer.addr().into(),
            crate::update::OutboundPrefixLimitPair {
                ipv4: std::num::NonZeroU32::new(ipv4),
                ipv6: None,
            },
        )]
        .into_iter()
        .collect(),
        interfaces: HashMap::new(),
        groups: HashMap::new(),
    };
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareOutboundPrefixLimits { txn, config, reply });
    rx.try_recv().unwrap().unwrap();
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::ApplyOutboundPrefixLimits {
        txn,
        activate: true,
        reply,
    });
    rx.try_recv().unwrap().unwrap();
}

fn set_peer_group(manager: &mut RibManager, peer: PeerId, group: &str) {
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some(group.to_string()),
    });
}

const CONDITIONAL: &str = "backup";

/// A conditional advertisement controlling the walked route, present while
/// some route for `condition` passes `condition_policy`, with no debounce.
fn conditional_set(
    condition: Prefix,
    condition_policy: Option<PolicyChain>,
    attached: &[PeerId],
) -> crate::ConditionalAdvertisementSet {
    crate::ConditionalAdvertisementSet {
        definitions: vec![crate::ConditionalAdvertisement {
            name: Arc::from(CONDITIONAL),
            advertise_policy: rpol_chain(
                "policy ctl { term t { if route.prefix == 203.0.113.7/32 { accept } } term rest { reject } }",
                "ctl",
            ),
            advertise_if: crate::ConditionalAdvertiseIf::Present,
            condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(condition)],
            condition_policy,
            settle_time: std::time::Duration::ZERO,
            retiring: false,
        }],
        attachments: attached
            .iter()
            .map(|peer| (peer.addr().into(), vec![Arc::from(CONDITIONAL)]))
            .collect(),
    }
}

fn install_conditional(
    manager: &mut RibManager,
    set: crate::ConditionalAdvertisementSet,
) -> crate::ConditionalAdvertisementCapture {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::InstallConditionalAdvertisements {
        set,
        swapping_datasets: vec![],
        reply,
    });
    rx.try_recv().unwrap()
}

fn other_prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32))
}

/// A reload that sets a listed peer's outbound prefix limit invalidates the
/// walk. Red proof: not advancing the export-settings generation in
/// `install_outbound_limit` fails this test.
#[test]
fn outbound_prefix_limit_changed_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    install_prefix_limits(&mut manager, 1, PeerId::from_addr(v4(2)), 10);
    assert_walk_invalidated(&mut manager, &first);
}

/// A reload that moves a listed peer into a peer group invalidates the walk.
/// Red proof: not advancing the export-settings generation in
/// `set_peer_group` fails this test.
#[test]
fn peer_group_changed_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    set_peer_group(&mut manager, PeerId::from_addr(v4(2)), "rs-clients");
    assert_walk_invalidated(&mut manager, &first);
}

/// A larger effective Add-Path send limit for a listed peer changes which
/// paths it is sent, so it invalidates the walk. Red proof: not advancing
/// the export-settings generation on an effective `PeerAddPathLimits`
/// change fails this test.
#[test]
fn add_path_send_limit_changed_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started_with(1, |_| {});
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer: PeerId::from_addr(v4(2)),
        session_id: 0,
        limits: vec![((Afi::Ipv4, Safi::Unicast), 2)],
    });
    assert_walk_invalidated(&mut manager, &first);
}

/// Attaching a conditional advertisement to a listed peer gates its export,
/// so the install invalidates the walk. Red proof: not advancing the
/// export-settings generation in `settle_conditional_advertisement_change`
/// fails this test.
#[test]
fn conditional_advertisement_installed_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = walk_started();
    install_conditional(
        &mut manager,
        conditional_set(other_prefix(), None, &[PeerId::from_addr(v4(2))]),
    );
    assert_walk_invalidated(&mut manager, &first);
}

/// Compensating an install restores the prior gate, which invalidates a
/// walk begun under the installed one. The peer stays attached throughout,
/// so it never changes update group. Red proof as for the install.
#[test]
fn conditional_advertisement_restored_mid_walk_invalidates_the_resumed_walk() {
    let listed = PeerId::from_addr(v4(2));
    let mut capture = None;
    let (mut manager, _receivers, first) = walk_started_with(0, |manager| {
        install_conditional(manager, conditional_set(other_prefix(), None, &[listed]));
        capture = Some(install_conditional(
            manager,
            conditional_set(v4_prefix(), None, &[listed]),
        ));
    });
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::RestoreConditionalAdvertisements {
        capture: capture.unwrap(),
        reply,
    });
    rx.try_recv().unwrap();
    assert_walk_invalidated(&mut manager, &first);
}

/// Re-observing a conditional advertisement after its condition dataset
/// is swapped flips the gate of the attached listed peer, which invalidates
/// the walk even though no export chain reads that dataset. Red proof: not
/// advancing the export-settings generation in
/// `mark_conditional_advertisement_peers_dirty` fails this test.
#[test]
fn conditional_advertisement_reobserved_mid_walk_invalidates_the_resumed_walk() {
    let (condition_policy, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { accept } reject } }",
        true,
    );
    let (mut manager, _receivers, first) = walk_started_with(0, |manager| {
        install_conditional(
            manager,
            conditional_set(
                v4_prefix(),
                Some(condition_policy),
                &[PeerId::from_addr(v4(2))],
            ),
        );
    });
    assert_eq!(
        row(&first, PeerId::from_addr(v4(2))).disposition,
        RouteExportDisposition::Committed
    );
    handle.refresh(allowed_dataset(false));
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::ReobserveConditionalAdvertisements {
        datasets: vec!["allowed".to_string()],
        changed: vec![],
        reply,
    });
    rx.try_recv().unwrap();
    assert_walk_invalidated(&mut manager, &first);
}

/// A family the session withheld becoming sendable after a reload (for
/// example one that supplies `local_ipv6_nexthop`) invalidates the walk.
/// Red proof: not advancing the export-settings generation in
/// `handle_peer_family_sendable` fails this test.
#[test]
fn family_becoming_sendable_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _tx) = manager();
    let withheld = PeerId::from_addr(v4(2));
    manager.handle_update(RibUpdate::SetPeerWithheldFamilies {
        peer: withheld,
        session_id: 0,
        families: vec![(
            (Afi::Ipv6, Safi::Unicast),
            crate::update::ExactExportErrorCode::MissingIpv6NextHop,
        )],
    });
    // ORF keeps the peer out of update groups, so no regroup reinstalls
    // its export chain and only the export-settings generation can move.
    let _withheld_rx = orf_peer_up(&mut manager, 2, ipv4_sendable(), true);
    let _receivers: Vec<_> = [3, 4]
        .into_iter()
        .map(|octet| {
            peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                dual_stack_sendable(),
                None,
                0,
                64,
            )
        })
        .collect();
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::7".parse().unwrap(), 128));
    inject(&mut manager, local_route(prefix, 0));
    let first = query(&mut manager, prefix, 0, None, 2).unwrap();
    assert_eq!(
        row(&first, withheld).reason,
        "family_suppressed:missing_ipv6_next_hop"
    );

    manager.handle_update(RibUpdate::PeerFamilySendable {
        peer: withheld,
        session_id: 0,
        family: (Afi::Ipv6, Safi::Unicast),
        add_path_send_limit: None,
    });
    assert_eq!(
        query(&mut manager, prefix, 0, resume_of(&first), 2),
        Err(RouteExportPageError::Invalidated)
    );
}

/// Register peer `10.0.0.<octet>`, negotiating Address-Prefix ORF for
/// IPv4 unicast when `orf`, which also keeps it out of update groups.
fn orf_peer_up(
    manager: &mut RibManager,
    octet: u8,
    sendable_families: Vec<(Afi, Safi)>,
    orf: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer: PeerId::from_addr(v4(octet)),
        session_id: 0,
        peer_asn: 65_010,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: if orf { ipv4_sendable() } else { vec![] },
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

/// [`walk_started`] where peer 10.0.0.2 negotiated Address-Prefix ORF for
/// IPv4 unicast, so its export starts behind the RFC 5291 §6 gate.
fn orf_walk_started(
    setup: impl FnOnce(&mut RibManager),
) -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    RouteExportPage,
) {
    let (mut manager, _tx) = manager();
    let receivers = [2, 3, 4]
        .into_iter()
        .map(|octet| orf_peer_up(&mut manager, octet, ipv4_sendable(), octet == 2))
        .collect();
    setup(&mut manager);
    inject(&mut manager, local_route(v4_prefix(), 0));
    let first = query(&mut manager, v4_prefix(), 0, None, 2).unwrap();
    assert_eq!(peers_of(&first), vec![v4(2), v4(3)]);
    (manager, receivers, first)
}

fn push_orf(manager: &mut RibManager, entries: Vec<AddressPrefixOrf>) {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::PeerOrfUpdate {
        peer: PeerId::from_addr(v4(2)),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Defer,
        entries,
        reply,
    });
    rx.try_recv().unwrap().unwrap();
}

fn orf_entry(sequence: u32, match_: OrfMatch, prefix: Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_,
        sequence,
        min_len: 32,
        max_len: 32,
        prefix: Some(prefix),
    }
}

/// The peer's ROUTE-REFRESH lifting the initial ORF gate changes its row
/// from `orf_pending`, so it invalidates the walk. Red proof: not advancing
/// the export-settings generation in `lift_orf_gate` fails this test.
#[test]
fn orf_gate_lifted_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first) = orf_walk_started(|_| {});
    assert_eq!(row(&first, PeerId::from_addr(v4(2))).reason, "orf_pending");
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer: PeerId::from_addr(v4(2)),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_walk_invalidated(&mut manager, &first);
}

/// A change to the peer's installed ORF filter invalidates the walk, while
/// resending the installed entries does not. Red proof: not advancing the
/// export-settings generation when `handle_peer_orf_update` changes the
/// filter fails this test.
#[test]
fn orf_filter_changed_mid_walk_invalidates_the_resumed_walk() {
    let permit = orf_entry(10, OrfMatch::Permit, v4_prefix());
    let installed = permit;
    let (mut manager, _receivers, first) =
        orf_walk_started(move |manager| push_orf(manager, vec![installed]));
    push_orf(&mut manager, vec![permit]);
    assert_walk_resumes(&mut manager, &first);

    push_orf(
        &mut manager,
        vec![orf_entry(20, OrfMatch::Deny, other_prefix())],
    );
    assert_walk_invalidated(&mut manager, &first);
}

/// A session's exact export encoder can change profile without a reset,
/// for example when a reload changes `local_ipv6_nexthop`, and the RIB
/// hears of it only on the next probe; the walk reads the encoders'
/// generations directly. Red proof: leaving the encoder generations out of
/// the policy version fails this test.
#[test]
fn export_encoder_profile_changed_mid_walk_invalidates_the_resumed_walk() {
    use super::exportability::MockExactExportEncoder;

    let (mut manager, _tx) = manager();
    let encoders: Vec<_> = [2, 3, 4]
        .into_iter()
        .map(|octet| {
            let encoder = MockExactExportEncoder::accepting(1);
            manager.handle_update(RibUpdate::SetPeerExportEncoder {
                peer: PeerId::from_addr(v4(octet)),
                session_id: 0,
                encoder: Arc::clone(&encoder) as Arc<dyn crate::update::ExactExportEncoder>,
            });
            let rx = peer_up(
                &mut manager,
                PeerId::from_addr(v4(octet)),
                ipv4_sendable(),
                None,
                0,
                64,
            );
            (encoder, rx)
        })
        .collect();
    inject(&mut manager, local_route(v4_prefix(), 0));
    let first = query(&mut manager, v4_prefix(), 0, None, 2).unwrap();
    assert!(first.next.is_some());

    encoders[0].0.set_profile(2, []);
    assert_walk_invalidated(&mut manager, &first);
}

/// A reload that leaves every listed peer's export settings as they were
/// leaves the walk resumable: the same peer group and outbound prefix
/// limit, an identical conditional-advertisement install, and an
/// attachment for a peer with no session.
#[test]
fn unchanged_export_settings_leave_the_walk_resumable() {
    let listed = PeerId::from_addr(v4(2));
    let (mut manager, _receivers, first) = walk_started_with(0, |manager| {
        set_peer_group(manager, listed, "rs-clients");
        install_prefix_limits(manager, 1, listed, 10);
        install_conditional(manager, conditional_set(other_prefix(), None, &[listed]));
    });
    set_peer_group(&mut manager, listed, "rs-clients");
    install_prefix_limits(&mut manager, 2, listed, 10);
    install_conditional(
        &mut manager,
        conditional_set(other_prefix(), None, &[listed]),
    );
    let mut unrelated = conditional_set(other_prefix(), None, &[listed]);
    unrelated
        .attachments
        .insert(v4(9).into(), vec![Arc::from(CONDITIONAL)]);
    install_conditional(&mut manager, unrelated);
    assert_walk_resumes(&mut manager, &first);
}

/// [`walk_started`] where peer 10.0.0.2 has a conditional advertisement
/// attached whose condition is absent, so the gate suppresses whatever its
/// `advertise_policy` selects: the local route while the returned dataset,
/// which no export chain reads, lists it.
fn advertise_policy_dataset_walk_started() -> (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    RouteExportPage,
    Arc<rustbgpd_policy::datasets::DatasetHandle>,
) {
    let (advertise_policy, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { accept } reject } }",
        true,
    );
    let mut set = conditional_set(other_prefix(), None, &[PeerId::from_addr(v4(2))]);
    set.definitions[0].advertise_policy = advertise_policy;
    let (manager, receivers, first) = walk_started_with(0, |manager| {
        install_conditional(manager, set);
    });
    assert_eq!(row(&first, PeerId::from_addr(v4(2))).reason, "export_rule");
    (manager, receivers, first, handle)
}

/// A suppressing gate evaluates its `advertise_policy` live, so refreshing a
/// dataset only that policy reads changes the attached peer's row with no
/// change to the definition, its applied state or any export chain; the
/// walk is invalidated. Red proof: leaving the attached `advertise_policy`
/// chains out of the policy version's dataset generations fails this test.
#[test]
fn advertise_policy_dataset_swapped_mid_walk_invalidates_the_resumed_walk() {
    let (mut manager, _receivers, first, handle) = advertise_policy_dataset_walk_started();
    handle.refresh(allowed_dataset(false));
    assert_walk_invalidated(&mut manager, &first);
}

/// The same refresh landing while a page's rows evaluate refuses that page.
/// Red proof as above.
#[test]
fn advertise_policy_dataset_swapped_while_a_page_evaluates_invalidates_the_page() {
    use crate::manager::queries::BEFORE_EXPORT_ROWS;

    let (mut manager, _receivers, first, handle) = advertise_policy_dataset_walk_started();
    BEFORE_EXPORT_ROWS.set(Some(Box::new(move || {
        handle.refresh(allowed_dataset(false));
    })));
    assert_walk_invalidated(&mut manager, &first);
    // Without a refresh in the window, a restarted walk is served.
    assert!(query(&mut manager, v4_prefix(), 0, None, 2).is_ok());
}
