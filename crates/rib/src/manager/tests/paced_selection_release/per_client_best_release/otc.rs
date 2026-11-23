//! Per-client selection with a preferred route carrying Only-To-Customer.

use super::*;
use rustbgpd_wire::BgpRole;

fn join(lab: &mut Lab, role: BgpRole, private: bool) {
    lab.manager.test_force_ungrouped = private;
    lab.manager.handle_update(RibUpdate::SetPeerExportContext {
        peer: client(0),
        session_id: 2,
        local_role: Some(role),
    });
    lab.join(false, 64);
    assert_eq!(lab.manager.grouped_member_of(client(0)).is_none(), private);
}

fn marked(mut route: Route, attr: PathAttribute) -> Route {
    AttrSet::edit(&mut route.attributes, |attrs| attrs.push(attr));
    route
}

/// Read one member's export in delivery order, applying its source exclusion.
/// A marker can share the last envelope with the rows it follows.
#[derive(Default)]
struct Delivery {
    announced: Vec<(Prefix, PeerId, u32, IpAddr)>,
    withdrawn: Vec<(Prefix, u32)>,
    blocked: Vec<(Prefix, PeerId)>,
    markers: usize,
}

fn receive(lab: &mut Lab) -> Delivery {
    receive_member(lab, 0)
}

fn receive_member(lab: &mut Lab, n: usize) -> Delivery {
    let mut delivery = Delivery::default();
    let rx = lab.receivers[n].as_mut().unwrap();
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            if update.announce_source_exclusion == Some(route.peer) {
                continue;
            }
            assert_eq!(delivery.markers, 0, "announcement after End-of-RIB");
            assert_eq!(route.path_id, 0);
            assert!(
                route
                    .attributes
                    .iter()
                    .all(|a| a.only_to_customer().is_none())
            );
            delivery.announced.push(identity(route));
        }
        delivery
            .withdrawn
            .extend(update.unicast_withdrawals().copied());
        delivery
            .blocked
            .extend(update.otc_blocked.iter().map(|r| (r.prefix, r.peer)));
        delivery.markers += usize::from(update.end_of_rib.contains(&lab.family));
    }
    delivery
}

fn identity(route: &Route) -> (Prefix, PeerId, u32, IpAddr) {
    (route.prefix, route.peer, route.local_pref(), route.next_hop)
}

fn paced_release(family: (Afi, Safi)) {
    let mut lab = Lab::cold(family);
    join(&mut lab, BgpRole::Customer, false);
    let clean = path(family, 1, OTHER_SOURCE, 100, vec![]);
    // Distinct inbound path IDs from one source. Pruning the source when the
    // marked path is skipped would hide the clean candidate as well.
    let mut same_source = clean.clone();
    same_source.path_id = 42;
    let preferred = marked(
        path(family, 1, OTHER_SOURCE, 190, vec![]),
        PathAttribute::OnlyToCustomer(64512),
    );
    let only = marked(
        path(family, 2, OTHER_SOURCE, 180, vec![]),
        PathAttribute::OnlyToCustomer(64512),
    );
    lab.send(1, vec![preferred, same_source, only]);
    let middle = marked(
        path(family, 1, THIRD, 140, vec![]),
        PathAttribute::OnlyToCustomerPartial(64513),
    );
    lab.send(1, vec![middle]);
    let held = receive(&mut lab);
    assert_eq!(held.announced, []);
    assert_eq!(held.markers, 0);
    lab.end_hold();
    drain_unicast_release(&mut lab.manager);
    drain_resync_ticks(&mut lab.manager);
    let mut released = receive(&mut lab);
    assert_eq!(released.announced, [identity(&clean)]);
    assert!(
        released.withdrawn.is_empty(),
        "neither prefix had a prior advertisement"
    );
    assert_eq!(released.markers, 1);
    released.blocked.sort_unstable();
    assert_eq!(
        released.blocked,
        [
            (clean.prefix, clean.peer),
            (prefix_of(family, 2), clean.peer)
        ]
    );
    assert_eq!(lab.manager.actual_unicast_advertised_count(client(0)), 1);
}

fn synchronous_rerank(family: (Afi, Safi)) {
    let mut lab = Lab::warm(family);
    join(&mut lab, BgpRole::Peer, false);
    receive(&mut lab);
    let preferred = path(family, 1, OTHER_SOURCE, 190, vec![]);
    let alternate = path(family, 1, SOURCE, 100, vec![]);
    lab.send(1, vec![preferred.clone()]);
    lab.send(1, vec![alternate.clone()]);
    assert_eq!(receive(&mut lab).announced, [identity(&preferred)]);

    // Install the replacement at the same indexed source/slot without issuing
    // a steady UPDATE. Only the explicit synchronous pass can replace the
    // route the receiver already holds.
    let prefix = preferred.prefix;
    let blocked = marked(preferred, PathAttribute::OnlyToCustomerPartial(64512));
    assert!(
        lab.manager
            .ribs
            .get_mut(&blocked.peer)
            .unwrap()
            .insert(blocked.clone())
    );
    lab.manager
        .loc_rib
        .recompute(prefix, [&blocked, &alternate].into_iter());
    let keys = HashSet::from([prefix]);
    lab.manager.distribute_changes(&keys, &keys);
    let delta = receive(&mut lab);
    assert_eq!(delta.announced, [identity(&alternate)]);
    assert_eq!(delta.withdrawn, []);
    assert_eq!(delta.blocked, [(prefix, blocked.peer)]);
    assert_eq!(lab.manager.actual_unicast_advertised_count(client(0)), 1);
}

fn steady(family: (Afi, Safi), private: bool) {
    let mut lab = Lab::warm(family);
    join(&mut lab, BgpRole::RouteServerClient, private);
    receive(&mut lab);
    let alternate = path(family, 1, SOURCE, 100, vec![]);
    lab.send(1, vec![alternate.clone()]);
    assert_eq!(receive(&mut lab).announced, [identity(&alternate)]);
    let preferred = marked(
        path(family, 1, OTHER_SOURCE, 190, vec![]),
        PathAttribute::OnlyToCustomer(64512),
    );
    lab.send(1, vec![preferred.clone()]);
    let delta = receive(&mut lab);
    assert!(
        delta.withdrawn.is_empty(),
        "the eligible alternate was withdrawn"
    );
    assert!(
        delta.announced.is_empty(),
        "the installed alternate was repeated"
    );
    assert_eq!(delta.blocked, [(alternate.prefix, preferred.peer)]);
    assert_eq!(lab.manager.actual_unicast_advertised_count(client(0)), 1);

    lab.sent
        .withdraw(&mut lab.manager, alternate.peer, 1, vec![alternate.prefix]);
    let gone = receive(&mut lab);
    assert_eq!(gone.withdrawn, [(alternate.prefix, 0)]);
    assert_eq!(gone.announced, []);
    assert!(gone.blocked.is_empty(), "repeated the same rejection");
    assert_eq!(lab.manager.actual_unicast_advertised_count(client(0)), 0);
}

#[test]
fn pcb_otc_paced_release_ipv4() {
    paced_release(V4);
}
#[test]
fn pcb_otc_paced_release_ipv6() {
    paced_release(V6);
}
#[test]
fn pcb_otc_synchronous_rerank_ipv4() {
    synchronous_rerank(V4);
}
#[test]
fn pcb_otc_synchronous_rerank_ipv6() {
    synchronous_rerank(V6);
}
#[test]
fn pcb_otc_steady_grouped_ipv4() {
    steady(V4, false);
}
#[test]
fn pcb_otc_steady_grouped_ipv6() {
    steady(V6, false);
}
#[test]
fn pcb_otc_steady_private_ipv4() {
    steady(V4, true);
}
#[test]
fn pcb_otc_steady_private_ipv6() {
    steady(V6, true);
}

#[test]
fn otc_fallback_member_control_and_split_horizon_select_the_same_wire_and_explain() {
    for private in [false, true] {
        let mut lab = Lab::warm(V4);
        lab.manager.test_force_ungrouped = private;
        for n in 0..4 {
            lab.manager.handle_update(RibUpdate::SetPeerExportContext {
                peer: client(n),
                session_id: 2,
                local_role: Some(BgpRole::Customer),
            });
            lab.join(true, 64);
            assert_eq!(lab.manager.grouped_member_of(client(n)).is_none(), private);
            receive_member(&mut lab, n);
        }

        // Client 0 sources the winner. Clients 1 and 2 cannot receive it by
        // policy. Client 2 also sources the marked second path, so it has
        // nothing to report when it receives the third.
        let best = path(
            V4,
            1,
            client_addr(0),
            190,
            vec![client_asn(1), client_asn(2)],
        );
        let blocked = marked(
            path(V4, 1, client_addr(2), 150, vec![]),
            PathAttribute::OnlyToCustomer(64512),
        );
        let third = path(V4, 1, THIRD, 100, vec![]);
        lab.send(2, vec![best.clone()]);
        lab.send(2, vec![blocked.clone()]);
        lab.send(1, vec![third.clone()]);
        for n in 0..4 {
            let expected = if n == 3 { &best } else { &third };
            let delta = receive_member(&mut lab, n);
            assert_eq!(
                delta.announced,
                [identity(expected)],
                "client {n}, private {private}"
            );
            assert_eq!(delta.withdrawn, []);
            let rejected: Vec<_> = (n < 2)
                .then_some((blocked.prefix, blocked.peer))
                .into_iter()
                .collect();
            assert_eq!(delta.blocked, rejected, "client {n}, private {private}");
            assert_eq!(lab.manager.actual_unicast_advertised_count(client(n)), 1);

            let (reply, mut rx) = oneshot::channel();
            lab.manager.handle_explain_advertised_route(
                client(n),
                best.prefix,
                None,
                false,
                None,
                reply,
            );
            let explain = rx.try_recv().unwrap().unwrap();
            assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
            assert_eq!(explain.route_peer, Some(expected.peer));
            assert!(explain.already_advertised);
            assert_eq!(
                explain
                    .reasons
                    .iter()
                    .any(|r| r.code == "otc_egress_blocked"),
                n < 2
            );
        }
    }
}
