//! A single changed prefix in a clean group must cost the same work as
//! unrelated blocked winners or member-local export refusals accumulate.

use rustbgpd_wire::BgpRole;

use super::*;
use crate::manager::tests::exportability::MockExactExportEncoder;
use crate::update::ExactExportKey;

const FEW: usize = 4;
const MANY: usize = 32;
const MARKER: u32 = (64_500 << 16) | 7;

#[derive(Clone, Copy, Debug)]
enum Filter {
    Otc(BgpRole),
    Exact,
}

impl Filter {
    fn register(
        self,
        manager: &mut RibManager,
        index: usize,
        retained: usize,
    ) -> mpsc::Receiver<OutboundRouteUpdate> {
        let peer = member(index);
        let (tx, rx) = mpsc::channel(32);
        let mut up = test_peer_up(peer, 1, tx);
        let RibUpdate::PeerUp {
            peer_asn,
            per_client_best,
            ..
        } = &mut up
        else {
            unreachable!()
        };
        *peer_asn = 65_100 + u32::try_from(index).unwrap();
        match self {
            Self::Otc(role) => {
                *per_client_best = true;
                manager.handle_update(RibUpdate::SetPeerExportContext {
                    peer,
                    session_id: 1,
                    local_role: Some(role),
                });
                manager.handle_update(RibUpdate::SetPeerRsControl {
                    peer,
                    session_id: 1,
                    rs_control_asn: Some(RS_AS),
                });
            }
            Self::Exact => {
                let encoder = MockExactExportEncoder::accepting(1);
                encoder.set_profile(
                    1,
                    (0..retained).map(|i| ExactExportKey::Unicast(Prefix::V4(prefix(1, i)), 0)),
                );
                manager.handle_update(RibUpdate::SetPeerExportEncoder {
                    peer,
                    session_id: 1,
                    encoder,
                });
            }
        }
        manager.handle_update(up);
        rx
    }
}

fn assert_counts(manager: &mut RibManager, members: usize, expected: usize) {
    let (reply, mut bmp) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let bmp = bmp.try_recv().unwrap();
    for i in 0..members {
        let peer = member(i);
        let (reply, mut count) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedCount { peer, reply });
        assert_eq!(count.try_recv().unwrap(), expected, "count for {peer}");
        let family = (Afi::Ipv4, Safi::Unicast);
        let rows: Vec<_> = bmp.adj_rib_out_post[&peer]
            .iter()
            .copied()
            .filter(|(_, n)| *n != 0)
            .collect();
        let expected = u32::try_from(expected).unwrap();
        assert_eq!(
            rows,
            [(family, u64::from(expected))],
            "BMP count for {peer}"
        );
        let gauge = gauge_metric_value(
            &manager.metrics,
            "bgp_rib_adj_out_prefixes",
            &[("peer", &peer.label()), ("family", "ipv4_unicast")],
        );
        assert!(
            (gauge - f64::from(expected)).abs() < f64::EPSILON,
            "gauge for {peer}: {gauge}"
        );
    }
}

fn assert_deliveries(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected: Option<&Route>,
) {
    for (i, rx) in receivers.iter_mut().enumerate() {
        let mut prefixes = Vec::new();
        while let Ok(update) = rx.try_recv() {
            assert_eq!(update.unicast_withdrawals().count(), 0);
            for row in update.announce.iter() {
                let mut bytes = Vec::new();
                rustbgpd_wire::attribute::encode_path_attributes(
                    row.attributes.as_slice(),
                    &mut bytes,
                    true,
                    false,
                )
                .unwrap();
                let attrs =
                    rustbgpd_wire::attribute::decode_path_attributes(&bytes, true, &[]).unwrap();
                let route = expected.expect("unexpected announcement");
                assert_eq!(
                    attrs,
                    route.attributes.as_slice(),
                    "member {i} wire attributes"
                );
                assert_eq!(row.next_hop, route.next_hop);
                assert_eq!(row.path_id, route.path_id);
                prefixes.push(row.prefix);
            }
        }
        assert_eq!(
            prefixes,
            expected.map(|route| route.prefix).as_slice(),
            "member {i} changed prefixes"
        );
    }
}

fn clean_update(members: usize, filter: Filter, history: usize, retained: usize) -> Work {
    let (_tx, mut manager) = manager();
    let clean_ip = Ipv4Addr::new(198, 51, 100, 2);
    let source = peer_v4(clean_ip);
    register_test_peer(&mut manager, source, 0);
    let mut receivers: Vec<_> = (0..members)
        .map(|i| filter.register(&mut manager, i, retained))
        .collect();
    let mut setup = routes_from(external(), 0, 1, history);
    let RibUpdate::RoutesReceived { announced, .. } = &mut setup else {
        unreachable!()
    };
    if matches!(filter, Filter::Otc(_)) {
        for route in &mut announced[..retained] {
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::OnlyToCustomer(64_999));
            });
        }
    }
    let mut first = announced[0].clone();
    manager.handle_update(setup);
    drain_route_chunks(&mut manager);
    let group = manager.grouped_member_of(member(0)).unwrap();
    let hidden = match filter {
        Filter::Otc(BgpRole::RouteServer) => 0,
        _ => retained,
    };
    for (i, rx) in receivers.iter_mut().enumerate() {
        let peer = member(i);
        assert_eq!(manager.grouped_member_of(peer), Some(group));
        match filter {
            Filter::Otc(_) => {
                assert!(manager.group_ribs[&group].per_client_best);
                assert_eq!(
                    manager.group_ribs[&group]
                        .otc_blocked_for_member(peer, None)
                        .len(),
                    hidden
                );
            }
            Filter::Exact => assert_eq!(
                manager.peer_unexportable.get(&peer).map_or(0, HashSet::len),
                hidden
            ),
        }
        assert_eq!(drain(std::slice::from_mut(rx)), (history - hidden, 0));
    }
    let mut changed = make_route(prefix(3, 0), clean_ip);
    AttrSet::edit(&mut changed.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![MARKER]));
    });
    let work = checkpoints_in(|| {
        manager.handle_update(test_routes_received(source, vec![changed.clone()]));
        drain_route_chunks(&mut manager);
    });
    assert_deliveries(&mut receivers, Some(&changed));
    assert_counts(&mut manager, members, history - hidden + 1);

    // Alter a historical row too. The blocking arms keep it withheld;
    // the two controls deliver its new community, preserving the count.
    AttrSet::edit(&mut first.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![MARKER]));
    });
    manager.handle_update(test_routes_received(external(), vec![first.clone()]));
    drain_route_chunks(&mut manager);
    assert_deliveries(&mut receivers, (hidden == 0).then_some(&first));
    assert_counts(&mut manager, members, history - hidden + 1);
    work
}

/// One announcement per member in each measured pass. The four-checkpoint
/// allowance also catches a single group-wide scan over the extra 28 keys.
fn assert_flat(filter: Filter, runs: [(usize, usize); 2]) {
    let measurements = [SMALL, LARGE].map(|members| {
        let [small, large] =
            runs.map(|(history, retained)| clean_update(members, filter, history, retained)[ALL]);
        (members, small, large)
    });
    eprintln!("{filter:?} (members, small, large): {measurements:?}");
    for (members, small, large) in measurements {
        assert!(small > 0);
        assert!(
            large <= small + 4,
            "{filter:?} with {members} members grew {small} -> {large}"
        );
    }
}

#[test]
fn clean_group_update_work_is_flat_in_otc_blocked_winners() {
    assert_flat(
        Filter::Otc(BgpRole::Customer),
        [(MANY + 1, FEW), (MANY + 1, MANY)],
    );
}

#[test]
fn clean_group_update_work_is_flat_in_exact_refusals() {
    assert_flat(Filter::Exact, [(MANY + 1, FEW), (MANY + 1, MANY)]);
}

#[test]
fn clean_group_update_route_server_role_control() {
    assert_flat(
        Filter::Otc(BgpRole::RouteServer),
        [(MANY + 1, FEW), (MANY + 1, MANY)],
    );
}

#[test]
fn clean_group_update_accepting_encoder_control() {
    assert_flat(Filter::Exact, [(FEW, 0), (MANY, 0)]);
}
