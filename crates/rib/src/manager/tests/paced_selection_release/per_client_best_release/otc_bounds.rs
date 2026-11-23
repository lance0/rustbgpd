//! Work and retained diagnostic routes for a shared per-client-best walk.

use super::*;

fn release_crowded_prefix(members: usize) -> usize {
    let mut lab = Lab::cold(V4);
    for n in 0..members {
        lab.manager.handle_update(RibUpdate::SetPeerExportContext {
            peer: client(n),
            session_id: 2,
            local_role: Some(rustbgpd_wire::BgpRole::Customer),
        });
        lab.join(false, 32);
    }
    let group_id = lab.manager.grouped_member_of(client(0)).unwrap();
    assert!((1..members).all(|n| lab.manager.grouped_member_of(client(n)) == Some(group_id)));

    let eligible = path(V4, 1, THIRD, 100, vec![]);
    let prefix = eligible.prefix;
    // More than one release page of independently identifiable rejected
    // attributes. Split horizon can require the second source's diagnostic.
    let mut blocked_attrs = Vec::new();
    for (offset, source) in [(0, SOURCE), (65, OTHER_SOURCE)] {
        let mut routes = Vec::new();
        for i in 0..65 {
            let id = offset + i;
            let mut route = path(V4, 1, source, if id == 0 { 191 } else { 190 }, vec![]);
            route.path_id = i;
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::OnlyToCustomer(64_512 + id));
            });
            routes.push(route);
        }
        lab.send(1, routes);
        for i in 0..65 {
            let attrs = &lab.manager.ribs[&peer_v4(source)]
                .get(&prefix, i)
                .unwrap()
                .attributes;
            blocked_attrs.push(Arc::downgrade(attrs));
        }
    }
    lab.send(1, vec![eligible.clone()]);
    let before: Vec<_> = blocked_attrs
        .iter()
        .map(std::sync::Weak::strong_count)
        .collect();
    lab.receive();
    assert!(lab.seen.iter().all(|seen| seen.envelopes == 0));
    lab.end_hold();
    let _ = crate::adj_rib_in::AdjRibIn::take_path_visits();
    drain_unicast_release(&mut lab.manager);
    let visits = crate::adj_rib_in::AdjRibIn::take_path_visits();

    // The receiver queue charges the retained OTC diagnostic to each
    // member, even when the eligible announcement shares its route storage.
    for n in 0..members {
        assert!(lab.manager.outbound_credit_rows(client(n)) >= 1);
    }
    lab.receive();
    for (n, seen) in lab.seen.iter().enumerate() {
        assert_eq!(seen.rows.get(&prefix), Some(&(eligible.peer, 100)));
        assert_eq!(seen.markers, 1);
        assert_eq!(lab.manager.outbound_credit_rows(client(n)), 0);
        let rejected = lab.manager.group_ribs[&group_id]
            .otc_blocked_for_member(client(n), Some(&HashSet::from([prefix])));
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].peer, peer_v4(SOURCE));
        assert_eq!(rejected[0].local_pref(), 191);
    }
    let retained = blocked_attrs
        .iter()
        .zip(before)
        .filter(|(attrs, old)| attrs.strong_count() > *old)
        .count();
    assert!(
        (1..=2).contains(&retained),
        "{retained} distinct marked attribute sets retained past release"
    );
    assert!(
        lab.manager.group_ribs[&group_id].release_history_len(&prefix) <= 2,
        "one diagnostic per possible winning source suffices without control communities"
    );
    visits
}

#[test]
fn grouped_otc_candidate_reads_and_retained_diagnostics_are_bounded() {
    let reads = [8, 32].map(release_crowded_prefix);
    assert!(reads[0] >= 131, "did not visit the candidates: {reads:?}");
    assert_eq!(reads[0], reads[1], "candidate reads by fleet size");
}
