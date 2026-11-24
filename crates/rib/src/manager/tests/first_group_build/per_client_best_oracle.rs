//! Cold route-server registration from independently ranked inputs.
use super::*;

const THIRD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const SOURCES: [Ipv4Addr; 3] = [SOURCE, OTHER, THIRD];
const FOUNDER_AS: u32 = 64521;
const RS_AS: u32 = 64512;
const MARKER: u32 = 64999 << 16;

#[derive(Clone, Copy, Debug)]
struct Candidate {
    source: Ipv4Addr,
    router_id: Ipv4Addr,
    pref: u32,
    suppress: bool,
}

type Candidates = BTreeMap<Prefix, [Option<Candidate>; 3]>;

impl Candidate {
    fn communities(self, scrub: bool) -> Vec<u32> {
        // 0:FOUNDER_AS suppresses the path only toward the first client.
        let mut tags = Vec::new();
        if self.suppress && !scrub {
            tags.push(FOUNDER_AS);
        }
        tags.push(MARKER | self.pref);
        tags
    }

    fn input(self, prefix: Prefix) -> Route {
        let mut row = route(prefix, self.source, self.pref);
        row.peer_router_id = self.router_id;
        AttrSet::edit(&mut row.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(self.communities(false)));
        });
        row
    }

    fn check(self, row: &Route, prefix: Prefix, scrub: bool) {
        assert_eq!(row.prefix, prefix);
        assert_eq!(row.path_id, 0);
        assert_eq!(row.peer, peer_v4(self.source), "source for {prefix}");
        assert_eq!(row.peer_router_id, self.router_id, "source ID for {prefix}");
        assert_eq!(row.local_pref(), self.pref, "preference for {prefix}");
        assert_eq!(
            row.communities(),
            self.communities(scrub),
            "tags for {prefix}"
        );
    }
}

fn inputs() -> Candidates {
    (0..1200)
        .flat_map(|n| {
            // Between zero and three higher-ranked candidates are suppressed.
            let suppressed = usize::from(n % 4);
            prefixes(n).map(|prefix| {
                (
                    prefix,
                    std::array::from_fn(|i| {
                        Some(Candidate {
                            source: SOURCES[i],
                            router_id: SOURCES[i],
                            pref: [300, 200, 100][i],
                            suppress: i < suppressed,
                        })
                    }),
                )
            })
        })
        .collect()
}

fn seed(manager: &mut RibManager, candidates: &Candidates) {
    for (i, source) in SOURCES.into_iter().enumerate() {
        register_test_peer(manager, peer_v4(source), 0);
        let rows = candidates
            .iter()
            .filter_map(|(&prefix, paths)| paths[i].map(|candidate| candidate.input(prefix)))
            .collect();
        manager.handle_update(test_routes_received(peer_v4(source), rows));
        drain_route_chunks(manager);
    }
    assert_eq!(manager.loc_rib.len(), candidates.len());
}

fn registration(
    manager: &mut RibManager,
    n: u8,
    rs: bool,
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: rs.then_some(RS_AS),
    });
    let (tx, rx) = mpsc::channel(64);
    let mut up = test_peer_up(peer, 1, tx);
    let RibUpdate::PeerUp {
        peer_asn,
        per_client_best,
        sendable_families,
        interpret_rfc1997,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = FOUNDER_AS + u32::from(n - 1);
    *per_client_best = true;
    *interpret_rfc1997 = false;
    *sendable_families = DUAL.to_vec();
    (up, rx)
}

fn check_replay(
    manager: &RibManager,
    candidates: &Candidates,
    n: u8,
    rs: bool,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) {
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(n)).unwrap()];
    let mut expected = BTreeMap::new();
    for (&prefix, paths) in candidates {
        let selected = paths
            .iter()
            .flatten()
            .find(|candidate| !(rs && n == 1 && candidate.suppress));
        if let Some(&candidate) = selected {
            expected.insert(prefix, candidate);
        }
    }
    // These fast family counts rely on seeding the first RS member's target index.
    assert_eq!(group.advertised_count_for(receiver(n)), expected.len());
    let counts: Vec<_> = DUAL
        .into_iter()
        .map(|family| {
            let count = expected
                .keys()
                .filter(|p| crate::manager::helpers::prefix_family(p) == family)
                .count();
            (family, count as u64)
        })
        .collect();
    assert_eq!(group.family_counts_for(receiver(n)), counts);
    let mut ends = HashSet::new();
    while let Ok(update) = rx.try_recv() {
        assert_eq!(update.unicast_withdrawals().count(), 0);
        for row in update.announce.iter() {
            assert!(!ends.contains(&crate::manager::helpers::prefix_family(&row.prefix)));
            expected
                .remove(&row.prefix)
                .expect("unexpected or duplicate advertisement")
                .check(row, row.prefix, rs);
        }
        for family in update.end_of_rib {
            assert!(ends.insert(family), "repeated End-of-RIB");
        }
    }
    assert!(
        expected.is_empty(),
        "{} missing advertisements",
        expected.len()
    );
    assert_eq!(ends, DUAL.into_iter().collect());
}

fn check_lanes(manager: &RibManager, candidates: &Candidates) {
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(1)).unwrap()];
    assert!(group.per_client_best);
    assert_eq!(group.table.len(), candidates.len());
    assert_eq!(group.runner_up_count(), candidates.len());
    for (&prefix, paths) in candidates {
        let mut ordered = paths.iter().flatten();
        let best = ordered.next().unwrap();
        best.check(manager.loc_rib.get(&prefix).unwrap(), prefix, false);
        best.check(group.table.get(&prefix, 0).unwrap(), prefix, false);
        let lane = group.adv_entry(peer_v4(best.source), &prefix, 0).unwrap();
        ordered.next().unwrap().check(lane.route, prefix, false);
    }
}

fn copied_keys(manager: &mut RibManager, candidates: &Candidates) -> [Prefix; 4] {
    // Use only completed rows in the unpublished table. Hash order is per process.
    for _ in 0..10_000 {
        assert!(manager.first_group_build.is_some());
        manager.advance_first_group_build();
        let keys: Vec<_> = candidates
            .iter()
            .filter_map(|(&prefix, paths)| {
                (paths[1].unwrap().suppress && manager.first_group_contains(prefix))
                    .then_some(prefix)
            })
            .take(4)
            .collect();
        if let Ok(keys) = keys.try_into() {
            return keys;
        }
    }
    panic!("no copied route-server rows");
}

fn change_runner(
    manager: &mut RibManager,
    candidates: &mut Candidates,
    prefix: Prefix,
    replacement: Option<Candidate>,
) {
    let source = peer_v4(OTHER);
    let mut received = test_routes_received(source, vec![]);
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = &mut received
    else {
        unreachable!()
    };
    match replacement {
        Some(candidate) => announced.push(candidate.input(prefix)),
        None => withdrawn.push((prefix, 0)),
    }
    manager.handle_update(received);
    drain_route_chunks(manager);
    let paths = candidates.get_mut(&prefix).unwrap();
    paths[1] = replacement;
    paths[0]
        .unwrap()
        .check(manager.loc_rib.get(&prefix).unwrap(), prefix, false);
}

#[test]
fn per_client_best_founder_repairs_runner_up_churn_before_first_replay() {
    let mut candidates = inputs();
    let (mut paced, _primary, _) = fixture(0);
    seed(&mut paced, &candidates);
    let (up, mut first) = registration(&mut paced, 1, true);
    paced.handle_update(up);
    assert!(
        paced.first_group_build.is_some(),
        "eligible route-server founder must pace construction"
    );
    let [replaced, removed, reannounced, metadata] = copied_keys(&mut paced, &candidates);
    let replacement = Candidate {
        source: OTHER,
        router_id: OTHER,
        pref: 250,
        suppress: false,
    };
    change_runner(&mut paced, &mut candidates, replaced, Some(replacement));
    change_runner(&mut paced, &mut candidates, removed, None);
    change_runner(&mut paced, &mut candidates, reannounced, None);
    change_runner(&mut paced, &mut candidates, reannounced, Some(replacement));
    // Selection and export attributes stay equal when this source changes its
    // router ID. The published winner must still match fresh construction.
    let winner = candidates.get_mut(&metadata).unwrap()[0].as_mut().unwrap();
    winner.router_id = Ipv4Addr::new(203, 0, 113, 91);
    paced.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![winner.input(metadata)],
    ));
    drain_route_chunks(&mut paced);
    winner.check(paced.loc_rib.get(&metadata).unwrap(), metadata, false);
    let (up, mut sibling) = registration(&mut paced, 2, true);
    paced.handle_update(up);
    assert!(
        first.is_empty() && sibling.is_empty(),
        "partial group replayed"
    );

    // The synchronous founder receives just the final input; it shares no scan,
    // repair log or table with the paced founder.
    let (mut synchronous, _primary, _) = fixture(0);
    synchronous.first_group_build_min_routes = usize::MAX;
    seed(&mut synchronous, &candidates);
    let (up, mut reference_first) = registration(&mut synchronous, 1, true);
    synchronous.handle_update(up);
    assert!(synchronous.first_group_build.is_none());
    let (up, mut reference_sibling) = registration(&mut synchronous, 2, true);
    synchronous.handle_update(up);
    for (manager, first, sibling) in [
        (
            &mut synchronous,
            &mut reference_first,
            &mut reference_sibling,
        ),
        (&mut paced, &mut first, &mut sibling),
    ] {
        for _ in 0..100_000 {
            if manager.pending_initial_registrations.is_empty()
                && manager.first_group_build.is_none()
            {
                break;
            }
            manager.advance_pending_initial_registration();
        }
        assert!(manager.first_group_build.is_none());
        assert_eq!(
            manager.grouped_member_of(receiver(1)).unwrap(),
            manager.grouped_member_of(receiver(2)).unwrap()
        );
        check_lanes(manager, &candidates);
        check_replay(manager, &candidates, 1, true, first);
        check_replay(manager, &candidates, 2, true, sibling);
        // A transparent warm join shares the table and retains its control tags.
        let (up, mut transparent) = registration(manager, 3, false);
        manager.handle_update(up);
        assert_eq!(
            manager.grouped_member_of(receiver(3)),
            manager.grouped_member_of(receiver(1))
        );
        check_replay(manager, &candidates, 3, false, &mut transparent);
    }
}

#[test]
fn first_per_client_best_build_admits_only_eligible_unicast() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Case {
        RsOnly,
        WithPolicy,
        WithVpn,
        Ibgp,
        WithoutControl,
    }
    use Case::{Ibgp, RsOnly, WithPolicy, WithVpn, WithoutControl};
    let (mut manager, _tx, _) = fixture(1);
    // A different group key per case keeps an earlier table from masking admission.
    for (n, case) in [
        (1, RsOnly),
        (2, WithPolicy),
        (3, WithVpn),
        (4, Ibgp),
        (5, WithoutControl),
    ] {
        let (mut up, _rx) = registration(&mut manager, n, case != WithoutControl);
        let RibUpdate::PeerUp {
            per_client_best,
            export_policy,
            sendable_families,
            is_ebgp,
            ..
        } = &mut up
        else {
            unreachable!()
        };
        match case {
            RsOnly => *per_client_best = false,
            WithPolicy => {
                *export_policy = Some(crate::manager::tests::update_groups::community_chain(
                    MARKER,
                ))
            }
            WithVpn => sendable_families.push((Afi::Ipv4, Safi::MplsVpn)),
            Ibgp => *is_ebgp = false,
            WithoutControl => {}
        }
        manager.handle_update(up);
        assert_eq!(
            manager.first_group_build.is_some(),
            case == WithoutControl,
            "{case:?}"
        );
        if case != WithoutControl {
            assert_eq!(
                manager.grouped_member_of(receiver(n)).is_some(),
                case != WithVpn
            );
        }
    }
}
