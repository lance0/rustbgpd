//! A policy command arrives after a cold registration evicts an idle Prepare.

use super::*;

const NEXT_TAG: u32 = 0xfde8_2411;
const ROWS: u32 = 10_240;

#[derive(Default)]
struct Received {
    // Actual outbound state, including the source and effective export policy.
    rows: BTreeMap<Prefix, (PeerId, u32, Vec<u32>)>,
    ends: usize,
}

impl Received {
    fn apply(&mut self, update: &OutboundRouteUpdate) {
        for &(prefix, path_id) in update.unicast_withdrawals() {
            assert_eq!(path_id, 0);
            self.rows.remove(&prefix);
        }
        for row in update
            .announce
            .iter()
            .filter(|r| update.announce_source_exclusion != Some(r.peer))
        {
            assert_eq!(row.path_id, 0);
            self.rows.insert(
                row.prefix,
                (row.peer, row.local_pref(), row.communities().to_vec()),
            );
        }
        if !update.end_of_rib.is_empty() {
            assert_eq!(update.end_of_rib, ipv4_sendable());
            self.ends += 1;
        }
    }

    fn check(&self, expected: &BTreeMap<Prefix, u32>, tags: &[u32]) {
        assert_eq!(self.rows.len(), expected.len());
        for (prefix, &wanted) in expected {
            let (source, pref, communities) = &self.rows[prefix];
            assert_eq!(
                (*source, *pref),
                (peer_v4(OVERLAP_SOURCE), wanted),
                "{prefix}"
            );
            assert_eq!(communities.as_slice(), tags, "{prefix}");
        }
    }

    fn initial(
        receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
        expected: &BTreeMap<Prefix, u32>,
        tags: &[u32],
    ) {
        let mut state = Self::default();
        while let Ok(update) = receiver.try_recv().map(delivered) {
            assert_eq!(state.ends, 0, "unexpected output following initial EoR");
            assert!(update.unicast_withdrawals().next().is_none());
            let before = state.rows.len();
            state.apply(&update);
            assert_eq!(
                state.rows.len() - before,
                update.announce.len(),
                "duplicate or unexpected excluded founder row"
            );
            if state.ends != 0 {
                state.check(expected, tags);
            }
        }
        assert_eq!(state.ends, 1);
    }
}

fn completed_preparation(manager: &mut RibManager, peer: PeerId, target: &PolicyChain) -> usize {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
        peer,
        export_policy: Some(target.clone()),
        reply,
    });
    assert!(manager.pending_destination_prestage.is_some());
    while manager.pending_destination_prestage.is_some() {
        manager.advance_destination_prestage();
    }
    assert_eq!(response.try_recv().unwrap(), Ok(()));
    let gid = manager
        .prepared_destination
        .expect("acknowledged optional destination");
    assert!(manager.group_ribs[&gid].members.is_empty());
    assert_eq!(manager.group_ribs[&gid].table.len(), ROWS as usize);
    gid
}

fn seed_old_inventory(
    manager: &mut RibManager,
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
) -> (Received, BTreeMap<Prefix, u32>) {
    let mut affected = Received::default();
    let expected: BTreeMap<_, _> = (0..ROWS)
        .map(|i| (Prefix::V4(overlap_prefix(i)), 100))
        .collect();
    for i in (0..ROWS).step_by(512) {
        distribute_direct_routes(manager, OVERLAP_SOURCE, (i..i + 512).map(overlap_prefix));
        for (n, rx) in receivers.iter_mut().enumerate() {
            while let Ok(update) = rx.try_recv().map(delivered) {
                if n == 0 {
                    affected.apply(&update);
                }
            }
        }
    }
    affected.check(&expected, &[OVERLAP_TAG]);
    (affected, expected)
}

fn queue_late_registration(
    primary: &mpsc::Sender<RibUpdate>,
    late: PeerId,
    target: PolicyChain,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out, late_rx) = mpsc::channel(32);
    let mut up = super::super::lifecycle::test_peer_up(late, 19, out);
    if let RibUpdate::PeerUp {
        export_policy,
        is_ebgp,
        route_reflector_client,
        ..
    } = &mut up
    {
        *export_policy = Some(target);
        *is_ebgp = false;
        *route_reflector_client = true;
    }
    primary.try_send(up).unwrap();
    late_rx
}

#[tokio::test]
async fn late_policy_writer_uses_old_authority_until_optional_eviction_finishes() {
    let (mut manager, members, mut receivers) = direct_clean_transition_manager(3, 0, None);
    manager.outbound_row_credit_override = None;
    let (mut affected, mut expected) = seed_old_inventory(&mut manager, &mut receivers);
    let original = manager.grouped_member_of(members[0]).unwrap();
    let target = community_chain(NEXT_TAG);
    let prepared = completed_preparation(&mut manager, members[0], &target);
    manager.first_group_build_min_routes = 1;
    manager.initial_dump_defer_min_routes = 1;
    let mut cold = join_overlap_founder(&mut manager, 1);
    // One older source registration may precede the cold receiver in the queue.
    for _ in 0..3 {
        if manager.optional_destination_retirement_active() {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.optional_destination_retirement_active());
    assert!(!manager.group_ribs.contains_key(&prepared));
    assert!(manager.first_group_build.is_none());
    // The fixture forces a zero flush deadline to step the optional Prepare.
    // Remove that time trigger so the queued UPDATE uses the ordinary primary
    // admission path deterministically, before the next owed retirement slice.
    manager.flush_poll_budget = std::time::Duration::MAX;
    let (query, query_rx) = mpsc::channel(8);
    manager.query_rx = query_rx;
    let (primary, rx) = mpsc::channel(16);
    manager.rx = rx;
    let (reply, mut applied) = oneshot::channel();
    primary
        .try_send(RibUpdate::ReplacePeerExportPolicy {
            peer: members[0],
            export_policy: Some(target.clone()),
            reply,
        })
        .unwrap();
    let source = peer_v4(OVERLAP_SOURCE);
    let marker = overlap_prefix(ROWS);
    let victim = overlap_prefix(5);
    let mut delta = super::super::lifecycle::test_routes_received(
        source,
        vec![make_route_with_lp(marker, OVERLAP_SOURCE, 170)],
    );
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut delta else {
        unreachable!()
    };
    withdrawn.push((Prefix::V4(victim), 0));
    primary.try_send(delta).unwrap();

    let late = peer_v4(Ipv4Addr::new(10, 43, 0, 2));
    let mut late_rx = queue_late_registration(&primary, late, target);
    let mut actor = Box::pin(manager.run_actor());
    // The detached table alone has ROWS physical slots. These bounded actor
    // polls cannot finish eviction, even if inventory retirement costs zero.
    let logs = observe_policy_during_retirement(
        actor.as_mut(),
        ROWS as usize,
        &mut receivers,
        query_update_group(&query, members[0]),
        original,
    );
    assert!(matches!(
        applied.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(cold.is_empty() && late_rx.is_empty());
    assert!(expected.remove(&Prefix::V4(victim)).is_some());
    expected.insert(Prefix::V4(marker), 170);
    for update in &logs[0] {
        affected.apply(update);
    }
    affected.check(&expected, &[OVERLAP_TAG]);
    for witness in [&logs[0], &logs[2]] {
        assert_eq!(
            overlap_events(witness, Prefix::V4(marker), Prefix::V4(victim)),
            [
                OverlapEvent::EndOfRibWithdrawal,
                OverlapEvent::Marker(170, true)
            ]
        );
    }
    let actor = tokio::spawn(actor);
    applied.await.unwrap().unwrap();
    drop(query);
    drop(primary);
    let manager = actor.await.unwrap();
    while let Ok(update) = receivers[0].try_recv().map(delivered) {
        affected.apply(&update);
    }
    affected.check(&expected, &[NEXT_TAG]);
    assert_eq!(
        manager.grouped_member_of(members[0]),
        manager.grouped_member_of(late)
    );
    assert_ne!(manager.grouped_member_of(late).unwrap(), original);
    Received::initial(&mut late_rx, &expected, &[NEXT_TAG]);
    Received::initial(&mut cold, &expected, &[]);
}
