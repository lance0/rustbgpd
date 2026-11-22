//! A distinct policy reload sends one authoritative command per singleton group.

use super::*;

const ROWS: usize = 257;

struct Member {
    addr: Ipv4Addr,
    old_tag: u32,
    new_tag: u32,
    output: mpsc::Receiver<OutboundRouteUpdate>,
}

type Inventory = BTreeMap<Prefix, PeerId>;

fn drain_inventory(
    output: &mut mpsc::Receiver<OutboundRouteUpdate>,
    tag: u32,
    rows: &mut Inventory,
) {
    while let Ok(update) = output.try_recv().map(delivered) {
        assert_eq!(update.unicast_withdrawals().count(), 0);
        assert_eq!(update.end_of_rib, Vec::<(Afi, Safi)>::new());
        assert!(update.next_hop_override.iter().all(Option::is_none));
        for route in &*update.announce {
            if update.announce_source_exclusion == Some(route.peer) {
                continue;
            }
            assert_eq!(route.path_id, 0);
            assert_eq!(route.next_hop, route.peer.addr());
            assert_eq!(
                route.communities(),
                &[tag],
                "policy tag for {}",
                route.prefix
            );
            assert!(
                rows.insert(route.prefix, route.peer).is_none(),
                "duplicate {}",
                route.prefix
            );
        }
    }
}

fn replace(manager: &mut RibManager, id: PeerId, tag: u32, restore: bool) {
    let replacements = batch_replacements(&[id], &community_chain(tag));
    if restore {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        });
        assert_eq!(
            result.try_recv().unwrap(),
            Ok(vec![
                crate::update::PeerExportPolicyRestoreReceipt::Restored { peer: id }
            ])
        );
    } else {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        });
        assert_eq!(result.try_recv().unwrap(), Ok(vec![]));
    }
}

fn fixture(member_count: usize) -> (RibManager, Vec<Member>, Vec<Inventory>, Arc<AtomicUsize>) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let probes = Arc::new(AtomicUsize::new(0));
    let mut members = Vec::new();
    for i in 1..=u8::try_from(member_count).unwrap() {
        let addr = Ipv4Addr::new(192, 0, 2, i);
        let id = peer_v4(addr);
        let old_tag = 0xfde8_1000 + u32::from(i);
        let new_tag = 0xfde8_2000 + u32::from(i);
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer: id,
            session_id: 0,
            encoder: Arc::new(CohortExactEncoder {
                owner: u64::from(i),
                profile: 42,
                max_len: 65_535,
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::clone(&probes),
                reuses: Arc::new(AtomicUsize::new(0)),
            }),
        });
        let mut output =
            register_direct_peer_with_policy(&mut manager, id, Some(community_chain(old_tag)));
        assert_eq!(
            output.try_recv().map(delivered).unwrap().end_of_rib,
            ipv4_sendable()
        );
        members.push(Member {
            addr,
            old_tag,
            new_tag,
            output,
        });
    }

    // The oracle comes exclusively from the inputs: each member originates a
    // disjoint stripe and should receive every other stripe under its own policy.
    let mut base = Inventory::new();
    let mut initial = vec![Inventory::new(); member_count];
    for index in 0..member_count {
        let source = members[index].addr;
        let prefixes = (index..ROWS).step_by(member_count).map(|row| {
            let prefix = overlap_prefix(u32::try_from(row).unwrap());
            assert!(base.insert(Prefix::V4(prefix), peer_v4(source)).is_none());
            prefix
        });
        distribute_direct_routes(&mut manager, source, prefixes);
        for (member, rows) in members.iter_mut().zip(&mut initial) {
            drain_inventory(&mut member.output, member.old_tag, rows);
        }
    }
    assert_eq!(base.len(), ROWS);
    let expected: Vec<Inventory> = members
        .iter()
        .map(|member| {
            base.iter()
                .filter(|(_, source)| **source != peer_v4(member.addr))
                .map(|(&prefix, &source)| (prefix, source))
                .collect()
        })
        .collect();
    assert_eq!(initial, expected);
    (manager, members, expected, probes)
}

fn check_distinct_reload(member_count: usize) {
    let (mut manager, mut members, expected, probes) = fixture(member_count);
    for restore in [false, true] {
        crate::manager::reset_distinct_reload_visits();
        let probes_before = probes.load(Ordering::Relaxed);
        for (member, expected_rows) in members.iter_mut().zip(&expected) {
            let id = peer_v4(member.addr);
            let prior = manager.grouped_member_of(id).unwrap();
            assert_eq!(manager.group_ribs[&prior].members, HashSet::from([id]));
            let before = manager.export_policy_counters[&id].snapshot();
            let receipts_before = manager.authoritative_transition_receipts.len();
            let tag = if restore {
                member.old_tag
            } else {
                member.new_tag
            };
            replace(&mut manager, id, tag, restore);
            assert_eq!(
                manager.authoritative_transition_receipts.len(),
                receipts_before + 1
            );
            let receipt = &manager.authoritative_transition_receipts[receipts_before];
            assert_eq!(
                (receipt.outcome, receipt.classification),
                ("committed", "shared")
            );
            assert_eq!(
                (
                    receipt.membership_moves,
                    receipt.emits_succeeded,
                    receipt.fallback_members,
                    receipt.emits_degraded
                ),
                (1, 1, 0, 0)
            );
            assert_eq!(
                (receipt.inventory_announces, receipt.inventory_withdraws),
                (ROWS, 0)
            );
            assert_eq!((receipt.dirty_after, receipt.pending_after), (0, 0));
            let next = manager.grouped_member_of(id).unwrap();
            assert_ne!(prior, next);
            assert_eq!(manager.group_ribs[&next].members, HashSet::from([id]));
            let mut rows = Inventory::new();
            drain_inventory(&mut member.output, tag, &mut rows);
            assert_eq!(&rows, expected_rows, "member {id} restore={restore}");
            let after = manager.export_policy_counters[&id].snapshot();
            assert_eq!(
                after.export_policy_routes_denied,
                before.export_policy_routes_denied
            );
            assert_eq!(
                after.export_policy_routes_permitted - before.export_policy_routes_permitted,
                u64::try_from(expected_rows.len()).unwrap()
            );
        }
        assert!(probes.load(Ordering::Relaxed) > probes_before);
        assert_eq!(
            crate::manager::distinct_reload_visits(),
            (0, 0, 0),
            "{member_count} disjoint policy pairs, restore={restore}"
        );
    }
}

#[test]
fn eight_distinct_reload_groups_skip_empty_scans() {
    check_distinct_reload(8);
}

#[test]
fn thirty_two_distinct_reload_groups_skip_empty_scans() {
    check_distinct_reload(32);
}
