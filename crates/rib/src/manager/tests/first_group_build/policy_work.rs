//! Count cold construction through the production actor's physical poll boundary.

use std::future::{Future, poll_fn};

use rustbgpd_policy::{NextHopAction, Policy, PolicyAction, PolicyChain};

use super::*;

const TAG: u32 = 64_501 << 16 | 7;
const PAGE: usize = crate::loc_rib::REGISTRATION_PAGE_SIZE;

pub(super) type Counts = BTreeMap<&'static str, usize>;

#[derive(Debug, Default)]
pub(super) struct Build {
    pub(super) peak: Counts,
    longest: Counts,
    pub(super) total: Counts,
    pub(super) polls: usize,
}

pub(super) fn snapshot() -> Counts {
    use crate::manager::slice_timing::{checkpoints, group_work};
    let mut counts = group_work();
    let build_row = crate::manager::GROUP_TABLE_BUILD_ROW;
    counts.insert(
        build_row,
        checkpoints().get(build_row).copied().unwrap_or(0),
    );
    counts.entry("group_staged_key").or_default();
    counts
}

impl Build {
    pub(super) fn record(&mut self, before: &Counts, after: Counts, stages: &[&str]) {
        let mut poll: Counts = after
            .into_iter()
            .map(|(stage, count)| (stage, count - before.get(stage).copied().unwrap_or(0)))
            .collect();
        let discovery = poll.get("first_group_discovery").copied().unwrap_or(0)
            + poll[crate::manager::GROUP_TABLE_BUILD_ROW];
        poll.insert("discovery", discovery);
        let units = stages
            .iter()
            .map(|name| poll.get(*name).copied().unwrap_or(0))
            .sum();
        if units == 0 {
            return;
        }
        self.polls += 1;
        poll.insert("work_units", units);
        if units > self.longest.get("work_units").copied().unwrap_or(0) {
            self.longest.clone_from(&poll);
        }
        for (stage, count) in poll {
            let peak = self.peak.entry(stage).or_default();
            *peak = (*peak).max(count);
            *self.total.entry(stage).or_default() += count;
        }
    }
}

fn mixed_policy() -> PolicyChain {
    // All v4 rows need both a changed source-attributes entry and a specific
    // next-hop override. All v6 rows enter the policy-denial table.
    let mut permit =
        super::super::update_groups::deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    permit.le = Some(32);
    permit.action = PolicyAction::Permit;
    permit.modifications.communities_add.push(TAG);
    permit.modifications.set_next_hop = Some(NextHopAction::Specific(IpAddr::V4(OTHER)));
    PolicyChain::new(vec![Policy {
        entries: vec![permit],
        default_action: PolicyAction::Deny,
    }])
}

// Readiness checkpoints include the per-prefix stage loop. The other
// counters record inside work that a single checkpoint can cover.
const WORK: &[&str] = &[
    "discovery",
    "first_group_repairs",
    "first_group_evaluated_lookups",
    "group_stage_checkpoints",
    "group_policy_evals",
    "group_inverse_evals",
    "group_source_writes",
    "group_denials_written",
    "group_denials_removed",
    "group_rehashed_keys",
    "group_growing_slab_slots",
];

async fn cold_policy_peak(per_family: u16) -> Build {
    let (mut manager, tx, _) = fixture(0);
    let base: Vec<_> = (0..per_family)
        .flat_map(prefixes)
        .map(|prefix| {
            let mut row = route(prefix, SOURCE, 100);
            crate::attr_set::AttrSet::edit(&mut row.attributes, |attrs| {
                attrs.push(rustbgpd_wire::PathAttribute::Communities(vec![42]));
            });
            row
        })
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), base));
    drain_route_chunks(&mut manager);
    let rows = usize::from(per_family) * 2;
    assert_eq!(manager.loc_rib.len(), rows);

    let peer = receiver(1);
    let (out, mut receiver) = mpsc::channel(32);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        sendable_families,
        is_ebgp,
        route_reflector_client,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *sendable_families = DUAL.to_vec();
    *is_ebgp = false;
    *route_reflector_client = true;
    *export_policy = Some(mixed_policy());
    tx.try_send(up).unwrap();

    let mut actor = Box::pin(manager.run_actor());
    let mut tx = Some(tx);
    let mut build = Build::default();
    let mut seen = 0;
    let mut markers = 0;
    let manager = poll_fn(|cx| {
        let before = snapshot();
        let result = actor.as_mut().poll(cx);
        build.record(&before, snapshot(), WORK);
        while let Ok(update) = receiver.try_recv().map(delivered) {
            for row in update.announce.iter() {
                assert!(matches!(row.prefix, Prefix::V4(_)));
                assert!(row.communities().contains(&TAG));
                seen += 1;
            }
            markers += update.end_of_rib.len();
        }
        if markers == DUAL.len() && tx.take().is_some() {
            cx.waker().wake_by_ref();
        }
        result
    })
    .await;
    let family_rows = usize::from(per_family);
    let group = &manager.group_ribs[&manager.grouped_member_of(peer).unwrap()];
    assert_eq!(group.table.next_hop_override_count(), family_rows);
    assert_eq!(
        group.table.next_hop_override(&prefixes(0)[0], 0),
        Some(&NextHopAction::Specific(IpAddr::V4(OTHER)))
    );
    assert_eq!((seen, markers), (family_rows, DUAL.len()));
    assert_eq!(
        manager
            .export_policy_for(peer)
            .unwrap()
            .hit_counters()
            .evals(),
        rows as u64
    );
    assert_eq!(build.total["group_staged_key"], rows);
    assert_eq!(build.total["group_policy_evals"], rows);
    assert_eq!(build.total["group_source_writes"], family_rows);
    assert_eq!(build.total["group_denials_written"], family_rows);
    assert_eq!(
        build
            .total
            .get("group_denials_removed")
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(
        build.total.get("first_group_repairs").copied().unwrap_or(0),
        0
    );
    build
}

#[tokio::test]
async fn policy_cold_build_bounds_work_per_physical_poll() {
    let small = cold_policy_peak(20_480).await;
    let large = cold_policy_peak(40_960).await;
    eprintln!("40,960 prefixes: {small:?}\n81,920 prefixes: {large:?}");
    assert!(large.polls > small.polls, "{small:?}, {large:?}");
    for build in [&small, &large] {
        let peak = &build.peak;
        assert_eq!(peak["discovery"], PAGE, "{peak:?}");
        assert!((1..=PAGE).contains(&peak["group_staged_key"]), "{peak:?}");
        // One bucket page, per-row evaluation and storage, the staging passes,
        // and growth of the first route slab segment all belong to this poll.
        assert!(peak["work_units"] <= 10 * PAGE, "{peak:?}");
        assert_eq!(
            build.total["first_group_evaluated_lookups"],
            build.total["group_policy_evals"]
        );
        assert!(peak["group_policy_evals"] <= PAGE, "{peak:?}");
        assert!(peak["group_source_writes"] <= PAGE, "{peak:?}");
        assert!(peak["group_denials_written"] <= PAGE, "{peak:?}");
        assert!(peak["group_growing_slab_slots"] <= 2 * PAGE, "{peak:?}");
    }
}
