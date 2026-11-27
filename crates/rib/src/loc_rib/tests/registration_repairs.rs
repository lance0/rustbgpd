use super::{
    FastSet, Ipv4Addr, LocRib, Prefix, REGISTRATION_PAGE_SIZE, REGISTRATION_VISITS,
    RegistrationScanStatus, Route, ScanBoundary, registration_route,
};

/// Finish physical discovery on a populated, stable layout. Each later change
/// replaces an already discovered winner and can only reach the build by repair.
fn discovered_winners(count: usize) -> (LocRib, Vec<Route>) {
    let mut loc = LocRib::with_capacity(count);
    let routes: Vec<_> = (0..u32::try_from(count).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    loc.start_registration_scan();
    let mut discovered = FastSet::default();
    while loc.registration_scan_status() == RegistrationScanStatus::Scanning {
        let page = loc.take_registration_page();
        assert!(page.bucket_visits <= REGISTRATION_PAGE_SIZE);
        assert_eq!(page.repairs, 0);
        discovered.extend(page.keys);
    }
    assert_eq!(discovered.len(), count);
    assert_eq!(
        loc.registration_scan_status(),
        RegistrationScanStatus::Ready
    );
    (loc, routes)
}

#[test]
fn candidate_only_changes_belong_to_the_per_client_best_founder() {
    let mut loc = LocRib::new();
    let route = registration_route(0);
    let prefix = route.prefix;
    let affected = std::collections::HashSet::from([prefix]);
    assert!(loc.recompute(prefix, [&route].into_iter()));
    loc.start_registration_scan();
    loc.start_member_replay_scan(route.peer);

    loc.record_registration_candidate_changes(&affected);
    assert!(!loc.registration_candidate_queued(&prefix));
    loc.track_registration_candidates();
    loc.record_registration_candidate_changes(&affected);
    loc.record_registration_candidate_changes(&affected);
    assert!(loc.registration_candidate_queued(&prefix));
    assert!(!loc.member_replay_change_recorded(route.peer, prefix));

    let discovery = loc.take_registration_page();
    assert!(discovery.keys.is_empty(), "the repair owns this prefix");
    let repair = loc.take_registration_page();
    assert_eq!(repair.keys, [prefix]);
    assert_eq!(repair.repairs, 1);
    assert!(!loc.registration_candidate_queued(&prefix));

    // A later mutation must invalidate even a prefix already handed to a
    // candidate walk. Such a walk may still be between source or path visits.
    loc.record_registration_candidate_changes(&affected);
    assert!(loc.registration_candidate_queued(&prefix));
    assert_eq!(loc.take_registration_page().keys, [prefix]);
    assert_eq!(
        loc.registration_scan_status(),
        RegistrationScanStatus::Ready
    );
}

#[test]
fn bulk_candidate_overflow_invalidates_an_unqueued_partial_walk() {
    let mut loc = LocRib::new();
    let prefix = registration_route(0).prefix;
    loc.start_registration_scan();
    loc.track_registration_candidates();
    assert!(loc.begin_bulk_candidate_changes(1));
    assert!(!loc.registration_candidate_queued(&prefix));

    assert!(!loc.begin_bulk_candidate_changes(super::REGISTRATION_REPAIR_LIMIT + 1));
    assert_eq!(
        loc.registration_scan_status(),
        RegistrationScanStatus::Overflow
    );
    assert!(loc.registration_candidate_queued(&prefix));
}

fn change_next_hops(loc: &mut LocRib, routes: &mut [Route], last_octet: u8) {
    for route in routes {
        route.next_hop = Ipv4Addr::new(192, 0, 2, last_octet).into();
        assert!(loc.recompute(route.prefix, [&*route].into_iter()));
    }
}

#[test]
fn registration_repairs_cold_winners_amid_a_full_page_of_hot_changes() {
    let (mut loc, mut routes) = discovered_winners(REGISTRATION_PAGE_SIZE + 2);
    let (cold, hot) = routes.split_at_mut(2);
    change_next_hops(&mut loc, cold, 1);
    let mut repaired = FastSet::default();
    for turn in 0..4 {
        change_next_hops(&mut loc, hot, 1 + turn % 2);
        let page = loc.take_registration_page();
        assert_eq!(page.bucket_visits, 0);
        assert_eq!(page.repairs, REGISTRATION_PAGE_SIZE);
        repaired.extend(page.keys);
        if loc.registration_scan_status() == RegistrationScanStatus::Ready {
            break;
        }
    }
    assert!(
        cold.iter().all(|r| repaired.contains(&r.prefix)),
        "both older changes must get a repair visit while hot changes continue"
    );
    assert_eq!(repaired.len(), cold.len() + hot.len());
    assert_eq!(
        loc.registration_scan_status(),
        RegistrationScanStatus::Ready
    );
}

#[test]
fn registration_repairs_over_one_page_of_hot_changes_finish_when_arrivals_stop() {
    let (mut loc, mut routes) = discovered_winners(REGISTRATION_PAGE_SIZE + 1);
    let mut repaired = FastSet::default();
    let mut last_page = Vec::new();
    for turn in 0..4 {
        change_next_hops(&mut loc, &mut routes, 1 + turn % 2);
        let page = loc.take_registration_page();
        assert_eq!(page.bucket_visits, 0);
        assert_eq!(page.repairs, REGISTRATION_PAGE_SIZE);
        last_page = page.keys;
        repaired.extend(last_page.iter().copied());
        assert_eq!(
            loc.registration_scan_status(),
            RegistrationScanStatus::Scanning
        );
    }
    assert_eq!(repaired.len(), routes.len(), "each hot key gets service");
    let tail = loc.take_registration_page();
    assert_eq!(tail.bucket_visits, 0);
    assert_eq!(tail.repairs, 1);
    let last_changes: FastSet<_> = last_page.into_iter().chain(tail.keys).collect();
    assert_eq!(last_changes.len(), routes.len());
    assert_eq!(
        loc.registration_scan_status(),
        RegistrationScanStatus::Ready
    );
}

/// A route message of sixteen chunks changes a full page of keys on every
/// turn but the one that receives it. Alternating with discovery serves half
/// of that and overflows the log within a dozen turns.
#[test]
fn registration_keeps_up_with_a_full_page_of_changes_on_sixteen_turns_in_seventeen() {
    const ROUTES: usize = 8 * REGISTRATION_PAGE_SIZE;
    let mut loc = LocRib::with_capacity(ROUTES);
    let mut routes: Vec<_> = (0..u32::try_from(ROUTES).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    loc.start_registration_scan();
    let mut built = FastSet::default();
    let (mut discovery_pages, mut changed) = (0, 0);
    for turn in 0..4096 {
        if turn % 17 != 0 {
            let start = changed % ROUTES;
            let octet = u8::try_from(1 + changed / ROUTES % 2).unwrap();
            change_next_hops(
                &mut loc,
                &mut routes[start..start + REGISTRATION_PAGE_SIZE],
                octet,
            );
            changed += REGISTRATION_PAGE_SIZE;
        }
        assert_eq!(
            loc.registration_scan_status(),
            RegistrationScanStatus::Scanning,
            "turn {turn}"
        );
        let page = loc.take_registration_page();
        assert!(page.bucket_visits + page.repairs <= REGISTRATION_PAGE_SIZE);
        discovery_pages += usize::from(page.bucket_visits > 0);
        let discovery_done = page.bucket_visits > 0 && {
            built.extend(page.keys);
            built.len() == ROUTES
        };
        if discovery_done {
            // Every route was discovered while the changes continued, on the
            // turns the log left free: about one per message.
            assert!(changed > 4 * ROUTES, "changes outlasted the repair log");
            assert!(
                discovery_pages <= turn / 17 + 3,
                "{discovery_pages} of {turn}"
            );
            while loc.registration_scan_status() == RegistrationScanStatus::Scanning {
                loc.take_registration_page();
            }
            assert_eq!(
                loc.registration_scan_status(),
                RegistrationScanStatus::Ready
            );
            return;
        }
    }
    panic!("discovery did not finish under sustained changes");
}

#[test]
fn member_replay_tracks_changed_keys_and_keeps_each_cursor_independent() {
    let (mut loc, mut routes) = discovered_winners(2 * REGISTRATION_PAGE_SIZE);
    let [a, b] = [1, 2].map(|n| crate::PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, n)));
    loc.start_member_replay_scan(a);
    let first = loc.take_member_replay_page(a);
    assert_eq!(first.bucket_visits, REGISTRATION_PAGE_SIZE);
    let prefix = first.keys[0];
    let route = routes.iter_mut().find(|r| r.prefix == prefix).unwrap();
    route.next_hop = Ipv4Addr::new(198, 51, 100, 1).into();
    assert!(loc.recompute(prefix, [&*route].into_iter()));

    loc.start_member_replay_scan(b);
    assert!(loc.recompute(prefix, std::iter::empty()));
    let a_page = loc.take_member_replay_page(a);
    assert_eq!(a_page.keys, [prefix]);
    assert!(a_page.displaced.is_empty());
    loc.stop_member_replay_scan(a);
    // Finishing a different member does not consume this member's repair.
    let discovery = loc.take_member_replay_page(b);
    assert_eq!(discovery.bucket_visits, REGISTRATION_PAGE_SIZE);
    assert!(!discovery.keys.contains(&prefix));
    let repair = loc.take_member_replay_page(b);
    assert_eq!(repair.keys, [prefix]);
    assert!(repair.displaced.is_empty());
    loc.stop_member_replay_scan(b);
    // Both members coexisted with the private group scan.
    assert_eq!(loc.take_registration_page().keys, [prefix]);
    loc.stop_registration_scan();
    assert!(loc.registration_scans.is_none());

    // Replacing the session under the same peer begins a fresh discovery.
    loc.start_member_replay_scan(a);
    assert_eq!(
        loc.member_replay_scan_status(a),
        RegistrationScanStatus::Scanning
    );
    let page = loc.take_member_replay_page(a);
    assert_eq!(page.bucket_visits, REGISTRATION_PAGE_SIZE);
    assert_eq!(page.repairs, 0);
    assert!(!page.keys.contains(&prefix));
    let surviving = page.keys[0];
    loc.record_targeted_replay_changes(&[a].into(), &[], &[surviving].into());
    let repair = loc.take_member_replay_page(a);
    assert_eq!(repair.keys, [surviving]);
    assert_eq!(repair.repairs, 1);
}

/// Take discovery pages of cohort scan `id` until it reaches `end`,
/// returning every key they carried.
fn ride_until(loc: &mut LocRib, id: u32, end: ScanBoundary) -> FastSet<Prefix> {
    let mut seen = FastSet::default();
    for _ in 0..10_000 {
        if loc.cohort_replay_lap_reached(id, end) {
            return seen;
        }
        let page = loc.take_cohort_replay_page(id, true);
        assert!(page.bucket_visits + page.repairs <= REGISTRATION_PAGE_SIZE);
        seen.extend(page.keys);
    }
    panic!("the scan never came back around");
}

// A cohort's scan wraps. A rider that joins at its first bucket completes
// after one pass. A late joiner completes one pass after the next shard
// boundary, having seen every key, including those the scan had passed
// before it joined.
#[test]
fn a_cohort_scan_wraps_and_serves_a_late_joiner_one_whole_pass() {
    // Enough rows for the table to have split into shards.
    let count = 3 * crate::fast_hash::SHARD_SPLIT_AT / 2;
    let mut loc = LocRib::new();
    let routes: Vec<_> = (0..u32::try_from(count).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    assert!(loc.routes.shards().len() > 1);
    let all: FastSet<_> = routes.iter().map(|route| route.prefix).collect();
    let buckets = || REGISTRATION_VISITS.with(|visits| visits.get().0);
    let mut total = 0;
    for shard in loc.routes.shards() {
        total += shard.num_buckets();
    }

    loc.start_cohort_replay_scan(7);
    let first = loc.cohort_replay_lap_end(7);
    let before = buckets();
    // The first rider is part of the way round when the late one joins,
    // inside a shard.
    let mut early = FastSet::default();
    for _ in 0..3 {
        early.extend(loc.take_cohort_replay_page(7, true).keys);
    }
    let late = loc.cohort_replay_lap_end(7);
    assert!(late > first && !loc.cohort_replay_lap_reached(7, first));
    let joined = buckets();

    early.extend(ride_until(&mut loc, 7, first));
    assert_eq!(early, all, "the first rider's pass missed keys");
    assert_eq!(
        buckets() - before,
        total,
        "one pass visits each bucket once"
    );

    // The late joiner rides on from where the first rider's pass ended.
    let mut seen: FastSet<_> = ride_until(&mut loc, 7, late);
    assert!(
        seen.len() < all.len(),
        "the rest of the pass was the whole table"
    );
    // What it saw between joining and the end of the first rider's pass.
    seen.extend(early.iter().copied());
    assert_eq!(seen, all);
    let ridden = buckets() - joined;
    assert!(
        (total..total + total / 4).contains(&ridden),
        "a late joiner rides one pass and the rest of a shard: {ridden} of {total}"
    );
    loc.stop_cohort_replay_scan(7);
    assert!(loc.registration_scans.is_none());
}

// Growth that rehashes the single table mid-pass rewinds the cohort's
// cursor. A rider that joined inside the pass still sees every key before
// the scan reaches its boundary, and each new key is queued as a repair.
#[test]
fn a_rehash_mid_pass_leaves_a_late_joiner_no_missed_key() {
    let count = 3 * REGISTRATION_PAGE_SIZE;
    let mut loc = LocRib::new();
    let routes: Vec<_> = (0..u32::try_from(8 * count).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes[..count] {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    loc.start_cohort_replay_scan(1);
    let first = loc.take_cohort_replay_page(1, true);
    assert_eq!(first.bucket_visits, REGISTRATION_PAGE_SIZE);
    let late = loc.cohort_replay_lap_end(1);
    let buckets = loc.routes.shards()[0].num_buckets();
    let mut grown = count;
    while loc.routes.shards()[0].num_buckets() == buckets && loc.routes.shards().len() == 1 {
        let route = &routes[grown];
        assert!(loc.recompute(route.prefix, [route].into_iter()));
        grown += 1;
    }
    let mut seen = FastSet::default();
    for _ in 0..10_000 {
        if loc.cohort_replay_lap_reached(1, late) && !loc.cohort_replay_repairs_pending(1) {
            break;
        }
        assert!(!loc.cohort_replay_overflowed(1));
        seen.extend(loc.take_cohort_replay_page(1, true).keys);
    }
    let all: FastSet<_> = routes[..grown].iter().map(|route| route.prefix).collect();
    assert_eq!(seen, all);
}

// A shard that rehashes while the cohort's scan is inside it rewinds the
// scan to that shard's first bucket. On a table split into shards, the
// first rider and a late joiner whose pass ends at the next shard boundary
// both pass the rehashed shard once, and both still see every key.
#[test]
fn a_rehash_of_the_shard_under_the_scan_rewinds_it_for_riders_that_pass_it_once() {
    let count = 3 * crate::fast_hash::SHARD_SPLIT_AT / 2;
    let mut loc = LocRib::new();
    let routes: Vec<_> = (0..u32::try_from(4 * count).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes[..count] {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    assert!(loc.routes.shards().len() > 1);
    let cursor = |loc: &LocRib| {
        let scan = &loc.registration_scans.as_ref().unwrap().cohorts[&1];
        (scan.shard, scan.bucket)
    };
    // What the first rider and the late joiner have seen.
    let mut seen = [FastSet::default(), FastSet::default()];
    let mut take = |loc: &mut LocRib, discover: bool, riders: std::ops::Range<usize>| {
        let page = loc.take_cohort_replay_page(1, discover);
        for rider in riders {
            seen[rider].extend(page.keys.iter().copied());
        }
    };

    loc.start_cohort_replay_scan(1);
    let first = loc.cohort_replay_lap_end(1);
    take(&mut loc, true, 0..1);
    // The late rider joins inside shard 0: its pass ends at shard 1.
    assert!(cursor(&loc).0 == 0 && cursor(&loc).1 != 0);
    let late = loc.cohort_replay_lap_end(1);
    assert_eq!(late, ScanBoundary { lap: 1, shard: 1 });
    while cursor(&loc).0 < 2 || cursor(&loc).1 == 0 {
        take(&mut loc, true, 0..2);
    }
    assert_eq!(cursor(&loc).0, 2, "the scan is not inside shard 2");

    // Grow the table until shard 2 rehashes. Each new key is a repair.
    let buckets = loc.routes.shards()[2].num_buckets();
    let mut grown = count;
    while loc.routes.shards()[2].num_buckets() == buckets {
        let route = &routes[grown];
        assert!(loc.recompute(route.prefix, [route].into_iter()));
        grown += 1;
        while loc.cohort_replay_repairs_pending(1) {
            take(&mut loc, false, 0..2);
        }
    }
    assert!(!loc.cohort_replay_overflowed(1));
    assert_eq!(cursor(&loc).0, 2);

    for (rider, end) in [first, late].into_iter().enumerate() {
        for _ in 0..10_000 {
            if loc.cohort_replay_lap_reached(1, end) && !loc.cohort_replay_repairs_pending(1) {
                break;
            }
            take(&mut loc, true, rider..2);
        }
        assert!(loc.cohort_replay_lap_reached(1, end));
    }
    let all: FastSet<_> = routes[..grown].iter().map(|route| route.prefix).collect();
    assert!(seen[0] == all, "the first rider missed keys");
    assert!(seen[1] == all, "the late joiner missed keys");
}

// The single table splits into shards while the cohort's scan is inside
// it, which moves every key. The scan rewinds to the first bucket of shard
// 0, so the rider that started the pass sees every key before its pass
// ends. Without the rewind it would miss the keys of shard 0 that sat past
// the cursor in the single table.
#[test]
fn a_split_under_the_scan_rewinds_it_for_the_rider_that_started_the_pass() {
    let split = crate::fast_hash::SHARD_SPLIT_AT;
    let count = split - 512;
    let mut loc = LocRib::new();
    let routes: Vec<_> = (0..u32::try_from(split + 512).unwrap())
        .map(registration_route)
        .collect();
    for route in &routes[..count] {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    assert_eq!(loc.routes.shards().len(), 1);
    loc.start_cohort_replay_scan(1);
    let end = loc.cohort_replay_lap_end(1);
    let mut seen = FastSet::default();
    for _ in 0..8 {
        seen.extend(loc.take_cohort_replay_page(1, true).keys);
    }
    assert!(!seen.is_empty() && seen.len() < count);
    for route in &routes[count..] {
        assert!(loc.recompute(route.prefix, [route].into_iter()));
    }
    assert!(loc.routes.shards().len() > 1, "the table never split");
    for _ in 0..10_000 {
        if loc.cohort_replay_lap_reached(1, end) && !loc.cohort_replay_repairs_pending(1) {
            break;
        }
        assert!(!loc.cohort_replay_overflowed(1));
        seen.extend(loc.take_cohort_replay_page(1, true).keys);
    }
    assert!(loc.cohort_replay_lap_reached(1, end));
    let all: FastSet<_> = routes.iter().map(|route| route.prefix).collect();
    assert!(
        seen == all,
        "the rider missed {} keys",
        all.len() - seen.len()
    );
}
