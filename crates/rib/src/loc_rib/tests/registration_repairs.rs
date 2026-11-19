use super::{
    FastSet, Ipv4Addr, LocRib, REGISTRATION_PAGE_SIZE, RegistrationScanStatus, Route,
    registration_route,
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
