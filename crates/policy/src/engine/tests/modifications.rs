use super::*;

// -----------------------------------------------------------------------
// Policy with modifications
// -----------------------------------------------------------------------

#[test]
fn evaluate_returns_modifications() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_local_pref: Some(200),
                ..RouteModifications::default()
            },
        }],
        default_action: PolicyAction::Deny,
    };
    let r = evaluate_policy(
        Some(&pl),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.set_local_pref, Some(200));
}
// -----------------------------------------------------------------------
// apply_modifications
// -----------------------------------------------------------------------
use rustbgpd_wire::{AsPath, AsPathSegment, PathAttribute};

#[test]
fn apply_set_local_pref_absent() {
    let mut attrs = vec![PathAttribute::Origin(rustbgpd_wire::Origin::Igp)];
    let mods = RouteModifications {
        set_local_pref: Some(200),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(200)))
    );
}

#[test]
fn apply_set_local_pref_present() {
    let mut attrs = vec![PathAttribute::LocalPref(100)];
    let mods = RouteModifications {
        set_local_pref: Some(200),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    assert_eq!(
        attrs
            .iter()
            .filter(|a| matches!(a, PathAttribute::LocalPref(_)))
            .count(),
        1
    );
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(200)))
    );
}

#[test]
fn apply_set_med() {
    let mut attrs = vec![];
    let mods = RouteModifications {
        set_med: Some(50),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    assert!(attrs.iter().any(|a| matches!(a, PathAttribute::Med(50))));
}

#[test]
fn apply_community_add_remove() {
    let c1 = (65001u32 << 16) | 0x0064;
    let c2 = (65001u32 << 16) | 0x00C8;
    let mut attrs = vec![PathAttribute::Communities(vec![c1])];
    let mods = RouteModifications {
        communities_add: vec![c2],
        communities_remove: vec![c1],
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let comms = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::Communities(c) => Some(c),
            _ => None,
        })
        .unwrap();
    assert!(!comms.contains(&c1));
    assert!(comms.contains(&c2));
}

#[test]
fn apply_community_add_remove_preserves_order_and_legacy_attr_position() {
    let c1 = (65001u32 << 16) | 0x0064;
    let c2 = (65001u32 << 16) | 0x00C8;
    let c3 = (65001u32 << 16) | 0x012C;
    let mut attrs = vec![
        PathAttribute::Communities(vec![c1, c2]),
        PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
    ];
    let mods = RouteModifications {
        communities_add: vec![c2, c3, c3],
        communities_remove: vec![c1],
        ..Default::default()
    };

    apply_modifications(&mut attrs, &mods);

    assert!(matches!(
        attrs.as_slice(),
        [
            PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
            PathAttribute::Communities(_)
        ]
    ));
    let comms = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::Communities(c) => Some(c),
            _ => None,
        })
        .unwrap();
    assert_eq!(comms, &[c2, c3]);
}

#[test]
fn merge_exact_community_lists_preserves_later_wins_order() {
    let c1 = (65001u32 << 16) | 0x0064;
    let c2 = (65001u32 << 16) | 0x00C8;
    let c3 = (65001u32 << 16) | 0x012C;
    let c4 = (65001u32 << 16) | 0x0190;
    let c5 = (65001u32 << 16) | 0x01F4;
    let mut merged = RouteModifications {
        communities_add: vec![c1, c2],
        communities_remove: vec![c3],
        ..Default::default()
    };
    merged.merge_from(RouteModifications {
        communities_add: vec![c3, c4, c4],
        communities_remove: vec![c2, c5],
        ..Default::default()
    });

    assert_eq!(merged.communities_add, vec![c1, c3, c4, c4]);
    assert_eq!(merged.communities_remove, vec![c2, c5]);
}

#[test]
fn merge_exact_large_community_lists_preserves_later_wins_order() {
    let lc1 = LargeCommunity::new(65001, 1, 100);
    let lc2 = LargeCommunity::new(65001, 1, 200);
    let lc3 = LargeCommunity::new(65001, 1, 300);
    let lc4 = LargeCommunity::new(65001, 1, 400);
    let lc5 = LargeCommunity::new(65001, 1, 500);
    let mut merged = RouteModifications {
        large_communities_add: vec![lc1, lc2],
        large_communities_remove: vec![lc3],
        ..Default::default()
    };
    merged.merge_from(RouteModifications {
        large_communities_add: vec![lc3, lc4, lc4],
        large_communities_remove: vec![lc2, lc5],
        ..Default::default()
    });

    assert_eq!(merged.large_communities_add, vec![lc1, lc3, lc4, lc4]);
    assert_eq!(merged.large_communities_remove, vec![lc2, lc5]);
}

#[test]
fn merge_exact_community_lists_set_path_preserves_later_wins_order() {
    // Drive merge_from with >4-element add/remove lists on both sides so the
    // adaptive set-backed conflict check (use_exact_list_set: each len > 4 and
    // product > 32) runs instead of the small-input linear scan. The output
    // must be byte-identical to the linear path: retain_without keeps surviving
    // items in original order, a later add cancels an earlier remove (and vice
    // versa), and the trailing un-deduped extend is preserved.
    let c = |n: u16| (65001u32 << 16) | u32::from(n);
    let mut merged = RouteModifications {
        communities_add: vec![c(1), c(2), c(3), c(4), c(5), c(6)],
        communities_remove: vec![c(20), c(21), c(22), c(10), c(11), c(12)],
        ..Default::default()
    };
    merged.merge_from(RouteModifications {
        communities_add: vec![c(10), c(11), c(12), c(13), c(14), c(15)],
        communities_remove: vec![c(2), c(4), c(6), c(7), c(8), c(9)],
        ..Default::default()
    });

    // add = retain_without([1..=6], new_remove=[2,4,6,7,8,9]) ++ new_add
    assert_eq!(
        merged.communities_add,
        vec![c(1), c(3), c(5), c(10), c(11), c(12), c(13), c(14), c(15)]
    );
    // remove = retain_without([20,21,22,10,11,12], new_add=[10..=15]) ++ new_remove;
    // the later add of c(10..12) cancels their earlier removal (later-wins).
    assert_eq!(
        merged.communities_remove,
        vec![c(20), c(21), c(22), c(2), c(4), c(6), c(7), c(8), c(9)]
    );
}

#[test]
fn apply_extended_community_remove_matches_semantic_equivalent() {
    let mut attrs = vec![PathAttribute::ExtendedCommunities(vec![make_rt_as4(
        65001, 100,
    )])];
    let mods = RouteModifications {
        extended_communities_remove: vec![make_rt(65001, 100)],
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    assert!(
        !attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
    );
}

#[test]
fn apply_extended_community_add_avoids_semantic_duplicate() {
    let existing = make_rt_as4(65001, 100);
    let mut attrs = vec![PathAttribute::ExtendedCommunities(vec![existing])];
    let mods = RouteModifications {
        extended_communities_add: vec![make_rt(65001, 100)],
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let ecs = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(c) => Some(c),
            _ => None,
        })
        .unwrap();
    assert_eq!(ecs, &[existing]);
}

#[test]
fn apply_large_community_add_remove() {
    let lc1 = LargeCommunity::new(65001, 100, 200);
    let lc2 = LargeCommunity::new(65001, 300, 400);
    let mut attrs = vec![PathAttribute::LargeCommunities(vec![lc1])];
    let mods = RouteModifications {
        large_communities_add: vec![lc2],
        large_communities_remove: vec![lc1],
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let lcs = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::LargeCommunities(c) => Some(c),
            _ => None,
        })
        .unwrap();
    assert!(!lcs.contains(&lc1));
    assert!(lcs.contains(&lc2));
}

#[test]
fn apply_as_path_prepend_existing() {
    let mut attrs = vec![PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
    })];
    let mods = RouteModifications {
        as_path_prepend: Some((65001, 2)),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    match &path.segments[0] {
        AsPathSegment::AsSequence(seq) => {
            assert_eq!(seq, &[65001, 65001, 65002, 65003]);
        }
        AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
    }
}

#[test]
fn apply_as_path_prepend_empty() {
    let mut attrs = vec![];
    let mods = RouteModifications {
        as_path_prepend: Some((65001, 3)),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    match &path.segments[0] {
        AsPathSegment::AsSequence(seq) => {
            assert_eq!(seq, &[65001, 65001, 65001]);
        }
        AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
    }
}

#[test]
fn apply_as_path_prepend_avoids_first_segment_overflow() {
    let long_seq: Vec<u32> = (0..250).map(|i| 65002 + i).collect();
    let mut attrs = vec![PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(long_seq.clone())],
    })];
    let mods = RouteModifications {
        as_path_prepend: Some((65001, 10)),
        ..Default::default()
    };
    apply_modifications(&mut attrs, &mods);
    let path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(path.segments.len(), 2);
    match &path.segments[0] {
        AsPathSegment::AsSequence(seq) => {
            assert_eq!(seq.len(), 10);
            assert!(seq.iter().all(|asn| *asn == 65001));
        }
        AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
    }
    match &path.segments[1] {
        AsPathSegment::AsSequence(seq) => assert_eq!(seq, &long_seq),
        AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
    }
}

#[test]
fn apply_next_hop_self() {
    let mut attrs = vec![];
    let mods = RouteModifications {
        set_next_hop: Some(NextHopAction::Self_),
        ..Default::default()
    };
    let nh = apply_modifications(&mut attrs, &mods);
    assert_eq!(nh, Some(NextHopAction::Self_));
}

#[test]
fn apply_noop_default() {
    let orig = vec![PathAttribute::Origin(rustbgpd_wire::Origin::Igp)];
    let mut attrs = orig.clone();
    let mods = RouteModifications::default();
    let nh = apply_modifications(&mut attrs, &mods);
    assert!(nh.is_none());
    assert_eq!(attrs, orig);
}
