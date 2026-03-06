use super::*;

// -----------------------------------------------------------------------
// RouteModifications::merge_from
// -----------------------------------------------------------------------

#[test]
fn merge_from_scalar_later_wins() {
    let mut base = RouteModifications {
        set_local_pref: Some(100),
        set_med: Some(50),
        ..Default::default()
    };
    let other = RouteModifications {
        set_local_pref: Some(200),
        // set_med: None — should not overwrite
        ..Default::default()
    };
    base.merge_from(other);
    assert_eq!(base.set_local_pref, Some(200));
    assert_eq!(base.set_med, Some(50));
}

#[test]
fn merge_from_lists_accumulate() {
    let mut base = RouteModifications {
        communities_add: vec![100],
        ..Default::default()
    };
    let other = RouteModifications {
        communities_add: vec![200],
        communities_remove: vec![300],
        ..Default::default()
    };
    base.merge_from(other);
    assert_eq!(base.communities_add, vec![100, 200]);
    assert_eq!(base.communities_remove, vec![300]);
}

#[test]
fn merge_from_later_remove_cancels_earlier_add() {
    let mut base = RouteModifications {
        communities_add: vec![100],
        ..Default::default()
    };
    let other = RouteModifications {
        communities_remove: vec![100],
        ..Default::default()
    };
    base.merge_from(other);
    assert!(base.communities_add.is_empty());
    assert_eq!(base.communities_remove, vec![100]);
}

#[test]
fn merge_from_later_add_cancels_earlier_remove() {
    let mut base = RouteModifications {
        communities_remove: vec![100],
        ..Default::default()
    };
    let other = RouteModifications {
        communities_add: vec![100],
        ..Default::default()
    };
    base.merge_from(other);
    assert_eq!(base.communities_add, vec![100]);
    assert!(base.communities_remove.is_empty());
}

#[test]
fn chain_later_remove_overrides_earlier_add() {
    let p1 = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            modifications: RouteModifications {
                communities_add: vec![100],
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    let p2 = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            modifications: RouteModifications {
                communities_remove: vec![100],
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    let chain = PolicyChain::new(vec![p1, p2]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Permit);
    assert!(r.modifications.communities_add.is_empty());
    assert_eq!(r.modifications.communities_remove, vec![100]);
}

// -----------------------------------------------------------------------
// PolicyChain
// -----------------------------------------------------------------------

fn make_permit_policy_with_lp(lp: u32) -> Policy {
    Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            modifications: RouteModifications {
                set_local_pref: Some(lp),
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    }
}

fn make_deny_all_policy() -> Policy {
    Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }
}

fn eval_chain(chain: &PolicyChain) -> PolicyResult {
    evaluate_chain(
        Some(chain),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    )
}

#[test]
fn chain_empty_permits() {
    let chain = PolicyChain::new(vec![]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Permit);
    assert!(r.modifications.set_local_pref.is_none());
}

#[test]
fn chain_single_permit_passes_mods() {
    let chain = PolicyChain::new(vec![make_permit_policy_with_lp(150)]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.set_local_pref, Some(150));
}

#[test]
fn chain_single_deny_stops() {
    let chain = PolicyChain::new(vec![make_deny_all_policy()]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Deny);
}

#[test]
fn chain_permit_then_deny_stops() {
    let chain = PolicyChain::new(vec![
        make_permit_policy_with_lp(150),
        make_deny_all_policy(),
    ]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Deny);
}

#[test]
fn chain_two_permits_accumulate_communities() {
    let p1 = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            modifications: RouteModifications {
                communities_add: vec![100],
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    let p2 = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            modifications: RouteModifications {
                communities_add: vec![200],
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    let chain = PolicyChain::new(vec![p1, p2]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.communities_add, vec![100, 200]);
}

#[test]
fn chain_later_lp_wins() {
    let chain = PolicyChain::new(vec![
        make_permit_policy_with_lp(100),
        make_permit_policy_with_lp(200),
    ]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.set_local_pref, Some(200));
}

#[test]
fn chain_default_deny_stops_chain() {
    // First policy: default_action=deny, no matching entries
    let deny_policy = make_deny_all_policy();
    let permit_policy = make_permit_policy_with_lp(100);
    let chain = PolicyChain::new(vec![deny_policy, permit_policy]);
    let r = eval_chain(&chain);
    assert_eq!(r.action, PolicyAction::Deny);
}

#[test]
fn evaluate_chain_none_returns_permit() {
    let r = evaluate_chain(
        None,
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.action, PolicyAction::Permit);
}
