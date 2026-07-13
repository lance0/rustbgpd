use super::*;

#[test]
fn warm_checkpoint_identity_is_deterministic_and_semantic() {
    let permit = PolicyChain::new(vec![Policy {
        entries: vec![stmt(
            Some(v4_prefix([203, 0, 113, 0], 24)),
            PolicyAction::Permit,
            vec![],
        )],
        default_action: PolicyAction::Deny,
    }]);
    let same = permit.clone();
    let deny = PolicyChain::new(vec![Policy {
        entries: vec![stmt(
            Some(v4_prefix([203, 0, 113, 0], 24)),
            PolicyAction::Deny,
            vec![],
        )],
        default_action: PolicyAction::Deny,
    }]);

    assert_eq!(
        permit.warm_checkpoint_identity_v1().unwrap(),
        same.warm_checkpoint_identity_v1().unwrap()
    );
    assert_ne!(
        permit.warm_checkpoint_identity_v1().unwrap(),
        deny.warm_checkpoint_identity_v1().unwrap()
    );
}

#[test]
fn warm_checkpoint_identity_rejects_validation_dependent_policy() {
    let mut validation_statement = stmt(None, PolicyAction::Permit, vec![]);
    validation_statement.match_rpki_validation = Some(RpkiValidation::Valid);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![validation_statement],
        default_action: PolicyAction::Deny,
    }]);

    let error = chain.warm_checkpoint_identity_v1().unwrap_err();
    assert!(error.contains("RPKI or ASPA"), "{error}");
}
