use super::*;

/// ADR-0119 pre-activation matrix. Removing either raw `Option`, collapsing
/// omission into false before posture derivation, or changing any accepted
/// epoch/value cell makes at least one exact tuple red.
#[test]
fn rfc8212_epoch_and_policy_presence_matrix_is_lossless_without_flipping_default() {
    for (epoch, epoch_raw, epoch_effective, epoch_source) in [
        (None, None, ConfigEpoch::V1, ConfigEpochSource::Omitted),
        (
            Some("1"),
            Some(ConfigEpoch::V1),
            ConfigEpoch::V1,
            ConfigEpochSource::Explicit,
        ),
        (
            Some("2"),
            Some(ConfigEpoch::V2),
            ConfigEpoch::V2,
            ConfigEpochSource::Explicit,
        ),
    ] {
        for (raw, effective, source) in [
            (Some(false), false, Rfc8212PolicySource::ExplicitFalse),
            (Some(true), true, Rfc8212PolicySource::ExplicitTrue),
        ] {
            let config = parse(&rfc8212_representation_toml(epoch, raw)).unwrap();
            let posture = config.rfc8212_posture();
            assert_eq!(posture.config_epoch_raw, epoch_raw);
            assert_eq!(posture.config_epoch_effective, epoch_effective);
            assert_eq!(posture.config_epoch_source, epoch_source);
            assert_eq!(posture.policy_raw, raw);
            assert_eq!(posture.policy_effective, effective);
            assert_eq!(posture.policy_source, source);
            assert!(!posture.requires_explicit_policy);
        }
    }

    for epoch in [None, Some("1")] {
        let posture = parse(&rfc8212_representation_toml(epoch, None))
            .unwrap()
            .rfc8212_posture();
        assert_eq!(posture.policy_raw, None);
        assert!(!posture.policy_effective);
        assert_eq!(posture.policy_source, Rfc8212PolicySource::LegacyOmission);
    }
}

#[test]
fn rfc8212_epoch_two_omission_and_invalid_epochs_fail_closed() {
    const EXACT: &str = "config_epoch = 2 requires [global].ebgp_requires_policy = true or [global].ebgp_requires_policy = false: the RFC 8212 secure default is not activated yet (ADR-0119 gates activation on its production-mutation proofs), so epoch 2 does not infer the omitted value. This is a pending activation, not a misconfiguration; add one explicit assignment";
    let source = rfc8212_representation_toml(Some("2"), None);
    assert_eq!(parse(&source).unwrap_err().to_string(), EXACT);
    let schema_only = parse_schema_only(&source).unwrap();
    assert!(schema_only.rfc8212_posture().requires_explicit_policy);
    assert_eq!(
        persisted_config_document(&schema_only)
            .unwrap_err()
            .to_string(),
        EXACT
    );

    for invalid in ["0", "-1", "3", "1.5", "\"2\""] {
        let error = parse(&rfc8212_representation_toml(Some(invalid), Some(false)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("config_epoch"), "{invalid}: {error}");
    }
}

/// ADR-0112 restart pinning. Changing only `[global] ebgp_requires_policy` must
/// classify as restart-required, name the *field* (not just `[global]`) in the
/// human diff and in the v1 transaction rejection, and leave the running
/// snapshot on its startup value after a SIGHUP-time pin. Hot-applying it would
/// flip import and export on every EBGP session inside a reload.
#[test]
fn ebgp_requires_policy_diff_is_restart_required_named_and_pinned() {
    let old = parse(valid_toml()).unwrap();
    let new = parse(&ebgp_requires_policy_toml()).unwrap();

    let diff = super::diff_config(&old, &new);
    assert!(diff.ebgp_requires_policy_changed);
    assert!(diff.global_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an enforcement-mode-only edit must not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["restart_required"]["ebgp_requires_policy_changed"],
        true
    );
    assert_eq!(
        json["ebgp_requires_policy"]["before"]["raw"],
        serde_json::Value::Null
    );
    assert_eq!(json["ebgp_requires_policy"]["after"]["raw"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[global].ebgp_requires_policy"), "{text}");

    let class = super::classify_config_transaction_v1(&diff);
    assert!(!class.is_committable());
    assert!(
        class
            .restart_required_sections
            .contains(&"[global].ebgp_requires_policy".to_string()),
        "the v1 transaction receipt must name the enforcement mode: {class:?}"
    );

    // SIGHUP pins the running value back to the live snapshot.
    let mut runtime = new.clone();
    assert!(super::pin_rfc8212_posture_startup_only(&mut runtime, &old));
    assert!(
        !runtime.rfc8212_posture().policy_effective,
        "the running enforcement mode stays at the startup value until restart"
    );
    let repinned = super::diff_config(&old, &runtime);
    assert!(!repinned.ebgp_requires_policy_changed);
    assert!(!repinned.global_changed);

    // Idempotent: nothing to pin once the candidate already matches.
    assert!(!super::pin_rfc8212_posture_startup_only(&mut runtime, &old));

    // Disabling an enabled mode is pinned the same way.
    let mut downgrade = old.clone();
    assert!(super::pin_rfc8212_posture_startup_only(
        &mut downgrade,
        &new
    ));
    assert!(downgrade.rfc8212_posture().policy_effective);
}

/// Representation-only changes are still restart-required and survive both
/// text/JSON rendering. Pinning must restore the complete raw tuple, not just
/// its equal effective false value.
#[test]
fn rfc8212_representation_only_diff_and_pin_cover_the_complete_raw_tuple() {
    let old = parse(valid_toml()).unwrap();
    let explicit = parse(&rfc8212_representation_toml(Some("1"), Some(false))).unwrap();
    let diff = super::diff_config(&old, &explicit);
    assert!(diff.config_epoch_changed);
    assert!(diff.ebgp_requires_policy_changed);
    assert!(diff.has_restart_required_changes());
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["config_epoch"]["before"]["raw"],
        serde_json::Value::Null
    );
    assert_eq!(json["config_epoch"]["after"]["raw"], 1);
    assert_eq!(json["ebgp_requires_policy"]["before"]["effective"], false);
    assert_eq!(json["ebgp_requires_policy"]["after"]["effective"], false);
    let text = super::format_config_diff(&diff);
    assert!(text.contains("config_epoch: raw=<omitted> effective=1 source=omitted -> raw=1 effective=1 source=explicit"), "{text}");
    assert!(text.contains("[global].ebgp_requires_policy: raw=<omitted> effective=false source=legacy_omission -> raw=false effective=false source=explicit_false"), "{text}");

    let class = super::classify_config_transaction_v1(&diff);
    assert!(
        class
            .restart_required_sections
            .contains(&"config_epoch".to_string())
    );
    assert!(
        class
            .restart_required_sections
            .contains(&"[global].ebgp_requires_policy".to_string())
    );

    let mut running = explicit;
    assert!(super::pin_rfc8212_posture_startup_only(&mut running, &old));
    assert_eq!(running.rfc8212_posture(), old.rfc8212_posture());
    assert!(!super::diff_config(&old, &running).has_any_changes());
}

/// The raw RFC 8212 fields must remain optional in input without advertising
/// JSON `null` as a valid TOML value. Reverting `schemars(with = ...)` exposes
/// nullable `Option` schemas; dropping either explicit default makes this red.
#[test]
fn rfc8212_schema_preserves_optional_non_null_defaults() {
    let schema: serde_json::Value = serde_json::from_str(&config_json_schema()).unwrap();
    let epoch = &schema["properties"]["config_epoch"];
    let policy = &schema["$defs"]["Global"]["properties"]["ebgp_requires_policy"];
    assert!(
        !schema["required"]
            .as_array()
            .unwrap()
            .contains(&"config_epoch".into())
    );
    assert!(
        !schema["$defs"]["Global"]["required"]
            .as_array()
            .is_some_and(|required| required.contains(&"ebgp_requires_policy".into()))
    );
    assert_eq!(epoch["default"], 1);
    assert_eq!(policy["type"], "boolean");
    assert_eq!(policy["default"], false);
    assert!(!epoch.to_string().contains("null"), "{epoch}");
    assert!(!policy.to_string().contains("null"), "{policy}");
    assert_eq!(
        schema["$defs"]["ConfigEpoch"]["enum"],
        serde_json::json!([1, 2])
    );
}

/// Disabled compatibility. With the knob off, an EBGP peer with no operator
/// policy still resolves permit-all in both directions — including when the
/// implicit RFC 8326 / RFC 7999 tails are the only thing in the chain.
/// Dropping the `ebgp_requires_policy` gate on the substitution makes this red.
#[test]
fn rfc8212_disabled_keeps_unconfigured_ebgp_permit_all() {
    let bare = rfc8212_resolve(&rfc8212_toml("", "", 65002, ""));
    assert!(
        bare.import.is_none() && bare.export.is_none(),
        "knob off must leave both directions at the permit-all default"
    );
    assert!(!bare.import_explicit && !bare.export_explicit);
    assert!(bare.external, "classification is independent of the knob");

    let with_tails = rfc8212_resolve(&rfc8212_toml(
        "honor_graceful_shutdown = true\nhonor_blackhole = true",
        "",
        65002,
        "",
    ));
    let import = with_tails
        .import
        .as_ref()
        .expect("the honor knobs still build their implicit chain");
    assert_eq!(
        import.policies.len(),
        2,
        "knob off must leave the GShut + BLACKHOLE tails exactly as they were"
    );
    assert!(import.policies.iter().all(|member| member.name.is_none()));
    assert!(with_tails.export.is_none());
}

/// Directional fail-closed: the two directions are independent, and only the
/// one without explicit operator policy gets the reserved deny. Substituting
/// `None` for the reserved chain makes the matching assertion red.
#[test]
fn rfc8212_denies_only_the_direction_without_explicit_policy() {
    let policy_block = "\n[policy.definitions.permit-all]\ndefault_action = \"permit\"\n";

    let export_only = rfc8212_resolve(&rfc8212_toml(
        "ebgp_requires_policy = true",
        policy_block,
        65002,
        "export_policy_chain = [\"permit-all\"]",
    ));
    assert!(!export_only.import_explicit && export_only.export_explicit);
    assert_reserved_deny(
        export_only.import.as_ref(),
        super::RFC8212_MISSING_IMPORT_POLICY,
    );
    assert_eq!(
        export_only
            .export
            .as_ref()
            .expect("explicit export chain survives untouched")
            .policies
            .iter()
            .map(|member| member.name.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("permit-all")]
    );

    let import_only = rfc8212_resolve(&rfc8212_toml(
        "ebgp_requires_policy = true",
        policy_block,
        65002,
        "import_policy_chain = [\"permit-all\"]",
    ));
    assert!(import_only.import_explicit && !import_only.export_explicit);
    assert_not_reserved_deny(import_only.import.as_ref());
    assert_reserved_deny(
        import_only.export.as_ref(),
        super::RFC8212_MISSING_EXPORT_POLICY,
    );
}

/// The reserved deny actually denies, through the ordinary compiled chain
/// path — so `evaluate_chain(None, ..)` permit-all semantics stay untouched
/// for every session the knob does not govern.
#[test]
fn rfc8212_reserved_deny_denies_every_route() {
    let resolved = rfc8212_resolve(&rfc8212_toml("ebgp_requires_policy = true", "", 65002, ""));
    let ctx = route_server_test_context(
        route_server_test_prefix("192.0.2.0/24"),
        rustbgpd_wire::RpkiValidation::NotFound,
        rustbgpd_wire::AspaValidation::Unknown,
    );
    for chain in [resolved.import.as_ref(), resolved.export.as_ref()] {
        assert_eq!(
            rustbgpd_policy::evaluate_chain(chain, &ctx).action,
            PolicyAction::Deny,
            "a governed direction with no operator policy must deny"
        );
    }
    assert_eq!(
        rustbgpd_policy::evaluate_chain(None, &ctx).action,
        PolicyAction::Permit,
        "the process-wide `None` contract must not move"
    );
}

/// Provenance is decided before the implicit tails. Enabling the honor knobs
/// with no operator import policy leaves the import direction unsatisfied and
/// installs the reserved deny in place of the tails; counting an appended tail
/// as operator provenance makes this red.
#[test]
fn rfc8212_implicit_tails_are_not_explicit_policy() {
    let resolved = rfc8212_resolve(&rfc8212_toml(
        "ebgp_requires_policy = true\nhonor_graceful_shutdown = true\nhonor_blackhole = true",
        "",
        65002,
        "",
    ));
    assert!(
        !resolved.import_explicit,
        "a daemon-owned tail is not an operator import relationship"
    );
    assert_reserved_deny(
        resolved.import.as_ref(),
        super::RFC8212_MISSING_IMPORT_POLICY,
    );
}

/// ADR-0112 requires the reserved deny to be a chain no configured name can
/// reference or shadow. Enforcement never depended on that — the chain is
/// built directly — but the *reporting* surfaces do: neighbor status compares
/// the installed chain against the reserved deny, and import/export explain
/// attribute a rejection by the deciding member's name. Allowing an operator
/// policy to take either name would make both ambiguous, so both are refused
/// at load in the one namespace TOML and `.rpol` policies share.
#[test]
fn rfc8212_reserved_chain_names_are_refused_to_operator_policies() {
    for reserved in [
        super::RFC8212_MISSING_IMPORT_POLICY,
        super::RFC8212_MISSING_EXPORT_POLICY,
    ] {
        let err = parse(&rfc8212_toml(
            "",
            &format!("\n[policy.definitions.{reserved}]\ndefault_action = \"permit\"\n"),
            65002,
            "",
        ))
        .expect_err("a reserved RFC 8212 chain name must not load");
        let rendered = err.to_string();
        assert!(
            rendered.contains(reserved) && rendered.contains("reserved"),
            "the error must name the offending policy: {rendered}"
        );
    }
}

/// The identity test behind the status surface: only the chain the daemon
/// builds compares equal to it. An operator deny-all is deliberate policy and
/// must not read as the reserved deny, and neither direction's reserved chain
/// answers for the other. Comparing on shape (empty entries plus a deny
/// default) instead of the whole chain makes the deny-all case red.
#[test]
fn rfc8212_reserved_deny_identity_matches_only_the_reserved_chain() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain};

    let import = super::reserved_rfc8212_deny_chain(super::RFC8212_MISSING_IMPORT_POLICY);
    let export = super::reserved_rfc8212_deny_chain(super::RFC8212_MISSING_EXPORT_POLICY);
    let operator_deny_all = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    assert!(super::is_reserved_rfc8212_deny(
        Some(&import),
        super::RFC8212_MISSING_IMPORT_POLICY
    ));
    assert!(super::is_reserved_rfc8212_deny(
        Some(&export),
        super::RFC8212_MISSING_EXPORT_POLICY
    ));
    assert!(!super::is_reserved_rfc8212_deny(
        Some(&export),
        super::RFC8212_MISSING_IMPORT_POLICY
    ));
    assert!(!super::is_reserved_rfc8212_deny(
        Some(&operator_deny_all),
        super::RFC8212_MISSING_IMPORT_POLICY
    ));
    assert!(!super::is_reserved_rfc8212_deny(
        None,
        super::RFC8212_MISSING_IMPORT_POLICY
    ));
}

/// Every inheritance level the ADR counts as explicit satisfies the
/// requirement, including chains whose configured result is permit-all.
#[test]
fn rfc8212_counts_each_explicit_provenance_source() {
    let named = "\n[policy.definitions.permit-all]\ndefault_action = \"permit\"\n";
    let cases: [(&str, String, &str); 5] = [
        (
            "global named",
            format!(
                "{named}\n[policy]\nimport_chain = [\"permit-all\"]\nexport_chain = [\"permit-all\"]\n"
            ),
            "",
        ),
        (
            "peer-group named",
            format!(
                "{named}\n[peer_groups.edge]\nimport_policy_chain = [\"permit-all\"]\nexport_policy_chain = [\"permit-all\"]\n"
            ),
            "peer_group = \"edge\"",
        ),
        (
            "peer-group inline",
            "\n[[peer_groups.edge.import_policy]]\naction = \"permit\"\nprefix = \"0.0.0.0/0\"\nle = 32\n\n[[peer_groups.edge.export_policy]]\naction = \"permit\"\nprefix = \"0.0.0.0/0\"\nle = 32\n".to_string(),
            "peer_group = \"edge\"",
        ),
        (
            "neighbor named",
            named.to_string(),
            "import_policy_chain = [\"permit-all\"]\nexport_policy_chain = [\"permit-all\"]",
        ),
        (
            "neighbor inline",
            String::new(),
            "import_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\", le = 32 }]\nexport_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\", le = 32 }]",
        ),
    ];
    for (label, policy_block, neighbor_extra) in cases {
        let resolved = rfc8212_resolve(&rfc8212_toml(
            "ebgp_requires_policy = true",
            &policy_block,
            65002,
            neighbor_extra,
        ));
        assert!(
            resolved.import_explicit && resolved.export_explicit,
            "{label} policy must satisfy RFC 8212 in both directions"
        );
        assert_not_reserved_deny(resolved.import.as_ref());
        assert_not_reserved_deny(resolved.export.as_ref());
    }
}

/// An iBGP session is not applicable and keeps its current behavior.
#[test]
fn rfc8212_leaves_ibgp_untouched() {
    let resolved = rfc8212_resolve(&rfc8212_toml("ebgp_requires_policy = true", "", 65001, ""));
    assert!(!resolved.external, "remote_asn == global.asn is iBGP");
    assert!(
        resolved.import.is_none() && resolved.export.is_none(),
        "an iBGP session keeps permit-all"
    );
}

/// Accept-any dynamic range. It is external for the whole accepted session:
/// before OPEN, where the sentinel is still the record's ASN, and after, where
/// the pin is the only thing keeping the classification from following a
/// learned ASN that happens to equal the local one. Reading the sentinel as an
/// ordinary ASN, or dropping the pin, makes this red.
#[test]
fn rfc8212_classifies_accept_any_dynamic_range_as_external() {
    let toml_str = rfc8212_toml(
        "ebgp_requires_policy = true",
        "\n[peer_groups.ix]\nfamilies = [\"ipv4_unicast\"]\n\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"ix\"\nremote_asn = 0\n",
        65002,
        "",
    );
    let cfg = parse(&toml_str).expect("dynamic fixture parses");
    let group = &cfg.peer_groups["ix"];
    let addr: IpAddr = "192.0.2.7".parse().unwrap();

    // Accept time: the range's own sentinel is the classification input.
    let accepted = cfg
        .resolve_dynamic_neighbor(addr, 0, "ix-auto", group, "ix", false)
        .expect("accept-time resolution");
    assert!(accepted.rfc8212_external);
    assert_reserved_deny(
        accepted.import_policy.as_ref(),
        super::RFC8212_MISSING_IMPORT_POLICY,
    );
    assert_reserved_deny(
        accepted.export_policy.as_ref(),
        super::RFC8212_MISSING_EXPORT_POLICY,
    );

    // After OPEN the peer manager replaces the sentinel with the learned ASN.
    // Worst case that ASN is the local one, and only the pin keeps enforcement.
    let relearned = cfg
        .resolve_dynamic_neighbor(addr, 65001, "ix-auto", group, "ix", true)
        .expect("pinned re-resolution");
    assert!(relearned.rfc8212_external);
    assert_reserved_deny(
        relearned.import_policy.as_ref(),
        super::RFC8212_MISSING_IMPORT_POLICY,
    );

    // Control: without the pin the same input classifies as iBGP, which is
    // exactly the fail-open the pin exists to prevent.
    let unpinned = cfg
        .resolve_dynamic_neighbor(addr, 65001, "ix-auto", group, "ix", false)
        .expect("unpinned re-resolution");
    assert!(!unpinned.rfc8212_external);
    assert!(unpinned.import_policy.is_none());
}

/// A governed static neighbor carries the reserved deny out of
/// `resolved_neighbors()` — the roster the daemon hands to `AddPeer` before
/// any session starts — so registration ordering cannot expose a permit-all
/// window on a governed peer.
#[test]
fn rfc8212_resolved_neighbors_carry_the_deny_before_peers_start() {
    let cfg = parse(&rfc8212_toml("ebgp_requires_policy = true", "", 65002, "")).unwrap();
    let resolved = cfg.resolved_neighbors().expect("startup roster resolves");
    let peer = resolved.first().expect("one neighbor");
    assert!(peer.rfc8212_external);
    assert_reserved_deny(
        peer.import_policy.as_ref(),
        super::RFC8212_MISSING_IMPORT_POLICY,
    );
    assert_reserved_deny(
        peer.export_policy.as_ref(),
        super::RFC8212_MISSING_EXPORT_POLICY,
    );
}

/// What `rustbgpd --check` warns on. The query is independent of
/// `ebgp_requires_policy`: the knob decides whether an unpoliced direction is
/// permit-all or reserved-deny, not whether it is worth reporting.
#[test]
fn unpoliced_ebgp_neighbors_names_the_missing_directions() {
    let unpoliced = |toml_str: &str| {
        parse(toml_str)
            .expect("fixture parses")
            .unpoliced_ebgp_neighbors()
    };
    let permit_all = "\n[policy.definitions.permit-all]\ndefault_action = \"permit\"\n";

    let both = unpoliced(&rfc8212_toml("", "", 65002, ""));
    assert_eq!(both.len(), 1);
    assert_eq!(both[0].address, "10.0.0.2");
    assert_eq!(both[0].remote_asn, 65002);
    assert_eq!(
        both[0].missing_phrase(),
        "no import policy and no export policy"
    );

    // Enforcement on changes the consequence, not the finding.
    assert_eq!(
        unpoliced(&rfc8212_toml("ebgp_requires_policy = true", "", 65002, "")),
        both
    );

    // One direction covered: only the other is reported.
    let import_only = unpoliced(&rfc8212_toml(
        "",
        permit_all,
        65002,
        "import_policy_chain = [\"permit-all\"]",
    ));
    assert_eq!(import_only.len(), 1);
    assert!(!import_only[0].import_missing);
    assert_eq!(import_only[0].missing_phrase(), "no export policy");

    // Fully policed eBGP, and iBGP at any policy state, are silent.
    assert!(
        unpoliced(&rfc8212_toml(
            "",
            permit_all,
            65002,
            "import_policy_chain = [\"permit-all\"]\nexport_policy_chain = [\"permit-all\"]",
        ))
        .is_empty()
    );
    assert!(unpoliced(&rfc8212_toml("", "", 65001, "")).is_empty());
}

#[test]
fn unpoliced_ebgp_boundaries_include_dynamic_ranges() {
    let unpoliced = |toml: &str| parse(toml).unwrap().unpoliced_ebgp_boundaries();
    let dynamic = |global: &str, static_asn, range_asn, group: &str| {
        format!(
            "{}\n[peer_groups.ix]\n{group}\n[[dynamic_neighbors]]\n\
             prefix = \"192.0.2.0/24\"\npeer_group = \"ix\"\nremote_asn = {range_asn}\n",
            rfc8212_toml(global, "", static_asn, "")
        )
    };
    let wildcard = unpoliced(&dynamic("", 65001, 0, ""));
    assert!(wildcard[0].identity_phrase().ends_with("(any AS)"));
    assert_eq!(
        unpoliced(&dynamic("ebgp_requires_policy = true", 65001, 0, "")),
        wildcard
    );
    let fixed = unpoliced(&dynamic("", 65001, 65002, ""));
    assert!(fixed[0].identity_phrase().ends_with("(AS 65002)"));
    assert!(unpoliced(&dynamic("", 65001, 65001, "")).is_empty());
    let import = "import_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\", le = 32 }]";
    assert_eq!(
        unpoliced(&dynamic("", 65001, 0, import))[0].missing_phrase(),
        "no export policy"
    );
    let export = "export_policy = [{ action = \"permit\", prefix = \"0.0.0.0/0\" }]";
    let complete = format!("{import}\n{export}");
    assert!(unpoliced(&dynamic("", 65001, 0, &complete)).is_empty());
    let mixed = unpoliced(&dynamic("", 65002, 0, ""));
    assert!(mixed[0].identity_phrase().starts_with("10.0.0.2"));
    assert!(mixed[1].identity_phrase().starts_with("dynamic range"));
}
