//! Golden-file, refusal, abort, and fingerprint coverage for the
//! renderer. The single checked-in fixture carries three clients; the
//! third has a deliberately empty IRR prefix bundle, so the untouched
//! fixture proves the implausible-set abort and every other case is a
//! targeted mutation of the same context.

use rs_config_render::{Options, RenderError, render};

const FIXTURE: &str = include_str!("fixtures/context-small.yml");

/// A verbatim `arouteserver template-context` dump (pinned
/// pierky/arouteserver image, arouteserver 1.23.2) of the M90
/// differential lab's site — the *sectioned report* form.
const SECTIONED: &str =
    include_str!("../../../tests/interop/m90-differential/context-sectioned.yml");
/// The hand-authored single-document context for the same site.
const M90_HAND: &str = include_str!("../../../tests/interop/m90-differential/context.yml");

fn fixture_value() -> serde_yaml::Value {
    serde_yaml::from_str(FIXTURE).expect("fixture parses")
}

/// Set a nested mapping value, creating no intermediate nodes — every
/// path used here exists in the fixture.
fn set_path(root: &mut serde_yaml::Value, path: &[&str], new: serde_yaml::Value) {
    let mut node = root;
    for key in &path[..path.len() - 1] {
        node = node
            .as_mapping_mut()
            .unwrap_or_else(|| panic!("{key}: parent is not a mapping"))
            .get_mut(serde_yaml::Value::String((*key).to_owned()))
            .unwrap_or_else(|| panic!("missing fixture path segment {key}"));
    }
    node.as_mapping_mut()
        .expect("leaf parent is a mapping")
        .insert(
            serde_yaml::Value::String(path[path.len() - 1].to_owned()),
            new,
        );
}

fn to_yaml(value: &serde_yaml::Value) -> String {
    serde_yaml::to_string(value).expect("value serializes")
}

/// The fixture with the deliberately-broken third client removed — the
/// healthy context every non-abort test renders.
fn healthy_value() -> serde_yaml::Value {
    let mut value = fixture_value();
    let clients = value["clients"].as_sequence_mut().expect("clients list");
    clients.retain(|c| c["id"].as_str() != Some("AS51325_1"));
    value["irrdb_info"]
        .as_mapping_mut()
        .expect("irrdb_info mapping")
        .remove(serde_yaml::Value::String("AS51325_bundle".to_owned()));
    value
}

fn rtr_options() -> Options {
    Options {
        rtr_caches: vec!["127.0.0.1:3323".to_owned()],
        ..Options::default()
    }
}

fn refusals(result: Result<rs_config_render::Rendered, RenderError>) -> Vec<String> {
    match result {
        Err(RenderError::Refused(items)) => items,
        Ok(_) => panic!("expected refusal, render succeeded"),
        Err(other) => panic!("expected refusal, got: {other}"),
    }
}

#[test]
fn golden_files_match() {
    let rendered = render(&to_yaml(&healthy_value()), &rtr_options()).expect("healthy render");
    let goldens = [
        ("config.toml", include_str!("golden/config.toml")),
        (
            "policy/rs-hygiene.rpol",
            include_str!("golden/rs-hygiene.rpol"),
        ),
        (
            "policy/client-as4242-1.rpol",
            include_str!("golden/client-as4242-1.rpol"),
        ),
        (
            "policy/client-as197000-1.rpol",
            include_str!("golden/client-as197000-1.rpol"),
        ),
    ];
    assert_eq!(
        rendered.files.len(),
        goldens.len(),
        "unexpected file set: {:?}",
        rendered.files.keys().collect::<Vec<_>>()
    );
    for (path, expected) in goldens {
        let actual = rendered
            .files
            .get(path)
            .unwrap_or_else(|| panic!("missing rendered file {path}"));
        assert_eq!(actual, expected, "golden mismatch for {path}");
    }
    assert!(rendered.warnings.is_empty(), "{:?}", rendered.warnings);
}

#[test]
fn receipt_carries_cardinalities_and_fingerprint() {
    let rendered = render(&to_yaml(&healthy_value()), &rtr_options()).expect("healthy render");
    let receipt = &rendered.receipt;
    assert_eq!(
        receipt["context_fingerprint"],
        rs_config_render::expected_fingerprint()
    );
    let clients = receipt["clients"].as_array().expect("clients array");
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0]["id"], "AS4242_1");
    assert_eq!(clients[0]["prefix_set_size"], 2);
    assert_eq!(clients[0]["origin_set_size"], 2);
    assert_eq!(clients[0]["max_prefixes_ipv4"], 5000);
    assert_eq!(clients[1]["id"], "AS197000_1");
    assert_eq!(clients[1]["prefix_set_size"], 1);
    assert_eq!(clients[1]["max_prefixes_ipv6"], 1000);
    assert!(receipt["rendered_at_utc"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn empty_prefix_set_aborts_the_render() {
    // The untouched fixture: client AS51325_1 resolved zero IRR prefixes.
    match render(FIXTURE, &rtr_options()) {
        Err(RenderError::Implausible(items)) => {
            assert_eq!(items.len(), 1, "{items:?}");
            assert!(items[0].contains("AS51325_1"), "{items:?}");
            assert!(items[0].contains("0 IRR prefix"), "{items:?}");
        }
        other => panic!("expected implausible-set abort, got {other:?}"),
    }
}

#[test]
fn prefix_floor_is_configurable() {
    let opts = Options {
        min_prefixes: 3,
        ..rtr_options()
    };
    match render(&to_yaml(&healthy_value()), &opts) {
        Err(RenderError::Implausible(items)) => {
            // Both healthy clients sit under a floor of 3.
            assert_eq!(items.len(), 2, "{items:?}");
        }
        other => panic!("expected floor abort, got {other:?}"),
    }
}

#[test]
fn shape_drift_is_refused_and_overridable() {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["a_new_upstream_key"],
        serde_yaml::Value::Bool(true),
    );
    let yaml = to_yaml(&value);
    match render(&yaml, &rtr_options()) {
        Err(RenderError::ShapeMismatch {
            missing,
            unexpected,
            expected_fingerprint,
            found_fingerprint,
        }) => {
            assert!(missing.is_empty(), "{missing:?}");
            assert_eq!(unexpected, vec!["a_new_upstream_key".to_owned()]);
            assert_ne!(expected_fingerprint, found_fingerprint);
        }
        other => panic!("expected shape mismatch, got {other:?}"),
    }
    let opts = Options {
        allow_shape_drift: true,
        ..rtr_options()
    };
    let rendered = render(&yaml, &opts).expect("override renders");
    assert!(
        rendered
            .warnings
            .iter()
            .any(|w| w.contains("fingerprint mismatch overridden")),
        "{:?}",
        rendered.warnings
    );
}

#[test]
fn missing_top_level_key_is_named_in_the_mismatch() {
    let mut value = healthy_value();
    value
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("rpki_roas".to_owned()));
    match render(&to_yaml(&value), &rtr_options()) {
        Err(RenderError::ShapeMismatch { missing, .. }) => {
            assert_eq!(missing, vec!["rpki_roas".to_owned()]);
        }
        other => panic!("expected shape mismatch, got {other:?}"),
    }
}

#[test]
fn refusal_matrix() {
    use serde_yaml::Value;
    let cases: &[(&[&str], Value, &str)] = &[
        (
            &["cfg", "filtering", "next_hop", "policy"],
            Value::String("same-as".into()),
            "same-as",
        ),
        (
            &["cfg", "filtering", "reject_policy", "policy"],
            Value::String("tag".into()),
            "reject_policy `tag`",
        ),
        (
            &["cfg", "filtering", "reject_policy", "policy"],
            Value::String("tag_and_reject".into()),
            "reject_policy `tag_and_reject`",
        ),
        (
            &["rtt_based_functions_are_used"],
            Value::Bool(true),
            "RTT-based communities",
        ),
        (
            &["cfg", "prepend_rs_as"],
            Value::Bool(true),
            "prepend_rs_as",
        ),
        (
            &["perform_graceful_shutdown"],
            Value::Bool(true),
            "perform_graceful_shutdown",
        ),
        (
            &["cfg", "filtering", "max_prefix", "action"],
            Value::String("block".into()),
            "max_prefix.action `block`",
        ),
        (
            &[
                "cfg",
                "communities",
                "do_not_announce_to_peers_with_rtt_lower_than",
                "std",
            ],
            Value::String("0:64999".into()),
            "RTT-based community",
        ),
    ];
    for (path, new, marker) in cases {
        let mut value = healthy_value();
        set_path(&mut value, path, new.clone());
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items.iter().any(|i| i.contains(marker)),
            "no refusal containing {marker:?} for {path:?}: {items:?}"
        );
    }
}

#[test]
fn per_client_next_hop_override_is_refused() {
    let mut value = healthy_value();
    let mut clients = value["clients"].clone();
    set_path(
        &mut clients[1],
        &["cfg", "filtering", "next_hop", "policy"],
        serde_yaml::Value::String("same-as".into()),
    );
    set_path(&mut value, &["clients"], clients);
    let items = refusals(render(&to_yaml(&value), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|i| i.contains("client AS197000_1") && i.contains("same-as")),
        "{items:?}"
    );
}

#[test]
fn disabling_all_irr_enforcement_is_refused() {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "filtering", "irrdb", "enforce_origin_in_as_set"],
        serde_yaml::Value::Bool(false),
    );
    set_path(
        &mut value,
        &["cfg", "filtering", "irrdb", "enforce_prefix_in_as_set"],
        serde_yaml::Value::Bool(false),
    );
    let items = refusals(render(&to_yaml(&value), &rtr_options()));
    assert!(
        items.iter().any(|i| i.contains("enforce_origin_in_as_set")),
        "{items:?}"
    );
}

#[test]
fn rpki_without_rtr_cache_is_refused() {
    let items = refusals(render(&to_yaml(&healthy_value()), &Options::default()));
    assert!(items.iter().any(|i| i.contains("--rtr-cache")), "{items:?}");
}

#[test]
fn add_path_replaces_per_client_best() {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "add_path"],
        serde_yaml::Value::Bool(true),
    );
    let rendered = render(&to_yaml(&value), &rtr_options()).expect("render");
    let toml = &rendered.files["config.toml"];
    assert!(toml.contains("[neighbors.add_path]"), "{toml}");
    assert!(!toml.contains("per_client_best"), "{toml}");
}

// ---------------------------------------------------------------------------
// Sectioned template-context ingestion (the format arouteserver 1.23.2
// actually emits)
// ---------------------------------------------------------------------------

/// Drop the context-shape fingerprint line — the one legitimate
/// difference between renders of the two input forms.
fn strip_fingerprint(text: &str) -> String {
    text.lines()
        .filter(|line| !line.contains("fingerprint"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn sectioned_dump_renders_identically_to_the_hand_authored_context() {
    let real = render(SECTIONED, &Options::default()).expect("sectioned dump renders");
    let hand = render(M90_HAND, &Options::default()).expect("hand-authored context renders");
    assert_eq!(
        real.files.keys().collect::<Vec<_>>(),
        hand.files.keys().collect::<Vec<_>>()
    );
    for (path, content) in &real.files {
        assert_eq!(
            strip_fingerprint(content),
            strip_fingerprint(&hand.files[path]),
            "render divergence between input forms in {path}"
        );
    }
    assert_eq!(real.warnings, hand.warnings);
    assert_eq!(real.receipt["clients"], hand.receipt["clients"]);
    // The real dump resolves TWO overlapping bundles per client (the
    // AS-SET and the bare origin-ASN object); the union must dedupe.
    assert_eq!(real.receipt["clients"][0]["prefix_set_size"], 2);
    assert_eq!(real.receipt["clients"][0]["origin_set_size"], 1);
}

#[test]
fn sectioned_unknown_section_is_refused_and_overridable() {
    let doctored = format!("{SECTIONED}\n\nshiny_new_knob\n--------------\ntrue\n");
    match render(&doctored, &Options::default()) {
        Err(RenderError::ShapeMismatch {
            missing,
            unexpected,
            ..
        }) => {
            assert!(missing.is_empty(), "{missing:?}");
            assert_eq!(unexpected, vec!["shiny_new_knob".to_owned()]);
        }
        other => panic!("expected shape mismatch, got {other:?}"),
    }
    let opts = Options {
        allow_shape_drift: true,
        ..Options::default()
    };
    let rendered = render(&doctored, &opts).expect("drift override renders");
    assert!(
        rendered
            .warnings
            .iter()
            .any(|w| w.contains("fingerprint mismatch overridden")),
        "{:?}",
        rendered.warnings
    );
}

#[test]
fn sectioned_missing_section_is_refused() {
    // The never-via section is the report's last; cut it off.
    let truncated = SECTIONED
        .split("never_via_route_servers_asns")
        .next()
        .expect("fixture carries the never-via section");
    match render(truncated, &Options::default()) {
        Err(RenderError::ShapeMismatch { missing, .. }) => {
            assert_eq!(missing, vec!["never_via_route_servers_asns".to_owned()]);
        }
        other => panic!("expected shape mismatch, got {other:?}"),
    }
}

#[test]
fn sectioned_malformed_section_body_is_a_parse_error() {
    let corrupted = SECTIONED.replace("\nrpki_roas\n---------\n[]", "\nrpki_roas\n---------\n[");
    assert_ne!(corrupted, SECTIONED, "corruption target not found");
    match render(&corrupted, &Options::default()) {
        Err(err @ RenderError::Parse(_)) => {
            assert_eq!(err.exit_code(), 1);
            assert!(err.to_string().contains("rpki_roas"), "{err}");
        }
        other => panic!("expected parse error, got {other:?}"),
    }
}

#[test]
fn client_black_and_white_lists_are_refused() {
    use serde_yaml::Value;
    let entry: Value = serde_yaml::from_str("[{prefix: 203.0.113.0, length: 24}]").unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["cfg", "filtering", "black_list_pref"], "black_list_pref"),
        (
            &["cfg", "filtering", "irrdb", "white_list_pref"],
            "white_list_pref",
        ),
        (
            &["cfg", "filtering", "irrdb", "white_list_asn"],
            "white_list_asn",
        ),
        (
            &["cfg", "filtering", "irrdb", "white_list_route"],
            "white_list_route",
        ),
    ];
    for (path, marker) in cases {
        let mut value = healthy_value();
        let mut clients = value["clients"].clone();
        set_path(&mut clients[0], path, entry.clone());
        set_path(&mut value, &["clients"], clients);
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items
                .iter()
                .any(|i| i.contains(marker) && i.contains("client AS4242_1")),
            "no refusal containing {marker:?}: {items:?}"
        );
    }
}

#[test]
/// Load-bearing proof: removing the effective-action gate, client-to-general
/// fallback, or zero-limit filter emits or suppresses an asserted config or
/// receipt field.
fn effective_max_prefix_action_controls_limit_emission() {
    let mut value = healthy_value();
    // ARouteServer can leave resolved limits populated while disabling
    // enforcement with an absent action. Neither the config nor receipt may
    // imply an active ceiling in that state.
    set_path(
        &mut value,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::Null,
    );
    let mut clients = value["clients"].clone();
    set_path(
        &mut clients[0],
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::Null,
    );
    set_path(&mut value, &["clients"], clients);
    let disabled = render(&to_yaml(&value), &rtr_options()).expect("no-action render");
    assert!(
        !disabled.files["config.toml"].contains("max_prefixes_"),
        "{}",
        disabled.files["config.toml"]
    );
    for client in disabled.receipt["clients"].as_array().unwrap() {
        assert!(client["max_prefixes_ipv4"].is_null(), "{client}");
        assert!(client["max_prefixes_ipv6"].is_null(), "{client}");
    }

    // The same clients inherit an enabled general shutdown action. Positive
    // limits emit, while ARouteServer's zero sentinel remains unset.
    set_path(
        &mut value,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::String("shutdown".into()),
    );
    let enabled = render(&to_yaml(&value), &rtr_options()).expect("inherited shutdown render");
    let toml = &enabled.files["config.toml"];
    assert!(toml.contains("max_prefixes_ipv4 = 5000"), "{toml}");
    assert!(toml.contains("max_prefixes_ipv6 = 1000"), "{toml}");
    assert!(!toml.contains("max_prefixes_ipv4 = 0"), "{toml}");
    assert!(!toml.contains("max_prefixes_ipv6 = 0"), "{toml}");
}

#[test]
/// Load-bearing proof: validating the raw general action instead of the
/// client-effective action makes this render refuse `block`.
fn client_shutdown_overrides_unsupported_general_max_prefix_action() {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::String("block".into()),
    );
    let mut clients = value["clients"].clone();
    for client in clients.as_sequence_mut().unwrap() {
        set_path(
            client,
            &["cfg", "filtering", "max_prefix", "action"],
            serde_yaml::Value::String("shutdown".into()),
        );
    }
    set_path(&mut value, &["clients"], clients);
    let rendered = render(&to_yaml(&value), &rtr_options()).expect("client override render");
    assert!(
        rendered.files["config.toml"].contains("max_prefixes_ipv4 = 5000"),
        "{}",
        rendered.files["config.toml"]
    );
}

#[test]
/// Load-bearing proof: accepting any listed action, dropping `restart_after`
/// parsing, or dropping general-action inheritance misses an asserted refusal.
fn unsupported_effective_max_prefix_actions_are_refused() {
    for action in ["restart", "block", "warning"] {
        let mut value = healthy_value();
        let mut clients = value["clients"].clone();
        set_path(
            &mut clients[0],
            &["cfg", "filtering", "max_prefix", "action"],
            serde_yaml::Value::String(action.into()),
        );
        if action == "restart" {
            set_path(
                &mut clients[0],
                &["cfg", "filtering", "max_prefix", "restart_after"],
                serde_yaml::Value::Number(37.into()),
            );
        }
        set_path(&mut value, &["clients"], clients);
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items.iter().any(|item| item.contains("client AS4242_1")
                && item.contains(&format!("action `{action}`"))),
            "{action}: {items:?}"
        );
        if action == "restart" {
            assert!(
                items
                    .iter()
                    .any(|item| item.contains("restart_after=37 minutes")),
                "{items:?}"
            );
        }
    }

    // An absent client action inherits the general action.
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::String("restart".into()),
    );
    let items = refusals(render(&to_yaml(&value), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|item| item.contains("client AS197000_1") && item.contains("action `restart`")),
        "{items:?}"
    );
}

#[test]
/// Load-bearing proof: defaulting an omitted value to false, checking the
/// value without an active shutdown/positive limit, deleting the true-value
/// refusal, or reversing client-over-general precedence breaks an asserted
/// success or refusal below.
fn rejected_route_counting_is_checked_only_for_an_active_limit() {
    // ARouteServer 1.23.2 defaults an omitted value to true. Silently treating
    // this context as accepted-only would change when shutdown happens.
    let mut omitted = healthy_value();
    omitted["cfg"]["filtering"]["max_prefix"]
        .as_mapping_mut()
        .expect("max_prefix mapping")
        .remove(serde_yaml::Value::String(
            "count_rejected_routes".to_owned(),
        ));
    let items = refusals(render(&to_yaml(&omitted), &rtr_options()));
    assert!(
        items.iter().any(|item| item.contains("client AS4242_1")
            && item.contains("defaults this option to true")),
        "{items:?}"
    );

    let mut inherited = healthy_value();
    set_path(
        &mut inherited,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let items = refusals(render(&to_yaml(&inherited), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|item| item.contains("client AS197000_1") && item.contains("=true")),
        "{items:?}"
    );

    let mut overridden = healthy_value();
    let mut clients = overridden["clients"].clone();
    set_path(
        &mut clients[0],
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    set_path(&mut overridden, &["clients"], clients);
    let items = refusals(render(&to_yaml(&overridden), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|item| item.contains("client AS4242_1") && item.contains("=true")),
        "{items:?}"
    );

    // A client can explicitly select rustbgpd's accepted-route model over an
    // inherited general true value.
    let mut allowed_override = healthy_value();
    set_path(
        &mut allowed_override,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let mut clients = allowed_override["clients"].clone();
    for client in clients.as_sequence_mut().expect("clients list") {
        set_path(
            client,
            &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
            serde_yaml::Value::Bool(false),
        );
    }
    set_path(&mut allowed_override, &["clients"], clients);
    render(&to_yaml(&allowed_override), &rtr_options()).expect("explicit false override");

    // Counting semantics are irrelevant when no shutdown action is active,
    // even if ARouteServer leaves resolved positive limits in the context.
    let mut disabled = healthy_value();
    set_path(
        &mut disabled,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::Null,
    );
    set_path(
        &mut disabled,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let mut clients = disabled["clients"].clone();
    set_path(
        &mut clients[0],
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::Null,
    );
    set_path(&mut disabled, &["clients"], clients);
    render(&to_yaml(&disabled), &rtr_options()).expect("disabled max-prefix counting");

    // A shutdown action with only zero/unset family limits is also inactive.
    let mut zero_limits = healthy_value();
    set_path(
        &mut zero_limits,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let mut clients = zero_limits["clients"].clone();
    for client in clients.as_sequence_mut().expect("clients list") {
        set_path(
            client,
            &["cfg", "filtering", "max_prefix", "limit_ipv4"],
            serde_yaml::Value::Number(0.into()),
        );
        set_path(
            client,
            &["cfg", "filtering", "max_prefix", "limit_ipv6"],
            serde_yaml::Value::Number(0.into()),
        );
    }
    set_path(&mut zero_limits, &["clients"], clients);
    render(&to_yaml(&zero_limits), &rtr_options()).expect("zero limits disable enforcement");
}
