//! Golden-file, refusal, abort, and fingerprint coverage for the
//! renderer. The single checked-in fixture carries three clients; the
//! third has a deliberately empty IRR prefix bundle, so the untouched
//! fixture proves the implausible-set abort and every other case is a
//! targeted mutation of the same context.

use rs_config_render::{Options, RenderError, render};

const FIXTURE: &str = include_str!("fixtures/context-small.yml");

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

#[test]
fn restart_max_prefix_action_degrades_with_a_warning() {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::String("restart".into()),
    );
    let rendered = render(&to_yaml(&value), &rtr_options()).expect("render");
    assert!(
        rendered
            .warnings
            .iter()
            .any(|w| w.contains("teardown-only")),
        "{:?}",
        rendered.warnings
    );
}
