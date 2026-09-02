//! Golden-file, refusal, abort, and fingerprint coverage for the
//! renderer. The single checked-in fixture carries three clients; the
//! third has a deliberately empty IRR prefix bundle, so the untouched
//! fixture proves the implausible-set abort and every other case is a
//! targeted mutation of the same context.

use rs_config_render::{Exit, Options, RenderError, render};
use rustbgpd_policy::rpol::run_rpol_tests;

const FIXTURE: &str = include_str!("fixtures/context-small.yml");

/// A verbatim `arouteserver template-context` dump (pinned
/// pierky/arouteserver image, arouteserver 1.23.2) of the M90
/// differential lab's site — the *sectioned report* form.
const SECTIONED: &str =
    include_str!("../../../tests/interop/m90-differential/context-sectioned.yml");
/// The hand-authored single-document context for the same site.
const M90_HAND: &str = include_str!("../../../tests/interop/m90-differential/context.yml");
/// The M106 sibling site (IRR white lists plus the daemon's control
/// matrix), dumped by the same pinned image, and its hand-authored twin.
const M106_SECTIONED: &str = include_str!(
    "../../../tests/interop/m106-rs-white-list-control-differential/context-sectioned.yml"
);
const M106_HAND: &str =
    include_str!("../../../tests/interop/m106-rs-white-list-control-differential/context.yml");
/// The M107 RFC 8950 uniform-fleet site (IPv6-only members, `rfc8950`
/// on), dumped by the same pinned image, and its hand-authored twin.
const M107_SECTIONED: &str =
    include_str!("../../../tests/interop/m107-rs-rfc8950-uniform-fleet/context-sectioned.yml");
const M107_HAND: &str =
    include_str!("../../../tests/interop/m107-rs-rfc8950-uniform-fleet/context.yml");

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

fn set_client(root: &mut serde_yaml::Value, n: usize, path: &[&str], new: serde_yaml::Value) {
    set_path(&mut root["clients"][n], path, new);
}

fn set_client_multihop(root: &mut serde_yaml::Value, n: usize, ttl: u64) {
    set_client(root, n, &["cfg", "multihop"], ttl.into());
}

fn set_client_announce(root: &mut serde_yaml::Value, n: usize, value: bool) {
    set_client(
        root,
        n,
        &["cfg", "blackhole_filtering", "announce_to_client"],
        value.into(),
    );
}

fn set_blackhole_policy(root: &mut serde_yaml::Value, family: &str, policy: Option<&str>) {
    let value = policy.map_or(serde_yaml::Value::Null, |p| p.into());
    set_path(root, &["cfg", "blackhole_filtering", family], value);
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

fn set_general_community(root: &mut serde_yaml::Value, name: &str, value: serde_yaml::Value) {
    root["cfg"]["communities"]
        .as_mapping_mut()
        .expect("fixture cfg.communities is a mapping")
        .insert(serde_yaml::Value::String(name.to_owned()), value);
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
        (
            "datasets/client-as4242-1-origins.list",
            include_str!("golden/client-as4242-1-origins.list"),
        ),
        (
            "datasets/client-as4242-1-prefixes.list",
            include_str!("golden/client-as4242-1-prefixes.list"),
        ),
        (
            "datasets/client-as197000-1-origins.list",
            include_str!("golden/client-as197000-1-origins.list"),
        ),
        (
            "datasets/client-as197000-1-prefixes.list",
            include_str!("golden/client-as197000-1-prefixes.list"),
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
    assert!(!rendered.files["config.toml"].contains("blackhole-cover"));
    assert!(
        rendered
            .files
            .keys()
            .all(|path| !path.contains("blackhole-cover"))
    );
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
fn one_client_irr_change_only_changes_its_dataset_and_receipt_cardinality() {
    let baseline = render(&to_yaml(&healthy_value()), &rtr_options()).unwrap();
    let mut changed = healthy_value();
    changed["irrdb_info"]["AS197000_bundle"]["prefixes"]
        .as_sequence_mut()
        .unwrap()
        .push(
            serde_yaml::from_str("{prefix: '2001:db8:ffff::', length: 48, exact: true}").unwrap(),
        );
    let changed = render(&to_yaml(&changed), &rtr_options()).unwrap();
    let changed_paths = baseline
        .files
        .iter()
        .filter_map(|(path, before)| (changed.files[path] != *before).then_some(path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(changed_paths, ["datasets/client-as197000-1-prefixes.list"]);
    assert_eq!(
        changed.files["datasets/client-as197000-1-prefixes.list"],
        "2001:db8:ffff::/48\n2a10:cc40::/29 le 48\n"
    );
    let mut before_receipt = baseline.receipt;
    let mut after_receipt = changed.receipt;
    for receipt in [&mut before_receipt, &mut after_receipt] {
        receipt.as_object_mut().unwrap().remove("rendered_at_unix");
        receipt.as_object_mut().unwrap().remove("rendered_at_utc");
    }
    assert_eq!(before_receipt["clients"][0], after_receipt["clients"][0]);
    assert_eq!(before_receipt["clients"][1]["prefix_set_size"], 1);
    assert_eq!(after_receipt["clients"][1]["prefix_set_size"], 2);
    before_receipt["clients"][1]["prefix_set_size"] = 2.into();
    assert_eq!(before_receipt, after_receipt);
}

#[test]
fn client_dataset_names_are_safe_and_collision_free() {
    let mut unsafe_id = healthy_value();
    unsafe_id["clients"][0]["id"] = "../escape".into();
    assert!(
        render(&to_yaml(&unsafe_id), &rtr_options())
            .unwrap_err()
            .to_string()
            .contains("safe policy/dataset artifact name")
    );

    let mut collision = healthy_value();
    let mut twin = collision["clients"][0].clone();
    twin["id"] = "AS4242-1".into();
    twin["ip"] = "192.0.2.99".into();
    collision["clients"].as_sequence_mut().unwrap().push(twin);
    assert!(
        render(&to_yaml(&collision), &rtr_options())
            .unwrap_err()
            .to_string()
            .contains("collides with another client")
    );
}

#[cfg(unix)]
#[test]
fn cli_stdout_matrix_retains_files_and_receipt() {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::process::{Command, Stdio};

    fn command(context: &std::path::Path, out: &std::path::Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
        command
            .arg("--context")
            .arg(context)
            .arg("--out-dir")
            .arg(out)
            .arg("--rtr-cache")
            .arg("127.0.0.1:3323");
        command
    }

    fn assert_outputs(out: &std::path::Path) {
        for path in [
            "config.toml",
            "policy/rs-hygiene.rpol",
            "policy/client-as4242-1.rpol",
            "policy/client-as197000-1.rpol",
            "datasets/client-as4242-1-origins.list",
            "datasets/client-as4242-1-prefixes.list",
            "datasets/client-as197000-1-origins.list",
            "datasets/client-as197000-1-prefixes.list",
            "render-receipt.json",
        ] {
            assert!(out.join(path).is_file(), "missing retained {path}");
        }
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("render-receipt.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["clients"].as_array().unwrap().len(), 2);
    }

    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context.yml");
    std::fs::write(&context, to_yaml(&healthy_value())).unwrap();

    let healthy_dir = temp.path().join("healthy");
    let healthy = command(&context, &healthy_dir).output().unwrap();
    assert_eq!(healthy.status.code(), Some(0), "{healthy:?}");
    assert!(healthy.stderr.is_empty(), "{healthy:?}");
    assert_eq!(
        healthy.stdout,
        format!(
            "rendered 8 file(s) + receipt into {} — gate with `rustbgpd --check --strict {}` before swapping\n",
            healthy_dir.display(),
            healthy_dir.join("config.toml").display()
        )
        .as_bytes()
    );
    assert_outputs(&healthy_dir);

    let closed_dir = temp.path().join("closed");
    let (peer, stdout) = UnixStream::pair().unwrap();
    drop(peer);
    let mut closed_command = command(&context, &closed_dir);
    closed_command.stdout(Stdio::from(OwnedFd::from(stdout)));
    let closed = closed_command.output().unwrap();
    assert_eq!(closed.status.code(), Some(1), "{closed:?}");
    assert!(
        closed.stdout.is_empty() && closed.stderr.is_empty(),
        "{closed:?}"
    );
    assert_outputs(&closed_dir);
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

fn tag_and_reject_value() -> serde_yaml::Value {
    let mut value = healthy_value();
    set_path(
        &mut value,
        &["cfg", "filtering", "reject_policy", "policy"],
        "tag_and_reject".into(),
    );
    for (name, values) in [
        (
            "reject_cause",
            "{std: '65520:dyn_val', lrg: '64496:65520:dyn_val'}",
        ),
        (
            "reject_cause_map_3",
            "{std: '64512:3', lrg: '64496:65521:3'}",
        ),
        ("reject_cause_map_12", "{lrg: '64496:65521:12'}"),
    ] {
        set_general_community(&mut value, name, serde_yaml::from_str(values).unwrap());
    }
    set_client(
        &mut value,
        0,
        &["cfg", "filtering", "reject_policy"],
        serde_yaml::from_str("{policy: reject}").unwrap(),
    );
    value
}

#[test]
fn tag_and_reject_artifact_and_order_are_exact_and_mixed_policy_scoped() {
    let baseline = render(&to_yaml(&healthy_value()), &rtr_options()).unwrap();
    let rendered = render(&to_yaml(&tag_and_reject_value()), &rtr_options()).unwrap();
    assert_eq!(
        rendered.files["birdwatcher-reject-communities.json"],
        "{\n  \"schema\": \"rustbgpd.arouteserver-reject-communities.v1\",\n  \"peers\": [\n    \"2001:db8:0:1::22\"\n  ],\n  \"std\": {\n    \"dynamic\": \"65520:dyn_val\",\n    \"cause_map\": {\n      \"3\": \"64512:3\"\n    }\n  },\n  \"lrg\": {\n    \"dynamic\": \"64496:65520:dyn_val\",\n    \"cause_map\": {\n      \"3\": \"64496:65521:3\",\n      \"12\": \"64496:65521:12\"\n    }\n  }\n}\n"
    );
    assert_eq!(
        rendered.files["policy/client-as4242-1.rpol"],
        baseline.files["policy/client-as4242-1.rpol"]
    );
    let policy = &rendered.files["policy/client-as197000-1.rpol"];
    let positions = [
        "reject-irrdb-origin-as-filtered",
        "reject-irrdb-prefix-filtered",
        "term accept-authorized",
    ]
    .map(|term| policy.find(term).unwrap());
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{policy}"
    );
    assert!(!policy.contains("term rest"), "{policy}");

    let mut reverse = tag_and_reject_value();
    set_path(
        &mut reverse,
        &["cfg", "filtering", "reject_policy", "policy"],
        "reject".into(),
    );
    set_client(
        &mut reverse,
        0,
        &["cfg", "filtering", "reject_policy"],
        serde_yaml::from_str("{policy: tag_and_reject}").unwrap(),
    );
    let reverse = render(&to_yaml(&reverse), &rtr_options()).unwrap();
    let artifact: serde_json::Value =
        serde_json::from_str(&reverse.files["birdwatcher-reject-communities.json"]).unwrap();
    assert_eq!(artifact["peers"], serde_json::json!(["192.0.2.11"]));
    assert!(reverse.files["policy/client-as4242-1.rpol"].contains("reject-irrdb-prefix-filtered"));
    assert_eq!(
        reverse.files["policy/client-as197000-1.rpol"],
        baseline.files["policy/client-as197000-1.rpol"]
    );
}

#[test]
fn tag_and_reject_refuses_malformed_extended_announcer_and_invalid_causes() {
    for (name, values, marker) in [
        ("reject_cause", "{std: 'dyn_val:1'}", "dyn_val exactly last"),
        (
            "reject_cause",
            "{lrg: '64496:65520:dyn_val', ext: 'RT:1:1'}",
            ".ext is unsupported",
        ),
        (
            "rejected_route_announced_by",
            "{std: '65520:dyn_val'}",
            "authoritative announcer data",
        ),
        ("reject_cause_map_16", "{std: '64512:16'}", "outside 1..15"),
    ] {
        let mut value = tag_and_reject_value();
        set_general_community(&mut value, name, serde_yaml::from_str(values).unwrap());
        let errors = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            errors.iter().any(|error| error.contains(marker)),
            "{errors:?}"
        );
    }
}

#[test]
fn rpki_not_performed_community_refuses_configured_forms() {
    for (kind, marker) in [
        ("std", "65000:1"),
        ("lrg", "65000:1:1"),
        ("ext", "RT:65000:1"),
    ] {
        let mut value = healthy_value();
        set_general_community(
            &mut value,
            "rpki_bgp_origin_validation_not_performed",
            serde_yaml::from_str(&format!("{{{kind}: '{marker}'}}")).unwrap(),
        );
        assert_eq!(
            refusals(render(&to_yaml(&value), &rtr_options())),
            [
                "communities.rpki_bgp_origin_validation_not_performed is configured; unsupported tagging/scrubbing cannot be rendered"
            ]
        );
    }
}

#[test]
fn null_rpki_not_performed_community_is_output_identity() {
    let missing = render(&to_yaml(&healthy_value()), &rtr_options()).unwrap();
    let mut value = healthy_value();
    set_general_community(
        &mut value,
        "rpki_bgp_origin_validation_not_performed",
        serde_yaml::from_str("{std: null, lrg: null, ext: null}").unwrap(),
    );
    let all_null = render(&to_yaml(&value), &rtr_options()).unwrap();
    assert_eq!(all_null.files, missing.files);
    assert_eq!(all_null.warnings, missing.warnings);
    for field in [
        "context_fingerprint",
        "source_data_ages",
        "clients",
        "warnings",
    ] {
        assert_eq!(all_null.receipt[field], missing.receipt[field], "{field}");
    }
}

#[test]
/// Load-bearing: removing either field/refusal makes a nonzero case render;
/// ignoring precedence wrongly refuses AS4242_1's explicit zero override.
fn effective_nonzero_multihop_is_refused() {
    use serde_yaml::Value;
    for (general, client, id, ttl) in [(2, Some(0), "AS197000_1", 2), (0, Some(3), "AS4242_1", 3)] {
        let mut value = healthy_value();
        set_path(
            &mut value,
            &["cfg", "multihop"],
            Value::Number(general.into()),
        );
        if let Some(client) = client {
            set_client_multihop(&mut value, 0, client);
        }
        assert_eq!(
            refusals(render(&to_yaml(&value), &rtr_options())),
            [format!(
                "client {id}: effective multihop={ttl} is not rendered; set this client to 0 or disable general multihop"
            )]
        );
    }
}

/// The healthy fixture without its IPv4 member: an IPv6-only fleet.
fn ipv6_only_value() -> serde_yaml::Value {
    let mut value = healthy_value();
    let clients = value["clients"].as_sequence_mut().expect("clients list");
    clients.retain(|c| c["id"].as_str() != Some("AS4242_1"));
    value["irrdb_info"]
        .as_mapping_mut()
        .expect("irrdb_info mapping")
        .remove(serde_yaml::Value::String("AS4242_bundle".to_owned()));
    value
}

const MIXED_FLEET_REFUSAL: &str = "client AS197000_1: effective rfc8950=true needs next-hop \
translation toward IPv4-session client AS4242_1 (ADR-0128, not implemented); only a uniform \
IPv6 fleet is rendered";

#[test]
/// Load-bearing: an RFC 8950 session renders only inside a uniform IPv6
/// fleet; a mixed fleet would need the ADR-0128 translation and is refused.
fn rfc8950_renders_uniform_ipv6_fleets_and_refuses_mixed_ones() {
    use serde_yaml::Value;
    let mut inherited = healthy_value();
    set_path(&mut inherited, &["cfg", "rfc8950"], Value::Bool(true));
    inherited["clients"][1]["cfg"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("rfc8950".into()));
    assert_eq!(
        refusals(render(&to_yaml(&inherited), &rtr_options())),
        [MIXED_FLEET_REFUSAL]
    );

    let mut client = healthy_value();
    set_client(&mut client, 1, &["cfg", "rfc8950"], Value::Bool(true));
    assert_eq!(
        refusals(render(&to_yaml(&client), &rtr_options())),
        [MIXED_FLEET_REFUSAL]
    );

    let mut inert = healthy_value();
    set_path(&mut inert, &["cfg", "rfc8950"], Value::Bool(true));
    render(&to_yaml(&inert), &rtr_options()).expect("client false overrides general true");
    set_client(&mut inert, 0, &["cfg", "rfc8950"], Value::Bool(true));
    render(&to_yaml(&inert), &rtr_options()).expect("RFC8950 is inert on an IPv4 session");

    let mut uniform = ipv6_only_value();
    set_client(&mut uniform, 0, &["cfg", "rfc8950"], Value::Bool(true));
    set_client(
        &mut uniform,
        0,
        &["cfg", "filtering", "irrdb", "white_list_route"],
        serde_yaml::from_str("[{prefix: 198.51.100.0, length: 24}]").unwrap(),
    );
    let rendered = render(&to_yaml(&uniform), &rtr_options()).expect("uniform IPv6 fleet");
    let expected = "\n[[neighbors]]\naddress = \"2001:db8:0:1::22\"\nremote_asn = 197000\n\
description = \"member-two-v6\"\nfamilies = [\"ipv4_unicast\", \"ipv6_unicast\"]\n\
route_server_client = true\nrole = \"route_server\"\n\
# RFC 8950: IPv4 unicast rides this IPv6 session. The dual-family session\n\
# negotiates the extended next hop, and strict_peer accepts an IPv4 route\n\
# only with this session's own IPv6 address as its next hop.\n\
next_hop_ownership = \"strict_peer\"\nttl_security = true\nper_client_best = true\n\
rs_control_communities = false\nmax_prefixes_ipv6 = 1000\n\
import_policy_chain = [\"rs-hygiene\", \"client-as197000-1\"]\n";
    let config = &rendered.files["config.toml"];
    assert!(config.contains(expected), "{config}");
    // The session carries both families, so an IPv4 white-list route is kept.
    assert!(
        rendered.files["policy/client-as197000-1.rpol"]
            .contains("prefix-set client-as197000-1-white-list-route-1 { 198.51.100.0/24 le 32 }")
    );

    let mut blackhole = ipv6_only_value();
    set_client(&mut blackhole, 0, &["cfg", "rfc8950"], Value::Bool(true));
    set_blackhole_policy(&mut blackhole, "policy_ipv4", Some("propagate-unchanged"));
    assert_eq!(
        refusals(render(&to_yaml(&blackhole), &rtr_options())),
        [
            "client AS197000_1: effective rfc8950=true with blackhole_filtering.policy_ipv4 \
          is not rendered; IPv4 blackhole terms are bound to IPv4 sessions"
        ]
    );
}

#[test]
/// Load-bearing: an active, supported blackhole policy renders explicitly
/// instead of falling back to the daemon's global implicit behavior.
fn blackhole_policy_is_rendered_without_global_implicit_behavior() {
    use serde_yaml::Value;
    let mut value = healthy_value();
    set_blackhole_policy(&mut value, "policy_ipv4", Some("propagate-unchanged"));
    set_path(
        &mut value,
        &["cfg", "blackhole_filtering", "add_noexport"],
        Value::Bool(true),
    );
    set_path(
        &mut value,
        &["cfg", "communities", "blackholing", "std"],
        Value::String("65500:666".to_owned()),
    );
    set_client_announce(&mut value, 0, false);
    value["clients"][0]["cfg"]["blackhole_filtering"]["add_noexport"] = false.into();
    assert!(
        refusals(render(&to_yaml(&value), &rtr_options()))
            .iter()
            .any(|item| item
                .contains("only blackhole_filtering.announce_to_client may be overridden"))
    );
    value["clients"][0]["cfg"]["blackhole_filtering"]["add_noexport"] = Value::Null;
    let rendered = render(&to_yaml(&value), &rtr_options()).expect("supported policy renders");
    assert!(rendered.files["config.toml"].contains("honor_blackhole = false"));
    assert!(!rendered.files["config.toml"].contains("NO_ADVERTISE"));
    assert!(
        rendered.files["policy/rs-hygiene.rpol"]
            .contains("route { family ipv6-unicast; prefix 2001:db8::/32")
    );

    set_blackhole_policy(&mut value, "policy_ipv6", Some("propagate-unchanged"));
    let both = render(&to_yaml(&value), &rtr_options()).unwrap();
    assert!(!both.files["policy/rs-hygiene.rpol"].contains("test rpki-invalid-is-rejected"));

    value["clients"]
        .as_sequence_mut()
        .unwrap()
        .retain(|client| !client["ip"].as_str().unwrap().contains(':'));
    set_blackhole_policy(&mut value, "policy_ipv4", None);
    let no_matching_neighbor = render(&to_yaml(&value), &rtr_options()).unwrap();
    assert!(no_matching_neighbor.files["config.toml"].contains("honor_blackhole = false"));
    assert!(
        no_matching_neighbor.files["policy/rs-hygiene.rpol"]
            .contains("route { family ipv4-unicast; prefix 203.0.113.0/24")
    );
}

#[test]
fn blackhole_import_covering_markers_and_export_matrix() {
    let mut value = healthy_value();
    set_blackhole_policy(&mut value, "policy_ipv4", Some("propagate-unchanged"));
    set_path(
        &mut value,
        &["cfg", "blackhole_filtering", "add_noexport"],
        true.into(),
    );
    for (kind, marker) in [
        ("std", "65500:666"),
        ("lrg", "65500:666:1"),
        ("ext", "RT:65500:666"),
    ] {
        set_path(
            &mut value,
            &["cfg", "communities", "blackholing", kind],
            marker.into(),
        );
    }
    let prefix = &mut value["irrdb_info"]["AS4242_bundle"]["prefixes"][0];
    prefix["exact"] = false.into();
    prefix["ge"] = 26.into();
    prefix["le"] = 28.into();
    let mut twin = value["clients"][0].clone();
    twin["id"] = "AS4242_2".into();
    twin["ip"] = "192.0.2.12".into();
    value["clients"].as_sequence_mut().unwrap().push(twin);
    let rendered = render(&to_yaml(&value), &rtr_options()).unwrap();
    let client = &rendered.files["policy/client-as4242-1.rpol"];
    assert!(client.contains("dataset prefix-set client-as4242-1-blackhole-cover"));
    assert_eq!(
        rendered.files["datasets/client-as4242-1-blackhole-cover.list"],
        "198.51.100.0/24 le 32\n203.0.113.0/24 ge 26 le 32\n"
    );
    assert!(
        rendered.files["config.toml"].contains(
            "[policy.datasets.client-as4242-1-blackhole-cover]\npath = \"datasets/client-as4242-1-blackhole-cover.list\""
        )
    );
    let cases = r#"
test ordinary-exact-prefix-remains-authorized {
    dataset client-as4242-1-origins { 4242 }
    dataset client-as4242-1-prefixes { 203.0.113.0/24 }
    dataset client-as4242-1-blackhole-cover { 203.0.113.0/24 ge 26 le 32 }
    route { family ipv4-unicast; prefix 203.0.113.0/24; as-path "4242" }
    expect client-as4242-1 == accept
}
test marked-covered-host-is-authorized {
    dataset client-as4242-1-origins { 4242 }
    dataset client-as4242-1-prefixes { 203.0.113.0/24 }
    dataset client-as4242-1-blackhole-cover { 203.0.113.0/24 ge 26 le 32 }
    route { family ipv4-unicast; prefix 203.0.113.1/32; as-path "4242"; communities [65535:666] }
    expect client-as4242-1 == accept with community BLACKHOLE
}
test marked-prefix-below-cover-ge-is-rejected {
    dataset client-as4242-1-origins { 4242 }
    dataset client-as4242-1-prefixes { 203.0.113.0/24 }
    dataset client-as4242-1-blackhole-cover { 203.0.113.0/24 ge 26 le 32 }
    route { family ipv4-unicast; prefix 203.0.113.0/25; as-path "4242"; communities [65535:666] }
    expect client-as4242-1 == reject
}
test marked-prefix-outside-cover-is-rejected {
    dataset client-as4242-1-origins { 4242 }
    dataset client-as4242-1-prefixes { 203.0.113.0/24 }
    dataset client-as4242-1-blackhole-cover { 203.0.113.0/24 ge 26 le 32 }
    route { family ipv4-unicast; prefix 198.51.100.1/32; as-path "4242"; communities [65535:666] }
    expect client-as4242-1 == reject
}
test wrong-afi-never-uses-v4-cover {
    dataset client-as4242-1-origins { 4242 }
    dataset client-as4242-1-prefixes { 203.0.113.0/24 }
    dataset client-as4242-1-blackhole-cover { 203.0.113.0/24 ge 26 le 32 }
    route { family ipv6-unicast; prefix 2001:db8::1/128; as-path "4242"; communities [65535:666] }
    expect client-as4242-1 == reject
}
"#;
    let report = run_rpol_tests(&format!("{client}\n{cases}")).unwrap();
    assert!(report.all_passed(), "{:?}", report.failures);
    for guard in [
        "route.communities has 65500:666",
        "route.large-communities has 65500:666:1",
        "route.ext-communities has RT:65500:666",
    ] {
        assert!(client.contains(guard), "{guard}\n{client}");
    }
    let config = &rendered.files["config.toml"];
    assert!(config.contains("set_community_add = [\"BLACKHOLE\", \"NO_EXPORT\"]"));
    assert!(
        config.contains(
            "set_community_remove = [\"65500:666\", \"LC:65500:666:1\", \"RT:65500:666\"]"
        )
    );
    assert!(!config.contains("NO_ADVERTISE"));
    assert!(!config.contains("set_next_hop ="));
    assert_eq!(
        config
            .matches("[policy.definitions.rs-blackhole-export-1]")
            .count(),
        1
    );
    assert_eq!(
        config
            .matches("export_policy_chain = [\"rs-blackhole-export-1\"]")
            .count(),
        2
    );

    set_path(
        &mut value,
        &["cfg", "blackhole_filtering", "announce_to_client"],
        false.into(),
    );
    set_client_announce(&mut value, 0, true);
    let inherited_off_overridden_on = render(&to_yaml(&value), &rtr_options()).unwrap();
    assert!(
        inherited_off_overridden_on.files["config.toml"]
            .contains("set_community_add = [\"BLACKHOLE\", \"NO_EXPORT\"]")
    );
    set_path(
        &mut value,
        &["cfg", "blackhole_filtering", "announce_to_client"],
        true.into(),
    );
    set_client_announce(&mut value, 0, false);
    let inherited_on_overridden_off = render(&to_yaml(&value), &rtr_options()).unwrap();
    assert!(inherited_on_overridden_off.files["config.toml"].contains("action = \"deny\""));
}

#[test]
fn blackhole_unknown_malformed_and_rewrite_errors_refuse() {
    let cases = [
        ("unknown", None, "unknown blackhole_filtering.policy_ipv4"),
        (
            "rewrite-next-hop",
            None,
            "requires a valid rewrite_next_hop_ipv4",
        ),
        (
            "rewrite-next-hop",
            Some("2001:db8::66"),
            "wrong address family",
        ),
    ];
    for (policy, next_hop, expected) in cases {
        let mut value = healthy_value();
        set_blackhole_policy(&mut value, "policy_ipv4", Some(policy));
        if let Some(next_hop) = next_hop {
            set_path(
                &mut value,
                &["cfg", "blackhole_filtering", "rewrite_next_hop_ipv4"],
                next_hop.into(),
            );
        }
        assert!(
            refusals(render(&to_yaml(&value), &rtr_options()))
                .iter()
                .any(|item| item.contains(expected))
        );
    }
    let mut base = healthy_value();
    set_blackhole_policy(&mut base, "policy_ipv4", Some("propagate-unchanged"));
    for (kind, marker, accepted) in [
        ("ext", "RT:65000:4294967295", true),
        ("ext", "RO:65535:4294967295", true),
        ("ext", "RT:65536:65535", true),
        ("ext", "RO:4294967295:65535", true),
        ("ext", "RT:192.0.2.1:65535", true),
        ("ext", "RO:203.0.113.9:0", true),
        ("ext", "rt:65000:1", false),
        ("ext", "ro:65000:1", false),
        ("ext", "RT:4294967296:1", false),
        ("ext", "RT:65536:65536", false),
        ("ext", "RT:192.0.2.1:65536", false),
        ("ext", "RT:-1:1", false),
        ("ext", "RT:1:-1", false),
        ("ext", "RT:+1:1", false),
        ("ext", "RT:1:+1", false),
        ("ext", "RT:1", false),
        ("ext", "RT:1:2:3", false),
        ("ext", "not-a-community", false),
        ("lrg", "not-a-community", false),
    ] {
        let mut value = base.clone();
        set_path(
            &mut value,
            &["cfg", "communities", "blackholing", kind],
            marker.into(),
        );
        assert_eq!(
            render(&to_yaml(&value), &rtr_options()).is_ok(),
            accepted,
            "{marker}"
        );
    }
}

#[test]
fn active_blackhole_requires_irr_origin_enforcement() {
    let mut value = healthy_value();
    set_blackhole_policy(&mut value, "policy_ipv4", Some("propagate-unchanged"));
    set_path(
        &mut value,
        &["cfg", "filtering", "irrdb", "enforce_origin_in_as_set"],
        false.into(),
    );
    value["irrdb_info"]["AS4242_bundle"]["asns"] = serde_yaml::Value::Sequence(Vec::new());
    let items = refusals(render(&to_yaml(&value), &rtr_options()));
    assert!(
        items.iter().any(|item| item
            .contains("active blackhole policy requires irrdb.enforce_origin_in_as_set=true")),
        "{items:?}"
    );
}

#[test]
/// Load-bearing: deleting the refusal exits zero and overwrites the sentinel bytes.
fn cli_refusal_is_exit_two_and_writes_nothing() {
    use std::{fs, process::Command};
    let mut value = healthy_value();
    set_general_community(
        &mut value,
        "rpki_bgp_origin_validation_not_performed",
        serde_yaml::from_str("{std: '65000:1'}").unwrap(),
    );
    let tmp = tempfile::tempdir().unwrap();
    let context = tmp.path().join("context.yml");
    let out = tmp.path().join("out");
    let config = out.join("config.toml");
    fs::write(&context, to_yaml(&value)).unwrap();
    fs::create_dir(&out).unwrap();
    fs::write(&config, b"last-good\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .arg("--context")
        .arg(context)
        .arg("--out-dir")
        .arg(out)
        .arg("--rtr-cache")
        .arg("127.0.0.1:3323")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("communities.rpki_bgp_origin_validation_not_performed is configured; unsupported tagging/scrubbing cannot be rendered"),
        "{output:?}"
    );
    assert_eq!(fs::read(config).unwrap(), b"last-good\n");
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
    // The assignment, not the bare name: the export-policy comment block
    // names the knob prose-side in every render.
    assert!(!toml.contains("per_client_best = true"), "{toml}");
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
/// The real dump of the M106 site carries the white lists both raw and as a
/// synthetic bundle, plus the expanded control matrix; both forms render the
/// same tagged accept term, datasets, scrub, and explicit knob.
fn m106_sectioned_dump_renders_identically_and_exercises_both_surfaces() {
    let real = render(M106_SECTIONED, &Options::default()).expect("real M106 dump renders");
    let hand = render(M106_HAND, &Options::default()).expect("hand-authored M106 context renders");
    assert_eq!(real.files.len(), hand.files.len());
    for (path, content) in &real.files {
        assert_eq!(
            strip_fingerprint(content),
            strip_fingerprint(&hand.files[path]),
            "render divergence in {path}"
        );
    }
    let config = &real.files["config.toml"];
    assert_eq!(config.matches("rs_control_communities = true\n").count(), 3);
    assert!(
        real.files["datasets/client-as64500-1-prefixes.list"].contains("198.51.100.128/25 le 32\n")
    );
    assert_eq!(
        real.files["datasets/client-as64500-1-origins.list"],
        "64500\n64510\n"
    );
    assert!(real.files["policy/client-as64501-1.rpol"].contains(
        "term accept-white-list-route-1 { if route.prefix in client-as64501-1-white-list-route-1 && route.origin-as == 64501 { add community 65530:2; add large-community 64496:65530:2; accept } }"
    ));
    assert!(real.files["policy/rs-hygiene.rpol"].contains(
        "term scrub-white-list-tag { remove community 65530:2; remove large-community 64496:65530:2 }"
    ));
    for rpol in ["policy/rs-hygiene.rpol", "policy/client-as64501-1.rpol"] {
        let report = run_rpol_tests(&real.files[rpol]).unwrap();
        assert!(report.all_passed(), "{rpol}: {:?}", report.failures);
    }
    assert_eq!(
        real.receipt["clients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["white_list_routes"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1, 0]
    );
}

#[test]
/// The real dump of the M107 site carries `rfc8950: true` on both IPv6
/// clients; both forms render the uniform-fleet shape identically.
fn m107_sectioned_dump_renders_the_uniform_fleet_shape() {
    let real = render(M107_SECTIONED, &Options::default()).expect("real M107 dump renders");
    let hand = render(M107_HAND, &Options::default()).expect("hand-authored M107 context renders");
    assert_eq!(
        real.files.keys().collect::<Vec<_>>(),
        hand.files.keys().collect::<Vec<_>>()
    );
    for (path, content) in &real.files {
        assert_eq!(
            strip_fingerprint(content),
            strip_fingerprint(&hand.files[path]),
            "render divergence in {path}"
        );
    }
    let config = &real.files["config.toml"];
    assert_eq!(
        config
            .matches("families = [\"ipv4_unicast\", \"ipv6_unicast\"]\n")
            .count(),
        2
    );
    assert_eq!(
        config
            .matches("next_hop_ownership = \"strict_peer\"\n")
            .count(),
        2
    );
    assert_eq!(
        config.matches("rs_control_communities = false\n").count(),
        2
    );
    assert!(!config.contains("families = [\"ipv6_unicast\"]"));
    assert_eq!(
        real.files["datasets/client-as64500-1-prefixes.list"],
        "198.51.100.0/24 le 25\n2001:db8:1::/48\n"
    );
    for rpol in ["policy/rs-hygiene.rpol", "policy/client-as64500-1.rpol"] {
        let report = run_rpol_tests(&real.files[rpol]).unwrap();
        assert!(report.all_passed(), "{rpol}: {:?}", report.failures);
    }
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
            assert_eq!(err.exit_code(), Exit::InvalidInput);
            assert!(err.to_string().contains("rpki_roas"), "{err}");
        }
        other => panic!("expected parse error, got {other:?}"),
    }
}

#[test]
fn client_black_list_is_refused() {
    let entry: serde_yaml::Value =
        serde_yaml::from_str("[{prefix: 203.0.113.0, length: 24}]").unwrap();
    let mut value = healthy_value();
    set_client(
        &mut value,
        0,
        &["cfg", "filtering", "black_list_pref"],
        entry,
    );
    let items = refusals(render(&to_yaml(&value), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|i| i.contains("black_list_pref") && i.contains("client AS4242_1")),
        "{items:?}"
    );
}

fn white_listed_value() -> serde_yaml::Value {
    let mut value = healthy_value();
    set_client(
        &mut value,
        0,
        &["cfg", "filtering", "irrdb", "white_list_pref"],
        serde_yaml::from_str("[{prefix: 192.0.2.0, length: 24, max_length: 32}]").unwrap(),
    );
    set_client(
        &mut value,
        0,
        &["cfg", "filtering", "irrdb", "white_list_asn"],
        serde_yaml::from_str("[64500, AS64501]").unwrap(),
    );
    set_client(
        &mut value,
        0,
        &["cfg", "filtering", "irrdb", "white_list_route"],
        serde_yaml::from_str(
            "[{prefix: 198.51.100.0, length: 25, le: 26, asn: 64502}, \
             {prefix: 10.0.0.0, length: 8}, {prefix: '2001:db8::', length: 32}]",
        )
        .unwrap(),
    );
    set_general_community(
        &mut value,
        "route_validated_via_white_list",
        serde_yaml::from_str("{std: '65530:2', lrg: '65500:65530:2', ext: null}").unwrap(),
    );
    value
}

#[test]
fn irr_result_communities_are_refused_even_when_as_set_tagging_is_disabled() {
    for name in [
        "origin_present_in_as_set",
        "origin_not_present_in_as_set",
        "prefix_present_in_as_set",
        "prefix_not_present_in_as_set",
    ] {
        let mut value = healthy_value();
        set_path(
            &mut value,
            &["cfg", "filtering", "irrdb", "tag_as_set"],
            false.into(),
        );
        set_general_community(
            &mut value,
            name,
            serde_yaml::from_str("{std: '65000:1', lrg: null, ext: null}").unwrap(),
        );
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items.iter().any(|item| item.contains(name)),
            "{name}: {items:?}"
        );
    }
}

#[test]
/// Load-bearing: white lists render as extra IRR members plus ordered accept
/// terms ahead of the fail-closed tail, tagged only when the site tags and
/// scrubbed in shared hygiene; removing any half breaks an exact assertion.
fn white_lists_render_as_irr_members_and_ordered_accept_terms() {
    use serde_yaml::Value;
    let rendered = render(&to_yaml(&white_listed_value()), &rtr_options()).expect("render");
    let prefixes = &rendered.files["datasets/client-as4242-1-prefixes.list"];
    assert!(prefixes.contains("192.0.2.0/24 le 32\n"), "{prefixes}");
    let origins = &rendered.files["datasets/client-as4242-1-origins.list"];
    assert_eq!(origins, "4242\n4243\n64500\n64501\n");
    let client = &rendered.files["policy/client-as4242-1.rpol"];
    let expected = "dataset asn-set client-as4242-1-origins\n\
dataset prefix-set client-as4242-1-prefixes\n\
prefix-set client-as4242-1-white-list-route-1 { 10.0.0.0/8 le 32 }\n\
prefix-set client-as4242-1-white-list-route-2 { 198.51.100.0/25 le 26 }\n\
\npolicy client-as4242-1 {\n\
\x20   # IRR white list: accepted before origin/prefix enforcement.\n\
\x20   term accept-white-list-route-1 { if route.prefix in client-as4242-1-white-list-route-1 { add community 65530:2; add large-community 65500:65530:2; accept } }\n\
\x20   term accept-white-list-route-2 { if route.prefix in client-as4242-1-white-list-route-2 && route.origin-as == 64502 { add community 65530:2; add large-community 65500:65530:2; accept } }\n\
\x20   term accept-authorized {\n";
    assert!(client.contains(expected), "{client}");
    assert!(
        !client.contains("2001:db8::"),
        "IPv6 entry skipped on an IPv4 session"
    );
    assert!(client.contains(
        "test client-as4242-1-white-listed-route-is-accepted {\n    dataset client-as4242-1-origins { 64498 }\n    dataset client-as4242-1-prefixes { 192.0.2.0/24 }\n    route { prefix 10.0.0.0/8; as-path \"64497\" }\n    expect client-as4242-1 == accept\n}\n"
    ), "{client}");
    let cases = r#"
test wrong-origin-is-not-white-listed {
    dataset client-as4242-1-origins { 64498 }
    dataset client-as4242-1-prefixes { 192.0.2.0/24 }
    route { prefix 198.51.100.0/26; as-path "64503" }
    expect client-as4242-1 == reject
}
test bound-origin-is-white-listed {
    dataset client-as4242-1-origins { 64498 }
    dataset client-as4242-1-prefixes { 192.0.2.0/24 }
    route { prefix 198.51.100.0/26; as-path "64502" }
    expect client-as4242-1 == accept
}
test outside-window-is-not-white-listed {
    dataset client-as4242-1-origins { 64498 }
    dataset client-as4242-1-prefixes { 192.0.2.0/24 }
    route { prefix 198.51.100.0/27; as-path "64502" }
    expect client-as4242-1 == reject
}
"#;
    let report = run_rpol_tests(&format!("{client}\n{cases}")).unwrap();
    assert!(report.all_passed(), "{:?}", report.failures);
    let hygiene = &rendered.files["policy/rs-hygiene.rpol"];
    assert!(
        hygiene.contains(
            "    term reject-as-set { if route.as-path matches \"\\\\{\" { reject } }\n\
             \x20   # The white-list tag is set by the route server only; members cannot pre-tag.\n\
             \x20   term scrub-white-list-tag { remove community 65530:2; remove large-community 65500:65530:2 }\n"
        ),
        "{hygiene}"
    );
    assert!(run_rpol_tests(hygiene).unwrap().all_passed());
    assert_eq!(rendered.receipt["clients"][0]["white_list_routes"], 2);

    // tag_and_reject keeps the white-list terms ahead of the IRR reject terms.
    let mut tagged = white_listed_value();
    set_path(
        &mut tagged,
        &["cfg", "filtering", "reject_policy", "policy"],
        Value::String("tag_and_reject".into()),
    );
    set_general_community(
        &mut tagged,
        "reject_cause",
        serde_yaml::from_str("{std: '65520:dyn_val', lrg: null, ext: null}").unwrap(),
    );
    let client = render(&to_yaml(&tagged), &rtr_options())
        .expect("render")
        .files["policy/client-as4242-1.rpol"]
        .clone();
    let white = client.find("term accept-white-list-route-1").unwrap();
    let origin = client.find("term reject-irrdb-origin-as-filtered").unwrap();
    assert!(white < origin, "{client}");

    // Without tag_as_set nothing is tagged and nothing needs scrubbing.
    let mut untagged = white_listed_value();
    set_path(
        &mut untagged,
        &["cfg", "filtering", "irrdb", "tag_as_set"],
        Value::Bool(false),
    );
    let rendered = render(&to_yaml(&untagged), &rtr_options()).expect("render");
    assert!(rendered.files["policy/client-as4242-1.rpol"].contains(
        "term accept-white-list-route-1 { if route.prefix in client-as4242-1-white-list-route-1 { accept } }"
    ));
    assert!(!rendered.files["policy/rs-hygiene.rpol"].contains("scrub-white-list-tag"));

    for (tag, marker) in [
        (
            "{std: '65530:2', lrg: null, ext: 'rt:65530:2'}",
            "communities.route_validated_via_white_list.ext is unsupported",
        ),
        (
            "{std: 'rs_as:2', lrg: null, ext: null}",
            "communities.route_validated_via_white_list is malformed",
        ),
    ] {
        let mut value = white_listed_value();
        set_general_community(
            &mut value,
            "route_validated_via_white_list",
            serde_yaml::from_str(tag).unwrap(),
        );
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(items.iter().any(|i| i == marker), "{items:?}");
    }
}

/// The daemon's control matrix as arouteserver spells it for `rs_as`.
fn set_control_matrix(root: &mut serde_yaml::Value, rs_as: u64) {
    let std16 = rs_as <= u64::from(u16::MAX);
    let entries: [(&str, Option<String>, String); 9] = [
        (
            "do_not_announce_to_peer",
            Some("0:peer_as".into()),
            format!("{rs_as}:0:peer_as"),
        ),
        (
            "announce_to_peer",
            std16.then(|| format!("{rs_as}:peer_as")),
            format!("{rs_as}:1:peer_as"),
        ),
        (
            "do_not_announce_to_any",
            std16.then(|| format!("0:{rs_as}")),
            format!("{rs_as}:0:0"),
        ),
        ("prepend_once_to_peer", None, format!("{rs_as}:101:peer_as")),
        (
            "prepend_twice_to_peer",
            None,
            format!("{rs_as}:102:peer_as"),
        ),
        (
            "prepend_thrice_to_peer",
            None,
            format!("{rs_as}:103:peer_as"),
        ),
        ("prepend_once_to_any", None, format!("{rs_as}:101:0")),
        ("prepend_twice_to_any", None, format!("{rs_as}:102:0")),
        ("prepend_thrice_to_any", None, format!("{rs_as}:103:0")),
    ];
    for (name, std, lrg) in entries {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            "std".into(),
            std.map_or(serde_yaml::Value::Null, Into::into),
        );
        map.insert("lrg".into(), lrg.into());
        map.insert("ext".into(), serde_yaml::Value::Null);
        set_general_community(root, name, serde_yaml::Value::Mapping(map));
    }
}

#[test]
/// Load-bearing: the daemon's control matrix is fixed, so the knob renders
/// off for a site without control communities and on only when the site
/// configures exactly that matrix; any other value or an unsupported action
/// refuses with the offending key.
fn control_communities_follow_the_daemon_matrix() {
    use serde_yaml::Value;
    let off = render(&to_yaml(&healthy_value()), &rtr_options()).expect("render");
    let config = &off.files["config.toml"];
    assert_eq!(
        config.matches("rs_control_communities = false\n").count(),
        2
    );
    assert!(config.contains("# The site configures no control communities"));

    let mut on = healthy_value();
    set_control_matrix(&mut on, 65500);
    let config =
        render(&to_yaml(&on), &rtr_options()).expect("render").files["config.toml"].clone();
    assert_eq!(config.matches("rs_control_communities = true\n").count(), 2);
    assert!(!config.contains("rs_control_communities = false"));
    assert!(
        config.contains("# RFC 7947 §2.3.2 control communities: the site configures exactly the")
    );

    let mut missing = on.clone();
    set_general_community(
        &mut missing,
        "prepend_thrice_to_any",
        serde_yaml::from_str("{std: null, lrg: null, ext: null}").unwrap(),
    );
    assert_eq!(
        refusals(render(&to_yaml(&missing), &rtr_options())),
        [
            "communities.prepend_thrice_to_any: the daemon enforces a fixed control matrix; \
          expected std=null lrg=65500:103:0 ext=null, got std=null lrg=null ext=null"
        ]
    );

    let mut differs = on.clone();
    set_general_community(
        &mut differs,
        "prepend_once_to_peer",
        serde_yaml::from_str("{std: null, lrg: '65500:65504:peer_as', ext: null}").unwrap(),
    );
    assert_eq!(
        refusals(render(&to_yaml(&differs), &rtr_options())),
        [
            "communities.prepend_once_to_peer: the daemon enforces a fixed control matrix; \
          expected std=null lrg=65500:101:peer_as ext=null, got std=null \
          lrg=65500:65504:peer_as ext=null"
        ]
    );

    let mut extended = on.clone();
    set_general_community(
        &mut extended,
        "do_not_announce_to_peer",
        serde_yaml::from_str("{std: '0:peer_as', lrg: '65500:0:peer_as', ext: 'rt:0:peer_as'}")
            .unwrap(),
    );
    let items = refusals(render(&to_yaml(&extended), &rtr_options()));
    assert!(
        items
            .iter()
            .any(|i| i.starts_with("communities.do_not_announce_to_peer:")
                && i.ends_with("ext=rt:0:peer_as")),
        "{items:?}"
    );

    // A lone subset is still a mismatch: the daemon would act on the rest.
    let mut subset = healthy_value();
    set_general_community(
        &mut subset,
        "do_not_announce_to_peer",
        serde_yaml::from_str("{std: '0:peer_as', lrg: '65500:0:peer_as', ext: null}").unwrap(),
    );
    let items = refusals(render(&to_yaml(&subset), &rtr_options()));
    assert_eq!(items.len(), 8, "{items:?}");
    assert!(items.iter().all(|i| i.contains("fixed control matrix")));

    for name in [
        "add_noexport_to_any",
        "add_noadvertise_to_any",
        "add_noexport_to_peer",
        "add_noadvertise_to_peer",
    ] {
        let mut value = healthy_value();
        set_general_community(
            &mut value,
            name,
            serde_yaml::from_str("{std: '65281:peer_as', lrg: null, ext: null}").unwrap(),
        );
        assert_eq!(
            refusals(render(&to_yaml(&value), &rtr_options())),
            [format!(
                "communities.{name} is configured; the daemon has no equivalent action"
            )]
        );
    }

    // A 32-bit route-server ASN has no standard form embedding it.
    let mut wide = healthy_value();
    set_path(
        &mut wide,
        &["cfg", "rs_as"],
        Value::Number(4_200_000_000u64.into()),
    );
    set_control_matrix(&mut wide, 4_200_000_000);
    let config = render(&to_yaml(&wide), &rtr_options())
        .expect("render")
        .files["config.toml"]
        .clone();
    assert!(config.contains("rs_control_communities = true\n"));
    set_general_community(
        &mut wide,
        "do_not_announce_to_any",
        serde_yaml::from_str("{std: '0:65500', lrg: '4200000000:0:0', ext: null}").unwrap(),
    );
    assert_eq!(
        refusals(render(&to_yaml(&wide), &rtr_options())),
        [
            "communities.do_not_announce_to_any: the daemon enforces a fixed control matrix; \
          expected std=null lrg=4200000000:0:0 ext=null, got std=0:65500 \
          lrg=4200000000:0:0 ext=null"
        ]
    );
}

#[test]
/// Load-bearing proof: removing the effective-action gate, client-to-general
/// fallback, minute conversion, client timer override, receipt field, or
/// zero-limit filter breaks an exact config or receipt assertion below.
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
    assert!(!disabled.files["config.toml"].contains("max_prefix_restart_seconds"));
    for client in disabled.receipt["clients"].as_array().unwrap() {
        assert!(client["max_prefixes_ipv4"].is_null(), "{client}");
        assert!(client["max_prefixes_ipv6"].is_null(), "{client}");
        assert!(client["max_prefix_restart_seconds"].is_null(), "{client}");
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
    assert!(!toml.contains("max_prefix_restart_seconds"), "{toml}");
    assert!(
        enabled.receipt["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|client| client["max_prefix_restart_seconds"].is_null())
    );

    // General and client restart timers inherit leaf-wise and convert from
    // ARouteServer minutes to rustbgpd seconds.
    value["cfg"]["filtering"]["max_prefix"]["action"] = "restart".into();
    value["cfg"]["filtering"]["max_prefix"]["restart_after"] = 37.into();
    value["clients"][0]["cfg"]["filtering"]["max_prefix"]["action"] = "restart".into();
    value["clients"][0]["cfg"]["filtering"]["max_prefix"]["restart_after"] = 2.into();
    let restarted = render(&to_yaml(&value), &rtr_options()).expect("timed restart render");
    let toml = &restarted.files["config.toml"];
    assert!(
        toml.contains("max_prefixes_ipv4 = 5000\nmax_prefix_restart_seconds = 120"),
        "{toml}"
    );
    assert!(
        toml.contains("max_prefixes_ipv6 = 1000\nmax_prefix_restart_seconds = 2220"),
        "{toml}"
    );
    let clients = restarted.receipt["clients"].as_array().unwrap();
    assert_eq!(clients[0]["max_prefix_restart_seconds"], 120);
    assert_eq!(clients[1]["max_prefix_restart_seconds"], 2220);
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
/// Load-bearing proof: accepting an unsupported action or deleting the
/// required/nonzero/checked restart timer validation breaks a refusal; changing
/// the largest representable minute conversion breaks the boundary assertion.
fn restart_action_validates_timer_and_unsupported_actions_are_refused() {
    for action in ["block", "warning", "mystery"] {
        let mut value = healthy_value();
        let mut clients = value["clients"].clone();
        set_path(
            &mut clients[0],
            &["cfg", "filtering", "max_prefix", "action"],
            serde_yaml::Value::String(action.into()),
        );
        set_path(&mut value, &["clients"], clients);
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items.iter().any(|item| item.contains("client AS4242_1")
                && item.contains(&format!("action `{action}`"))),
            "{action}: {items:?}"
        );
    }

    for (restart_after, marker) in [
        (None, "requires restart_after > 0"),
        (Some(0), "requires restart_after > 0"),
        (Some(71_582_789), "u32-second maximum"),
    ] {
        let mut value = healthy_value();
        value["cfg"]["filtering"]["max_prefix"]["restart_after"] =
            restart_after.map_or(serde_yaml::Value::Null, |_| 37.into());
        value["clients"][0]["cfg"]["filtering"]["max_prefix"]["action"] = "restart".into();
        value["clients"][0]["cfg"]["filtering"]["max_prefix"]["limit_ipv4"] = 0.into();
        if let Some(minutes) = restart_after {
            value["clients"][0]["cfg"]["filtering"]["max_prefix"]["restart_after"] = minutes.into();
        }
        let items = refusals(render(&to_yaml(&value), &rtr_options()));
        assert!(
            items
                .iter()
                .any(|item| item.contains("client AS4242_1") && item.contains(marker)),
            "{restart_after:?}: {items:?}"
        );
    }

    let mut boundary = healthy_value();
    boundary["clients"][0]["cfg"]["filtering"]["max_prefix"]["action"] = "restart".into();
    boundary["clients"][0]["cfg"]["filtering"]["max_prefix"]["restart_after"] = 71_582_788.into();
    let rendered = render(&to_yaml(&boundary), &rtr_options()).expect("boundary restart");
    assert!(
        rendered.files["config.toml"].contains("max_prefix_restart_seconds = 4294967280"),
        "{}",
        rendered.files["config.toml"]
    );
}

#[test]
/// Load-bearing proof: defaulting an omitted value to false, reversing
/// client-over-general precedence, emitting the accepted-route keys for a
/// true value, or emitting any limit key without an active shutdown/restart
/// positive limit breaks an asserted key below.
fn rejected_route_counting_selects_the_received_prefix_keys() {
    fn client_keys(rendered: &rs_config_render::Rendered, ip: &str) -> Vec<String> {
        let config = &rendered.files["config.toml"];
        let start = config
            .find(&format!("address = \"{ip}\""))
            .unwrap_or_else(|| panic!("client {ip} missing from {config}"));
        let block = &config[start..];
        let block = block.find("\n[[").map_or(block, |end| &block[..end]);
        block
            .lines()
            .filter(|line| line.starts_with("max_prefixes_"))
            .map(str::to_owned)
            .collect()
    }

    // ARouteServer 1.23.2 defaults an omitted value to true: the pre-policy
    // received bounds are the faithful translation, not accepted-only ones.
    let mut omitted = healthy_value();
    omitted["cfg"]["filtering"]["max_prefix"]
        .as_mapping_mut()
        .expect("max_prefix mapping")
        .remove(serde_yaml::Value::String(
            "count_rejected_routes".to_owned(),
        ));
    let rendered = render(&to_yaml(&omitted), &rtr_options()).expect("omitted value renders");
    let keys = client_keys(&rendered, "192.0.2.11");
    assert!(
        keys.iter()
            .any(|key| key.starts_with("max_prefixes_received_ipv4 = ")),
        "{keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|key| key.starts_with("max_prefixes_ipv4 = ")),
        "{keys:?}"
    );

    // A general true value is inherited by every client and lands in the
    // receipt under the received key only.
    let mut inherited = healthy_value();
    set_path(
        &mut inherited,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let rendered = render(&to_yaml(&inherited), &rtr_options()).expect("inherited true renders");
    for client in rendered.receipt["clients"].as_array().expect("clients") {
        if client["max_prefixes_received_ipv4"].is_null()
            && client["max_prefixes_received_ipv6"].is_null()
        {
            continue;
        }
        assert!(client["max_prefixes_ipv4"].is_null(), "{client}");
        assert!(client["max_prefixes_ipv6"].is_null(), "{client}");
    }
    assert!(
        rendered.files["config.toml"].contains("max_prefixes_received_ipv6 = "),
        "{}",
        rendered.files["config.toml"]
    );
    assert!(!rendered.files["config.toml"].contains("\nmax_prefixes_ipv"));

    // A client can select the accepted-route model over an inherited true.
    let mut overridden = inherited.clone();
    let mut clients = overridden["clients"].clone();
    set_path(
        &mut clients[0],
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(false),
    );
    set_path(&mut overridden, &["clients"], clients);
    let rendered = render(&to_yaml(&overridden), &rtr_options()).expect("override renders");
    let keys = client_keys(&rendered, "192.0.2.11");
    assert!(
        keys.iter().any(|key| key.starts_with("max_prefixes_ipv")),
        "{keys:?}"
    );
    assert!(!keys.iter().any(|key| key.contains("received")), "{keys:?}");
    assert!(
        rendered.files["config.toml"].contains("max_prefixes_received_ipv"),
        "sibling keeps the inherited received model: {}",
        rendered.files["config.toml"]
    );

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
    let rendered = render(&to_yaml(&disabled), &rtr_options()).expect("disabled max-prefix");
    assert!(client_keys(&rendered, "192.0.2.11").is_empty());

    // A timed restart with only zero/unset family limits is also inactive.
    let mut zero_limits = healthy_value();
    set_path(
        &mut zero_limits,
        &["cfg", "filtering", "max_prefix", "action"],
        serde_yaml::Value::String("restart".into()),
    );
    set_path(
        &mut zero_limits,
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    let mut clients = zero_limits["clients"].clone();
    for client in clients.as_sequence_mut().expect("clients list") {
        set_path(
            client,
            &["cfg", "filtering", "max_prefix", "action"],
            serde_yaml::Value::String("restart".into()),
        );
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
    let rendered =
        render(&to_yaml(&zero_limits), &rtr_options()).expect("zero limits disable enforcement");
    assert!(!rendered.files["config.toml"].contains("max_prefixes_"));
    assert!(!rendered.files["config.toml"].contains("max_prefix_restart_seconds"));
    assert!(
        rendered.receipt["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|client| client["max_prefix_restart_seconds"].is_null()
                && client["max_prefixes_received_ipv4"].is_null())
    );
}

#[test]
/// M90 fixture proof: the checked-in differential context keeps every member
/// on the accepted-route model; flipping one member to ARouteServer's default
/// moves exactly that member's limits to the received keys with the same
/// values, and the receipt reports them under the emitted key only.
fn m90_member_with_rejected_route_counting_renders_received_limits() {
    let mut value: serde_yaml::Value = serde_yaml::from_str(M90_HAND).expect("M90 context parses");
    let mut clients = value["clients"].clone();
    set_path(
        &mut clients[2],
        &["cfg", "filtering", "max_prefix", "count_rejected_routes"],
        serde_yaml::Value::Bool(true),
    );
    set_path(&mut value, &["clients"], clients);
    let rendered = render(&to_yaml(&value), &Options::default()).expect("M90 variant renders");
    let config = &rendered.files["config.toml"];
    assert_eq!(
        config.matches("\nmax_prefixes_ipv4 = 100\n").count(),
        2,
        "{config}"
    );
    assert_eq!(
        config.matches("\nmax_prefixes_ipv6 = 12000\n").count(),
        2,
        "{config}"
    );
    assert_eq!(
        config
            .matches("\nmax_prefixes_received_ipv4 = 100\n")
            .count(),
        1,
        "{config}"
    );
    assert_eq!(
        config
            .matches("\nmax_prefixes_received_ipv6 = 12000\n")
            .count(),
        1,
        "{config}"
    );
    let receipt = rendered.receipt["clients"].as_array().expect("clients");
    let flipped = receipt
        .iter()
        .find(|client| client["id"] == "AS64502_1")
        .expect("flipped member in receipt");
    assert_eq!(flipped["max_prefixes_received_ipv4"], 100);
    assert_eq!(flipped["max_prefixes_received_ipv6"], 12000);
    assert!(flipped["max_prefixes_ipv4"].is_null());
    assert!(flipped["max_prefixes_ipv6"].is_null());
    let untouched = receipt
        .iter()
        .find(|client| client["id"] == "AS64500_1")
        .expect("untouched member in receipt");
    assert_eq!(untouched["max_prefixes_ipv4"], 100);
    assert!(untouched["max_prefixes_received_ipv4"].is_null());
}
