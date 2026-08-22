use std::fs;

use rs_config_render::ixp_manager::{Error, SchemaVersion, render_document};
use rs_config_render::ixp_manager_host::RenderBinding;
use rustbgpd_policy::rpol::{RpolFile, run_rpol_tests};
use rustbgpd_policy::sets::SetStore;

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const V2_FILTERS: &[u8] = include_bytes!("fixtures/ixp-manager-v2-ui-filters.json");
const V2_SUPPORTED: &[u8] = include_bytes!("fixtures/ixp-manager-v2-supported.json");
const SECRET: &str = "mcWsqMdzGwTKt67g";
const DEFAULT_TRANSIT: [u32; 15] = [
    174, 701, 1299, 2914, 3257, 3320, 3356, 3491, 4134, 5511, 6453, 6461, 6762, 6830, 7018,
];

fn digest(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .fold(String::new(), |mut out, byte| {
            std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}")).unwrap();
            out
        })
}

fn content_digest(contents: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(contents)
        .iter()
        .fold(String::new(), |mut out, byte| {
            std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}")).unwrap();
            out
        })
}

fn value() -> serde_json::Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn v2_value(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

fn binding() -> RenderBinding {
    RenderBinding::new(
        "b2-rs1-lan1-ipv4",
        std::path::Path::new("/var/lib/rustbgpd/b2-rs1-lan1-ipv4"),
    )
    .unwrap()
}

fn rendered(input: &serde_json::Value) -> Result<rs_config_render::ixp_manager::Candidate, Error> {
    render_document(
        &serde_json::to_vec(input).unwrap(),
        300,
        &binding(),
        SchemaVersion::V1,
    )
}

fn rendered_v2(
    input: &serde_json::Value,
) -> Result<rs_config_render::ixp_manager::Candidate, Error> {
    render_document(
        &serde_json::to_vec(input).unwrap(),
        300,
        &binding(),
        SchemaVersion::V2,
    )
}

fn receive_filter(
    id: u64,
    order: u64,
    peer: Option<u32>,
    prefix: Option<String>,
    action: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id, "customer_id": 2,
        "peer": peer.map(|asn| serde_json::json!({"customer_id": 4, "asn": asn})),
        "received_prefix": prefix, "advertised_prefix": null, "protocol": 4,
        "action_advertise": "AS_IS", "action_receive": action, "order_by": order
    })
}

fn with_receive_filters(filters: Vec<serde_json::Value>) -> serde_json::Value {
    let mut input = v2_value(V2_SUPPORTED);
    input["complete"]["ui_filter_count"] = filters.len().into();
    input["ui_filters"] = filters.into();
    input
}

fn assert_terms(source: &str, policy: &str, expected: &[&str]) {
    let file = RpolFile::parse(source).unwrap();
    let compiled = file
        .compile_policy(policy, &[], &mut SetStore::new())
        .unwrap();
    assert_eq!(
        compiled.policies[0]
            .terms
            .iter()
            .map(|term| term.name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        expected
    );
}

fn assert_policy_tests(source: &str, tests: &str) {
    let report = run_rpol_tests(&format!("{source}\n{tests}")).unwrap();
    assert!(report.all_passed(), "{:?}", report.failures);
}

#[test]
fn supported_render_is_deterministic_and_explicit() {
    let first = render_document(FIXTURE, 300, &binding(), SchemaVersion::V1).unwrap();
    assert_eq!(
        first.files,
        render_document(FIXTURE, 300, &binding(), SchemaVersion::V1)
            .unwrap()
            .files
    );
    assert_eq!(first.files.len(), 4);
    let aliases = &first.files["birdwatcher-protocol-aliases.conf"];
    assert_eq!(aliases, "pb_0003_as42=10.1.0.36@master4\n");
    assert!(!aliases.contains("PCH DNS"));
    assert!(!aliases.contains(SECRET));
    let config = &first.files["config.toml"];
    for expected in [
        "listen_addresses = [\"192.0.2.18\"]",
        "runtime_state_dir = \"/var/lib/rustbgpd/b2-rs1-lan1-ipv4\"",
        "path = \"/var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock\"",
        "next_hop_ownership = \"strict_peer\"",
        "per_client_best = true",
        "rs_control_communities = true",
        "interpret_rfc1997 = true",
        "max_prefix_restart_seconds = 300",
        "md5_password = \"mcWsqMdzGwTKt67g\"",
        "export_chain = [\"ixp-transparent-export\", \"ixp-manager-own-as-export-scrub\"]",
    ] {
        assert!(config.contains(expected), "missing {expected}");
    }
    let client = &first.files["policy/client-3.rpol"];
    assert!(client.contains("asn-set client-3-origins { 42 }"));
    assert!(client.contains("31.135.128.0/19"));
    assert!(client.contains("term accept-authorized { accept }"));
    let mut loose = value();
    loose["clients"][0]["more_specifics"] = true.into();
    assert!(
        rendered(&loose).unwrap().files["policy/client-3.rpol"].contains("31.135.128.0/19 le 24")
    );
    let mut transit = value();
    transit["policy"]["no_transit"]["asns"] = serde_json::json!([42]);
    let hygiene = &rendered(&transit).unwrap().files["policy/ixp-hygiene.rpol"];
    assert!(hygiene.contains("if route.as-path matches \"_(42)_\""));
    assert!(!hygiene.contains("peer.asn in ixp-manager-no-transit"));
    assert!(hygiene.contains("remove large-community 65501:*:*"));
    assert_terms(
        hygiene,
        "ixp-manager-own-as-export-scrub",
        &["remove-own-as-large-communities", "accept-unmatched"],
    );
    assert_policy_tests(
        hygiene,
        "test own-as-scrub-executes { route { large-communities [65501:1:2, 64496:3:4, 65501:5:6] } expect ixp-manager-own-as-export-scrub == accept }",
    );
    let mut maximum = value();
    maximum["policy"]["minimum_prefix_length"] = 32.into();
    assert!(
        !rendered(&maximum).unwrap().files["policy/ixp-hygiene.rpol"]
            .contains("ixp-manager-too-specific")
    );
}

#[test]
fn effective_default_no_transit_is_v2_only_exact_and_executable() {
    let mut default = v2_value(V2_SUPPORTED);
    default["policy"]["no_transit"]["source"] = "IXP_MANAGER_EFFECTIVE_DEFAULT".into();
    default["policy"]["no_transit"]["asns"] = serde_json::to_value(DEFAULT_TRANSIT).unwrap();
    let files = rendered_v2(&default).unwrap().files;
    assert_eq!(
        files["birdwatcher-protocol-aliases.conf"],
        "pb_0001_as1213=10.1.0.10@master4\npb_0004_as112=10.1.0.6@master4\n"
    );
    let hygiene = &files["policy/ixp-hygiene.rpol"];
    assert!(hygiene.contains(
        "asn-set ixp-manager-no-transit-asns { 174, 701, 1299, 2914, 3257, 3320, 3356, 3491, 4134, 5511, 6453, 6461, 6762, 6830, 7018 }"
    ));
    assert!(hygiene.contains(
        "term reject-transit-leak { if route.as-path matches \"_(174|701|1299|2914|3257|3320|3356|3491|4134|5511|6453|6461|6762|6830|7018)_\" { reject } }"
    ));
    assert_policy_tests(
        hygiene,
        r#"
test pinned-default-rejects { route { prefix 77.72.72.0/21; as-path "174"; rpki valid } expect ixp-manager-hygiene == reject }
test unlisted-accepts { route { prefix 77.72.72.0/21; as-path "64512"; rpki valid } expect ixp-manager-hygiene == accept }
"#,
    );

    let mut empty = default.clone();
    empty["policy"]["no_transit"]["asns"] = serde_json::json!([]);
    assert!(
        !rendered_v2(&empty).unwrap().files["policy/ixp-hygiene.rpol"]
            .contains("reject-transit-leak")
    );
    for invalid in [
        serde_json::json!([0]),
        serde_json::json!([701, 174]),
        serde_json::json!([174, 174]),
    ] {
        let mut input = default.clone();
        input["policy"]["no_transit"]["asns"] = invalid;
        assert_eq!(
            rendered_v2(&input).unwrap_err(),
            Error::Refused("invalid no-transit data")
        );
    }
    let mut implicit = empty;
    implicit["policy"]["no_transit"]["source"] = "IXP_MANAGER_IMPLICIT_DEFAULT".into();
    assert_eq!(
        rendered_v2(&implicit).unwrap_err(),
        Error::Refused("unsupported no-transit source")
    );
    let mut v1 = value();
    v1["policy"]["no_transit"]["source"] = "IXP_MANAGER_EFFECTIVE_DEFAULT".into();
    v1["policy"]["no_transit"]["asns"] = serde_json::to_value(DEFAULT_TRANSIT).unwrap();
    assert!(rendered(&v1).is_err());
}

#[test]
fn generated_reason_policies_execute_at_exact_boundaries_and_terms() {
    let files = rendered(&value()).unwrap().files;
    let hygiene = &files["policy/ixp-hygiene.rpol"];
    assert_terms(
        hygiene,
        "ixp-manager-hygiene",
        &[
            "reject-too-specific",
            "reject-as-path-too-short",
            "reject-as-path-too-long",
            "reject-rpki-invalid",
        ],
    );
    let path64 = std::iter::repeat_n("42", 64).collect::<Vec<_>>().join(" ");
    let path65 = std::iter::repeat_n("42", 65).collect::<Vec<_>>().join(" ");
    assert_policy_tests(
        hygiene,
        &format!(
            r#"
test empty-as-path {{
    route {{ prefix 31.135.128.0/19; as-path ""; rpki valid }}
    expect ixp-manager-hygiene == reject
}}
test as-path-64 {{
    route {{ prefix 31.135.128.0/19; as-path "{path64}"; rpki valid }}
    expect ixp-manager-hygiene == accept
}}
test as-path-65 {{
    route {{ prefix 31.135.128.0/19; as-path "{path65}"; rpki valid }}
    expect ixp-manager-hygiene == reject
}}
"#,
        ),
    );

    let client = &files["policy/client-3.rpol"];
    assert!(
        hygiene.contains("term reject-as-path-too-short { if route.as-path.len == 0 { reject } }")
    );
    assert!(
        hygiene.contains("term reject-as-path-too-long { if route.as-path.len >= 65 { reject } }")
    );
    assert!(client.contains(
        "term reject-irrdb-origin-as-filtered { if !(route.origin-as in client-3-origins) { reject } }"
    ));
    assert!(client.contains(
        "term reject-irrdb-prefix-filtered { if !(route.prefix in client-3-prefixes) { reject } }"
    ));
    assert_terms(
        client,
        "client-3",
        &[
            "reject-first-as-not-peer-as",
            "reject-irrdb-origin-as-filtered",
            "reject-irrdb-prefix-filtered",
            "accept-authorized",
        ],
    );
    assert_policy_tests(
        client,
        r#"
test nonempty-first-as-mismatch {
    route { prefix 31.135.128.0/19; as-path "43 42" }
    expect client-3 == reject
}
test bad-irrdb-origin {
    route { prefix 31.135.128.0/19; as-path "42 43" }
    expect client-3 == reject
}
test bad-irrdb-prefix {
    route { prefix 31.135.160.0/19; as-path "42" }
    expect client-3 == reject
}
test authorized-fallthrough {
    route { prefix 31.135.128.0/19; as-path "42" }
    expect client-3 == accept
}
"#,
    );
}

#[test]
fn strict_schema_completion_and_refusal_matrix_fail_closed() {
    let forged: RenderBinding = serde_json::from_value(serde_json::json!({
        "router_handle": "b2-rs1-lan1-ipv4",
        "runtime_state_dir": "/var/lib/rustbgpd/foreign"
    }))
    .unwrap();
    assert!(matches!(
        render_document(FIXTURE, 300, &forged, SchemaVersion::V1),
        Err(Error::Refused("invalid router host binding"))
    ));
    let refuses = |pointer: &str, replacement: serde_json::Value| {
        let mut input = value();
        *input.pointer_mut(pointer).unwrap() = replacement;
        assert!(rendered(&input).is_err(), "{pointer} unexpectedly rendered");
    };
    refuses("/schema", serde_json::json!("wrong"));
    refuses("/ixp_manager/version", serde_json::json!("7.5.0"));
    refuses("/router/type", serde_json::json!("collector"));
    refuses("/router/protocol", serde_json::json!(5));
    refuses("/router/quarantine", serde_json::json!(true));
    refuses("/router/bgp_lc", serde_json::json!(false));
    refuses("/policy/no_transit/source", serde_json::json!("default"));
    refuses(
        "/unsupported/active_ui_filters",
        serde_json::json!([{"customer_id":3,"filter_ids":[]}]),
    );
    refuses(
        "/unsupported/route_server_skin_files",
        serde_json::json!(["bird2/standard.foil.php"]),
    );
    refuses("/clients/0/irr_filter", serde_json::json!(false));
    refuses("/clients/0/origins", serde_json::json!([]));
    refuses("/clients/0/origins/0", serde_json::json!(0));
    refuses("/clients/0/prefixes", serde_json::json!([]));
    refuses("/clients/0/address", serde_json::json!("not-an-ip"));
    refuses("/clients/0/address", serde_json::json!("2001:db8::1"));
    refuses(
        "/clients/0/peering_ips",
        serde_json::json!(["10.1.0.36", "10.1.0.37"]),
    );
    refuses("/clients/0/auth/value", serde_json::json!("changeme"));
    refuses("/clients/0/auth/value", serde_json::json!("x".repeat(81)));
    refuses("/policy/rtr_caches", serde_json::json!(["127.0.0.1:0"]));
    refuses("/policy/rtr_caches", serde_json::json!([]));
    refuses("/complete/marker", serde_json::json!("END"));
    refuses("/complete/handle", serde_json::json!("other"));
    refuses("/complete/client_count", serde_json::json!(2));
    refuses("/router/skip_md5", serde_json::json!(true));
    let mut unknown = value();
    unknown["router"]["mystery"] = true.into();
    assert_eq!(rendered(&unknown).unwrap_err(), Error::Input);
    let mut dropped = value();
    dropped["clients"][0]["more_specifics"] = true.into();
    dropped["clients"][0]["prefixes"] = serde_json::json!(["31.135.128.0/25"]);
    assert!(rendered(&dropped).is_err());
    let mut repeated = value();
    let mut client = repeated["clients"][0].clone();
    client["customer_id"] = 4.into();
    client["vlan_interface_id"] = 4.into();
    client["address"] = "10.1.0.37".into();
    client["peering_ips"] = serde_json::json!(["10.1.0.37"]);
    repeated["clients"].as_array_mut().unwrap().push(client);
    repeated["complete"]["client_count"] = 2.into();
    assert!(rendered(&repeated).is_err());
    let mut no_auth = value();
    no_auth["clients"][0]["auth"] = serde_json::json!({"type":"none"});
    assert!(rendered(&no_auth).is_ok());
    no_auth["router"]["skip_md5"] = true.into();
    assert!(rendered(&no_auth).is_ok());
}

#[test]
fn v1_and_v2_dispatch_are_strict_and_v1_output_stays_legacy() {
    let v1 = render_document(FIXTURE, 300, &binding(), SchemaVersion::V1).unwrap();
    for (name, expected) in [
        (
            "config.toml",
            "7ed88dd78d15be8b4e0949afbcc9479afa13d852db472e1d2d7b37ff71f48685",
        ),
        (
            "policy/client-3.rpol",
            "1ac6975245e79cd317de99870071fcac768f616ae7e2cf7fef1680e35ce292f7",
        ),
        (
            "policy/ixp-hygiene.rpol",
            "326b2121b023329d2b4a7542a2510d01220782552fcfd4e7920de1df5f658094",
        ),
    ] {
        assert_eq!(content_digest(&v1.files[name]), expected, "{name} drifted");
    }
    assert!(!v1.files["config.toml"].contains("client-3-receive"));
    assert!(!v1.files["policy/client-3.rpol"].contains("ui-advertise"));
    assert!(render_document(FIXTURE, 300, &binding(), SchemaVersion::V2).is_err());
    assert!(render_document(V2_SUPPORTED, 300, &binding(), SchemaVersion::V1).is_err());
    assert!(render_document(V2_SUPPORTED, 300, &binding(), SchemaVersion::V2).is_ok());
    let mut v1_null = value();
    v1_null["ui_filters"] = serde_json::Value::Null;
    assert!(rendered(&v1_null).is_err());
    let mut v1_null = value();
    v1_null["complete"]["ui_filter_count"] = serde_json::Value::Null;
    assert!(rendered(&v1_null).is_err());
    let mut v3 = v2_value(V2_SUPPORTED);
    v3["schema"] = "rustbgpd.ixp-manager.router-config/v3".into();
    assert!(rendered_v2(&v3).is_err());
}

#[test]
fn protocol_aliases_are_sorted_family_exact_and_bounded() {
    let mut v2 = v2_value(V2_SUPPORTED);
    v2["clients"].as_array_mut().unwrap().reverse();
    assert_eq!(
        rendered_v2(&v2).unwrap().files["birdwatcher-protocol-aliases.conf"],
        "pb_0001_as1213=10.1.0.10@master4\npb_0004_as112=10.1.0.6@master4\n"
    );

    let mut v6 = value();
    v6["router"]["protocol"] = 6.into();
    v6["router"]["peering_ip"] = "2001:db8::1".into();
    v6["clients"][0]["vlan_interface_id"] = 12345.into();
    v6["clients"][0]["address"] = "2001:db8::2".into();
    v6["clients"][0]["peering_ips"] = serde_json::json!(["2001:db8::2"]);
    v6["clients"][0]["prefixes"] = serde_json::json!(["2001:db8:1::/48"]);
    assert_eq!(
        rendered(&v6).unwrap().files["birdwatcher-protocol-aliases.conf"],
        "pb_12345_as42=2001:db8::2@master6\n"
    );

    let mut capped = value();
    let template = capped["clients"][0].clone();
    let mut clients = (0..4097_u64)
        .map(|index| {
            let mut client = template.clone();
            let asn = 64_000 + index;
            let address = format!("10.{}.{}.1", index / 256, index % 256);
            client["customer_id"] = (index + 1).into();
            client["vlan_interface_id"] = (index + 1).into();
            client["asn"] = asn.into();
            client["address"] = address.clone().into();
            client["peering_ips"] = serde_json::json!([address]);
            client["origins"] = serde_json::json!([asn]);
            client
        })
        .collect::<Vec<_>>();
    let extra = clients.pop().unwrap();
    capped["clients"] = clients.into();
    capped["complete"]["client_count"] = 4096.into();
    let aliases = &rendered(&capped).unwrap().files["birdwatcher-protocol-aliases.conf"];
    assert_eq!(aliases.lines().count(), 4096);
    assert!(aliases.starts_with("pb_0001_as64000=10.0.0.1@master4\n"));
    assert!(aliases.ends_with("pb_4096_as68095=10.15.255.1@master4\n"));
    capped["clients"].as_array_mut().unwrap().push(extra);
    capped["complete"]["client_count"] = 4097.into();
    assert_eq!(
        rendered(&capped).err(),
        Some(Error::Refused("Birdwatcher protocol alias cap exceeded"))
    );
}

#[test]
fn v2_filter_policies_preserve_order_direction_and_reachability() {
    let full = rendered_v2(&v2_value(V2_FILTERS)).unwrap().files;
    assert_eq!(
        content_digest(&full.values().map(String::as_str).collect::<String>()),
        "4b860dad0edf95be0af40c2e873338994aa464d3342187d72a74fae60049f391"
    );
    let import = &full["policy/client-1.rpol"];
    assert_terms(
        import,
        "client-1",
        &[
            "reject-first-as-not-peer-as",
            "reject-irrdb-origin-as-filtered",
            "reject-irrdb-prefix-filtered",
            "ui-advertise-31",
            "ui-advertise-33",
            "accept-authorized",
        ],
    );
    assert!(import.contains("term ui-advertise-31 { add large-community 65501:0:0 }"));
    assert!(import.contains("route.prefix == 77.72.72.0/21 { add large-community 65501:102:112"));
    assert!(!import.contains("ui-advertise-35"));
    assert_terms(
        import,
        "client-1-receive",
        &["ui-receive-31", "accept-unmatched"],
    );
    assert!(!import.contains("ui-receive-33"));
    assert!(!import.contains("ui-receive-35"));
    assert!(!full["policy/client-4.rpol"].contains("ui-"));
    assert!(
        full["config.toml"]
            .contains("export_policy_chain = [\"ixp-transparent-export\", \"client-1-receive\", \"ixp-manager-own-as-export-scrub\"]")
    );
    assert_eq!(full["config.toml"].matches("client-1-receive").count(), 1);
    assert_policy_tests(
        &full["policy/client-4.rpol"],
        r#"
test other-client-has-no-ui-filter-effects {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-4 == accept
}
"#,
    );
    assert_policy_tests(
        import,
        r#"
test advertise-rules-accumulate-after-irr {
    route { prefix 77.72.72.0/21; as-path "1213" }
    expect client-1 == accept with large-community 65501:0:0, large-community 65501:102:112
}
test full-first-rule-denies-receive {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == reject
}
"#,
    );

    let supported = rendered_v2(&v2_value(V2_SUPPORTED)).unwrap().files;
    let client = &supported["policy/client-1.rpol"];
    assert_terms(
        client,
        "client-1-receive",
        &[
            "ui-receive-cell-0000",
            "ui-receive-cell-0001",
            "ui-receive-cell-0002",
            "ui-receive-cell-0003",
            "accept-unmatched",
        ],
    );
    assert!(client.contains(
        "route.as-path matches \"^112_\" && route.prefix == 192.175.48.0/24 { prepend as 112 3; accept }"
    ));
    assert!(client.contains("prepend as path-first 1; accept"));
    assert!(!client.contains("ui-receive-31"));
    assert_policy_tests(
        client,
        r#"
test prepend-continues-to-as-is {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 3
}
test wrong-received-prefix-keeps-global-prepend {
    route { prefix 198.51.100.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 1
}
test wrong-first-as-keeps-global-prepend {
    route { prefix 192.175.48.0/24; as-path "113" }
    expect client-1-receive == accept with prepend as 113 1
}
test global-prepend-uses-path-first-not-origin {
    route { prefix 203.0.113.0/24; as-path "64501 64500" }
    expect client-1-receive == accept with prepend as 64501 1
}
test global-prepend-is-unscoped {
    route { prefix 203.0.114.0/24; as-path "64501 64500" }
    expect client-1-receive == accept with prepend as 64501 1
}
"#,
    );

    let mut unscoped = v2_value(V2_SUPPORTED);
    unscoped["ui_filters"].as_array_mut().unwrap().remove(1);
    unscoped["ui_filters"][0]["received_prefix"] = serde_json::Value::Null;
    unscoped["complete"]["ui_filter_count"] = 2.into();
    let unscoped = &rendered_v2(&unscoped).unwrap().files["policy/client-1.rpol"];
    assert!(unscoped.contains("term ui-receive-32 { prepend as path-first 1 }"));
    assert_policy_tests(
        unscoped,
        r#"
test unscoped-global-prepend {
    route { prefix 203.0.113.0/24; as-path "64501 64500" }
    expect client-1-receive == accept with prepend as 64501 1
}
"#,
    );

    let mut guarded = v2_value(V2_SUPPORTED);
    guarded["clients"][0]["prefixes"] = serde_json::json!(["77.72.72.0/21", "87.32.0.0/12"]);
    let guarded = &rendered_v2(&guarded).unwrap().files["policy/client-1.rpol"];
    assert!(guarded.contains(
        "term ui-advertise-33 { if route.prefix == 77.72.72.0/21 { add large-community 65501:102:112 } }"
    ));
    assert_policy_tests(
        guarded,
        r#"
test wrong-advertised-prefix-is-a-no-op {
    route { prefix 87.32.0.0/12; as-path "1213" }
    expect client-1 == accept
}
"#,
    );
}

#[test]
fn v2_all_action_variants_execute_with_exact_effects() {
    let mut input = v2_value(V2_SUPPORTED);
    input["clients"][0]["prefixes"] = serde_json::json!([
        "77.72.72.0/21",
        "87.32.0.0/12",
        "91.189.88.0/21",
        "185.1.0.0/24"
    ]);
    input["ui_filters"] = serde_json::json!([
        {
            "id": 41, "customer_id": 2, "peer": {"customer_id": 4, "asn": 112},
            "received_prefix": "192.0.2.0/24", "advertised_prefix": "77.72.72.0/21",
            "protocol": 4, "action_advertise": "NO_ADVERTISE",
            "action_receive": "PREPEND_ONCE", "order_by": 1
        },
        {
            "id": 42, "customer_id": 2, "peer": {"customer_id": 4, "asn": 112},
            "received_prefix": "192.175.48.0/24", "advertised_prefix": "87.32.0.0/12",
            "protocol": 4, "action_advertise": "PREPEND_ONCE",
            "action_receive": "PREPEND_TWICE", "order_by": 2
        },
        {
            "id": 43, "customer_id": 2, "peer": {"customer_id": 4, "asn": 112},
            "received_prefix": "198.51.100.0/24", "advertised_prefix": "91.189.88.0/21",
            "protocol": 4, "action_advertise": "PREPEND_TWICE",
            "action_receive": "PREPEND_THRICE", "order_by": 3
        },
        {
            "id": 44, "customer_id": 2, "peer": {"customer_id": 4, "asn": 112},
            "received_prefix": "203.0.113.0/24", "advertised_prefix": "185.1.0.0/24",
            "protocol": 4, "action_advertise": "PREPEND_THRICE",
            "action_receive": "AS_IS", "order_by": 4
        },
        {
            "id": 45, "customer_id": 2, "peer": null,
            "received_prefix": null, "advertised_prefix": null, "protocol": null,
            "action_advertise": "AS_IS", "action_receive": "AS_IS", "order_by": 5
        }
    ]);
    input["complete"]["ui_filter_count"] = 5.into();
    let source = &rendered_v2(&input).unwrap().files["policy/client-1.rpol"];
    assert_terms(
        source,
        "client-1",
        &[
            "reject-first-as-not-peer-as",
            "reject-irrdb-origin-as-filtered",
            "reject-irrdb-prefix-filtered",
            "ui-advertise-41",
            "ui-advertise-42",
            "ui-advertise-43",
            "ui-advertise-44",
            "accept-authorized",
        ],
    );
    assert!(!source.contains("ui-advertise-45"));
    assert_policy_tests(
        source,
        r#"
test advertise-deny-control {
    route { prefix 77.72.72.0/21; as-path "1213" }
    expect client-1 == accept with large-community 65501:0:112
}
test advertise-prepend-once-control {
    route { prefix 87.32.0.0/12; as-path "1213" }
    expect client-1 == accept with large-community 65501:101:112
}
test advertise-prepend-twice-control {
    route { prefix 91.189.88.0/21; as-path "1213" }
    expect client-1 == accept with large-community 65501:102:112
}
test advertise-prepend-thrice-control {
    route { prefix 185.1.0.0/24; as-path "1213" }
    expect client-1 == accept with large-community 65501:103:112
}
test receive-prepend-once {
    route { prefix 192.0.2.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 1
}
test receive-prepend-twice {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 2
}
test receive-prepend-thrice {
    route { prefix 198.51.100.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 3
}
test receive-as-is-terminates {
    route { prefix 203.0.113.0/24; as-path "112" }
    expect client-1-receive == accept
}
"#,
    );

    let scoped =
        |id, action| receive_filter(id, id, Some(112), Some("192.175.48.0/24".into()), action);
    let scoped = with_receive_filters(vec![
        scoped(1, "PREPEND_ONCE"),
        scoped(2, "PREPEND_TWICE"),
        scoped(3, "AS_IS"),
    ]);
    let source = &rendered_v2(&scoped).unwrap().files["policy/client-1.rpol"];
    assert_policy_tests(
        source,
        "test scoped-miss-accepts-unchanged { route { prefix 198.51.100.0/24; as-path \"64501\" } expect client-1-receive == accept }",
    );
}

#[test]
fn v2_receive_terminal_pruning_is_scope_aware_and_off_router_peers_are_valid() {
    let mut input = v2_value(V2_FILTERS);
    input["ui_filters"][0]["peer"] = serde_json::json!({"customer_id": 999, "asn": 64500});
    let source = &rendered_v2(&input).unwrap().files["policy/client-1.rpol"];
    assert!(source.contains("ui-receive-31"));
    assert!(source.contains("ui-receive-33"));
    assert!(source.contains("ui-receive-35"));

    let mut terminal = v2_value(V2_SUPPORTED);
    terminal["ui_filters"][0]["received_prefix"] = "203.0.113.0/24".into();
    terminal["ui_filters"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": 37, "customer_id": 2, "peer": null,
            "received_prefix": null, "advertised_prefix": null, "protocol": 4,
            "action_advertise": "AS_IS", "action_receive": "NO_ADVERTISE", "order_by": 7
        }));
    terminal["complete"]["ui_filter_count"] = 4.into();
    let source = &rendered_v2(&terminal).unwrap().files["policy/client-1.rpol"];
    assert!(source.contains("ui-receive-35"));
    assert!(!source.contains("ui-receive-37"));

    terminal["ui_filters"][2]["action_receive"] = "NO_ADVERTISE".into();
    let source = &rendered_v2(&terminal).unwrap().files["policy/client-1.rpol"];
    assert_policy_tests(
        source,
        r#"
test prepend-is-discarded-by-later-deny {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == reject
}
"#,
    );

    let mut nonoverlap = v2_value(V2_SUPPORTED);
    nonoverlap["ui_filters"][0]["received_prefix"] = "203.0.113.0/24".into();
    nonoverlap["ui_filters"].as_array_mut().unwrap().insert(
        0,
        serde_json::json!({
            "id": 34, "customer_id": 2, "peer": {"customer_id": 4, "asn": 112},
            "received_prefix": "198.51.100.0/24", "advertised_prefix": null, "protocol": 4,
            "action_advertise": "AS_IS", "action_receive": "PREPEND_ONCE", "order_by": 2
        }),
    );
    nonoverlap["complete"]["ui_filter_count"] = 4.into();
    let source = &rendered_v2(&nonoverlap).unwrap().files["policy/client-1.rpol"];
    assert_terms(
        source,
        "client-1-receive",
        &[
            "ui-receive-34",
            "ui-receive-32",
            "ui-receive-33",
            "ui-receive-35",
            "accept-unmatched",
        ],
    );
    assert_policy_tests(
        source,
        r#"
test first-nonoverlapping-prepend {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 2
}
test second-nonoverlapping-prepend {
    route { prefix 198.51.100.0/24; as-path "112" }
    expect client-1-receive == accept with prepend as 112 1
}
"#,
    );
}

#[test]
fn v2_overlapping_receive_cells_preserve_order_scope_and_path_first() {
    let mut input = v2_value(V2_SUPPORTED);
    input["ui_filters"]
        .as_array_mut()
        .unwrap()
        .push(receive_filter(37, 7, None, None, "NO_ADVERTISE"));
    input["complete"]["ui_filter_count"] = 4.into();
    let source = &rendered_v2(&input).unwrap().files["policy/client-1.rpol"];
    assert_terms(
        source,
        "client-1-receive",
        &[
            "ui-receive-cell-0000",
            "ui-receive-cell-0001",
            "ui-receive-cell-0002",
            "ui-receive-cell-0003",
            "accept-unmatched",
        ],
    );
    assert!(source.contains("prefix-set client-1-ui-receive-prefixes"));
    assert!(source.contains("route.as-path matches \"^112_\" && route.prefix == 192.175.48.0/24 { prepend as 112 3; accept }"));
    assert!(source.contains("prepend as path-first 1; accept"));
    assert!(!source.contains("prepend as origin"));
    assert!(!source.contains("prepend as peer"));
    assert_policy_tests(
        source,
        r#"
test overlap-accumulates-in-order {
    route { prefix 192.175.48.0/24; as-path "112 64500" }
    expect client-1-receive == accept with prepend as 112 3
}
test peer-miss-keeps-global-prepend {
    route { prefix 192.175.48.0/24; as-path "113 64500" }
    expect client-1-receive == accept with prepend as 113 1
}
test prefix-miss-keeps-global-prepend {
    route { prefix 198.51.100.0/24; as-path "112 64500" }
    expect client-1-receive == accept with prepend as 112 1
}
test other-cell-uses-path-first-not-origin-or-peer {
    route { prefix 198.51.100.0/24; as-path "64501 64500" }
    peer { asn 65010 }
    expect client-1-receive == accept with prepend as 64501 1
}
test empty-global-path-fails-closed {
    route { prefix 198.51.100.0/24; as-path "" }
    expect client-1-receive == error absent-prepend-operand
}
test leading-set-global-path-fails-closed {
    route { prefix 198.51.100.0/24; as-path "{64500 64501}" }
    expect client-1-receive == error absent-prepend-operand
}
"#,
    );

    let mut deny = v2_value(V2_SUPPORTED);
    deny["ui_filters"].as_array_mut().unwrap().insert(
        2,
        receive_filter(
            34,
            5,
            Some(112),
            Some("192.175.48.0/24".into()),
            "NO_ADVERTISE",
        ),
    );
    deny["complete"]["ui_filter_count"] = 4.into();
    let source = &rendered_v2(&deny).unwrap().files["policy/client-1.rpol"];
    assert_policy_tests(
        source,
        r#"
test no-advertise-terminates-before-later-as-is {
    route { prefix 192.175.48.0/24; as-path "112" }
    expect client-1-receive == reject
}
"#,
    );
}

#[test]
fn v2_overlapping_receive_prepend_and_cell_bounds_are_exact() {
    let mut filters = (1..=85)
        .map(|id| receive_filter(id, id, None, None, "PREPEND_THRICE"))
        .collect::<Vec<_>>();
    filters.push(receive_filter(86, 86, None, None, "AS_IS"));
    let source = &rendered_v2(&with_receive_filters(filters.clone()))
        .unwrap()
        .files["policy/client-1.rpol"];
    assert!(source.contains("prepend as path-first 255; accept"));
    assert_policy_tests(
        source,
        r#"
test accumulated-255-executes {
    route { prefix 198.51.100.0/24; as-path "64501" }
    expect client-1-receive == accept with prepend as 64501 255
}
"#,
    );
    filters.insert(85, receive_filter(87, 86, None, None, "PREPEND_ONCE"));
    filters[86]["order_by"] = 87.into();
    assert_eq!(
        rendered_v2(&with_receive_filters(filters)).unwrap_err(),
        Error::Refused("receive prepend accumulation exceeds 255")
    );

    let cells = |peer_count: u64| {
        let mut filters = vec![receive_filter(1, 1, None, None, "PREPEND_ONCE")];
        for index in 0..peer_count {
            let id = index + 2;
            filters.push(receive_filter(
                id,
                id,
                Some(64_000 + index as u32),
                None,
                "PREPEND_ONCE",
            ));
        }
        for index in 0..63_u64 {
            let id = peer_count + index + 2;
            filters.push(receive_filter(
                id,
                id,
                None,
                Some(format!("198.18.0.{}/32", index + 1)),
                "PREPEND_ONCE",
            ));
        }
        let id = filters.len() as u64 + 1;
        filters.push(receive_filter(id, id, None, None, "AS_IS"));
        with_receive_filters(filters)
    };
    let at_cap = rendered_v2(&cells(63)).unwrap();
    let source = &at_cap.files["policy/client-1.rpol"];
    assert_eq!(source.matches("term ui-receive-cell-").count(), 4096);
    let compiled = RpolFile::parse(source)
        .unwrap()
        .compile_policy("client-1-receive", &[], &mut SetStore::new())
        .unwrap();
    assert_eq!(compiled.policies[0].terms.len(), 4097);
    assert_eq!(
        rendered_v2(&cells(64)).unwrap_err(),
        Error::Refused("receive UI-filter cell cap exceeded")
    );

    let mut dead_axes = cells(64);
    let rows = dead_axes["ui_filters"].as_array_mut().unwrap();
    let terminal = rows.pop().unwrap();
    rows.insert(1, receive_filter(130, 2, None, None, "PREPEND_ONCE"));
    rows.insert(2, terminal);
    for (index, row) in rows.iter_mut().enumerate() {
        row["order_by"] = ((index + 1) as u64).into();
    }
    dead_axes["complete"]["ui_filter_count"] = rows.len().into();
    let source = &rendered_v2(&dead_axes).unwrap().files["policy/client-1.rpol"];
    assert_eq!(source.matches("term ui-receive-cell-").count(), 1);
    assert!(source.contains("prepend as path-first 2; accept"));
}

#[test]
fn v2_refuses_malformed_unrepresentable_and_capped_filter_sets() {
    let refuses = |mut input: serde_json::Value, pointer: &str, value: serde_json::Value| {
        *input.pointer_mut(pointer).unwrap() = value;
        assert!(
            rendered_v2(&input).is_err(),
            "{pointer} unexpectedly rendered"
        );
    };
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/peer/asn",
        serde_json::Value::Null,
    );
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/received_prefix",
        "192.175.48.1/24".into(),
    );
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/received_prefix",
        "192.175.48.0/024".into(),
    );
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/advertised_prefix",
        "2001:db8::/32".into(),
    );
    refuses(v2_value(V2_SUPPORTED), "/ui_filters/1/protocol", 6.into());
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/customer_id",
        999.into(),
    );
    refuses(v2_value(V2_SUPPORTED), "/ui_filters/0/order_by", 0.into());
    refuses(v2_value(V2_SUPPORTED), "/ui_filters/0/order_by", 4.into());
    refuses(
        v2_value(V2_SUPPORTED),
        "/ui_filters/1/action_receive",
        "UNKNOWN".into(),
    );
    for field in ["peer", "received_prefix", "advertised_prefix", "protocol"] {
        let mut missing = v2_value(V2_SUPPORTED);
        missing["ui_filters"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            rendered_v2(&missing).is_err(),
            "missing {field} unexpectedly rendered"
        );
    }

    let mut v6 = v2_value(V2_SUPPORTED);
    v6["router"]["protocol"] = 6.into();
    v6["router"]["peering_ip"] = "2001:db8::1".into();
    v6["policy"]["minimum_prefix_length"] = 64.into();
    for (index, (address, prefix)) in [
        ("2001:db8::2", "2001:db8:1::/48"),
        ("2001:db8::3", "2001:db8:2::/48"),
    ]
    .into_iter()
    .enumerate()
    {
        v6["clients"][index]["address"] = address.into();
        v6["clients"][index]["peering_ips"] = serde_json::json!([address]);
        v6["clients"][index]["prefixes"] = serde_json::json!([prefix]);
    }
    v6["ui_filters"][1]["protocol"] = 6.into();
    v6["ui_filters"][1]["received_prefix"] = "2001:db8:2::/48".into();
    v6["ui_filters"][1]["advertised_prefix"] = "2001:db8:1::/48".into();
    v6["ui_filters"][0]["protocol"] = 6.into();
    v6["ui_filters"][0]["received_prefix"] = "2001:db8:3::/064".into();
    assert!(rendered_v2(&v6).is_err());

    let template = serde_json::json!({
        "id": 1, "customer_id": 2, "peer": null,
        "received_prefix": null, "advertised_prefix": null, "protocol": 4,
        "action_advertise": "AS_IS", "action_receive": "AS_IS", "order_by": 1
    });
    let mut per_client = v2_value(V2_SUPPORTED);
    per_client["ui_filters"] = serde_json::Value::Array(
        (1..=257)
            .map(|id| {
                let mut filter = template.clone();
                filter["id"] = id.into();
                filter["order_by"] = id.into();
                filter
            })
            .collect(),
    );
    per_client["complete"]["ui_filter_count"] = 257.into();
    let mut per_client_at_cap = per_client.clone();
    per_client_at_cap["ui_filters"]
        .as_array_mut()
        .unwrap()
        .pop();
    per_client_at_cap["complete"]["ui_filter_count"] = 256.into();
    assert!(rendered_v2(&per_client_at_cap).is_ok());
    assert!(rendered_v2(&per_client).is_err());

    let mut total = v2_value(V2_SUPPORTED);
    let mut customers = vec![2_u64, 4];
    for index in 0..15_u64 {
        let customer = 100 + index;
        let asn = 65_000 + index as u32;
        let address = format!("10.200.{index}.1");
        let mut client = total["clients"][0].clone();
        client["customer_id"] = customer.into();
        client["vlan_interface_id"] = (100 + index).into();
        client["name"] = format!("cap-client-{index}").into();
        client["asn"] = asn.into();
        client["address"] = address.clone().into();
        client["peering_ips"] = serde_json::json!([address]);
        client["origins"] = serde_json::json!([asn]);
        total["clients"].as_array_mut().unwrap().push(client);
        customers.push(customer);
    }
    total["complete"]["client_count"] = 17.into();
    let mut filters = Vec::new();
    let mut id = 1_u64;
    for (index, customer) in customers.into_iter().enumerate() {
        for order in 1..=if index == 16 { 1 } else { 256_u64 } {
            let mut filter = template.clone();
            filter["id"] = id.into();
            filter["customer_id"] = customer.into();
            filter["order_by"] = order.into();
            filters.push(filter);
            id += 1;
        }
    }
    total["ui_filters"] = filters.into();
    total["complete"]["ui_filter_count"] = 4097.into();
    let mut total_at_cap = total.clone();
    total_at_cap["ui_filters"].as_array_mut().unwrap().pop();
    total_at_cap["complete"]["ui_filter_count"] = 4096.into();
    assert!(rendered_v2(&total_at_cap).is_ok());
    assert!(rendered_v2(&total).is_err());
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn run_cli(
    temp: &tempfile::TempDir,
    out: &std::path::Path,
    fail: bool,
    input_mode: u32,
    extra: &[&str],
) -> std::process::Output {
    use std::process::Command;
    let input = temp.path().join("input.json");
    fs::write(&input, FIXTURE).unwrap();
    set_mode(&input, input_mode);
    let log = temp.path().join("checker.log");
    let checker = temp.path().join("checker.sh");
    fs::write(&checker, "#!/bin/sh\n[ ! -e \"$OUT/render-receipt.json\" ] || exit 90\nprintf '%s\\n' \"$*\" >> \"$LOG\"\nif [ \"$1\" = --version ]; then echo \"rustbgpd 0.65.0 $SECRET\"; echo \"$SECRET\" >&2; exit 0; fi\n[ \"$FAIL\" = 0 ] || exit 91\n").unwrap();
    set_mode(&checker, 0o700);
    let runtime = temp.path().join("b2-rs1-lan1-ipv4");
    Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["--input-format", "ixp-manager-v1", "--context"])
        .arg(&input)
        .arg("--out-dir")
        .arg(out)
        .args(["--max-prefix-restart-seconds", "300", "--check-with"])
        .arg(&checker)
        .args(["--router-handle", "b2-rs1-lan1-ipv4"])
        .arg("--runtime-state-dir")
        .arg(&runtime)
        .env("OUT", out)
        .env("LOG", log)
        .env("SECRET", SECRET)
        .env("FAIL", if fail { "1" } else { "0" })
        .args(extra)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn cli_enforces_private_checker_order_receipt_last_and_redaction() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("candidate");
    fs::create_dir(&out).unwrap();
    set_mode(&out, 0o700);
    let result = run_cli(&temp, &out, false, 0o600, &[]);
    assert!(result.status.success(), "{result:?}");
    assert!(!String::from_utf8_lossy(&result.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(SECRET));
    let receipt = fs::read(out.join("render-receipt.json")).unwrap();
    assert!(
        !receipt
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
    );
    let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(receipt["strict_check"]["binary_version"], "rustbgpd 0.65.0");
    assert_eq!(receipt["strict_check"]["passed"], true);
    assert_eq!(receipt["counts"]["clients"], 1);
    assert_eq!(receipt["counts"]["prefixes"], 1);
    assert_eq!(receipt["counts"]["origins"], 1);
    assert_eq!(
        receipt["host"],
        serde_json::to_value(
            RenderBinding::new("b2-rs1-lan1-ipv4", &temp.path().join("b2-rs1-lan1-ipv4")).unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        receipt["input"]["sha256"],
        digest(&temp.path().join("input.json"))
    );
    assert_eq!(mode(&out), 0o700);
    assert_eq!(mode(&out.join("policy")), 0o700);
    for path in [
        "birdwatcher-protocol-aliases.conf",
        "config.toml",
        "policy/ixp-hygiene.rpol",
        "policy/client-3.rpol",
        "render-receipt.json",
    ] {
        assert_eq!(mode(&out.join(path)), 0o600);
        if path != "render-receipt.json" {
            assert_eq!(receipt["generated_files"][path], digest(&out.join(path)));
        }
    }
    let log = fs::read_to_string(temp.path().join("checker.log")).unwrap();
    let lines = log.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "--version");
    assert_eq!(
        lines[1],
        format!("--check --strict {}", out.join("config.toml").display())
    );

    let failed = temp.path().join("failed");
    let result = run_cli(&temp, &failed, true, 0o600, &[]);
    assert_eq!(result.status.code(), Some(9));
    assert!(failed.join("config.toml").is_file());
    assert!(!failed.join("render-receipt.json").exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(SECRET));
    let nonempty = temp.path().join("nonempty");
    fs::create_dir(&nonempty).unwrap();
    set_mode(&nonempty, 0o700);
    fs::write(nonempty.join("old"), b"stale").unwrap();
    assert_eq!(
        run_cli(&temp, &nonempty, false, 0o600, &[]).status.code(),
        Some(8)
    );
    let public = temp.path().join("public");
    fs::create_dir(&public).unwrap();
    set_mode(&public, 0o755);
    assert_eq!(
        run_cli(&temp, &public, false, 0o600, &[]).status.code(),
        Some(8)
    );
    assert_eq!(
        run_cli(&temp, &temp.path().join("public-input"), false, 0o644, &[])
            .status
            .code(),
        Some(2)
    );
    let legacy = temp.path().join("legacy");
    assert_eq!(
        run_cli(&temp, &legacy, false, 0o600, &["--min-prefixes", "1"])
            .status
            .code(),
        Some(2)
    );
    let empty = temp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    set_mode(&empty, 0o700);
    let out_link = temp.path().join("output-link");
    symlink(&empty, &out_link).unwrap();
    assert_eq!(
        run_cli(&temp, &out_link, false, 0o600, &[]).status.code(),
        Some(8)
    );
    fs::remove_file(temp.path().join("input.json")).unwrap();
    let input_target = temp.path().join("input-target.json");
    fs::write(&input_target, FIXTURE).unwrap();
    set_mode(&input_target, 0o600);
    symlink(&input_target, temp.path().join("input.json")).unwrap();
    assert_eq!(
        run_cli(&temp, &temp.path().join("linked-input"), false, 0o600, &[])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn workflow_and_gpl_source_only_boundaries_are_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = fs::read_to_string(root.join(".github/workflows/ixp-compat.yml")).unwrap();
    for path in ["tools/rs-config-render/**", "integrations/ixp-manager/**"] {
        assert_eq!(workflow.matches(&format!("- \"{path}\"")).count(), 2);
    }
    for source in [
        "tools/rs-config-render/src/ixp_manager.rs",
        "tools/rs-config-render/src/lib.rs",
        "tools/rs-config-render/src/main.rs",
    ] {
        let text = fs::read_to_string(root.join(source)).unwrap();
        assert!(!text.contains("include_str!(\"../../../integrations/"));
        assert!(!text.contains("include_bytes!(\"../../../integrations/"));
    }
    let foil =
        fs::read_to_string(root.join(
            "integrations/ixp-manager/gpl-2.0-only/api/v4/router/server/rustbgpd/json.foil.php",
        ))
        .unwrap();
    for required in [
        "'schema' => 'rustbgpd.ixp-manager.router-config/v2'",
        "'ui_filters' => $uiFilters",
        "'ui_filter_count' => count( $uiFilters )",
        "Customer::whereIn( 'id', $peerIds )",
    ] {
        assert!(foil.contains(required), "Foil v2 source lost {required}");
    }
    let binary = fs::read(env!("CARGO_BIN_EXE_rs-config-render")).unwrap();
    assert!(
        !binary
            .windows(b"integrations/ixp-manager/gpl-2.0-only".len())
            .any(|w| w == b"integrations/ixp-manager/gpl-2.0-only")
    );
    for manifest in [
        ".github/workflows/release.yml",
        "scripts/build-packages.sh",
        "Dockerfile",
    ] {
        assert!(
            !fs::read_to_string(root.join(manifest))
                .unwrap()
                .contains("integrations/ixp-manager")
        );
    }
    let allowed = |entries: &[&str]| {
        entries
            .iter()
            .all(|path| !path.starts_with("integrations/"))
    };
    assert!(allowed(&["rustbgpd", "share/rustbgpd/config.toml"]));
    assert!(!allowed(&[
        "rustbgpd",
        "integrations/ixp-manager/gpl-2.0-only/LICENSE"
    ]));
}

#[test]
fn missing_checker_is_refused_before_any_write() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.json");
    fs::write(&input, FIXTURE).unwrap();
    set_mode(&input, 0o600);
    let out = temp.path().join("candidate");
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["--input-format", "ixp-manager-v1", "--context"])
        .arg(&input)
        .arg("--out-dir")
        .arg(&out)
        .args(["--max-prefix-restart-seconds", "300", "--check-with"])
        .arg(temp.path().join("no-such-rustbgpd"))
        .args(["--router-handle", "b2-rs1-lan1-ipv4"])
        .arg("--runtime-state-dir")
        .arg(temp.path().join("b2-rs1-lan1-ipv4"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("strict checker is unavailable"),
        "{output:?}"
    );
    assert!(
        !out.exists(),
        "an unavailable checker must not leave a candidate"
    );
}
