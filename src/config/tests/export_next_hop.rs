//! Export `set_next_hop` is refused where it can reach a labeled-unicast or
//! VPN route: the route keeps its received labels, which are valid only at
//! the received next hop (RFC 8277 §3.2.2).

use super::*;

const LABELED_FAMILIES: [&str; 4] = [
    "ipv4_labeled_unicast",
    "ipv6_labeled_unicast",
    "l3vpn_ipv4_unicast",
    "l3vpn_ipv6_unicast",
];

/// Load `body` (appended to a minimal `[global]`) with `rpol` as the only
/// `.rpol` file.
fn load(rpol: &str, body: &str) -> Result<Config, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), rpol).expect("write rpol");
    let toml = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]
{body}"#
    );
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(&toml),
    )
    .expect("write config");
    load_dir(&dir)
}

fn toml_set_next_hop(next_hop: &str) -> String {
    format!(
        r#"
[policy.definitions.nh]
default_action = "permit"

[[policy.definitions.nh.statements]]
action = "permit"
match_as_path_length_ge = 0
set_next_hop = "{next_hop}"

[policy.definitions.plain]
default_action = "permit"
"#
    )
}

const UNUSED_RPOL: &str = "policy unused { term t { accept } }";

#[test]
fn set_next_hop_refused_for_each_labeled_and_vpn_family() {
    for family in LABELED_FAMILIES {
        for next_hop in ["self", "192.0.2.9", "2001:db8::9"] {
            let body = format!(
                r#"{}
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
families = ["ipv4_unicast", "{family}"]
export_policy_chain = ["nh"]
"#,
                toml_set_next_hop(next_hop)
            );
            let error = load(UNUSED_RPOL, &body)
                .expect_err("labeled/VPN export set_next_hop must fail validation");
            for needle in [
                family,
                "export policy \"nh\"",
                "neighbor 192.0.2.1",
                "RFC 8277",
            ] {
                assert!(
                    error.contains(needle),
                    "{family} {next_hop}: missing {needle:?} in {error}"
                );
            }
        }
    }
}

/// The binding named in the error carries the group the chain came from.
#[test]
fn set_next_hop_refusal_names_peer_group_binding() {
    let body = format!(
        r#"{}
[peer_groups.rr]
families = ["l3vpn_ipv6_unicast"]
export_policy_chain = ["nh"]

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65001
peer_group = "rr"
"#,
        toml_set_next_hop("self")
    );
    let error = load(UNUSED_RPOL, &body).expect_err("group binding must fail");
    assert!(
        error.contains("neighbor 192.0.2.1 (peer_group \"rr\")"),
        "{error}"
    );
    assert!(error.contains("l3vpn_ipv6_unicast"), "{error}");
}

/// A shared policy bound only to unicast peers stays legal, and a `.rpol`
/// term whose family guard excludes every labeled family (directly or
/// through an `else` branch) stays legal on a peer that carries them.
#[test]
fn set_next_hop_allowed_when_unreachable_for_labeled_families() {
    let shared = format!(
        r#"{}
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
export_policy_chain = ["nh"]

[[neighbors]]
address = "192.0.2.2"
remote_asn = 65003
families = ["l3vpn_ipv4_unicast"]
export_policy_chain = ["plain"]
"#,
        toml_set_next_hop("self")
    );
    load(UNUSED_RPOL, &shared).expect("unicast-only binding is legal");

    let all_families = r#"
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast", "ipv4_labeled_unicast", "ipv6_labeled_unicast", "l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"]
export_policy_chain = ["guarded"]
"#;
    for rpol in [
        "policy guarded {
            term v4 { if route.family == ipv4-unicast { set next-hop self } }
            term v6 { if route.family == ipv6-unicast && route.med >= 10 { set next-hop 2001:db8::9 } }
            term done { accept }
        }",
        "policy guarded {
            term t { if route.family != ipv6-unicast { accept } else { set next-hop self; accept } }
        }",
    ] {
        let config = load(rpol, all_families).unwrap_or_else(|error| panic!("{rpol}: {error}"));
        let (_, export) = config
            .effective_policy_chains_for_neighbor(&config.neighbors[0])
            .expect("chains resolve");
        assert!(export.is_some(), "the guarded chain is bound");
    }
}

/// Guards the analysis cannot prove exclusive are refused, with the term and
/// the scoping hint in the error.
#[test]
fn set_next_hop_refused_when_guard_does_not_exclude_labeled_families() {
    let body = r#"
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
families = ["ipv4_unicast", "ipv4_labeled_unicast"]
export_policy_chain = ["shared"]
"#;
    for (rpol, term) in [
        (
            "policy shared { term all { set next-hop self; accept } }",
            "all",
        ),
        (
            "policy shared { term edge { if route.prefix == 10.0.0.0/8 { set next-hop self } accept } }",
            "edge",
        ),
        (
            "policy shared { term v4 { if route.family == ipv4-unicast || route.med == 5 { set next-hop self } accept } }",
            "v4",
        ),
    ] {
        let error = load(rpol, body).expect_err(rpol);
        for needle in [
            "export policy \"shared\"",
            term,
            "ipv4_labeled_unicast",
            "route.family == ipv4-unicast",
        ] {
            assert!(
                error.contains(needle),
                "{rpol}: missing {needle:?} in {error}"
            );
        }
    }
}
