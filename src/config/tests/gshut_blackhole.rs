use super::*;

#[test]
fn effective_chain_appends_gshut_when_honor_enabled_for_ebgp() {
    let cfg = parse(&gshut_toml(true, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    assert!(
        !chain.policies.is_empty(),
        "implicit GShut policy must be present"
    );
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
        }],
        "tail statement must match GRACEFUL_SHUTDOWN"
    );
    assert_eq!(
        stmt.modifications.set_local_pref,
        Some(0),
        "RFC 8326 §4 receiver MUST set local_pref to a low value"
    );
}

#[test]
fn effective_chain_does_not_append_gshut_for_ibgp() {
    // remote_asn == local asn (65001) → iBGP, exempt per RFC 8326 §4.
    let cfg = parse(&gshut_toml(true, 65001)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "iBGP must not get the implicit GShut rule (LOCAL_PREF preserved within an AS)"
    );
}

#[test]
fn effective_chain_does_not_append_gshut_when_honor_disabled() {
    let cfg = parse(&gshut_toml(false, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "honor_graceful_shutdown = false must leave the chain untouched"
    );
}

#[test]
fn effective_chain_gshut_runs_after_operator_chain() {
    // Implicit GShut rule must sit at the END of the chain so its
    // set_local_pref=0 wins over an operator policy that also sets
    // local_pref. PolicyChain::evaluate accumulates with last-writer-
    // wins on scalar fields; running first would let the operator's
    // value silently overwrite the GShut demotion.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[policy.definitions.deny-everything]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["deny-everything"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    assert!(
        chain.policies.len() >= 2,
        "chain must contain operator's deny-everything + implicit GShut policy"
    );
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
        }],
        "implicit GShut policy must be at chain tail (last index), AFTER operator policies"
    );
}

#[test]
fn gshut_demotion_wins_over_operator_local_pref() {
    // Headline RFC 8326 §4 invariant: when both an operator policy
    // and the implicit GShut rule set local_pref on the same route,
    // the GShut demotion must win — otherwise an operator who set
    // local_pref = 200 on EBGP imports would silently defeat the
    // RFC 8326 receiver semantics for any GShut-tagged path.
    use rustbgpd_policy::{RouteContext, evaluate_chain};
    use rustbgpd_wire::{AspaValidation, RpkiValidation};
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[policy.definitions.bump-local-pref]
default_action = "permit"

  [[policy.definitions.bump-local-pref.statements]]
  prefix = "0.0.0.0/0"
  ge = 0
  action = "permit"
  set_local_pref = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["bump-local-pref"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");

    // Build a context for a route carrying GRACEFUL_SHUTDOWN.
    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        std::net::Ipv4Addr::new(10, 0, 0, 0),
        8,
    ));
    let comms = [rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN];
    let ctx = RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let result = evaluate_chain(Some(&chain), &ctx);
    assert_eq!(
        result.action,
        rustbgpd_policy::PolicyAction::Permit,
        "GShut-tagged route must permit through operator + implicit chain"
    );
    assert_eq!(
        result.modifications.set_local_pref,
        Some(0),
        "GShut demotion at chain tail MUST overwrite operator's set_local_pref=200; \
         got {:?}",
        result.modifications.set_local_pref
    );
}

#[test]
fn effective_chain_appends_blackhole_when_honor_enabled_for_ebgp() {
    let cfg = parse(&blackhole_toml(true, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_BLACKHOLE,
        }],
        "tail statement must match BLACKHOLE"
    );
    assert_eq!(
        stmt.modifications.communities_add,
        vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        ],
        "RFC 7999 receiver scoping must preserve BLACKHOLE and add NO_ADVERTISE"
    );
}

#[test]
fn effective_chain_does_not_append_blackhole_for_ibgp() {
    let cfg = parse(&blackhole_toml(true, 65001)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "iBGP must not get the implicit BLACKHOLE receiver rule"
    );
}

#[test]
fn effective_chain_does_not_append_blackhole_when_honor_disabled() {
    let cfg = parse(&blackhole_toml(false, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "honor_blackhole = false must leave the chain untouched"
    );
}

#[test]
fn blackhole_fib_discard_defaults_off() {
    let cfg = parse(&blackhole_toml(false, 65002)).unwrap();
    assert!(!cfg.global.install_blackhole_discard);
    assert!(!cfg.global.allow_blackhole_broad_prefixes);
}

#[test]
fn blackhole_fib_discard_flags_parse() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true
install_blackhole_discard = true
allow_blackhole_broad_prefixes = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#;
    let cfg = parse(toml).unwrap();
    assert!(cfg.global.honor_blackhole);
    assert!(cfg.global.install_blackhole_discard);
    assert!(cfg.global.allow_blackhole_broad_prefixes);
}

#[test]
fn blackhole_fib_discard_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\ninstall_blackhole_discard = true\nallow_blackhole_broad_prefixes = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(diff.blackhole_fib_discard_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn blackhole_honor_change_with_fib_discard_marks_fib_restart_only() {
    let old_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = false\ninstall_blackhole_discard = true\n",
    );
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = true\ninstall_blackhole_discard = true\n",
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(!diff.global_changed);
    assert!(!diff.honor_blackhole_changed);
    assert!(diff.blackhole_fib_discard_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn blackhole_tail_readds_marker_and_no_advertise_after_operator_remove() {
    use rustbgpd_policy::{RouteContext, evaluate_chain};
    use rustbgpd_wire::{AspaValidation, RpkiValidation};

    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true

[global.telemetry]
log_format = "json"

[policy.definitions.strip-communities]
default_action = "permit"

  [[policy.definitions.strip-communities.statements]]
  prefix = "0.0.0.0/0"
  ge = 0
  action = "permit"
  set_community_remove = ["BLACKHOLE", "NO_ADVERTISE"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["strip-communities"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");

    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        std::net::Ipv4Addr::new(10, 0, 0, 0),
        8,
    ));
    let comms = [rustbgpd_wire::COMMUNITY_BLACKHOLE];
    let ctx = RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let result = evaluate_chain(Some(&chain), &ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add,
        vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        ],
        "BLACKHOLE chain-tail rule must win after an earlier remove"
    );
    assert!(
        result.modifications.communities_remove.is_empty(),
        "tail add should cancel earlier removes for BLACKHOLE / NO_ADVERTISE"
    );
}
