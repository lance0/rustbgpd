//! The tool surface is fenced to the daemon's own read tiers.
//!
//! `docs/reference/grpc-method-inventory.json` is a machine-readable export of
//! the authorization matrix in `crates/api/src/authz.rs`, kept in step with it
//! by tests in that file. It carries no request or response types, so it
//! cannot generate tool schemas — it can only police the tool list, which is
//! what it is used for here.
//!
//! This is the mechanism behind control 1 of the server's safety model: "no
//! write tool exists in the binary" is checked, not asserted in prose.

use rustbgpd_mcp::TOOL_METHOD_PATHS;
use serde_json::Value;

const INVENTORY: &str = include_str!("../../../docs/reference/grpc-method-inventory.json");

fn inventory_tiers() -> Vec<(String, String)> {
    let parsed: Value =
        serde_json::from_str(INVENTORY).expect("the method inventory must be valid JSON");
    parsed["methods"]
        .as_array()
        .expect("the method inventory lists methods")
        .iter()
        .map(|method| {
            (
                method["path"]
                    .as_str()
                    .expect("every inventory entry has a path")
                    .to_string(),
                method["tier"]
                    .as_str()
                    .expect("every inventory entry has a tier")
                    .to_string(),
            )
        })
        .collect()
}

#[test]
fn every_tool_calls_a_method_the_daemon_publishes() {
    let inventory = inventory_tiers();
    for (tool, path) in TOOL_METHOD_PATHS {
        assert!(
            inventory.iter().any(|(known, _)| known == path),
            "tool `{tool}` declares `{path}`, which is not in the gRPC method inventory — \
             either the path is wrong or the RPC no longer exists"
        );
    }
}

#[test]
fn no_tool_reaches_a_mutating_or_operator_only_method() {
    let inventory = inventory_tiers();
    for (tool, path) in TOOL_METHOD_PATHS {
        let tier = inventory
            .iter()
            .find(|(known, _)| known == path)
            .map(|(_, tier)| tier.as_str())
            .unwrap_or_else(|| panic!("tool `{tool}` declares unknown method `{path}`"));
        assert!(
            matches!(tier, "read" | "sensitive_read"),
            "tool `{tool}` calls `{path}`, which the daemon classifies as `{tier}`. \
             This server is read-only: a `mutating` or `operator_only` method must not be \
             reachable from any tool."
        );
    }
}

#[test]
fn declared_paths_are_unique() {
    let mut paths: Vec<&str> = TOOL_METHOD_PATHS.iter().map(|(_, path)| *path).collect();
    paths.sort_unstable();
    let count = paths.len();
    paths.dedup();
    assert_eq!(
        paths.len(),
        count,
        "two tools declare the same gRPC method path; each entry must name a distinct method"
    );
}

#[test]
fn the_inventory_publishes_no_read_tier_to_bind_to() {
    // Documented in the ADR and the how-to: there is no tier below
    // `sensitive_read` to constrain a listener with, which is why the
    // deployment control alone cannot make this server read-only.
    let parsed: Value = serde_json::from_str(INVENTORY).expect("valid JSON");
    assert_eq!(
        parsed["tier_counts"]["read"].as_u64(),
        Some(0),
        "a `read` tier now exists; the safety model's claim that `sensitive_read` is the \
         lowest bindable tier needs revisiting in the ADR and how-to"
    );
}
