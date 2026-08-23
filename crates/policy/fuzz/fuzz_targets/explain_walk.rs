#![no_main]
//! Bounded explain-walk agreement fuzzing over valid TOML policy chains.

// The shared support module also contains the mixed-chain compiler recipe
// used by the sibling target.
#[allow(dead_code)]
#[path = "../support.rs"]
mod support;

use libfuzzer_sys::fuzz_target;
use rustbgpd_policy::{evaluate_chain, explain_chain_statements};
use support::{ChainRecipe, OwnedRoute, RouteRecipe, mixed_chain};

fuzz_target!(|bytes: [u8; 8]| {
    let chain_recipe = ChainRecipe {
        policies: bytes[0],
        statements: bytes[1],
        deny_at: bytes[2],
        selector: bytes[3],
    };
    let route_recipe = RouteRecipe {
        address: [
            if bytes[4] & 1 == 0 { 10 } else { bytes[4] },
            bytes[3],
            bytes[6],
            bytes[7],
        ],
        prefix_len: 16 + bytes[5] % 17,
        community: if bytes[4] & 2 == 0 {
            u16::from(bytes[3])
        } else {
            u16::from_be_bytes([bytes[6], bytes[7]])
        },
        local_pref: u16::from_be_bytes([bytes[0], bytes[6]]),
        med: u16::from_be_bytes([bytes[1], bytes[7]]),
    };
    let Some(chain) = mixed_chain(&chain_recipe) else {
        return;
    };
    let route = OwnedRoute::from_recipe(&route_recipe);
    let context = route.context();
    let trace = explain_chain_statements(Some(&chain), &context);
    let live = evaluate_chain(Some(&chain), &context);

    assert!(trace.steps.len() <= chain.policies.len());
    if let Some(deny_index) = trace
        .steps
        .iter()
        .position(|step| step.action == rustbgpd_policy::PolicyAction::Deny)
    {
        assert_eq!(deny_index + 1, trace.steps.len());
    }
    assert_eq!(trace.action, live.action);
});
