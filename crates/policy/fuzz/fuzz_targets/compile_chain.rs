#![no_main]
//! Structure-aware mixed TOML/`.rpol` chain compiler fuzzing.

// The shared support module also contains the route-walk recipe used by the
// sibling target.
#[allow(dead_code)]
#[path = "../support.rs"]
mod support;

use libfuzzer_sys::fuzz_target;
use rustbgpd_policy::compile::compile_chain;
use rustbgpd_policy::sets::SetStore;
use support::{assert_ids_resolve, mixed_chain, ChainRecipe};

fuzz_target!(|recipe: ChainRecipe| {
    let chain = mixed_chain(&recipe);
    let compiled = compile_chain(&chain, &mut SetStore::new());
    assert_ids_resolve(&compiled);
});
