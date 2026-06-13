#![cfg_attr(
    feature = "bench-internals",
    allow(dead_code, unfulfilled_lint_expectations, unused_imports)
)]

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod config;

#[cfg(feature = "bench-internals")]
mod fib_common;

#[cfg(feature = "bench-internals")]
mod fib;

// `fib`'s unit tests (the only bench-internals lib module with tests
// that use the shared builders) reach for `crate::test_support`. The
// bin declares it in `main.rs`; the lib needs its own declaration so
// `cargo clippy/test --features bench-internals --all-targets` can
// compile the lib test target. `test_support` only depends on
// `crate::config` + `crate::fib`, both exposed under this feature.
#[cfg(all(test, feature = "bench-internals"))]
mod test_support;

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod bench_internals {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    pub use crate::config::FibTableConfig;
    use rustbgpd_rib::FibInstallCandidate;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FibIntentCounts {
        pub routes: usize,
        pub drops: usize,
        pub frozen_tables: usize,
        pub frozen_eligible_keys: usize,
    }

    #[must_use]
    pub fn project_fib_intent_counts(
        tables: &[FibTableConfig],
        candidates: &[FibInstallCandidate],
        peer_groups: &BTreeMap<IpAddr, String>,
    ) -> FibIntentCounts {
        let intent =
            crate::fib::project_fib_intent_with_peer_groups(tables, candidates, peer_groups);
        FibIntentCounts {
            routes: intent.routes.len(),
            drops: intent.drops.len(),
            frozen_tables: intent.frozen_tables.len(),
            frozen_eligible_keys: intent.frozen_eligible_keys.len(),
        }
    }
}
