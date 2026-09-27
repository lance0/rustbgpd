#![deny(unsafe_code)]
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

#[cfg(feature = "bench-internals")]
mod forwarding_state;

// `config`'s reload-diff logic reaches only the pure plan decomposer. Its
// supported-shape policy lives in `rustbgpd-evpn`, so exposing config no
// longer pulls daemon actors into the library target (LAN-1002).
#[cfg(feature = "bench-internals")]
mod evpn_plan_decomposer;

// `fib` and `forwarding_state` unit tests use shared builders from
// `crate::test_support`. The lib needs its own declaration for Clippy
// and tests with `bench-internals`; those builders depend only on the
// mirrored `config` and `fib` modules.
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
