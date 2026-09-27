//! The hasher behind the per-batch outbound maps, named in one place so a
//! hasher change is a one-line edit. The `HashDoS` rationale is the block
//! above the outbound grouping indices in `session::outbound`.

/// `BuildHasher` for the outbound maps. Construct it with
/// `FastState::default()`, never a unit literal, so a seeded hasher can
/// replace it here without touching call sites.
pub(crate) type FastState = rustc_hash::FxBuildHasher;
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, FastState>;
