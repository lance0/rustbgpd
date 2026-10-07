//! The hasher behind the per-batch outbound maps, named in one place so a
//! hasher change is a one-line edit. The `HashDoS` rationale is the block
//! above the outbound grouping indices in `session::outbound`.

/// `BuildHasher` for the outbound maps. Construct it with
/// `FastState::default()`, never a unit literal, so a seeded hasher can
/// replace it here without touching call sites. Every key here carries a
/// source or next-hop address, so this is the RIB's address-aware Fx
/// hasher: sequentially numbered IPv6 peers would otherwise share one
/// hashbrown probe chain.
pub(crate) type FastState = std::hash::BuildHasherDefault<rustbgpd_rib::AddrHasher>;
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, FastState>;
