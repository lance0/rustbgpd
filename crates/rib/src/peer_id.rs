//! The RIB's neighbor identity.
//!
//! Every RIB structure that belongs to a neighbor (Adj-RIB-In/Out, per-peer
//! state, distribution, update groups, Graceful Restart and route refresh)
//! keys on [`PeerId`], never on the neighbor's transport address. A scoped
//! IPv6 link-local address can belong to a different neighbor on each
//! interface, so the address alone cannot identify one.
//!
//! Today a `PeerId` still wraps the neighbor's address, so its ordering and
//! hashing are exactly those of [`IpAddr`] and every map keyed by it keeps
//! the same iteration order. The intended representation is a compact
//! generational handle (a slot index plus a generation) allocated by the peer
//! manager, with a RIB peer table resolving it to the current endpoint. The
//! address therefore leaves the type only through [`PeerId::addr`], and only
//! [`PeerId::from_addr`] builds one: those two calls, and the `Display` and
//! `Debug` impls below, are the complete list of places that change with
//! the representation.

use std::fmt;
use std::net::IpAddr;

/// Opaque identity of one RIB neighbor. `Copy`, and cheap to hash and order.
///
/// Comparing two `PeerId`s says whether they name the same neighbor; their
/// order is a stable map order, not a route preference. Selection
/// tie-breaks compare [`PeerId::addr`] explicitly.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(IpAddr);

impl PeerId {
    /// The identity of locally originated and injected routes.
    pub const LOCAL: Self = Self(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    /// The identity of the neighbor at `addr`.
    ///
    /// Address-backed: a caller that can reach the peer manager's handle
    /// should carry that instead of rebuilding one from an address.
    #[must_use]
    #[inline]
    pub const fn from_addr(addr: IpAddr) -> Self {
        Self(addr)
    }

    /// The neighbor's transport address.
    ///
    /// Address-backed: with a handle representation this becomes a peer
    /// table lookup of the session's endpoint.
    #[must_use]
    #[inline]
    pub const fn addr(self) -> IpAddr {
        self.0
    }
}

/// Formats as the neighbor's address, so logs, metric labels and operator
/// text read exactly as they did when the RIB keyed peers by address.
impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Formats as the neighbor's address, like `Display`.
impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{BuildHasher, BuildHasherDefault};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn addrs() -> [IpAddr; 6] {
        [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fe80::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]
    }

    /// Maps keyed by `PeerId` iterate and select exactly as they did keyed
    /// by `IpAddr`: the same order, and the same hash under each hasher the RIB
    /// keys peers with.
    #[test]
    fn order_and_hash_match_the_address() {
        let addr_state = BuildHasherDefault::<crate::AddrHasher>::default();
        for a in addrs() {
            let peer = PeerId::from_addr(a);
            for b in addrs() {
                assert_eq!(peer.cmp(&PeerId::from_addr(b)), a.cmp(&b), "{a} vs {b}");
            }
            assert_eq!(
                rustc_hash::FxBuildHasher.hash_one(peer),
                rustc_hash::FxBuildHasher.hash_one(a)
            );
            assert_eq!(addr_state.hash_one(peer), addr_state.hash_one(a));
            let sip = std::collections::hash_map::RandomState::new();
            assert_eq!(sip.hash_one(peer), sip.hash_one(a));
        }
    }

    #[test]
    fn formats_as_the_address() {
        for addr in addrs() {
            let peer = PeerId::from_addr(addr);
            assert_eq!(peer.to_string(), addr.to_string());
            assert_eq!(format!("{peer:?}"), format!("{addr:?}"));
            assert_eq!(peer.addr(), addr);
        }
    }
}
