//! Fast external failover: the kernel link state a session checks its own
//! connection against.
//!
//! The daemon's netlink monitor keeps an authoritative [`LinkSnapshot`] and
//! publishes it on a `watch` channel ([`LinkStateFeed`]). Delivery is
//! level-triggered: a session asked to check re-reads the *current* snapshot
//! and decides from its own socket whether the interface carrying it is down
//! now. Nothing is queued per event, so a delayed check can never act on a
//! stale observation, and a link that went down and came back before the
//! check leaves a surviving session alone.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::watch;

/// Why the interface carrying a connection can no longer carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDownCause {
    /// `IFF_UP` set and `IFF_LOWER_UP` clear.
    CarrierLost,
    /// `IFF_UP` clear (operator `ip link set ... down`).
    AdminDown,
    /// The interface no longer exists.
    InterfaceRemoved,
    /// The connection's local address is no longer configured.
    AddressRemoved,
}

impl LinkDownCause {
    /// Stable operator-facing wording used in the session teardown cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CarrierLost => "carrier lost",
            Self::AdminDown => "administratively down",
            Self::InterfaceRemoved => "removed",
            Self::AddressRemoved => "local address removed",
        }
    }
}

/// One address configured on an interface, as the kernel reports it.
///
/// `local` is `IFA_LOCAL` (falling back to `IFA_ADDRESS`) and `prefix` is
/// `IFA_ADDRESS`; they differ on point-to-point links, where the connected
/// prefix is the remote end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The address a socket on this host is bound to.
    pub local: IpAddr,
    /// Base of the connected prefix.
    pub prefix: IpAddr,
    /// Connected prefix length.
    pub prefix_len: u8,
}

/// One interface's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    /// Interface name (operator output only).
    pub name: String,
    /// `IFF_UP`.
    pub admin_up: bool,
    /// `IFF_LOWER_UP` (carrier).
    pub lower_up: bool,
}

/// The kernel's interfaces and addresses as the monitor last saw them.
///
/// `valid` is false until the first complete dump and again from a netlink
/// overrun until a re-dump succeeds. An invalid snapshot proves nothing, so
/// no session is ever stopped on one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkSnapshot {
    /// The tables are complete and current.
    pub valid: bool,
    /// Interfaces by index.
    pub links: BTreeMap<u32, LinkState>,
    /// Addresses by interface index.
    pub addresses: BTreeMap<u32, Vec<InterfaceAddress>>,
}

/// A connection whose interface is down in the current snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkDown {
    /// Interface index.
    pub ifindex: u32,
    /// Interface name, or `ifindex<N>` once the interface is gone.
    pub ifname: String,
    /// Why it cannot carry the connection.
    pub cause: LinkDownCause,
}

impl LinkDown {
    /// Teardown cause recorded on the session and carried by its loss event.
    #[must_use]
    pub fn teardown_cause(&self) -> String {
        format!(
            "fast external failover: interface {} (ifindex {}) {}",
            self.ifname,
            self.ifindex,
            self.cause.as_str()
        )
    }
}

impl LinkSnapshot {
    /// The interface that directly carries `local` → `peer`: for a link-local
    /// peer the socket's scope, otherwise the interface holding the local
    /// address with the peer inside its connected prefix. `None` when the
    /// snapshot is invalid or nothing proves the connection is direct
    /// (loopback-sourced, multihop).
    #[must_use]
    pub fn carrier(&self, local: SocketAddr, peer: SocketAddr) -> Option<u32> {
        if !self.valid {
            return None;
        }
        if let Some(scope) = link_local_scope(local, peer) {
            return (scope != 0).then_some(scope);
        }
        let (local_ip, peer_ip) = (local.ip().to_canonical(), peer.ip().to_canonical());
        self.addresses.iter().find_map(|(ifindex, addresses)| {
            addresses
                .iter()
                .any(|address| {
                    address.local == local_ip
                        && in_prefix(peer_ip, address.prefix, address.prefix_len)
                })
                .then_some(*ifindex)
        })
    }

    /// Whether the connection `local` → `peer` is down now. `known_carrier`
    /// is the interface last proven to carry it: once its address is gone,
    /// that memory is what still ties the connection to an interface.
    #[must_use]
    pub fn connection_down(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        known_carrier: Option<u32>,
    ) -> Option<LinkDown> {
        if !self.valid {
            return None;
        }
        let local_ip = local.ip().to_canonical();
        let ifindex = match link_local_scope(local, peer) {
            Some(0) => return None,
            Some(scope) => scope,
            None => self.carrier(local, peer).or(known_carrier)?,
        };
        let down = |cause| {
            Some(LinkDown {
                ifindex,
                ifname: self
                    .links
                    .get(&ifindex)
                    .map_or_else(|| format!("ifindex{ifindex}"), |link| link.name.clone()),
                cause,
            })
        };
        let Some(link) = self.links.get(&ifindex) else {
            return down(LinkDownCause::InterfaceRemoved);
        };
        if !link.admin_up {
            return down(LinkDownCause::AdminDown);
        }
        if !link.lower_up {
            return down(LinkDownCause::CarrierLost);
        }
        let still_configured = self
            .addresses
            .get(&ifindex)
            .is_some_and(|addresses| addresses.iter().any(|address| address.local == local_ip));
        if still_configured {
            None
        } else {
            down(LinkDownCause::AddressRemoved)
        }
    }
}

/// The scope of a link-local connection, or `None` for any other.
fn link_local_scope(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    match (local, peer.ip().to_canonical()) {
        (SocketAddr::V6(local), IpAddr::V6(peer))
            if peer.is_unicast_link_local() && local.ip().is_unicast_link_local() =>
        {
            Some(local.scope_id())
        }
        _ => None,
    }
}

/// Read handle on the monitor's snapshot, carried in the transport config.
/// Runtime state, not configuration: two configs compare equal on it.
#[derive(Clone, Debug, Default)]
pub struct LinkStateFeed(Option<watch::Receiver<Arc<LinkSnapshot>>>);

impl LinkStateFeed {
    /// Wrap the monitor's receiver.
    #[must_use]
    pub fn new(receiver: watch::Receiver<Arc<LinkSnapshot>>) -> Self {
        Self(Some(receiver))
    }

    /// The current snapshot; an invalid empty one when there is no monitor.
    #[must_use]
    pub fn current(&self) -> Arc<LinkSnapshot> {
        self.0
            .as_ref()
            .map_or_else(Arc::default, |receiver| Arc::clone(&receiver.borrow()))
    }
}

impl PartialEq for LinkStateFeed {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for LinkStateFeed {}

pub(crate) fn in_prefix(addr: IpAddr, prefix: IpAddr, len: u8) -> bool {
    match (addr, prefix) {
        (IpAddr::V4(addr), IpAddr::V4(prefix)) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(addr) & mask == u32::from(prefix) & mask
        }
        (IpAddr::V6(addr), IpAddr::V6(prefix)) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(addr) & mask == u128::from(prefix) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// eth0 (ifindex 4) carrying `addresses`, with the given flags.
    fn snapshot(admin_up: bool, lower_up: bool, addresses: &[(&str, &str, u8)]) -> LinkSnapshot {
        LinkSnapshot {
            valid: true,
            links: BTreeMap::from([(
                4,
                LinkState {
                    name: "eth0".into(),
                    admin_up,
                    lower_up,
                },
            )]),
            addresses: BTreeMap::from([(
                4,
                addresses
                    .iter()
                    .map(|(local, prefix, len)| InterfaceAddress {
                        local: local.parse().unwrap(),
                        prefix: prefix.parse().unwrap(),
                        prefix_len: *len,
                    })
                    .collect(),
            )]),
        }
    }

    const V4: &[(&str, &str, u8)] = &[("10.0.0.1", "10.0.0.0", 30)];

    fn down(
        snapshot: &LinkSnapshot,
        local: &str,
        peer: &str,
        known: Option<u32>,
    ) -> Option<LinkDownCause> {
        snapshot
            .connection_down(sock(local), sock(peer), known)
            .map(|down| down.cause)
    }

    #[test]
    fn healthy_link_is_not_down() {
        let up = snapshot(true, true, V4);
        assert_eq!(
            up.carrier(sock("10.0.0.1:179"), sock("10.0.0.2:4000")),
            Some(4)
        );
        assert_eq!(down(&up, "10.0.0.1:179", "10.0.0.2:4000", None), None);
    }

    #[test]
    fn each_cause_in_the_current_state_is_down() {
        let (local, peer) = ("10.0.0.1:179", "10.0.0.2:4000");
        assert_eq!(
            down(&snapshot(true, false, V4), local, peer, None),
            Some(LinkDownCause::CarrierLost)
        );
        assert_eq!(
            down(&snapshot(false, false, V4), local, peer, None),
            Some(LinkDownCause::AdminDown)
        );
        // The address is gone; only the remembered carrier ties it to eth0.
        assert_eq!(down(&snapshot(true, true, &[]), local, peer, None), None);
        assert_eq!(
            down(&snapshot(true, true, &[]), local, peer, Some(4)),
            Some(LinkDownCause::AddressRemoved)
        );
        assert_eq!(
            down(
                &LinkSnapshot {
                    valid: true,
                    ..LinkSnapshot::default()
                },
                local,
                peer,
                Some(4)
            ),
            Some(LinkDownCause::InterfaceRemoved)
        );
    }

    #[test]
    fn an_invalid_snapshot_proves_nothing() {
        let mut gone = snapshot(true, false, V4);
        gone.valid = false;
        assert_eq!(down(&gone, "10.0.0.1:179", "10.0.0.2:4000", Some(4)), None);
        // An empty table that is not valid (failed dump) is not "everything
        // was removed".
        let empty = LinkSnapshot::default();
        assert_eq!(down(&empty, "10.0.0.1:179", "10.0.0.2:4000", Some(4)), None);
    }

    #[test]
    fn address_moved_or_readded_is_not_down() {
        // Removed and re-added before the check: the level state is healthy.
        assert_eq!(
            down(
                &snapshot(true, true, V4),
                "10.0.0.1:179",
                "10.0.0.2:4000",
                Some(4)
            ),
            None
        );
    }

    #[test]
    fn loopback_sourced_and_multihop_sessions_are_not_judged() {
        let carrier_down = snapshot(true, false, &[("10.0.0.1", "10.0.0.0", 24)]);
        assert_eq!(
            down(&carrier_down, "192.0.2.1:179", "10.0.0.2:4000", None),
            None
        );
        assert_eq!(
            down(&carrier_down, "10.0.0.1:179", "198.51.100.9:4000", None),
            None
        );
    }

    #[test]
    fn point_to_point_and_host_prefixes() {
        let ptp = snapshot(true, false, &[("10.0.0.1", "10.9.9.9", 32)]);
        assert_eq!(
            down(&ptp, "10.0.0.1:179", "10.9.9.9:4000", None),
            Some(LinkDownCause::CarrierLost)
        );
        let host = snapshot(true, false, &[("2001:db8::1", "2001:db8::1", 128)]);
        assert_eq!(
            down(&host, "[2001:db8::1]:179", "[2001:db8::2]:4000", None),
            None
        );
    }

    #[test]
    fn v4_mapped_socket_addresses_match() {
        let carrier_down = snapshot(true, false, V4);
        assert_eq!(
            down(
                &carrier_down,
                "[::ffff:10.0.0.1]:179",
                "[::ffff:10.0.0.2]:4000",
                None
            ),
            Some(LinkDownCause::CarrierLost)
        );
    }

    #[test]
    fn link_local_uses_the_socket_scope() {
        let ll = &[("fe80::1", "fe80::", 64)];
        let carrier_down = snapshot(true, false, ll);
        assert_eq!(
            down(&carrier_down, "[fe80::1%4]:179", "[fe80::2%4]:4000", None),
            Some(LinkDownCause::CarrierLost)
        );
        // Same fe80::1 on another interface (ifindex 5, absent: removed).
        assert_eq!(
            down(&carrier_down, "[fe80::1%5]:179", "[fe80::2%5]:4000", None),
            Some(LinkDownCause::InterfaceRemoved)
        );
        assert_eq!(
            down(
                &snapshot(true, true, ll),
                "[fe80::1%4]:179",
                "[fe80::2%4]:4000",
                None
            ),
            None
        );
        // No zone cannot be proven.
        assert_eq!(
            down(&carrier_down, "[fe80::1]:179", "[fe80::2]:4000", None),
            None
        );
    }

    #[test]
    fn prefix_length_boundaries() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_prefix(ip("10.1.2.3"), ip("0.0.0.0"), 0));
        assert!(!in_prefix(ip("10.1.2.3"), ip("10.1.2.3"), 33));
        assert!(!in_prefix(ip("10.1.2.3"), ip("::"), 0));
        assert!(in_prefix(ip("::1"), ip("::"), 0));
        assert!(!in_prefix(ip("::1"), ip("::"), 129));
    }
}
