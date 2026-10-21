//! Fast external failover: confirmed interface-down observations and the rule
//! that decides whether one of them carries a given TCP connection.
//!
//! The daemon's netlink monitor produces [`LinkDownEvent`]s only from explicit
//! kernel messages (carrier loss, admin down, interface removal, local address
//! removal). A session acts on one only when its own socket proves the
//! interface carries it: the socket's local address is configured on that
//! interface and the peer sits inside that address's connected prefix, or,
//! for an IPv6 link-local peer, the socket's scope is that interface. Nothing
//! here looks at eBGP status or TTL.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// What the kernel reported about the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDownCause {
    /// `RTM_NEWLINK` with `IFF_UP` set and `IFF_LOWER_UP` clear.
    CarrierLost,
    /// `RTM_NEWLINK` with `IFF_UP` clear (operator `ip link set ... down`).
    AdminDown,
    /// `RTM_DELLINK`.
    InterfaceRemoved,
    /// `RTM_DELADDR` for one address on the interface.
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

/// A confirmed interface-down observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkDownEvent {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Interface name at the time of the event (for operator output only).
    pub ifname: String,
    /// What went down.
    pub cause: LinkDownCause,
    /// Addresses the interface carried when the event arrived. For
    /// [`LinkDownCause::AddressRemoved`], only the removed address.
    pub addresses: Vec<InterfaceAddress>,
    /// When the monitor read the kernel message. A connection that started
    /// after this cannot be the one the event describes, so a delivery that
    /// was delayed past a reconnect is ignored.
    pub observed_at: Instant,
}

impl LinkDownEvent {
    /// True when the connection `local` → `peer` is directly carried by this
    /// interface.
    #[must_use]
    pub fn carries(&self, local: SocketAddr, peer: SocketAddr) -> bool {
        let local_ip = local.ip().to_canonical();
        let peer_ip = peer.ip().to_canonical();
        self.addresses.iter().any(|address| {
            if address.local != local_ip {
                return false;
            }
            match (local, peer_ip) {
                // A link-local address is only meaningful with its zone: the
                // same fe80:: address can exist on every interface.
                (SocketAddr::V6(local), IpAddr::V6(peer)) if peer.is_unicast_link_local() => {
                    local.ip().is_unicast_link_local() && local.scope_id() == self.ifindex
                }
                _ => in_prefix(peer_ip, address.prefix, address.prefix_len),
            }
        })
    }

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

fn in_prefix(addr: IpAddr, prefix: IpAddr, len: u8) -> bool {
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

    fn event(ifindex: u32, addresses: &[(&str, &str, u8)]) -> LinkDownEvent {
        LinkDownEvent {
            ifindex,
            ifname: "eth0".into(),
            cause: LinkDownCause::CarrierLost,
            observed_at: Instant::now(),
            addresses: addresses
                .iter()
                .map(|(local, prefix, len)| InterfaceAddress {
                    local: local.parse().unwrap(),
                    prefix: prefix.parse().unwrap(),
                    prefix_len: *len,
                })
                .collect(),
        }
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn numbered_peer_on_the_connected_prefix_is_carried() {
        let e = event(4, &[("10.0.0.1", "10.0.0.0", 30)]);
        assert!(e.carries(sock("10.0.0.1:179"), sock("10.0.0.2:40000")));
        // /31 point-to-point, both ends.
        let e = event(4, &[("10.0.0.0", "10.0.0.0", 31)]);
        assert!(e.carries(sock("10.0.0.0:179"), sock("10.0.0.1:40000")));
    }

    #[test]
    fn peer_just_outside_the_prefix_is_not_carried() {
        let e = event(4, &[("10.0.0.1", "10.0.0.0", 30)]);
        assert!(!e.carries(sock("10.0.0.1:179"), sock("10.0.0.4:40000")));
        assert!(!e.carries(sock("10.0.0.1:179"), sock("10.0.0.255:40000")));
    }

    #[test]
    fn a_different_local_source_is_not_carried() {
        // Loopback-sourced (multihop / iBGP) session whose peer happens to be
        // on this interface's subnet: the local address is elsewhere.
        let e = event(4, &[("10.0.0.1", "10.0.0.0", 24)]);
        assert!(!e.carries(sock("192.0.2.1:179"), sock("10.0.0.2:40000")));
    }

    #[test]
    fn point_to_point_peer_address_is_the_connected_prefix() {
        // `ip addr add 10.0.0.1 peer 10.9.9.9/32`
        let e = event(4, &[("10.0.0.1", "10.9.9.9", 32)]);
        assert!(e.carries(sock("10.0.0.1:179"), sock("10.9.9.9:40000")));
        assert!(!e.carries(sock("10.0.0.1:179"), sock("10.0.0.2:40000")));
    }

    #[test]
    fn host_routes_only_carry_the_exact_peer() {
        let e = event(4, &[("2001:db8::1", "2001:db8::1", 128)]);
        assert!(!e.carries(sock("[2001:db8::1]:179"), sock("[2001:db8::2]:40000")));
        let e = event(4, &[("2001:db8::1", "2001:db8::", 64)]);
        assert!(e.carries(sock("[2001:db8::1]:179"), sock("[2001:db8::2]:40000")));
    }

    #[test]
    fn v4_mapped_socket_addresses_match_v4_interface_addresses() {
        let e = event(4, &[("10.0.0.1", "10.0.0.0", 30)]);
        assert!(e.carries(
            sock("[::ffff:10.0.0.1]:179"),
            sock("[::ffff:10.0.0.2]:40000")
        ));
    }

    #[test]
    fn link_local_requires_the_socket_scope_to_be_this_interface() {
        let e = event(4, &[("fe80::1", "fe80::", 64)]);
        assert!(e.carries(sock("[fe80::1%4]:179"), sock("[fe80::2%4]:40000")));
        // Same fe80::1 configured on another interface (ifindex 5).
        assert!(!e.carries(sock("[fe80::1%5]:179"), sock("[fe80::2%5]:40000")));
        // No zone at all cannot be proven.
        assert!(!e.carries(sock("[fe80::1]:179"), sock("[fe80::2]:40000")));
    }

    #[test]
    fn prefix_length_boundaries() {
        assert!(in_prefix(
            "10.1.2.3".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0
        ));
        assert!(!in_prefix(
            "10.1.2.3".parse().unwrap(),
            "10.1.2.3".parse().unwrap(),
            33
        ));
        assert!(!in_prefix(
            "10.1.2.3".parse().unwrap(),
            "::".parse().unwrap(),
            0
        ));
        assert!(in_prefix("::1".parse().unwrap(), "::".parse().unwrap(), 0));
        assert!(!in_prefix(
            "::1".parse().unwrap(),
            "::".parse().unwrap(),
            129
        ));
    }
}
