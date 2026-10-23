//! Neighbor selectors in requests.
//!
//! A numbered neighbor is selected by its bare IP literal. An IPv6
//! link-local (`fe80::/10`) neighbor is selected only with its interface
//! scope: `fe80::1%eth0` in the address field, or the bare address plus a
//! structured interface field where the request has one. A bare link-local
//! selector is `INVALID_ARGUMENT` whatever the configuration, naming the
//! scoped neighbors configured on that address. RFC 4007 §11.6 permits a
//! default zone; requiring the scope is this API's contract, so adding a
//! second neighbor on an address never changes what an existing selector
//! means.

use std::net::IpAddr;

use tonic::Status;

use crate::import_roster::{ImportRoster, ImportRosterReader};
use crate::peer_types::PeerKey;

/// IPv6 link-local addresses are the only scoped neighbor addresses.
/// The RIB identity of the neighbor at `address` (on `interface` when one is
/// given), from the peer manager's roster. A standalone service without a
/// roster uses the address's pinned identity, as its sessions do.
pub(crate) fn rib_peer(
    roster: Option<&ImportRosterReader>,
    address: IpAddr,
    interface: Option<&str>,
) -> rustbgpd_rib::PeerId {
    roster.map_or_else(
        || rustbgpd_rib::PeerId::from_addr(address),
        |roster| roster.load().rib_peer(address, interface),
    )
}

pub(crate) fn is_scoped_address(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

/// Linux `dev_valid_name`: 1..=15 bytes, not `.` or `..`, and no `/`, `:`,
/// whitespace or `%`.
fn valid_interface_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == ':' || c == '%' || c.is_whitespace() || c.is_control())
}

/// The scoped forms configured at `address`, for an error message.
fn scoped_candidates(roster: Option<&ImportRoster>, address: IpAddr) -> Vec<String> {
    roster.map_or_else(Vec::new, |roster| {
        roster
            .peers()
            .iter()
            .filter(|peer| peer.key.address == address && peer.key.interface.is_some())
            .map(|peer| peer.key.label())
            .collect()
    })
}

fn candidates_clause(candidates: &[String]) -> String {
    if candidates.is_empty() {
        "no neighbor on this address is configured".to_string()
    } else {
        format!("configured: {}", candidates.join(", "))
    }
}

/// Parse a neighbor selector. `value` is a bare IP literal or a scoped
/// IPv6 link-local address (`fe80::1%eth0`); `interface` is the request's
/// structured scope field, empty when it has none. An empty `value` selects
/// nothing (`None`).
///
/// With a roster, a scoped selector for an address whose configured
/// neighbors all use other interfaces is `NOT_FOUND`, so a scope never
/// selects another neighbor's state. Addresses with no configured neighbor
/// are left to the caller's own not-found handling.
pub(crate) fn parse_neighbor(
    field: &str,
    value: &str,
    interface: &str,
    roster: Option<&ImportRosterReader>,
) -> Result<Option<PeerKey>, Status> {
    let roster = roster.map(ImportRosterReader::load);
    parse_neighbor_in(field, value, interface, roster.as_deref())
}

/// [`parse_neighbor`] against a roster snapshot the caller already holds,
/// so selection and the data it reads come from one publication.
pub(crate) fn parse_neighbor_in(
    field: &str,
    value: &str,
    interface: &str,
    roster: Option<&ImportRoster>,
) -> Result<Option<PeerKey>, Status> {
    let interface = interface.trim();
    if value.is_empty() {
        if !interface.is_empty() {
            return Err(Status::invalid_argument(format!(
                "{field}: interface {interface:?} requires an address"
            )));
        }
        return Ok(None);
    }
    let (literal, zone) = match value.split_once('%') {
        Some((literal, zone)) => (literal, Some(zone)),
        None => (value, None),
    };
    let address: IpAddr = literal
        .parse()
        .map_err(|error| Status::invalid_argument(format!("invalid {field} {value:?}: {error}")))?;
    let scope = match (zone, interface) {
        (None, "") => None,
        (None, interface) => Some(interface),
        (Some(zone), "") => Some(zone),
        (Some(zone), interface) if zone == interface => Some(zone),
        (Some(zone), interface) => {
            return Err(Status::invalid_argument(format!(
                "{field} {value:?}: scope {zone:?} conflicts with interface {interface:?}"
            )));
        }
    };
    match (is_scoped_address(address), scope) {
        (true, None) => Err(Status::invalid_argument(format!(
            "{field} {address} is an IPv6 link-local address and must name its \
             interface, as {address}%<interface>; {}",
            candidates_clause(&scoped_candidates(roster, address))
        ))),
        (false, Some(_)) => Err(Status::invalid_argument(format!(
            "{field} {value:?}: an interface scope is only valid on an IPv6 \
             link-local address"
        ))),
        (true, Some(scope)) if !valid_interface_name(scope) => Err(Status::invalid_argument(
            format!("{field} {value:?}: {scope:?} is not a valid interface name"),
        )),
        (_, scope) => {
            let key = PeerKey::new(address, scope.map(str::to_string));
            if key.interface.is_some() {
                let candidates = scoped_candidates(roster, address);
                if !candidates.is_empty() && !candidates.contains(&key.label()) {
                    return Err(Status::not_found(format!(
                        "neighbor {key} not found; {}",
                        candidates_clause(&candidates)
                    )));
                }
            }
            Ok(Some(key))
        }
    }
}

/// `NOT_FOUND` when a scoped `key` names an address that the data source's
/// own snapshot (`neighbors`, as address and interface) holds only on other
/// interfaces: a reload replaced the neighbor after the selector was parsed.
/// A numbered key, or an address absent from the snapshot, is left to the
/// caller, as in [`parse_neighbor`].
pub(crate) fn require_current_scope<'a>(
    key: &PeerKey,
    neighbors: impl IntoIterator<Item = (IpAddr, Option<&'a str>)>,
) -> Result<(), Status> {
    let Some(interface) = key.interface.as_deref() else {
        return Ok(());
    };
    let mut on_address = neighbors
        .into_iter()
        .filter(|(address, _)| *address == key.address)
        .peekable();
    if on_address.peek().is_none() || on_address.any(|(_, scope)| scope == Some(interface)) {
        Ok(())
    } else {
        Err(Status::not_found(format!("neighbor {key} not found")))
    }
}

/// [`parse_neighbor`] resolved to the neighbor's RIB identity.
pub(crate) fn parse_neighbor_rib_peer(
    field: &str,
    value: &str,
    roster: Option<&ImportRosterReader>,
) -> Result<Option<rustbgpd_rib::PeerId>, Status> {
    Ok(parse_neighbor(field, value, "", roster)?
        .map(|key| rib_peer(roster, key.address, key.interface.as_deref())))
}

/// [`parse_neighbor`] for a required selector.
pub(crate) fn require_neighbor(
    field: &str,
    value: &str,
    interface: &str,
    roster: Option<&ImportRosterReader>,
) -> Result<PeerKey, Status> {
    parse_neighbor(field, value, interface, roster)?
        .ok_or_else(|| Status::invalid_argument(format!("{field} is required")))
}

/// The address to echo for a selector: the request's own text for a
/// numbered neighbor, as before, and the bare address of a scoped one, whose
/// interface is echoed separately.
pub(crate) fn address_echo(raw: &str, key: &PeerKey) -> String {
    if key.interface.is_some() {
        key.address.to_string()
    } else {
        raw.to_string()
    }
}

/// The interface to echo for a selector, empty for a numbered neighbor.
pub(crate) fn interface_of(key: Option<&PeerKey>) -> String {
    key.and_then(|key| key.interface.clone())
        .unwrap_or_default()
}

/// Bind a selector's scope into a page token's query identity, so a token
/// issued for `fe80::1%eth0` is refused for `fe80::1%eth1` or a numbered
/// selector. A scoped identity is the SHA-256 of the identity and the
/// interface, in the 64 lowercase hex digits route tokens require; unscoped
/// identities are unchanged.
pub(crate) fn scoped_identity(identity: String, key: Option<&PeerKey>) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    match key.and_then(|key| key.interface.as_deref()) {
        None => identity,
        Some(interface) => {
            let digest = Sha256::new()
                .chain_update(b"rustbgpd-scoped-page-identity-v1\0")
                .chain_update(identity.as_bytes())
                .chain_update(b"\0")
                .chain_update(interface.as_bytes())
                .finalize();
            let mut scoped = String::with_capacity(64);
            for byte in digest {
                let _ = write!(scoped, "{byte:02x}");
            }
            scoped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_roster::{ImportRosterPeer, ImportRosterPublisher};

    fn roster(keys: &[(&str, Option<&str>)]) -> (ImportRosterPublisher, ImportRosterReader) {
        let peers = keys
            .iter()
            .map(|(address, interface)| ImportRosterPeer {
                key: PeerKey::new(address.parse().unwrap(), interface.map(str::to_string)),
                session_id: 1,
                publication: tokio::sync::watch::channel(None).1,
                rib_peer: rustbgpd_transport::RibPeerSlot::default(),
            })
            .collect();
        let publisher = crate::import_roster::test_support::publisher(peers, Vec::new());
        let reader = publisher.reader();
        (publisher, reader)
    }

    #[test]
    fn bare_link_local_is_rejected_and_names_scoped_candidates() {
        let (_publisher, reader) = roster(&[
            ("fe80::1", Some("eth0")),
            ("fe80::1", Some("eth1")),
            ("192.0.2.1", None),
        ]);
        let error = parse_neighbor("neighbor_address", "fe80::1", "", Some(&reader)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            error.message().contains("fe80::1%eth0"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains("fe80::1%eth1"),
            "{}",
            error.message()
        );
        // A single configured neighbor does not make the bare form valid.
        let (_publisher, single) = roster(&[("fe80::1", Some("eth0"))]);
        let error = parse_neighbor("neighbor_address", "fe80::1", "", Some(&single)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            error.message().contains("fe80::1%eth0"),
            "{}",
            error.message()
        );
        // Nor does an empty configuration or a missing roster.
        let error = parse_neighbor("neighbor_address", "fe80::9", "", None).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            error.message().contains("no neighbor"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn scoped_and_structured_link_local_are_accepted() {
        let (_publisher, reader) = roster(&[("fe80::1", Some("eth0"))]);
        let expected = PeerKey::new("fe80::1".parse().unwrap(), Some("eth0".to_string()));
        for (value, interface) in [
            ("fe80::1%eth0", ""),
            ("fe80::1", "eth0"),
            ("fe80::1%eth0", "eth0"),
        ] {
            assert_eq!(
                parse_neighbor("neighbor_address", value, interface, Some(&reader)).unwrap(),
                Some(expected.clone()),
                "{value} {interface}"
            );
        }
        // An unconfigured scoped address is left to the caller.
        assert!(parse_neighbor("neighbor_address", "fe80::9%eth3", "", Some(&reader)).is_ok());
    }

    #[test]
    fn scope_naming_another_interface_is_not_found() {
        let (_publisher, reader) = roster(&[("fe80::1", Some("eth0"))]);
        let error =
            parse_neighbor("neighbor_address", "fe80::1%eth1", "", Some(&reader)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert!(
            error.message().contains("fe80::1%eth0"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn numbered_selectors_are_unchanged_and_reject_a_scope() {
        for value in ["192.0.2.1", "2001:db8::1"] {
            let key = parse_neighbor("neighbor_address", value, "", None)
                .unwrap()
                .unwrap();
            assert_eq!(key.address, value.parse::<IpAddr>().unwrap());
            assert_eq!(key.interface, None);
        }
        for (value, interface) in [
            ("192.0.2.1%eth0", ""),
            ("2001:db8::1%eth0", ""),
            ("192.0.2.1", "eth0"),
        ] {
            let error = parse_neighbor("neighbor_address", value, interface, None).unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{value}");
            assert!(
                error.message().contains("only valid"),
                "{}",
                error.message()
            );
        }
        assert_eq!(
            parse_neighbor("neighbor_address", "", "", None).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_scopes_are_invalid() {
        for (value, interface) in [
            ("fe80::1%", ""),
            ("fe80::1%a%b", ""),
            ("fe80::1%eth 0", ""),
            ("fe80::1%0123456789abcdef", ""),
            ("fe80::1%..", ""),
            ("fe80::1%eth0", "eth1"),
            ("", "eth0"),
            ("not-an-ip%eth0", ""),
        ] {
            let error = parse_neighbor("neighbor_address", value, interface, None).unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::InvalidArgument,
                "{value:?} {interface:?}"
            );
        }
    }

    #[test]
    fn scope_is_part_of_the_page_identity() {
        let eth0 = PeerKey::new("fe80::1".parse().unwrap(), Some("eth0".to_string()));
        let eth1 = PeerKey::new("fe80::1".parse().unwrap(), Some("eth1".to_string()));
        let numbered = PeerKey::new("192.0.2.1".parse().unwrap(), None);
        let base = || "rp:abc".to_string();
        assert_eq!(scoped_identity(base(), Some(&numbered)), base());
        assert_eq!(scoped_identity(base(), None), base());
        assert_ne!(scoped_identity(base(), Some(&eth0)), base());
        assert_ne!(
            scoped_identity(base(), Some(&eth0)),
            scoped_identity(base(), Some(&eth1))
        );
        let scoped = scoped_identity(base(), Some(&eth0));
        assert_eq!(scoped.len(), 64);
        assert!(
            scoped
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
    }
}
