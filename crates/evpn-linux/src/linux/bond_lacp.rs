//! LACP partner read for RFC 7432 §5 type 1 ESI derivation.
//!
//! One synchronous `RTM_GETLINK` by name: the bond's mode, admin and
//! carrier flags, and `IFLA_BOND_AD_INFO` (the active aggregator's
//! partner system MAC and partner key) arrive in a single kernel
//! message, so the MAC and key can never be torn across a partner
//! change the way two separate sysfs reads could be. Synchronous: one
//! request/reply on a private socket, cheap enough for the daemon's
//! periodic readiness probe to call inline.

use std::fmt;
use std::time::Duration;

use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{
    BondAdInfo, BondMode, InfoBond, InfoData, InfoKind, LinkAttribute, LinkFlags, LinkInfo,
    LinkMessage,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

/// Bound on the kernel's `RTM_GETLINK` reply. A lost reply or wedged
/// netlink path becomes a `netlink_error` (not ready), never a hang.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// The CE side of an 802.3ad bond: what the PE's bond learned from
/// the partner's LACPDUs for its active aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LacpPartner {
    /// Partner (CE) LACP system MAC address.
    pub system_mac: [u8; 6],
    /// Partner (CE) LACP operational port key.
    pub port_key: u16,
}

/// Why no LACP partner identity could be read — each case fails closed.
#[derive(Debug)]
pub enum LacpPartnerError {
    /// No kernel link has this name.
    NotFound,
    /// The link exists but is not a bond.
    NotBond,
    /// The bond is not in 802.3ad (LACP) mode.
    NotLacpMode,
    /// The bond is administratively down or has no carrier.
    Down,
    /// The kernel reported no active aggregator.
    NoActiveAggregator,
    /// The active aggregator has no LACP partner (zero system MAC).
    NoPartner,
    /// Netlink socket or decode failure.
    Io(std::io::Error),
}

impl fmt::Display for LacpPartnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such interface"),
            Self::NotBond => f.write_str("interface is not a bond"),
            Self::NotLacpMode => f.write_str("bond is not in 802.3ad (LACP) mode"),
            Self::Down => f.write_str("bond is down (admin down or no carrier)"),
            Self::NoActiveAggregator => f.write_str("bond has no active LACP aggregator"),
            Self::NoPartner => f.write_str("bond has no LACP partner yet"),
            Self::Io(e) => write!(f, "netlink read failed: {e}"),
        }
    }
}

impl std::error::Error for LacpPartnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl LacpPartnerError {
    /// Stable snake-case reason code for logs and status surfaces.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotBond => "not_bond",
            Self::NotLacpMode => "not_lacp_mode",
            Self::Down => "down",
            Self::NoActiveAggregator => "no_active_aggregator",
            Self::NoPartner => "no_partner",
            Self::Io(_) => "netlink_error",
        }
    }
}

/// Read the LACP partner of bond `name` from the kernel.
///
/// # Errors
/// Returns a [`LacpPartnerError`] naming why the partner identity is
/// absent or unusable.
pub fn read_bond_lacp_partner(name: &str) -> Result<LacpPartner, LacpPartnerError> {
    lacp_partner_from_link(&get_link(name)?)
}

fn get_link(name: &str) -> Result<LinkMessage, LacpPartnerError> {
    let mut link = LinkMessage::default();
    link.attributes
        .push(LinkAttribute::IfName(name.to_string()));
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetLink(link));
    req.header.flags = NLM_F_REQUEST;
    req.header.sequence_number = 1;
    req.finalize();
    let mut buf = vec![0; req.buffer_len()];
    req.serialize(&mut buf);

    let socket = open_socket(REPLY_TIMEOUT)?;
    socket.send(&buf, 0).map_err(LacpPartnerError::Io)?;
    let reply = recv_reply(&socket, REPLY_TIMEOUT)?;
    let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&reply)
        .map_err(|e| LacpPartnerError::Io(std::io::Error::other(e.to_string())))?;
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => Ok(link),
        NetlinkPayload::Error(e) if e.raw_code() == -libc::ENODEV => {
            Err(LacpPartnerError::NotFound)
        }
        NetlinkPayload::Error(e) => Err(LacpPartnerError::Io(e.to_io())),
        other => Err(LacpPartnerError::Io(std::io::Error::other(format!(
            "unexpected RTM_GETLINK reply: {other:?}"
        )))),
    }
}

/// A connected `NETLINK_ROUTE` socket whose receives give up after
/// `timeout`.
fn open_socket(timeout: Duration) -> Result<Socket, LacpPartnerError> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(LacpPartnerError::Io)?;
    socket2::SockRef::from(&socket)
        .set_read_timeout(Some(timeout))
        .map_err(LacpPartnerError::Io)?;
    socket.bind_auto().map_err(LacpPartnerError::Io)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(LacpPartnerError::Io)?;
    Ok(socket)
}

fn recv_reply(socket: &Socket, timeout: Duration) -> Result<Vec<u8>, LacpPartnerError> {
    match socket.recv_from_full() {
        Ok((reply, _)) => Ok(reply),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(LacpPartnerError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no RTM_GETLINK reply within {timeout:?}"),
            )))
        }
        Err(e) => Err(LacpPartnerError::Io(e)),
    }
}

/// Project one `RTM_NEWLINK` message onto the bond's LACP partner.
fn lacp_partner_from_link(link: &LinkMessage) -> Result<LacpPartner, LacpPartnerError> {
    let infos = link
        .attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::LinkInfo(infos) => Some(infos.as_slice()),
            _ => None,
        })
        .unwrap_or_default();
    if !infos
        .iter()
        .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Bond)))
    {
        return Err(LacpPartnerError::NotBond);
    }
    let bond = infos
        .iter()
        .find_map(|i| match i {
            LinkInfo::Data(InfoData::Bond(bond)) => Some(bond.as_slice()),
            _ => None,
        })
        .unwrap_or_default();
    if !bond
        .iter()
        .any(|b| matches!(b, InfoBond::Mode(BondMode::Ieee8023Ad)))
    {
        return Err(LacpPartnerError::NotLacpMode);
    }
    if !link
        .header
        .flags
        .contains(LinkFlags::Up | LinkFlags::LowerUp)
    {
        return Err(LacpPartnerError::Down);
    }
    let ad_info = bond
        .iter()
        .find_map(|b| match b {
            InfoBond::AdInfo(ad) => Some(ad.as_slice()),
            _ => None,
        })
        .ok_or(LacpPartnerError::NoActiveAggregator)?;
    let system_mac = ad_info.iter().find_map(|a| match a {
        BondAdInfo::PartnerMac(mac) => Some(*mac),
        _ => None,
    });
    let port_key = ad_info.iter().find_map(|a| match a {
        BondAdInfo::PartnerKey(key) => Some(*key),
        _ => None,
    });
    match (system_mac, port_key) {
        (Some(system_mac), Some(port_key)) if system_mac != [0; 6] => Ok(LacpPartner {
            system_mac,
            port_key,
        }),
        _ => Err(LacpPartnerError::NoPartner),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTNER_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn bond_link(kind: InfoKind, bond: Vec<InfoBond>, flags: LinkFlags) -> LinkMessage {
        let mut link = LinkMessage::default();
        link.header.flags = flags;
        link.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(kind),
            LinkInfo::Data(InfoData::Bond(bond)),
        ]));
        link
    }

    fn ad_info(mac: [u8; 6], partner_key: u16) -> InfoBond {
        InfoBond::AdInfo(vec![
            // The local (actor) key must never leak into the ESI.
            BondAdInfo::ActorKey(0x0009),
            BondAdInfo::PartnerKey(partner_key),
            BondAdInfo::PartnerMac(mac),
        ])
    }

    fn up() -> LinkFlags {
        LinkFlags::Up | LinkFlags::LowerUp
    }

    #[test]
    fn io_cause_is_preserved_and_classification_errors_have_no_source() {
        use std::error::Error as _;

        let error = LacpPartnerError::Io(std::io::Error::from_raw_os_error(libc::EIO));
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.raw_os_error(), Some(libc::EIO));
        for error in [
            LacpPartnerError::NotFound,
            LacpPartnerError::NotBond,
            LacpPartnerError::NotLacpMode,
            LacpPartnerError::Down,
            LacpPartnerError::NoActiveAggregator,
            LacpPartnerError::NoPartner,
        ] {
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn reads_partner_mac_and_partner_key() {
        let link = bond_link(
            InfoKind::Bond,
            vec![
                InfoBond::Mode(BondMode::Ieee8023Ad),
                ad_info(PARTNER_MAC, 0x01c1),
            ],
            up(),
        );
        assert_eq!(
            lacp_partner_from_link(&link).unwrap(),
            LacpPartner {
                system_mac: PARTNER_MAC,
                port_key: 0x01c1
            }
        );
    }

    #[test]
    fn a_missing_reply_times_out_as_netlink_error() {
        // Nothing is sent, so the kernel never replies: the receive must
        // give up at the bound instead of blocking forever.
        let timeout = Duration::from_millis(100);
        let socket = open_socket(timeout).expect("NETLINK_ROUTE socket");
        let started = std::time::Instant::now();
        let err = recv_reply(&socket, timeout).unwrap_err();
        assert_eq!(err.code(), "netlink_error");
        assert!(err.to_string().contains("no RTM_GETLINK reply"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn fails_closed_on_every_absent_or_ambiguous_source() {
        let lacp = || InfoBond::Mode(BondMode::Ieee8023Ad);
        let cases = [
            (
                bond_link(InfoKind::Veth, vec![], up()),
                "interface is not a bond",
            ),
            (
                bond_link(
                    InfoKind::Bond,
                    vec![
                        InfoBond::Mode(BondMode::ActiveBackup),
                        ad_info(PARTNER_MAC, 1),
                    ],
                    up(),
                ),
                "bond is not in 802.3ad (LACP) mode",
            ),
            (
                bond_link(
                    InfoKind::Bond,
                    vec![lacp(), ad_info(PARTNER_MAC, 1)],
                    LinkFlags::Up,
                ),
                "bond is down (admin down or no carrier)",
            ),
            (
                bond_link(InfoKind::Bond, vec![lacp()], up()),
                "bond has no active LACP aggregator",
            ),
            (
                bond_link(InfoKind::Bond, vec![lacp(), ad_info([0; 6], 0)], up()),
                "bond has no LACP partner yet",
            ),
        ];
        for (link, want) in cases {
            assert_eq!(lacp_partner_from_link(&link).unwrap_err().to_string(), want);
        }
    }
}
