//! LACP partner read for RFC 7432 §5 type 1 ESI derivation.
//!
//! One synchronous `RTM_GETLINK` by name: the bond's mode, admin and
//! carrier flags, and `IFLA_BOND_AD_INFO` (the active aggregator's
//! partner system MAC and partner key) arrive in a single kernel
//! message, so the MAC and key can never be torn across a partner
//! change the way two separate sysfs reads could be. Synchronous
//! because the caller is config resolution, which is not async.

use std::fmt;

use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{
    BondAdInfo, BondMode, InfoBond, InfoData, InfoKind, LinkAttribute, LinkFlags, LinkInfo,
    LinkMessage,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

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

impl std::error::Error for LacpPartnerError {}

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

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(LacpPartnerError::Io)?;
    socket.bind_auto().map_err(LacpPartnerError::Io)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(LacpPartnerError::Io)?;
    socket.send(&buf, 0).map_err(LacpPartnerError::Io)?;
    let (reply, _) = socket.recv_from_full().map_err(LacpPartnerError::Io)?;
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
