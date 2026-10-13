//! Link admin-state primitives for the ADR-0140 core-isolation hold.
//!
//! The daemon takes the CE-facing members of a bound Ethernet Segment
//! administratively down (`RTM_SETLINK` clearing `IFF_UP`) while the PE
//! is core-isolated. This module only reads and writes kernel state:
//!
//! - [`AdminLinks::dump`] walks every link and returns the identity
//!   fields ADR-0140 decision 6 records (ifindex, name, master, assigned
//!   MAC, `IFLA_PERM_ADDRESS`, `IFLA_BOND_SLAVE_PERM_HWADDR`) together
//!   with admin state and carrier (`IFF_LOWER_UP`, the same bit the
//!   ADR-0085 `link_carrier` projection reads) and the lower device
//!   (`IFLA_LINK`) the uplink signal follows to find a stacked uplink.
//! - [`AdminLinks::get`] re-reads one link for the fresh check made
//!   immediately before each write.
//! - [`AdminLinks::set_admin_up`] writes only the `IFF_UP` bit.
//! - [`AdminLinks::open_with_events`] also subscribes to `RTNLGRP_LINK`
//!   and bumps a watch counter on every link add, change or delete, so
//!   the caller can rediscover bond members level-triggered.
//!
//! Ownership, receipts and policy live in the daemon.

use futures::StreamExt;
use futures::stream::TryStreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{
    InfoBondPort, InfoKind, InfoPortData, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use netlink_sys::AsyncSocket;
use rtnetlink::{Handle, LinkUnspec};
use tokio::sync::watch;
use tracing::warn;

use super::link_carrier::RTNLGRP_LINK;
use crate::error::DataplaneError;

/// One kernel link as the core-isolation hold sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLinkState {
    /// Kernel ifindex.
    pub ifindex: u32,
    /// `IFLA_IFNAME`.
    pub name: String,
    /// `IFF_UP`: administrative state.
    pub admin_up: bool,
    /// `IFF_LOWER_UP`: carrier, as in the `link_carrier` projection.
    pub carrier: bool,
    /// The link is a bond master (`IFLA_INFO_KIND` = `bond`).
    pub is_bond: bool,
    /// `IFLA_MASTER`.
    pub master: Option<u32>,
    /// `IFLA_LINK`: the lower device a VLAN, macvlan or ipvlan is stacked
    /// on, or a veth's peer. `None` when the kernel omits it (the link is
    /// its own lower), when it is 0, or when `IFLA_LINK_NETNSID` says the
    /// ifindex belongs to another namespace and so names no link here.
    pub lower: Option<u32>,
    /// `IFLA_ADDRESS`: the assigned MAC.
    pub address: Option<Vec<u8>>,
    /// `IFLA_PERM_ADDRESS`; the kernel omits an all-zero address.
    pub perm_address: Option<Vec<u8>>,
    /// `IFLA_BOND_SLAVE_PERM_HWADDR` for a bond member.
    pub bond_perm_hwaddr: Option<Vec<u8>>,
}

/// rtnetlink handle for admin-state reads and writes.
#[derive(Clone, Debug)]
pub struct AdminLinks {
    handle: Handle,
}

impl AdminLinks {
    /// Open a dedicated rtnetlink connection.
    ///
    /// # Errors
    /// [`DataplaneError::Io`] when the netlink socket cannot be opened.
    pub fn open() -> Result<Self, DataplaneError> {
        let (connection, handle, _messages) =
            rtnetlink::new_connection().map_err(DataplaneError::Io)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    /// Open a connection subscribed to `RTNLGRP_LINK`. The receiver's
    /// value is bumped on every `RTM_NEWLINK` / `RTM_DELLINK` (and on a
    /// receive-buffer overrun, which may hide one). The sender is
    /// dropped, closing the receiver, when the connection dies.
    ///
    /// # Errors
    /// [`DataplaneError::Io`] when the netlink socket cannot be opened
    /// or the group cannot be joined.
    pub fn open_with_events() -> Result<(Self, watch::Receiver<u64>), DataplaneError> {
        let (mut connection, handle, mut messages) =
            rtnetlink::new_connection().map_err(DataplaneError::Io)?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_LINK)
            .map_err(DataplaneError::Io)?;
        tokio::spawn(connection);
        let (tx, rx) = watch::channel(0_u64);
        tokio::spawn(async move {
            while let Some((message, _)) = messages.next().await {
                let relevant = match message.payload {
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewLink(_) | RouteNetlinkMessage::DelLink(_),
                    ) => true,
                    NetlinkPayload::Overrun(_) => {
                        warn!(
                            "core-isolation link subscription overran; rescanning links \
                             from current kernel state"
                        );
                        true
                    }
                    _ => false,
                };
                if relevant {
                    tx.send_modify(|count| *count = count.wrapping_add(1));
                }
            }
        });
        Ok((Self { handle }, rx))
    }

    /// Walk every link.
    ///
    /// # Errors
    /// [`DataplaneError::Other`] on a netlink dump failure.
    pub async fn dump(&self) -> Result<Vec<AdminLinkState>, DataplaneError> {
        let mut out = Vec::new();
        let mut stream = self.handle.link().get().execute();
        while let Some(message) = stream
            .try_next()
            .await
            .map_err(|e| DataplaneError::Other(format!("link dump: {e}")))?
        {
            if let Some(state) = parse_link(&message) {
                out.push(state);
            }
        }
        Ok(out)
    }

    /// Read one link by ifindex; `Ok(None)` when no such link exists.
    ///
    /// # Errors
    /// [`DataplaneError::Other`] on any other netlink failure.
    pub async fn get(&self, ifindex: u32) -> Result<Option<AdminLinkState>, DataplaneError> {
        let mut stream = self.handle.link().get().match_index(ifindex).execute();
        match stream.try_next().await {
            Ok(Some(message)) => Ok(parse_link(&message)),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(DataplaneError::Other(format!("link {ifindex} read: {e}"))),
        }
    }

    /// Set or clear `IFF_UP` on `ifindex` with `RTM_SETLINK`, changing
    /// no other flag.
    ///
    /// # Errors
    /// The classified netlink error.
    pub async fn set_admin_up(&self, ifindex: u32, up: bool) -> Result<(), DataplaneError> {
        let builder = LinkUnspec::new_with_index(ifindex);
        let message = if up { builder.up() } else { builder.down() }.build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| match e {
                rtnetlink::Error::NetlinkError(ref m)
                    if matches!(-m.raw_code(), libc::EPERM | libc::EACCES) =>
                {
                    DataplaneError::PermissionDenied(format!("link {ifindex} admin state: {e}"))
                }
                rtnetlink::Error::NetlinkError(ref m) if m.raw_code() == -libc::ENODEV => {
                    DataplaneError::LinkNotFound {
                        name: ifindex.to_string(),
                    }
                }
                other => DataplaneError::Other(format!("link {ifindex} admin state: {other}")),
            })
    }
}

/// Project one `RTM_NEWLINK` message; `None` without a name.
#[must_use]
pub fn parse_link(message: &LinkMessage) -> Option<AdminLinkState> {
    let mut state = AdminLinkState {
        ifindex: message.header.index,
        name: String::new(),
        admin_up: message.header.flags.contains(LinkFlags::Up),
        carrier: message.header.flags.contains(LinkFlags::LowerUp),
        is_bond: false,
        master: None,
        lower: None,
        address: None,
        perm_address: None,
        bond_perm_hwaddr: None,
    };
    let mut named = false;
    let mut other_netns = false;
    for attr in &message.attributes {
        match attr {
            LinkAttribute::IfName(name) => {
                state.name.clone_from(name);
                named = true;
            }
            LinkAttribute::Controller(master) => state.master = Some(*master),
            LinkAttribute::Link(lower) => state.lower = Some(*lower).filter(|&l| l != 0),
            LinkAttribute::LinkNetNsId(_) => other_netns = true,
            LinkAttribute::Address(mac) => state.address = Some(mac.clone()),
            LinkAttribute::PermAddress(mac) => state.perm_address = Some(mac.clone()),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(InfoKind::Bond) => state.is_bond = true,
                        LinkInfo::PortData(InfoPortData::BondPort(port)) => {
                            state.bond_perm_hwaddr = port.iter().find_map(|nla| match nla {
                                InfoBondPort::PermHwaddr(mac) => Some(mac.clone()),
                                _ => None,
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if other_netns {
        state.lower = None;
    }
    named.then_some(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_projects_identity_admin_and_carrier() {
        let mut message = LinkMessage::default();
        message.header.index = 7;
        message.header.flags = LinkFlags::Up;
        message.attributes = vec![
            LinkAttribute::IfName("m0".into()),
            LinkAttribute::Controller(3),
            LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
            LinkAttribute::LinkInfo(vec![LinkInfo::PortData(InfoPortData::BondPort(vec![
                InfoBondPort::PermHwaddr(vec![2, 0, 0, 0, 0, 9]),
            ]))]),
        ];
        let state = parse_link(&message).unwrap();
        assert_eq!(state.ifindex, 7);
        assert_eq!(state.name, "m0");
        assert!(state.admin_up);
        assert!(!state.carrier, "carrier is IFF_LOWER_UP, not IFF_UP");
        assert!(!state.is_bond);
        assert_eq!(state.master, Some(3));
        assert_eq!(state.bond_perm_hwaddr, Some(vec![2, 0, 0, 0, 0, 9]));
        assert_eq!(state.perm_address, None, "absent stays absent");
        assert_eq!(state.lower, None, "absent stays absent");

        // A VLAN's IFLA_LINK is its lower device; 0 or another namespace's
        // ifindex names no link here.
        message.attributes.push(LinkAttribute::Link(3));
        assert_eq!(parse_link(&message).unwrap().lower, Some(3));
        message.attributes.push(LinkAttribute::LinkNetNsId(1));
        assert_eq!(parse_link(&message).unwrap().lower, None);
        message
            .attributes
            .retain(|a| !matches!(a, LinkAttribute::Link(_) | LinkAttribute::LinkNetNsId(_)));
        message.attributes.push(LinkAttribute::Link(0));
        assert_eq!(parse_link(&message).unwrap().lower, None);

        message
            .attributes
            .retain(|a| !matches!(a, LinkAttribute::IfName(_)));
        assert_eq!(parse_link(&message), None);
    }
}
