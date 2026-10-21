//! Fast external failover link monitor.
//!
//! Watches `RTNLGRP_LINK` and the IPv4/IPv6 address groups on a dedicated
//! `NETLINK_ROUTE` socket and turns **explicit** kernel messages into
//! [`LinkDownEvent`]s for the peer manager:
//!
//! - `RTM_NEWLINK` with `IFF_UP` clear: administratively down;
//! - `RTM_NEWLINK` with `IFF_UP` set and `IFF_LOWER_UP` clear: carrier lost;
//! - `RTM_DELLINK`: interface removed;
//! - `RTM_DELADDR`: one local address removed.
//!
//! Each event carries the addresses the interface held, so a session can prove
//! from its own socket that the interface carries it. The monitor keeps that
//! address table from an initial dump plus `RTM_NEWADDR` / `RTM_DELADDR`.
//!
//! Unknown is never down. Unlike the EVPN carrier projection
//! (`evpn-linux` `link_carrier.rs`, which fails closed and so reads a missing
//! link as down), nothing here is inferred from absence: a netlink overrun is
//! counted and logged, the address table is re-dumped, the per-interface
//! down-edge memory is cleared, and no event is synthesized. A session whose
//! link-down notification was lost falls back to its hold timer or BFD. There
//! is no poll backstop that could turn a failed observation into a teardown.
//! There is no debounce either (FRR has none): dampening belongs in the bond's
//! `downdelay` or the link's carrier settings.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rustbgpd_transport::{InterfaceAddress, LinkDownCause, LinkDownEvent};

/// One classified kernel observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// `RTM_NEWLINK`: name and whether the link is down, and why.
    Link {
        ifindex: u32,
        ifname: Option<String>,
        down: Option<LinkDownCause>,
    },
    /// `RTM_DELLINK`.
    LinkRemoved {
        ifindex: u32,
        ifname: Option<String>,
    },
    /// `RTM_NEWADDR`.
    AddressAdded {
        ifindex: u32,
        address: InterfaceAddress,
    },
    /// `RTM_DELADDR`.
    AddressRemoved {
        ifindex: u32,
        address: InterfaceAddress,
    },
}

/// Classify link flags. `IFF_UP` clear is an operator admin-down (the kernel
/// also clears `IFF_LOWER_UP` then, so it is checked first); `IFF_UP` set with
/// `IFF_LOWER_UP` clear is carrier loss. `IFF_RUNNING` / operstate are not
/// consulted: a bond with one live member keeps `IFF_LOWER_UP`.
#[must_use]
pub(crate) const fn link_down_cause(up: bool, lower_up: bool) -> Option<LinkDownCause> {
    if !up {
        Some(LinkDownCause::AdminDown)
    } else if !lower_up {
        Some(LinkDownCause::CarrierLost)
    } else {
        None
    }
}

/// Interface addresses and down-edge memory. Pure: the netlink side feeds it
/// observations and forwards whatever events it returns.
#[derive(Debug, Default)]
pub(crate) struct LinkTable {
    addresses: HashMap<u32, Vec<InterfaceAddress>>,
    names: HashMap<u32, String>,
    /// Interfaces last seen down, so repeated `RTM_NEWLINK`s for a link that
    /// stays down produce one event.
    down: HashSet<u32>,
}

impl LinkTable {
    fn name(&self, ifindex: u32) -> String {
        self.names
            .get(&ifindex)
            .cloned()
            .unwrap_or_else(|| format!("ifindex{ifindex}"))
    }

    /// Apply one observation; return the confirmed-down event it proves, if
    /// any.
    pub(crate) fn apply(&mut self, observation: Observation) -> Option<LinkDownEvent> {
        match observation {
            Observation::Link {
                ifindex,
                ifname,
                down,
            } => {
                if let Some(ifname) = ifname {
                    self.names.insert(ifindex, ifname);
                }
                let cause = down?;
                if !self.down.insert(ifindex) {
                    return None;
                }
                Some(self.event(ifindex, cause, self.addresses_of(ifindex)))
            }
            Observation::LinkRemoved { ifindex, ifname } => {
                if let Some(ifname) = ifname {
                    self.names.insert(ifindex, ifname);
                }
                let addresses = self.addresses.remove(&ifindex).unwrap_or_default();
                let event = self.event(ifindex, LinkDownCause::InterfaceRemoved, addresses);
                self.names.remove(&ifindex);
                self.down.remove(&ifindex);
                Some(event)
            }
            Observation::AddressAdded { ifindex, address } => {
                let addresses = self.addresses.entry(ifindex).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                None
            }
            Observation::AddressRemoved { ifindex, address } => {
                if let Some(addresses) = self.addresses.get_mut(&ifindex) {
                    addresses.retain(|known| *known != address);
                }
                Some(self.event(ifindex, LinkDownCause::AddressRemoved, vec![address]))
            }
        }
        // An interface with no known address cannot carry a session.
        .filter(|event| !event.addresses.is_empty())
    }

    /// Clear an up edge so the next down for `ifindex` is reported.
    fn link_up(&mut self, ifindex: u32) {
        self.down.remove(&ifindex);
    }

    /// A lost notification leaves the table's view unknown: forget the
    /// down-edge memory (so the next explicit down is reported) and replace
    /// the addresses with a fresh dump. Never yields an event.
    pub(crate) fn resync(&mut self, addresses: Vec<(u32, InterfaceAddress)>) {
        self.down.clear();
        self.addresses.clear();
        for (ifindex, address) in addresses {
            self.apply(Observation::AddressAdded { ifindex, address });
        }
    }

    fn addresses_of(&self, ifindex: u32) -> Vec<InterfaceAddress> {
        self.addresses.get(&ifindex).cloned().unwrap_or_default()
    }

    fn event(
        &self,
        ifindex: u32,
        cause: LinkDownCause,
        addresses: Vec<InterfaceAddress>,
    ) -> LinkDownEvent {
        LinkDownEvent {
            ifindex,
            ifname: self.name(ifindex),
            cause,
            addresses,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::spawn;

#[cfg(target_os = "linux")]
mod linux {
    use super::{Arc, InterfaceAddress, LinkDownEvent, LinkTable, Observation, link_down_cause};
    use futures::{StreamExt, TryStreamExt};
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};
    use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
    use rtnetlink::sys::AsyncSocket;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_telemetry::metrics::NetlinkSubscriber;
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    /// Link-down events are rare and each is fanned out immediately; the
    /// monitor awaits capacity rather than dropping a confirmed down.
    const EVENT_BUFFER: usize = 64;

    /// Open the monitor's netlink socket and start it. `None` when the socket
    /// cannot be opened; sessions then rely on the hold timer and BFD.
    pub(crate) async fn spawn(metrics: BgpMetrics) -> Option<mpsc::Receiver<Arc<LinkDownEvent>>> {
        let (mut connection, handle, messages) = match rtnetlink::new_connection() {
            Ok(parts) => parts,
            Err(error) => {
                warn!(%error, "fast external failover disabled: cannot open NETLINK_ROUTE");
                return None;
            }
        };
        // Subscribe before the connection runs and before the dump, so no
        // change between the dump and the first event is missed.
        for group in [
            libc::RTNLGRP_LINK,
            libc::RTNLGRP_IPV4_IFADDR,
            libc::RTNLGRP_IPV6_IFADDR,
        ] {
            if let Err(error) = connection.socket_mut().socket_mut().add_membership(group) {
                warn!(%error, group, "fast external failover disabled: netlink subscription failed");
                return None;
            }
        }
        tokio::spawn(connection);
        let mut table = LinkTable::default();
        if let Err(error) = seed(&handle, &mut table).await {
            warn!(%error, "fast external failover: initial interface dump failed; \
                  sessions are matched as addresses are announced");
        }
        let (tx, rx) = mpsc::channel(EVENT_BUFFER);
        tokio::spawn(run(handle, messages, table, tx, metrics));
        info!("fast external failover link monitor started");
        Some(rx)
    }

    async fn seed(
        handle: &rtnetlink::Handle,
        table: &mut LinkTable,
    ) -> Result<(), rtnetlink::Error> {
        let mut links = handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            table.apply(link_observation(&link));
        }
        table.resync(dump_addresses(handle).await?);
        // The seed reports nothing: a link already down at startup has no
        // session on it yet.
        Ok(())
    }

    async fn dump_addresses(
        handle: &rtnetlink::Handle,
    ) -> Result<Vec<(u32, InterfaceAddress)>, rtnetlink::Error> {
        let mut out = Vec::new();
        let mut addresses = handle.address().get().execute();
        while let Some(message) = addresses.try_next().await? {
            if let Some(address) = interface_address(&message) {
                out.push((message.header.index, address));
            }
        }
        Ok(out)
    }

    async fn run(
        handle: rtnetlink::Handle,
        mut messages: futures::channel::mpsc::UnboundedReceiver<(
            NetlinkMessage<RouteNetlinkMessage>,
            rtnetlink::sys::SocketAddr,
        )>,
        mut table: LinkTable,
        tx: mpsc::Sender<Arc<LinkDownEvent>>,
        metrics: BgpMetrics,
    ) {
        while let Some((message, _)) = messages.next().await {
            let inner = match message.payload {
                NetlinkPayload::InnerMessage(inner) => inner,
                NetlinkPayload::Overrun(_) => {
                    metrics.record_netlink_subscription_overrun(
                        NetlinkSubscriber::FastExternalFailover,
                    );
                    warn!(
                        "fast external failover: netlink overrun; link state is unknown until \
                         the next explicit event, no session is stopped for it"
                    );
                    match dump_addresses(&handle).await {
                        Ok(addresses) => table.resync(addresses),
                        Err(error) => {
                            warn!(%error, "fast external failover: address resync failed");
                            table.resync(Vec::new());
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            let observation = match &inner {
                RouteNetlinkMessage::NewLink(link) => {
                    let observation = link_observation(link);
                    if let Observation::Link {
                        down: None,
                        ifindex,
                        ..
                    } = &observation
                    {
                        table.link_up(*ifindex);
                    }
                    Some(observation)
                }
                RouteNetlinkMessage::DelLink(link) => Some(Observation::LinkRemoved {
                    ifindex: link.header.index,
                    ifname: link_name(link),
                }),
                RouteNetlinkMessage::NewAddress(message) => {
                    interface_address(message).map(|address| Observation::AddressAdded {
                        ifindex: message.header.index,
                        address,
                    })
                }
                RouteNetlinkMessage::DelAddress(message) => {
                    interface_address(message).map(|address| Observation::AddressRemoved {
                        ifindex: message.header.index,
                        address,
                    })
                }
                _ => None,
            };
            let Some(event) = observation.and_then(|observation| table.apply(observation)) else {
                continue;
            };
            warn!(
                interface = %event.ifname,
                ifindex = event.ifindex,
                reason = event.cause.as_str(),
                "fast external failover: interface down confirmed by the kernel"
            );
            if tx.send(Arc::new(event)).await.is_err() {
                return;
            }
        }
        warn!("fast external failover: netlink connection closed; link monitor exiting");
    }

    fn link_name(link: &LinkMessage) -> Option<String> {
        link.attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            })
    }

    fn link_observation(link: &LinkMessage) -> Observation {
        let flags = link.header.flags;
        Observation::Link {
            ifindex: link.header.index,
            ifname: link_name(link),
            down: link_down_cause(
                flags.contains(LinkFlags::Up),
                flags.contains(LinkFlags::LowerUp),
            ),
        }
    }

    /// `IFA_LOCAL` is the address sockets bind to; `IFA_ADDRESS` is the
    /// connected prefix (the remote end on point-to-point links). IPv6
    /// usually carries only `IFA_ADDRESS`.
    fn interface_address(message: &AddressMessage) -> Option<InterfaceAddress> {
        let mut local = None;
        let mut address = None;
        for attribute in &message.attributes {
            match attribute {
                AddressAttribute::Local(ip) => local = Some(*ip),
                AddressAttribute::Address(ip) => address = Some(*ip),
                _ => {}
            }
        }
        let prefix = address.or(local)?;
        Some(InterfaceAddress {
            local: local.unwrap_or(prefix),
            prefix,
            prefix_len: message.header.prefix_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(local: &str, prefix: &str, len: u8) -> InterfaceAddress {
        InterfaceAddress {
            local: local.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
            prefix_len: len,
        }
    }

    fn table_with_eth0() -> LinkTable {
        let mut table = LinkTable::default();
        assert!(
            table
                .apply(Observation::Link {
                    ifindex: 4,
                    ifname: Some("eth0".into()),
                    down: None,
                })
                .is_none()
        );
        assert!(
            table
                .apply(Observation::AddressAdded {
                    ifindex: 4,
                    address: addr("10.0.0.1", "10.0.0.0", 30),
                })
                .is_none()
        );
        table
    }

    #[test]
    fn link_flags_classify_admin_down_before_carrier() {
        assert_eq!(
            link_down_cause(false, false),
            Some(LinkDownCause::AdminDown)
        );
        assert_eq!(link_down_cause(false, true), Some(LinkDownCause::AdminDown));
        assert_eq!(
            link_down_cause(true, false),
            Some(LinkDownCause::CarrierLost)
        );
        assert_eq!(link_down_cause(true, true), None);
    }

    #[test]
    fn carrier_loss_reports_the_interface_addresses_once() {
        let mut table = table_with_eth0();
        let down = Observation::Link {
            ifindex: 4,
            ifname: None,
            down: Some(LinkDownCause::CarrierLost),
        };
        let event = table.apply(down.clone()).expect("confirmed down");
        assert_eq!(event.ifname, "eth0");
        assert_eq!(event.cause, LinkDownCause::CarrierLost);
        assert_eq!(event.addresses, vec![addr("10.0.0.1", "10.0.0.0", 30)]);
        assert!(table.apply(down.clone()).is_none(), "repeat while down");
        table.link_up(4);
        assert!(table.apply(down).is_some(), "a new down edge reports again");
    }

    #[test]
    fn interface_removal_and_address_removal_are_distinct_events() {
        let mut table = table_with_eth0();
        let removed = table
            .apply(Observation::AddressRemoved {
                ifindex: 4,
                address: addr("10.0.0.1", "10.0.0.0", 30),
            })
            .expect("address removed");
        assert_eq!(removed.cause, LinkDownCause::AddressRemoved);
        assert_eq!(removed.addresses, vec![addr("10.0.0.1", "10.0.0.0", 30)]);

        let mut table = table_with_eth0();
        let gone = table
            .apply(Observation::LinkRemoved {
                ifindex: 4,
                ifname: Some("eth0".into()),
            })
            .expect("interface removed");
        assert_eq!(gone.cause, LinkDownCause::InterfaceRemoved);
        assert_eq!(gone.addresses, vec![addr("10.0.0.1", "10.0.0.0", 30)]);
        // A recreated interface reusing the index starts clean.
        assert!(
            table
                .apply(Observation::Link {
                    ifindex: 4,
                    ifname: Some("eth0".into()),
                    down: Some(LinkDownCause::AdminDown),
                })
                .is_none(),
            "no addresses yet, so nothing can be carried"
        );
    }

    #[test]
    fn down_on_an_interface_without_addresses_is_not_reported() {
        let mut table = LinkTable::default();
        assert!(
            table
                .apply(Observation::Link {
                    ifindex: 9,
                    ifname: Some("dummy0".into()),
                    down: Some(LinkDownCause::CarrierLost),
                })
                .is_none()
        );
    }

    /// Unknown is not down: a resync after an overrun reports nothing, even
    /// when the fresh dump no longer lists an interface's addresses.
    #[test]
    fn resync_never_reports_a_down() {
        let mut table = table_with_eth0();
        table.resync(Vec::new());
        assert_eq!(table.addresses_of(4), Vec::new());
        // ...and a link the monitor lost track of reports on its next
        // explicit down only if it still carries known addresses.
        table.resync(vec![(4, addr("10.0.0.1", "10.0.0.0", 30))]);
        let event = table
            .apply(Observation::Link {
                ifindex: 4,
                ifname: None,
                down: Some(LinkDownCause::CarrierLost),
            })
            .expect("explicit down after resync");
        assert_eq!(event.addresses.len(), 1);
    }

    #[test]
    fn resync_clears_down_edge_memory() {
        let mut table = table_with_eth0();
        let down = Observation::Link {
            ifindex: 4,
            ifname: None,
            down: Some(LinkDownCause::CarrierLost),
        };
        assert!(table.apply(down.clone()).is_some());
        // The up edge was lost in an overrun.
        table.resync(vec![(4, addr("10.0.0.1", "10.0.0.0", 30))]);
        assert!(table.apply(down).is_some());
    }

    #[test]
    fn duplicate_address_announcements_are_stored_once() {
        let mut table = table_with_eth0();
        table.apply(Observation::AddressAdded {
            ifindex: 4,
            address: addr("10.0.0.1", "10.0.0.0", 30),
        });
        assert_eq!(table.addresses_of(4).len(), 1);
    }
}
