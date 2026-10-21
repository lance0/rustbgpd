//! Fast external failover link monitor.
//!
//! Keeps an authoritative [`LinkSnapshot`] of the kernel's interfaces (name,
//! `IFF_UP`, `IFF_LOWER_UP`) and addresses on a dedicated `NETLINK_ROUTE`
//! socket subscribed to `RTNLGRP_LINK` and the IPv4/IPv6 address groups, and
//! publishes it on a `watch` channel. The monitor only ever writes the latest
//! state, so it is never blocked by its consumers; the peer manager treats
//! each published change as a coalesced "links changed" poke and asks
//! eligible sessions to judge their own connections against the snapshot
//! they then read.
//!
//! Unknown is never down. The snapshot is `valid` only after a complete dump.
//! A netlink overrun invalidates it until a re-dump succeeds, and a failed
//! dump leaves it invalid rather than empty: an empty table read as "every
//! address is gone" would stop every session. Unlike the EVPN carrier
//! projection (`evpn-linux` `link_carrier.rs`, which fails closed), nothing
//! here infers down from absence of observation. There is no debounce (FRR
//! has none): dampening belongs in the bond's `downdelay` or the link's
//! carrier settings.

use std::collections::btree_map::Entry;

use rustbgpd_transport::{InterfaceAddress, LinkSnapshot, LinkState};

/// One classified kernel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// `RTM_NEWLINK`.
    Link {
        ifindex: u32,
        name: Option<String>,
        admin_up: bool,
        lower_up: bool,
    },
    /// `RTM_DELLINK`.
    LinkRemoved { ifindex: u32 },
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

/// A complete dump: interfaces and addresses.
pub(crate) type Dump = (Vec<(u32, LinkState)>, Vec<(u32, InterfaceAddress)>);

/// The monitor's working copy of the snapshot. Pure: the netlink side feeds
/// it observations and dumps and publishes it when it changes.
#[derive(Debug, Default)]
pub(crate) struct LinkTable {
    snapshot: LinkSnapshot,
}

impl LinkTable {
    pub(crate) fn snapshot(&self) -> &LinkSnapshot {
        &self.snapshot
    }

    /// Apply one observation. Returns whether the snapshot changed.
    pub(crate) fn apply(&mut self, observation: Observation) -> bool {
        let snapshot = &mut self.snapshot;
        match observation {
            Observation::Link {
                ifindex,
                name,
                admin_up,
                lower_up,
            } => match snapshot.links.entry(ifindex) {
                Entry::Vacant(entry) => {
                    entry.insert(LinkState {
                        name: name.unwrap_or_else(|| format!("ifindex{ifindex}")),
                        admin_up,
                        lower_up,
                    });
                    true
                }
                Entry::Occupied(mut entry) => {
                    let link = entry.get_mut();
                    let before = link.clone();
                    if let Some(name) = name {
                        link.name = name;
                    }
                    link.admin_up = admin_up;
                    link.lower_up = lower_up;
                    *link != before
                }
            },
            Observation::LinkRemoved { ifindex } => {
                let link = snapshot.links.remove(&ifindex).is_some();
                snapshot.addresses.remove(&ifindex).is_some() || link
            }
            Observation::AddressAdded { ifindex, address } => {
                let addresses = snapshot.addresses.entry(ifindex).or_default();
                let added = !addresses.contains(&address);
                if added {
                    addresses.push(address);
                }
                added
            }
            Observation::AddressRemoved { ifindex, address } => snapshot
                .addresses
                .get_mut(&ifindex)
                .is_some_and(|addresses| {
                    let before = addresses.len();
                    addresses.retain(|known| *known != address);
                    addresses.len() != before
                }),
        }
    }

    /// Notifications may have been lost: the tables are no longer known to be
    /// current. Returns whether the snapshot changed.
    pub(crate) fn invalidate(&mut self) -> bool {
        std::mem::replace(&mut self.snapshot.valid, false)
    }

    /// Apply the result of a full dump. A successful dump replaces both tables
    /// and makes the snapshot valid; a failed one leaves it invalid with its
    /// last contents, never empty-and-valid. Returns whether it changed.
    pub(crate) fn resync<E>(&mut self, dump: Result<Dump, E>) -> bool {
        let Ok((links, addresses)) = dump else {
            return self.invalidate();
        };
        let mut fresh = LinkSnapshot {
            valid: true,
            links: links.into_iter().collect(),
            ..LinkSnapshot::default()
        };
        for (ifindex, address) in addresses {
            let known = fresh.addresses.entry(ifindex).or_default();
            if !known.contains(&address) {
                known.push(address);
            }
        }
        let changed = fresh != self.snapshot;
        self.snapshot = fresh;
        changed
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::spawn;

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{Dump, LinkTable, Observation};
    use futures::{StreamExt, TryStreamExt};
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};
    use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
    use rtnetlink::sys::AsyncSocket;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_telemetry::metrics::NetlinkSubscriber;
    use rustbgpd_transport::{InterfaceAddress, LinkSnapshot, LinkState};
    use tokio::sync::watch;
    use tracing::{info, warn};

    /// How often an invalid snapshot retries its full dump.
    const RESYNC_RETRY: Duration = Duration::from_secs(1);

    /// Open the monitor's netlink socket and start it. `None` when the socket
    /// cannot be opened; sessions then rely on the hold timer and BFD.
    pub(crate) async fn spawn(metrics: BgpMetrics) -> Option<watch::Receiver<Arc<LinkSnapshot>>> {
        let (mut connection, handle, messages) = match rtnetlink::new_connection() {
            Ok(parts) => parts,
            Err(error) => {
                warn!(%error, "fast external failover disabled: cannot open NETLINK_ROUTE");
                return None;
            }
        };
        // Subscribe before the connection runs and before the dump, so no
        // change between the dump and the first message is missed.
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
        table.resync(dump(&handle).await);
        if !table.snapshot().valid {
            warn!(
                "fast external failover: initial interface dump failed; no session is stopped \
                 until a dump succeeds"
            );
        }
        let (tx, rx) = watch::channel(Arc::new(table.snapshot().clone()));
        tokio::spawn(run(handle, messages, table, tx, metrics));
        info!("fast external failover link monitor started");
        Some(rx)
    }

    async fn dump(handle: &rtnetlink::Handle) -> Result<Dump, rtnetlink::Error> {
        let mut links = Vec::new();
        let mut stream = handle.link().get().execute();
        while let Some(link) = stream.try_next().await? {
            if let Observation::Link {
                ifindex,
                name,
                admin_up,
                lower_up,
            } = link_observation(&link)
            {
                links.push((
                    ifindex,
                    LinkState {
                        name: name.unwrap_or_else(|| format!("ifindex{ifindex}")),
                        admin_up,
                        lower_up,
                    },
                ));
            }
        }
        let mut addresses = Vec::new();
        let mut stream = handle.address().get().execute();
        while let Some(message) = stream.try_next().await? {
            if let Some(address) = interface_address(&message) {
                addresses.push((message.header.index, address));
            }
        }
        Ok((links, addresses))
    }

    async fn run(
        handle: rtnetlink::Handle,
        mut messages: futures::channel::mpsc::UnboundedReceiver<(
            NetlinkMessage<RouteNetlinkMessage>,
            rtnetlink::sys::SocketAddr,
        )>,
        mut table: LinkTable,
        tx: watch::Sender<Arc<LinkSnapshot>>,
        metrics: BgpMetrics,
    ) {
        let mut retry = tokio::time::interval(RESYNC_RETRY);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let changed = tokio::select! {
                message = messages.next() => {
                    let Some((message, _)) = message else {
                        break;
                    };
                    match message.payload {
                        NetlinkPayload::InnerMessage(inner) => {
                            observation(&inner).is_some_and(|observation| table.apply(observation))
                        }
                        NetlinkPayload::Overrun(_) => {
                            metrics.record_netlink_subscription_overrun(
                                NetlinkSubscriber::FastExternalFailover,
                            );
                            warn!(
                                "fast external failover: netlink overrun; link state is unknown \
                                 and no session is stopped until a re-dump succeeds"
                            );
                            let invalidated = table.invalidate();
                            if invalidated {
                                tx.send_replace(Arc::new(table.snapshot().clone()));
                            }
                            table.resync(dump(&handle).await) || invalidated
                        }
                        _ => false,
                    }
                }
                _ = retry.tick(), if !table.snapshot().valid => {
                    table.resync(dump(&handle).await)
                }
            };
            if changed {
                // The peer manager wakes on the watch and pokes sessions.
                tx.send_replace(Arc::new(table.snapshot().clone()));
            }
            if tx.is_closed() {
                return;
            }
        }
        // The snapshot can no longer be kept current.
        table.invalidate();
        tx.send_replace(Arc::new(table.snapshot().clone()));
        warn!("fast external failover: netlink connection closed; link monitor exiting");
    }

    fn observation(message: &RouteNetlinkMessage) -> Option<Observation> {
        match message {
            RouteNetlinkMessage::NewLink(link) => Some(link_observation(link)),
            RouteNetlinkMessage::DelLink(link) => Some(Observation::LinkRemoved {
                ifindex: link.header.index,
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
        }
    }

    fn link_observation(link: &LinkMessage) -> Observation {
        let flags = link.header.flags;
        Observation::Link {
            ifindex: link.header.index,
            name: link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                }),
            admin_up: flags.contains(LinkFlags::Up),
            lower_up: flags.contains(LinkFlags::LowerUp),
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

    fn addr(local: &str, len: u8) -> InterfaceAddress {
        InterfaceAddress {
            local: local.parse().unwrap(),
            prefix: local.parse().unwrap(),
            prefix_len: len,
        }
    }

    fn eth0(admin_up: bool, lower_up: bool) -> Observation {
        Observation::Link {
            ifindex: 4,
            name: Some("eth0".into()),
            admin_up,
            lower_up,
        }
    }

    fn dumped() -> LinkTable {
        let mut table = LinkTable::default();
        let dump: Dump = (
            vec![(
                4,
                LinkState {
                    name: "eth0".into(),
                    admin_up: true,
                    lower_up: true,
                },
            )],
            vec![(4, addr("10.0.0.1", 30))],
        );
        assert!(table.resync(Ok::<_, ()>(dump)));
        table
    }

    #[test]
    fn invalid_until_the_first_successful_dump() {
        let mut table = LinkTable::default();
        assert!(!table.snapshot().valid);
        assert!(!table.resync(Err::<Dump, _>("dump failed")));
        assert!(!table.snapshot().valid);
        assert!(dumped().snapshot().valid);
    }

    /// A failed re-dump after an overrun leaves the snapshot invalid with its
    /// last contents; it never publishes an empty table as valid.
    #[test]
    fn a_failed_dump_never_yields_an_empty_valid_table() {
        let mut table = dumped();
        assert!(table.invalidate());
        assert!(!table.resync(Err::<Dump, _>("dump failed")));
        let snapshot = table.snapshot();
        assert!(!snapshot.valid);
        assert_eq!(snapshot.addresses[&4], vec![addr("10.0.0.1", 30)]);
        assert!(table.resync(Ok::<_, ()>((Vec::new(), Vec::new()))));
        assert!(table.snapshot().valid, "a successful dump revalidates");
    }

    #[test]
    fn observations_update_link_and_address_state() {
        let mut table = dumped();
        assert!(table.apply(eth0(true, false)));
        assert!(!table.snapshot().links[&4].lower_up);
        assert!(
            !table.apply(eth0(true, false)),
            "unchanged state is not a change"
        );
        assert!(table.apply(eth0(true, true)));
        assert!(table.apply(Observation::AddressRemoved {
            ifindex: 4,
            address: addr("10.0.0.1", 30),
        }));
        assert_eq!(table.snapshot().addresses[&4], Vec::new());
        assert!(table.apply(Observation::AddressAdded {
            ifindex: 4,
            address: addr("10.0.0.1", 30),
        }));
        assert!(!table.apply(Observation::AddressAdded {
            ifindex: 4,
            address: addr("10.0.0.1", 30),
        }));
        assert!(table.apply(Observation::LinkRemoved { ifindex: 4 }));
        assert!(table.snapshot().links.is_empty());
        assert!(table.snapshot().addresses.is_empty());
        assert!(table.snapshot().valid);
    }

    #[test]
    fn a_name_less_link_message_keeps_the_known_name() {
        let mut table = dumped();
        table.apply(Observation::Link {
            ifindex: 4,
            name: None,
            admin_up: false,
            lower_up: false,
        });
        assert_eq!(table.snapshot().links[&4].name, "eth0");
    }
}
