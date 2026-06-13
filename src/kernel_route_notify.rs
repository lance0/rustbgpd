//! `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` subscriber — kernel
//! route-table change feed for the general-FIB and BLACKHOLE
//! reconcilers' kernel-side drift eventing.
//!
//! Both reconcilers were already event-driven for *RIB*-side changes
//! (best-route broadcasts), but kernel-side drift — a programmed route
//! row deleted or clobbered externally (`ip route del` / `ip route
//! replace`, a table flush) — was only repaired by the 30 s periodic
//! reconcile pass. This module subscribes each actor's existing
//! rtnetlink connection to the kernel route multicast groups and
//! forwards parsed [`KernelRouteEvent`]s; the actor-side classifiers
//! (`kernel_route_drift_wakes` in `fib_runtime` / `blackhole`) decide
//! whether an event is drift of *owned* state worth a coalesced wake.
//!
//! The evpn-linux notify task (PR #476's `notify.rs`) is the template:
//! pure classification on parsed messages, a coalesced wake, and the
//! periodic pass retained as the backstop. The evpn-linux socket
//! already subscribes to these same route groups for its own IP-VRF
//! observation — that subscription belongs to the EVPN dataplane
//! actor and cannot serve the FIB/blackhole actors, which run with
//! EVPN disabled and own their own `NETLINK_ROUTE` connections.
//! Multicast membership is per-socket, so each actor subscribes its
//! own connection; nothing here touches the evpn-linux socket.
//!
//! Subscription failures degrade gracefully: the actor keeps running
//! with the periodic reconcile as its only kernel-drift repair, which
//! is exactly the pre-eventing behavior.

use rustbgpd_wire::Prefix;
use tokio::sync::mpsc;

/// Bound for the kernel-route-event wake feed. Drop-on-full is safe:
/// the reconcile is level-triggered and a 30 s periodic pass is the
/// backstop, so a dropped wake under a route-message storm is repaired
/// on the next pass rather than lost (the #476 evpn-linux pattern).
const KERNEL_ROUTE_EVENT_BUFFER: usize = 64;

/// Multicast group ID for IPv4 route-table changes — enum value
/// `RTNLGRP_IPV4_ROUTE` from `<linux/rtnetlink.h>` (value `7`).
///
/// **Critical:** this is the **enum group id** consumed by
/// `NETLINK_ADD_MEMBERSHIP`, not the legacy bitmask
/// `RTMGRP_IPV4_ROUTE = 0x40`. See the pinned table in
/// `crates/evpn-linux/src/linux/notify.rs`, which documents how the
/// off-by-one / bitmask confusions were caught (the M37 and M39
/// interop smokes). The pin test below keeps the values honest.
#[cfg(any(target_os = "linux", test))]
pub(crate) const RTNLGRP_IPV4_ROUTE: u32 = 7;

/// Multicast group ID for IPv6 route-table changes — enum value
/// `RTNLGRP_IPV6_ROUTE` from `<linux/rtnetlink.h>` (value `11`).
#[cfg(any(target_os = "linux", test))]
pub(crate) const RTNLGRP_IPV6_ROUTE: u32 = 11;

/// Kind of `RTM_*ROUTE` notification we received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRouteEventKind {
    /// `RTM_NEWROUTE` — kernel added (or replaced) a route.
    New,
    /// `RTM_DELROUTE` — kernel removed a route.
    Del,
}

/// Kernel route type, reduced to the variants the drift classifiers
/// distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRouteType {
    /// `RTN_UNICAST` — the general-FIB reconciler's install type.
    Unicast,
    /// `RTN_BLACKHOLE` — half of the BLACKHOLE ownership marker.
    BlackHole,
    /// Anything else (`local`, `broadcast`, `unreachable`, ...).
    Other,
}

/// One parsed kernel route notification, reduced to the identity
/// fields the drift classifiers match on. Platform-neutral so the
/// classifiers and their unit tests build everywhere; only the parse
/// and subscription sides are Linux-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelRouteEvent {
    /// New (add/replace) or Del.
    pub kind: KernelRouteEventKind,
    /// Resolved route table id (`RTA_TABLE` over the header byte, so
    /// table ids ≥ 256 behind the `RT_TABLE_COMPAT` sentinel resolve
    /// correctly).
    pub table_id: u32,
    /// Kernel route metric / priority (`RTA_PRIORITY`, 0 when absent —
    /// the kernel omits the attribute for metric-0 rows).
    pub metric: u32,
    /// Destination prefix. `None` when the message carries no
    /// reconstructible destination (non-default routes missing
    /// `RTA_DST`).
    pub prefix: Option<Prefix>,
    /// `RTPROT_BGP` — our install protocol, half of each actor's
    /// ownership signature.
    pub protocol_is_bgp: bool,
    /// Reduced route type.
    pub route_type: KernelRouteType,
}

/// Await the next kernel route event from an optional stream. A `None`
/// stream (fake/non-Linux backing, or a stream the caller retired
/// after it closed) parks forever, so the actor's `select!` arm simply
/// never fires and the periodic backstop carries kernel-drift repair.
pub(crate) async fn recv_kernel_route_event(
    rx: &mut Option<mpsc::Receiver<KernelRouteEvent>>,
) -> Option<KernelRouteEvent> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Open the actor's `NETLINK_ROUTE` connection with route-group
/// multicast membership, returning the request handle plus the parsed
/// kernel route-event stream.
///
/// Membership is added **before** the connection task is spawned (the
/// evpn-linux `mod.rs` pattern), so no notification can slip past
/// between socket creation and subscription. A membership failure
/// warns and degrades: the handle still works and the reconciler
/// falls back to periodic-only kernel-drift repair.
#[cfg(target_os = "linux")]
pub(crate) fn connect_with_route_notifications(
    actor: &'static str,
) -> Result<(rtnetlink::Handle, mpsc::Receiver<KernelRouteEvent>), String> {
    use rtnetlink::sys::AsyncSocket;

    let (mut connection, handle, messages) =
        rtnetlink::new_connection().map_err(|e| format!("open NETLINK_ROUTE: {e}"))?;
    for (group, name) in [
        (RTNLGRP_IPV4_ROUTE, "RTNLGRP_IPV4_ROUTE"),
        (RTNLGRP_IPV6_ROUTE, "RTNLGRP_IPV6_ROUTE"),
    ] {
        if let Err(e) = connection.socket_mut().socket_mut().add_membership(group) {
            tracing::warn!(
                error = %e,
                group = name,
                actor,
                "kernel route-event subscription failed; kernel-side drift repair \
                 degrades to the periodic reconcile backstop"
            );
        }
    }
    tokio::spawn(connection);
    let (event_tx, event_rx) = mpsc::channel(KERNEL_ROUTE_EVENT_BUFFER);
    tokio::spawn(forward_route_notifications(messages, event_tx));
    Ok((handle, event_rx))
}

/// Drain the connection's unsolicited-message stream, forwarding
/// parsed `RTM_NEWROUTE` / `RTM_DELROUTE` notifications. Ends when
/// either side closes (connection shutdown or the actor dropping its
/// receiver).
#[cfg(target_os = "linux")]
async fn forward_route_notifications(
    mut messages: futures::channel::mpsc::UnboundedReceiver<(
        rtnetlink::packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
        rtnetlink::sys::SocketAddr,
    )>,
    event_tx: mpsc::Sender<KernelRouteEvent>,
) {
    use futures::StreamExt;
    use mpsc::error::TrySendError;
    use netlink_packet_route::RouteNetlinkMessage;
    use rtnetlink::packet_core::NetlinkPayload;

    // Log the first drop-on-full only, so a sustained storm doesn't
    // spam the log; the periodic backstop repairs whatever was dropped.
    let mut warned_full = false;
    while let Some((message, _addr)) = messages.next().await {
        let NetlinkPayload::InnerMessage(inner) = message.payload else {
            continue;
        };
        let event = match inner {
            RouteNetlinkMessage::NewRoute(msg) => {
                parse_kernel_route_event(KernelRouteEventKind::New, &msg)
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                parse_kernel_route_event(KernelRouteEventKind::Del, &msg)
            }
            _ => continue,
        };
        // Drop-on-full is the point: never `.await` the send. The
        // reconcile is level-triggered with a 30 s periodic backstop,
        // so a dropped wake under a storm is repaired on the next pass.
        match event_tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if !warned_full {
                    warned_full = true;
                    tracing::debug!(
                        "kernel route-event wake feed full; dropping events, the \
                         periodic reconcile backstop will repair the drift"
                    );
                }
            }
            // The actor dropped its receiver — the stream is retired.
            Err(TrySendError::Closed(_)) => return,
        }
    }
}

/// Reduce one kernel `RouteMessage` to the identity fields the drift
/// classifiers match on. Pure, so the table/metric/prefix resolution
/// rules are unit-testable without a netlink socket.
#[cfg(target_os = "linux")]
pub(crate) fn parse_kernel_route_event(
    kind: KernelRouteEventKind,
    msg: &netlink_packet_route::route::RouteMessage,
) -> KernelRouteEvent {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol, RouteType};
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    let mut table_id = u32::from(msg.header.table);
    let mut metric = 0;
    let mut destination = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Table(id) => table_id = *id,
            RouteAttribute::Priority(value) => metric = *value,
            RouteAttribute::Destination(addr) => destination = Some(addr),
            _ => {}
        }
    }

    let len = msg.header.destination_prefix_length;
    let prefix = match (msg.header.address_family, destination) {
        (AddressFamily::Inet, Some(RouteAddress::Inet(addr))) => {
            Some(Prefix::V4(Ipv4Prefix::new(*addr, len)))
        }
        (AddressFamily::Inet6, Some(RouteAddress::Inet6(addr))) => {
            Some(Prefix::V6(Ipv6Prefix::new(*addr, len)))
        }
        // A missing destination is only valid for the default route.
        (AddressFamily::Inet, None) if len == 0 => Some(Prefix::V4(Ipv4Prefix::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))),
        (AddressFamily::Inet6, None) if len == 0 => Some(Prefix::V6(Ipv6Prefix::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
        ))),
        _ => None,
    };

    KernelRouteEvent {
        kind,
        table_id,
        metric,
        prefix,
        protocol_is_bgp: msg.header.protocol == RouteProtocol::Bgp,
        route_type: match msg.header.kind {
            RouteType::Unicast => KernelRouteType::Unicast,
            RouteType::BlackHole => KernelRouteType::BlackHole,
            _ => KernelRouteType::Other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same enum-id-vs-legacy-bitmask pin as the evpn-linux notify
    /// module: `add_membership` takes the `rtnetlink_groups` enum
    /// value, and these constants silently subscribing to the wrong
    /// group is exactly the failure mode that needs a tripwire.
    #[test]
    fn route_group_ids_are_rtnetlink_enum_values() {
        assert_eq!(RTNLGRP_IPV4_ROUTE, 7);
        assert_eq!(RTNLGRP_IPV6_ROUTE, 11);
    }

    #[cfg(target_os = "linux")]
    mod parse {
        use netlink_packet_route::AddressFamily;
        use netlink_packet_route::route::{
            RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteType,
        };
        use rustbgpd_wire::Ipv4Prefix;

        use super::super::*;

        fn message(
            table: u8,
            protocol: RouteProtocol,
            kind: RouteType,
            attributes: Vec<RouteAttribute>,
        ) -> RouteMessage {
            let mut msg = RouteMessage::default();
            msg.header = RouteHeader {
                address_family: AddressFamily::Inet,
                destination_prefix_length: 32,
                table,
                protocol,
                kind,
                ..Default::default()
            };
            msg.attributes = attributes;
            msg
        }

        #[test]
        fn parse_resolves_table_attribute_over_header_byte() {
            // RT_TABLE_COMPAT sentinel in the header; real id in RTA_TABLE.
            let msg = message(
                252,
                RouteProtocol::Bgp,
                RouteType::Unicast,
                vec![RouteAttribute::Table(1000)],
            );
            let event = parse_kernel_route_event(KernelRouteEventKind::Del, &msg);
            assert_eq!(event.table_id, 1000);
            assert!(event.protocol_is_bgp);
            assert_eq!(event.route_type, KernelRouteType::Unicast);
        }

        #[test]
        fn parse_defaults_metric_to_zero_and_reads_priority() {
            let bare = message(254, RouteProtocol::Static, RouteType::Unicast, Vec::new());
            assert_eq!(
                parse_kernel_route_event(KernelRouteEventKind::New, &bare).metric,
                0
            );
            let with_metric = message(
                254,
                RouteProtocol::Static,
                RouteType::Unicast,
                vec![RouteAttribute::Priority(200)],
            );
            assert_eq!(
                parse_kernel_route_event(KernelRouteEventKind::New, &with_metric).metric,
                200
            );
        }

        #[test]
        fn parse_extracts_destination_prefix() {
            let msg = message(
                254,
                RouteProtocol::Bgp,
                RouteType::BlackHole,
                vec![RouteAttribute::Destination(RouteAddress::Inet(
                    "198.51.100.9".parse().unwrap(),
                ))],
            );
            let event = parse_kernel_route_event(KernelRouteEventKind::Del, &msg);
            assert_eq!(
                event.prefix,
                Some(Prefix::V4(Ipv4Prefix::new(
                    "198.51.100.9".parse().unwrap(),
                    32
                )))
            );
            assert_eq!(event.route_type, KernelRouteType::BlackHole);
        }

        #[test]
        fn parse_reconstructs_default_route_and_drops_unparseable_destination() {
            let mut default_route =
                message(254, RouteProtocol::Static, RouteType::Unicast, Vec::new());
            default_route.header.destination_prefix_length = 0;
            assert_eq!(
                parse_kernel_route_event(KernelRouteEventKind::Del, &default_route).prefix,
                Some(Prefix::V4(Ipv4Prefix::new(
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0
                )))
            );
            // /32 with no RTA_DST: no reconstructible destination.
            let missing = message(254, RouteProtocol::Static, RouteType::Unicast, Vec::new());
            assert_eq!(
                parse_kernel_route_event(KernelRouteEventKind::Del, &missing).prefix,
                None
            );
        }
    }
}
