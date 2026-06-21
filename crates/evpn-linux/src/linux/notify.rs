//! `RTNLGRP_NEIGH` subscriber — Linux kernel local-MAC + IP/MAC
//! observation feed.
//!
//! Subscribes to multicast group `RTNLGRP_NEIGH` — enum group id `3`
//! from `<linux/rtnetlink.h>`, **not** the legacy bitmask
//! `RTMGRP_NEIGH = 4` — on the daemon's existing rtnetlink
//! connection. The single subscription receives unsolicited
//! `RTM_NEWNEIGH` / `RTM_DELNEIGH` for every address family; the
//! classifier here splits them into two distinct origination paths:
//!
//! - **`AF_BRIDGE`** messages are bridge-FDB events on a local
//!   non-VXLAN port. They produce `LocalMacObservation::Learned` /
//!   `Aged`, the input to MAC-only Type 2 origination (Gate 7b+1).
//! - **`AF_INET` / `AF_INET6`** messages on a bridge ifindex are
//!   `(IP, MAC)` bindings populated by ARP/ND snooping when the
//!   bridge has `neigh_suppress on`. They produce
//!   `LocalMacObservation::IpAdded` / `IpRemoved`, the input to
//!   MAC+IP Type 2 origination (Gate 7b+2).
//!
//! # Classification rules
//!
//! `AF_BRIDGE` (matches existing `fdb.rs` invariants):
//!
//! 1. If `header.ifindex` is the VXLAN port of a managed VNI:
//!    `RTM_NEWNEIGH` emits `ObservedOnVxlanPort { vni, mac }` —
//!    the bridge FDB holds one row per `(bridge, MAC, VLAN)`, so a
//!    row appearing on the VXLAN port means the kernel does NOT hold
//!    the MAC on any local AC port. This is the only netlink
//!    evidence of an in-place port move off an AC port (the kernel
//!    emits no `RTM_DELNEIGH` for the replaced local row); the
//!    originator gates on its own local claim, so plain remote-MAC
//!    programming echoes (which dominate this shape, and carry
//!    `NTF_EXT_LEARNED`) cost one cheap lookup each.
//!    `RTM_DELNEIGH` on the VXLAN port stays dropped *as an
//!    observation* — a remote row withdrawing says nothing about
//!    local AC state — but fires the reconcile-wake path instead
//!    ([`classify_fdb_drift`]): a static remote-MAC row vanishing
//!    from the VXLAN port is kernel-side drift of programmed state.
//! 2. Drop if `NTF_EXT_LEARNED` on a non-VXLAN port — programmed
//!    rows never land there from us, so these are a foreign
//!    controller's entries, not kernel local learns.
//! 3. Resolve `header.ifindex` → VNI. Legacy single-VXLAN bridges use
//!    `LinkCache::bridge_port_to_vni`; ADR-0089 VLAN-aware bridges use
//!    `(ifindex, NDA_VLAN)` attribution and fail closed when the VLAN is
//!    missing or ambiguous.
//! 4. Extract MAC from the `LinkLayerAddress` attribute
//!    (`NDA_LLADDR`).
//! 5. Emit `Learned { vni, mac, ifindex }` (or `Aged` on
//!    `RTM_DELNEIGH`).
//!
//! `AF_INET` / `AF_INET6`:
//!
//! 1. Drop if `NTF_EXT_LEARNED` — kernel echo of routes we ourselves
//!    will program in a future slice (today there's no programmer for
//!    these, but the guard keeps the contract consistent with the
//!    `AF_BRIDGE` path).
//! 2. Drop if `header.state` doesn't include a "valid" NUD bit
//!    (`NUD_REACHABLE` / `NUD_STALE` / `NUD_PERMANENT` / `NUD_NOARP`).
//!    Kernel emits transient probe states (`NUD_INCOMPLETE`,
//!    `NUD_FAILED`) that don't represent a usable binding — those
//!    would just produce origination thrash if we acted on them.
//! 3. Resolve `header.ifindex` → VNI via `LinkCache::bridges` —
//!    `AF_INET` / `AF_INET6` neighbours sit on the **bridge** itself,
//!    not on a bridge port, so the `bridge_port_to_vni` map doesn't
//!    apply.
//! 4. Extract MAC (`NDA_LLADDR`) and IP (`NDA_DST`).
//! 5. Emit `IpAdded { vni, mac, ip }` (or `IpRemoved` on
//!    `RTM_DELNEIGH`).
//!
//! # Why classification is a pure function
//!
//! The actor task drains the rtnetlink message stream and calls
//! [`classify_neigh`] on every `NeighbourMessage`. Pure-function
//! shape lets unit tests construct synthetic `NeighbourMessage` /
//! `LinkCache` values and assert the upward emission without needing
//! `tokio::spawn`, a netlink socket, or `CAP_NET_ADMIN`.
//!
//! # Privileged netns test
//!
//! Real-kernel verification lives in `tests/netns_dataplane.rs` under
//! `EVPN_LINUX_NETNS=1` (Gate 7b's existing privileged test file).

use std::net::IpAddr;

use netlink_packet_route::{
    AddressFamily,
    link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage},
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
    },
    route::{RouteMessage, RouteProtocol, RouteType},
};
use rustbgpd_evpn::{EvpnInstanceId, LocalMacObservation, MacAddress};
use tracing::debug;

use super::links::LinkCache;

/// `NUD_*` bits used by the bitmask side of [`is_ip_neighbour_valid`].
/// The reachable / stale / noarp / permanent bits surface as typed
/// [`NeighbourState`] variants, so we only need the raw masks for the
/// [`NeighbourState::Other`] fallthrough where the kernel returns a
/// combined bitmask (e.g., `NUD_NOARP | NUD_PERMANENT` for our own
/// programmed entries).
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;
/// Bits that represent a confirmed `(IP, MAC)` binding.
const NUD_VALID_MASK: u16 = NUD_REACHABLE | NUD_STALE | NUD_NOARP | NUD_PERMANENT;
/// Bits that disqualify a binding regardless of what else is set.
/// `INCOMPLETE` (still probing), `DELAY` / `PROBE` (mid-revalidation,
/// no fresh confirmation), and `FAILED` (kernel gave up) are all
/// transient or negative states. Acting on them — even when combined
/// with a "valid" bit like `STALE` — would mean acting on the
/// kernel's *previous* belief while it's actively re-probing, which
/// produces origination thrash.
const NUD_INVALID_MASK: u16 = NUD_INCOMPLETE | NUD_DELAY | NUD_PROBE | NUD_FAILED;

/// Multicast group ID for neighbour-table changes — enum value
/// `RTNLGRP_NEIGH` from `<linux/rtnetlink.h>` (third entry in
/// `enum rtnetlink_groups`, hence value `3`).
///
/// **Critical:** this is the **enum group id**, not the legacy bitmask
/// `RTMGRP_NEIGH = 4` (`1 << RTNLGRP_NEIGH - 1`). `Socket::add_membership`
/// takes the enum value directly via `NETLINK_ADD_MEMBERSHIP` — passing
/// `4` here subscribes to `RTNLGRP_TC` (the next enum entry) and silently
/// loses every neighbour notification. v0.14.x originally shipped the
/// wrong value; the M37 origination smoke caught it. Cross-checked
/// against rtnetlink 0.14's `examples/ip_monitor.rs`.
pub(crate) const RTNLGRP_NEIGH: u32 = 3;

/// Multicast group ID for IPv4 route-table changes — enum value
/// `RTNLGRP_IPV4_ROUTE` from `<linux/rtnetlink.h>` (the **eighth**
/// entry in `enum rtnetlink_groups`, value `7`).
///
/// Same enum-vs-bitmask gotcha as [`RTNLGRP_NEIGH`]: `Socket::add_membership`
/// takes the enum value directly, not the legacy `RTMGRP_IPV4_ROUTE = 0x40`
/// bitmask form. Initial draft mistakenly used `5`, which is
/// `RTNLGRP_IPV4_IFADDR` — the subscription succeeded silently but
/// delivered address-change events instead of route events; the M39
/// smoke's tightened withdraw timeout caught the regression.
/// Cross-checked against `<linux/rtnetlink.h>`:
///
/// ```text
/// RTNLGRP_NONE          = 0
/// RTNLGRP_LINK          = 1
/// RTNLGRP_NOTIFY        = 2
/// RTNLGRP_NEIGH         = 3
/// RTNLGRP_TC            = 4
/// RTNLGRP_IPV4_IFADDR   = 5
/// RTNLGRP_IPV4_MROUTE   = 6
/// RTNLGRP_IPV4_ROUTE    = 7  ← here
/// RTNLGRP_IPV4_RULE     = 8
/// RTNLGRP_IPV6_IFADDR   = 9
/// RTNLGRP_IPV6_MROUTE   = 10
/// RTNLGRP_IPV6_ROUTE    = 11 ← and here
/// ```
pub(crate) const RTNLGRP_IPV4_ROUTE: u32 = 7;

/// Multicast group ID for IPv6 route-table changes — enum value
/// `RTNLGRP_IPV6_ROUTE` from `<linux/rtnetlink.h>` (the **twelfth**
/// entry, value `11`).
pub(crate) const RTNLGRP_IPV6_ROUTE: u32 = 11;

/// Kind of `RTM_*NEIGH` message we received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NeighEventKind {
    /// `RTM_NEWNEIGH` — a kernel learn (or re-learn) for a MAC.
    New,
    /// `RTM_DELNEIGH` — a kernel age/delete.
    Del,
}

/// Classify one `NeighbourMessage` into an upward observation. Returns
/// `None` for messages we don't act on (foreign families, our own
/// programmed entries, ports outside the EVPN topology, etc.).
pub(crate) fn classify_neigh(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    match msg.header.family {
        // The ExtLearned own-programming guard is per-family: the
        // `AF_BRIDGE` path applies it AFTER the VXLAN-port check,
        // because our own remote-MAC programming echo (which carries
        // `NTF_EXT_LEARNED`) is exactly the message that reveals an
        // in-place FDB port move off a local AC port.
        AddressFamily::Bridge => classify_bridge_fdb(kind, msg, cache),
        AddressFamily::Inet | AddressFamily::Inet6 => {
            // Drop our own programming echoes.
            if msg.header.flags.contains(NeighbourFlags::ExtLearned) {
                return None;
            }
            classify_ip_neighbour(kind, msg, cache)
        }
        _ => None,
    }
}

/// `AF_BRIDGE` classifier — kernel learns / ages a MAC on a bridge
/// port. See module-level docs for the full pipeline.
fn classify_bridge_fdb(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    // A row on the EVPN-owned VXLAN port of a managed VNI. Not a
    // local learn — but not droppable either: the bridge FDB holds
    // one row per `(bridge, MAC, VLAN)`, so an `RTM_NEWNEIGH` here
    // means the kernel does NOT hold the MAC on any local AC port.
    // When a remote Type 2 is programmed over a kernel-learned local
    // row the kernel performs an in-place port move and this echo is
    // the ONLY netlink evidence (no `RTM_DELNEIGH` for the old local
    // row — verified empirically by the M66 ES-drain handover and
    // matching `br_fdb.c`, where both `fdb_add_entry` and
    // `br_fdb_update` mutate `fdb->dst` and emit a single
    // `RTM_NEWNEIGH`). Surface it; the originator acts only on MACs
    // it currently claims as local. Deliberately BEFORE the
    // ExtLearned guard: our own programming echo carries
    // `NTF_EXT_LEARNED` and is precisely the usurpation signal.
    //
    // `RTM_DELNEIGH` on the VXLAN port stays dropped — a remote row
    // being withdrawn says nothing about local AC state. (It DOES
    // indicate dataplane drift; [`classify_fdb_drift`] handles that
    // on the separate reconcile-wake path.)
    let ifindex = msg.header.ifindex;
    let vlan = extract_vlan(msg);
    if let Some(vni_raw) = resolve_vxlan_observation_vni(cache, ifindex, vlan) {
        if !matches!(kind, NeighEventKind::New) {
            return None;
        }
        let vni = EvpnInstanceId::new(vni_raw).ok()?;
        let mac = extract_mac(msg)?;
        return Some(LocalMacObservation::ObservedOnVxlanPort { vni, mac });
    }

    // Drop programmed-entry echoes on non-VXLAN ports — ours never
    // land there, so these are a foreign controller's rows (ADR-0054
    // foreign-state discipline: not local learns).
    if msg.header.flags.contains(NeighbourFlags::ExtLearned) {
        return None;
    }

    // Resolve ifindex → VNI via the bridge-port map. Misses indicate
    // either the port isn't enslaved to an EVPN-managed bridge (drop
    // is correct) or the cache hasn't been primed yet (race window
    // between connect and the first dump_links — the event is lost
    // until the supervisor's next periodic dump). Logged at debug to
    // make the latter diagnosable in field issues without spamming
    // the happy path.
    let Some(vni_raw) = resolve_bridge_port_observation_vni(cache, ifindex, vlan) else {
        debug!(
            ifindex,
            vlan,
            "RTNLGRP_NEIGH AF_BRIDGE classifier: ifindex/VLAN not mapped to an EVPN VNI; event dropped"
        );
        return None;
    };
    let vni = EvpnInstanceId::new(vni_raw).ok()?;
    let mac = extract_mac(msg)?;

    Some(match kind {
        NeighEventKind::New => LocalMacObservation::Learned { vni, mac, ifindex },
        NeighEventKind::Del => LocalMacObservation::Aged { vni, mac },
    })
}

fn resolve_vxlan_observation_vni(
    cache: &LinkCache,
    ifindex: u32,
    vlan: Option<u16>,
) -> Option<u32> {
    if cache
        .vxlan_ports_requiring_vlan_attribution
        .contains(&ifindex)
    {
        return vlan.and_then(|vid| cache.vxlan_port_vlan_to_vni.get(&(ifindex, vid)).copied());
    }
    cache.vxlan_ifindex_to_vni.get(&ifindex).copied()
}

fn resolve_bridge_port_observation_vni(
    cache: &LinkCache,
    ifindex: u32,
    vlan: Option<u16>,
) -> Option<u32> {
    if cache
        .bridge_ports_requiring_vlan_attribution
        .contains(&ifindex)
    {
        return vlan.and_then(|vid| cache.bridge_port_vlan_to_vni.get(&(ifindex, vid)).copied());
    }
    cache.bridge_port_to_vni.get(&ifindex).copied()
}

/// `AF_INET` / `AF_INET6` classifier — kernel learns an `(IP, MAC)`
/// binding via ARP / ND on the bridge itself, surfaced for MAC+IP
/// Type 2 origination (Gate 7b+2).
fn classify_ip_neighbour(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    classify_ip_neighbour_with_cached_mac(kind, msg, cache, None)
}

/// Classify an `AF_INET` / `AF_INET6` neighbour delete using a MAC
/// remembered from the matching add edge. Linux delete notifications
/// for bridge neighbours can omit `NDA_LLADDR` (for example:
/// `Deleted 192.0.2.10 dev br100 FAILED`), but the originator needs
/// both `(MAC, IP)` to withdraw the precise Type 2 route.
pub(crate) fn classify_ip_neighbour_delete_with_cached_mac(
    msg: &NeighbourMessage,
    cache: &LinkCache,
    cached_mac: MacAddress,
) -> Option<LocalMacObservation> {
    classify_ip_neighbour_with_cached_mac(NeighEventKind::Del, msg, cache, Some(cached_mac))
}

/// Return the cache key for an advertisable IP-neighbour message.
/// The notify loop uses this to remember the MAC from the add edge
/// so a later delete edge can be classified even when the kernel omits
/// `NDA_LLADDR`.
pub(crate) fn ip_neighbour_cache_key(msg: &NeighbourMessage) -> Option<(u32, IpAddr)> {
    if !matches!(
        msg.header.family,
        AddressFamily::Inet | AddressFamily::Inet6
    ) {
        return None;
    }
    let ip = extract_ip(msg)?;
    if !is_advertisable_ip(ip) {
        return None;
    }
    Some((msg.header.ifindex, ip))
}

fn classify_ip_neighbour_with_cached_mac(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
    cached_mac: Option<MacAddress>,
) -> Option<LocalMacObservation> {
    // Resolve ifindex → VNI. Plain VLAN-unaware bridges still use the
    // bridge ifindex. VLAN-aware bridges must not use bridge-ifindex
    // fallback: AF_INET / AF_INET6 neighbour netlink does not carry a
    // bridge VLAN. The only VLAN-aware path accepted here is a VLAN
    // upper device (`br0.10`) that the link cache has already tied to
    // exactly one configured `bridge_vlan` instance.
    let ifindex = msg.header.ifindex;
    let Some(vni_raw) = cache
        .ip_neighbour_vlan_upper_to_vni
        .get(&ifindex)
        .copied()
        .or_else(|| {
            cache.bridges.values().find_map(|b| {
                if b.ifindex != ifindex {
                    return None;
                }
                if b.vlan_filtering {
                    // VLAN-aware bridge-neighbour notifications remain
                    // fail-closed unless they arrive on a validated VLAN
                    // upper device.
                    return None;
                }
                b.vxlan.as_ref().map(|v| v.vni)
            })
        })
    else {
        debug!(
            ifindex,
            "RTNLGRP_NEIGH AF_INET[6] classifier: ifindex not a known EVPN bridge or VLAN upper; \
             event dropped"
        );
        return None;
    };
    let vni = EvpnInstanceId::new(vni_raw).ok()?;

    // For RTM_NEWNEIGH, require a usable NUD state — a probe in
    // NUD_INCOMPLETE / NUD_FAILED isn't a binding worth originating.
    // RTM_DELNEIGH skips the check: a deletion is meaningful even if
    // the entry was in a transient state.
    if matches!(kind, NeighEventKind::New) && !is_ip_neighbour_valid(msg.header.state) {
        return None;
    }

    let mac = extract_mac(msg).or(cached_mac)?;
    let ip = extract_ip(msg)?;

    // Drop addresses that aren't valid EVPN MAC+IP advertisement
    // candidates (multicast, unspecified, link-local, loopback, etc.).
    // Filter both add and remove edges — if the domain shouldn't see
    // it as a candidate, the domain shouldn't see either edge.
    if !is_advertisable_ip(ip) {
        return None;
    }

    Some(match kind {
        NeighEventKind::New => LocalMacObservation::IpAdded { vni, mac, ip },
        NeighEventKind::Del => LocalMacObservation::IpRemoved { vni, mac, ip },
    })
}

/// Whether `ip` is eligible to ride on an EVPN MAC+IP Type 2
/// advertisement.
///
/// An EVPN MAC+IP route describes a host's `(IP, MAC)` binding; the
/// IP half must be a unicast host address that remote VTEPs can
/// usefully reach via VXLAN encap. Several kernel-side neighbour
/// rows are not that:
///
/// - **Unspecified** (`0.0.0.0`, `::`) — placeholder, no host.
/// - **Multicast** (`224.0.0.0/4`, `ff00::/8`) — group destinations,
///   not host bindings.
/// - **Broadcast** (`255.255.255.255`) — defunct on a bridge but
///   dropped defensively.
/// - **IPv4 link-local** (`169.254.0.0/16`) — APIPA self-assigned;
///   meaningless across VTEPs.
/// - **IPv6 link-local** (`fe80::/10`) — kernel ND populates these
///   from neighbour discovery; they don't survive VXLAN encap to a
///   remote VTEP and would mislead an L3 consumer.
/// - **Loopback** (`127.0.0.0/8`, `::1`) — local-only; defensive.
fn is_advertisable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_link_local()
                && !v4.is_loopback()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_loopback()
                && !is_ipv6_link_local(v6)
        }
    }
}

/// `fe80::/10` per RFC 4291 §2.5.6. `Ipv6Addr::is_unicast_link_local`
/// is unstable, so check the high-10-bits prefix manually.
fn is_ipv6_link_local(addr: std::net::Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ip_neighbour_valid(state: NeighbourState) -> bool {
    match state {
        NeighbourState::Reachable
        | NeighbourState::Stale
        | NeighbourState::Noarp
        | NeighbourState::Permanent => true,
        NeighbourState::Other(bits) => {
            // Require at least one valid bit AND no invalid bits.
            // Combined states like `NUD_STALE | NUD_PROBE` (kernel
            // re-probing a stale entry) intentionally fail this check
            // — acting on the stale half while the kernel is mid-
            // revalidation produces origination thrash.
            (bits & NUD_VALID_MASK) != 0 && (bits & NUD_INVALID_MASK) == 0
        }
        _ => false,
    }
}

/// Kind of `RTM_*ROUTE` message we received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteEventKind {
    /// `RTM_NEWROUTE` — kernel added (or replaced) a route.
    New,
    /// `RTM_DELROUTE` — kernel removed a route.
    Del,
}

/// Linux UAPI sentinel: kernel sets `header.table = 0` when no route
/// table is specified (unspecified) and `253`/`254`/`255` for the
/// reserved tables (default/main/local). Routes in those tables are
/// not part of any IP-VRF and waking the reconcile actor for them is
/// wasted work.
const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_DEFAULT: u8 = 253;
const RT_TABLE_MAIN: u8 = 254;
const RT_TABLE_LOCAL: u8 = 255;

/// Pre-filter for `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` events.
///
/// Returns `true` when the message is potentially relevant to slice
/// 6a's IP-VRF route observation — the reconcile actor should wake
/// and re-dump. Returns `false` for events the actor cannot care
/// about, so the kernel-event channel stays quiet during system route
/// churn.
///
/// The dataplane layer doesn't know the configured IP-VRF table set
/// (the supervisor owns that). The filter therefore drops only the
/// universally-irrelevant cases:
///
/// 1. **Reserved tables.** `RT_TABLE_MAIN` (254), `RT_TABLE_LOCAL`
///    (255), `RT_TABLE_DEFAULT` (253), `RT_TABLE_UNSPEC` (0) — IP-VRFs
///    use custom table ids; events in the reserved set cannot affect
///    any observation. The kernel's `RT_TABLE_COMPAT = 252` sentinel
///    appears in `header.table` when the real table id ≥ 256; that
///    case still passes through because the table id will resolve to
///    an IP-VRF via the upstream classifier in `routes.rs`.
/// 2. **Active routing-daemon protocols.** `RTPROT_BGP`,
///    `RTPROT_ZEBRA`, `RTPROT_OSPF`, etc. The slice 6a dump-side
///    classifier already drops these as origination candidates, and
///    they include our own `apply_add_ip_route` installs
///    (`RTPROT_BGP`) — letting them through here would create a
///    self-echo loop where every install fires a wake that triggers a
///    reconcile that re-installs the same row.
/// 3. **Non-forwardable route types.** `RTN_LOCAL`, `RTN_BROADCAST`,
///    `RTN_MULTICAST`, `RTN_BLACKHOLE`, `RTN_UNREACHABLE`,
///    `RTN_PROHIBIT`, `RTN_THROW` — same drop set as the dump
///    classifier in `routes.rs`. Waking on a `local` row (e.g., the
///    one `ip addr add` always emits alongside the unicast connected)
///    would double every observation event.
///
/// The reconcile actor's coalesce window (50 ms default) folds bursts
/// of accepted events into a single pass, so even a relatively chatty
/// `Keep` outcome only triggers one dump per burst.
#[must_use]
pub(crate) fn classify_route(msg: &RouteMessage, _kind: RouteEventKind) -> bool {
    let table = msg.header.table;
    if matches!(
        table,
        RT_TABLE_UNSPEC | RT_TABLE_DEFAULT | RT_TABLE_MAIN | RT_TABLE_LOCAL
    ) {
        return false;
    }

    if !matches!(msg.header.kind, RouteType::Unicast) {
        return false;
    }

    // Same drop set as `routes::classify` — both halves of the slice
    // 6a pipeline (notify-side pre-filter + dump-side classifier)
    // share the policy. The wildcard arm intentionally drops unknown
    // protocols so a future kernel addition doesn't cause us to wake
    // on traffic we'd never originate.
    matches!(
        msg.header.protocol,
        RouteProtocol::Kernel | RouteProtocol::Static | RouteProtocol::Boot
    )
}

/// `RTM_DELNEIGH` (`AF_BRIDGE`) drift classifier — does this delete
/// indicate kernel-side drift of dataplane-*programmed* FDB state?
///
/// Remote-MAC rows — unicast and BUM flood, plain and NHG-backed —
/// live exclusively on the VXLAN port of a managed VNI, and they are
/// static (`NUD_PERMANENT`-shaped) rows that never age out on their
/// own. A delete on that port is therefore either external
/// interference (`bridge fdb del` / a flush sweeping the port) or the
/// echo of our own withdraw. Both are safe to wake the reconcile
/// actor on: the pass re-diffs the kernel against intent, so the
/// interference case re-installs the row within the coalesce window
/// (50 ms default) instead of waiting for the 60 s periodic dump, and
/// the self-echo case (withdraws are reconcile-driven and bursty)
/// coalesces into a single no-op pass.
///
/// `RTM_NEWNEIGH` on the VXLAN port deliberately does NOT wake: every
/// remote-MAC install we perform echoes one, so waking there would
/// re-dump after every programming pass. The cost is that an external
/// in-place *modification* (`bridge fdb replace` with a wrong dst) is
/// only repaired by the periodic dump — flush/delete is the
/// overwhelmingly common interference shape.
///
/// This is a reconcile-wake classifier, fully independent of
/// [`classify_neigh`]'s observation pipeline: the observation side
/// still drops VXLAN-port deletes (a remote row withdrawing says
/// nothing about local AC state).
#[must_use]
pub(crate) fn classify_fdb_drift(msg: &NeighbourMessage, cache: &LinkCache) -> bool {
    matches!(msg.header.family, AddressFamily::Bridge)
        && (cache.vxlan_ifindex_to_vni.contains_key(&msg.header.ifindex)
            || cache.svd_vxlan_ifindexes.contains(&msg.header.ifindex))
}

/// `RTM_NEWLINK` / `RTM_DELLINK` drift classifier — should the
/// reconcile actor wake for this link change?
///
/// The BUM-filter and AC-gate reconcilers enforce bridge-port flags
/// (`flood` / `mcast_flood` / `learning`) and port `state` — all
/// surfaced by the kernel as link notifications on `RTNLGRP_LINK`
/// (`br_ifinfo_notify`). Before this classifier existed those drifts
/// were only repaired by the 60 s periodic dump.
///
/// Wakes on:
///
/// 1. A managed VXLAN port or a port of a VNI-resolved bridge
///    (`vxlan_ifindex_to_vni` / `bridge_port_to_vni`) — port state,
///    flag, carrier, and enslavement changes on exactly the surface
///    the BUM / AC-gate diffs enforce.
/// 2. A VNI-resolved bridge itself (`vxlan_attach_count >= 1`) —
///    bridge-level attribute drift and teardown.
/// 3. Any VXLAN-kind link (`IFLA_INFO_KIND == "vxlan"`) — topology
///    bring-up/teardown: the create/enslave events that turn a
///    `NotReady` instance `Ready`. VXLAN devices are EVPN-specific
///    and rare, so this arm cannot become a churn source.
/// 4. A link whose `Controller` (master) is a VNI-resolved bridge —
///    a new AC port being enslaved.
///
/// Deliberately does NOT wake on ports of VNI-less bridges (container
/// runtimes churn veths on their own bridges constantly) or on
/// non-VXLAN link creation. Mid-bring-up bridges that have no VXLAN
/// attached yet fall in that drop set; the VXLAN attach itself (arm 3)
/// and the periodic dump cover them. Our own port-flag/state writes
/// echo a `NEWLINK` and cost one coalesced no-op pass — they are rare
/// (DF transitions, topology changes), so no self-echo guard is
/// needed.
#[must_use]
pub(crate) fn classify_link_event(msg: &LinkMessage, cache: &LinkCache) -> bool {
    let ifindex = msg.header.index;
    if cache.vxlan_ifindex_to_vni.contains_key(&ifindex)
        || cache.svd_vxlan_ifindexes.contains(&ifindex)
        || cache.bridge_port_to_vni.contains_key(&ifindex)
    {
        return true;
    }

    let is_managed_bridge = |idx: u32| {
        cache
            .bridges
            .values()
            .any(|b| b.vxlan_attach_count >= 1 && b.ifindex == idx)
    };
    if is_managed_bridge(ifindex) {
        return true;
    }

    let mut controller = None;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::Controller(idx) => controller = Some(*idx),
            LinkAttribute::LinkInfo(infos)
                if infos
                    .iter()
                    .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Vxlan))) =>
            {
                return true;
            }
            _ => {}
        }
    }
    controller.is_some_and(is_managed_bridge)
}

fn extract_mac(msg: &NeighbourMessage) -> Option<MacAddress> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::LinkLayerAddress(bytes) = attr
            && bytes.len() == 6
        {
            return Some(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]));
        }
    }
    None
}

fn extract_vlan(msg: &NeighbourMessage) -> Option<u16> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::Vlan(vlan) = attr {
            return Some(*vlan);
        }
    }
    None
}

fn extract_ip(msg: &NeighbourMessage) -> Option<IpAddr> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::Destination(addr) = attr {
            return match addr {
                NeighbourAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
                NeighbourAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use netlink_packet_route::{
        AddressFamily,
        neighbour::{
            NeighbourAttribute, NeighbourFlags, NeighbourHeader, NeighbourMessage, NeighbourState,
        },
    };

    use super::super::links::{BridgeLink, LinkCache};
    use super::*;
    use crate::snapshot::KernelVxlanInfo;

    fn cache_for(vni: u32, vxlan_ifindex: u32, port_ifindex: u32) -> LinkCache {
        let mut bridges = HashMap::new();
        bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 99,
                mac: None,
                vlan_filtering: false,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: vxlan_ifindex,
                    vni,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }),
                vxlan_attach_count: 1,
                ce_port_ifindexes: vec![port_ifindex],
                ..BridgeLink::default()
            },
        );
        let mut vxlan_ifindex_to_vni = HashMap::new();
        vxlan_ifindex_to_vni.insert(vxlan_ifindex, vni);
        let mut bridge_port_to_vni = HashMap::new();
        bridge_port_to_vni.insert(port_ifindex, vni);
        let all_link_names = HashSet::from(["br100".to_string()]);
        LinkCache {
            all_link_names,
            bridges,
            vxlan_links: HashMap::new(),
            vrfs: HashMap::new(),
            vxlan_ifindex_to_vni,
            svd_vxlan_ifindexes: HashSet::new(),
            bridge_port_to_vni,
            local_mac_vlan_bindings: HashMap::new(),
            bridge_port_vlan_to_vni: HashMap::new(),
            bridge_ports_requiring_vlan_attribution: HashSet::new(),
            vlan_upper_links: HashMap::new(),
            ip_neighbour_vlan_upper_to_vni: HashMap::new(),
            vxlan_port_vlan_to_vni: HashMap::new(),
            vxlan_ports_requiring_vlan_attribution: HashSet::new(),
            bridge_ports_by_name: HashMap::new(),
            master_slaves_by_name: HashMap::new(),
        }
    }

    fn vlan_upper_cache() -> LinkCache {
        let mut cache = cache_for(100, /* vxlan */ 11, /* swp */ 22);
        cache.vxlan_ifindex_to_vni.insert(33, 200);
        cache.bridge_port_to_vni.clear();
        cache.bridge_port_vlan_to_vni.insert((22, 10), 100);
        cache.bridge_port_vlan_to_vni.insert((22, 20), 200);
        cache.bridge_ports_requiring_vlan_attribution.insert(22);
        cache.ip_neighbour_vlan_upper_to_vni.insert(44, 100);
        cache.ip_neighbour_vlan_upper_to_vni.insert(45, 200);
        cache.vxlan_port_vlan_to_vni.insert((11, 10), 100);
        cache.vxlan_port_vlan_to_vni.insert((33, 20), 200);
        cache.vxlan_ports_requiring_vlan_attribution.insert(11);
        cache.vxlan_ports_requiring_vlan_attribution.insert(33);
        cache
    }

    fn neigh_msg(
        family: AddressFamily,
        ifindex: u32,
        flags: NeighbourFlags,
        mac_attr: Option<Vec<u8>>,
    ) -> NeighbourMessage {
        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family,
            ifindex,
            state: NeighbourState::Permanent,
            flags,
            kind: netlink_packet_route::route::RouteType::Unspec,
        };
        if let Some(bytes) = mac_attr {
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(bytes));
        }
        msg
    }

    fn with_vlan(mut msg: NeighbourMessage, vlan: u16) -> NeighbourMessage {
        msg.attributes.push(NeighbourAttribute::Vlan(vlan));
        msg
    }

    #[test]
    fn classify_new_emits_learned_for_local_bridge_port() {
        let cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller,
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::Learned { vni, mac, ifindex } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(ifindex, 22);
            }
            other => panic!("expected Learned, got {other:?}"),
        }
    }

    #[test]
    fn classify_del_emits_aged() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller,
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::Del, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::Aged { .. }));
    }

    #[test]
    fn classify_vlan_aware_local_bridge_port_by_vlan() {
        let cache = vlan_upper_cache();
        let msg = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                22,
                NeighbourFlags::Controller,
                Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ),
            20,
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        assert!(
            matches!(
                obs,
                LocalMacObservation::Learned { vni, mac, ifindex }
                    if vni.as_u32() == 200
                        && mac.octets() == [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
                        && ifindex == 22
            ),
            "unexpected observation: {obs:?}"
        );
    }

    #[test]
    fn classify_vlan_aware_local_bridge_port_drops_missing_or_unknown_vlan() {
        let cache = vlan_upper_cache();
        let missing = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &missing, &cache).is_none());

        let unknown = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                22,
                NeighbourFlags::Controller,
                Some(vec![0xaa; 6]),
            ),
            30,
        );
        assert!(classify_neigh(NeighEventKind::New, &unknown, &cache).is_none());
    }

    #[test]
    fn classify_vlan_aware_local_bridge_port_does_not_fallback_when_map_missing() {
        let mut cache = cache_for(100, /* vxlan */ 11, /* swp */ 22);
        cache.bridge_ports_requiring_vlan_attribution.insert(22);
        let msg = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                22,
                NeighbourFlags::Controller,
                Some(vec![0xaa; 6]),
            ),
            10,
        );

        assert!(
            classify_neigh(NeighEventKind::New, &msg, &cache).is_none(),
            "VLAN-aware bridge port with missing attribution map must not use legacy ifindex fallback"
        );
    }

    #[test]
    fn classify_drops_ext_learned_echo() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    /// An `RTM_NEWNEIGH` on the VXLAN port of a managed VNI surfaces
    /// as `ObservedOnVxlanPort` — never as a local learn. With our own
    /// programming flags (`NTF_EXT_LEARNED` among them) this is the
    /// remote-takeover echo of an in-place FDB port move, the only
    /// netlink evidence the kernel emits when a remote row usurps a
    /// kernel-learned local AC row (M66 incident: no `RTM_DELNEIGH`
    /// for the replaced local row).
    #[test]
    fn classify_new_on_vxlan_port_emits_observed_on_vxlan_port() {
        let cache = cache_for(100, /* vxlan */ 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            11,
            NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::ObservedOnVxlanPort { vni, mac } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            }
            other => panic!("expected ObservedOnVxlanPort, got {other:?}"),
        }
    }

    #[test]
    fn classify_vlan_aware_vxlan_port_by_vlan() {
        let cache = vlan_upper_cache();
        let msg = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                33,
                NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
                Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ),
            20,
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        assert!(
            matches!(
                obs,
                LocalMacObservation::ObservedOnVxlanPort { vni, mac }
                    if vni.as_u32() == 200
                        && mac.octets() == [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
            ),
            "unexpected observation: {obs:?}"
        );

        let wrong_vlan = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                33,
                NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
                Some(vec![0xaa; 6]),
            ),
            10,
        );
        assert!(classify_neigh(NeighEventKind::New, &wrong_vlan, &cache).is_none());
    }

    #[test]
    fn classify_vlan_aware_vxlan_port_does_not_fallback_when_map_missing() {
        let mut cache = cache_for(100, /* vxlan */ 11, /* swp */ 22);
        cache.vxlan_ports_requiring_vlan_attribution.insert(11);
        let msg = with_vlan(
            neigh_msg(
                AddressFamily::Bridge,
                11,
                NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
                Some(vec![0xaa; 6]),
            ),
            10,
        );

        assert!(
            classify_neigh(NeighEventKind::New, &msg, &cache).is_none(),
            "VLAN-aware VXLAN port with missing attribution map must not use legacy ifindex fallback"
        );
    }

    /// Same shape without `NTF_EXT_LEARNED` — a foreign controller's
    /// or operator's remote row. The classifier still surfaces it
    /// (the kernel-side fact "this MAC resolves via the VXLAN port"
    /// is identical); the originator's local-claim gate is what keeps
    /// foreign rows from triggering withdrawals of MACs we never
    /// claimed.
    #[test]
    fn classify_new_on_vxlan_port_without_ext_learned_also_emits() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            11,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(matches!(
            classify_neigh(NeighEventKind::New, &msg, &cache),
            Some(LocalMacObservation::ObservedOnVxlanPort { .. })
        ));
    }

    /// `RTM_DELNEIGH` on the VXLAN port stays dropped — a remote row
    /// being withdrawn says nothing about local AC state (the MAC
    /// does not come back local until the kernel learns it again).
    #[test]
    fn classify_del_on_vxlan_port_emits_nothing() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            11,
            NeighbourFlags::Own | NeighbourFlags::Controller,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::Del, &msg, &cache).is_none());
    }

    #[test]
    fn classify_new_on_vxlan_port_without_mac_attribute_emits_nothing() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(AddressFamily::Bridge, 11, NeighbourFlags::empty(), None);
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_ifindex_outside_known_bridges() {
        let cache = cache_for(100, 11, 22);
        // ifindex 99 isn't in either map.
        let msg = neigh_msg(
            AddressFamily::Bridge,
            99,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_unhandled_family() {
        // Anything that isn't Bridge / Inet / Inet6 must drop. AF_PACKET
        // (raw socket family) is a representative non-handled case the
        // kernel does not normally use for RTM_NEWNEIGH but a buggy
        // kernel-side change shouldn't cause us to mis-classify.
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Packet,
            22,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_bridge_message_without_mac_attribute() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(AddressFamily::Bridge, 22, NeighbourFlags::empty(), None);
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_bridge_mac_attribute_with_wrong_length() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 4]), // not 6 bytes
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    // --- Gate 7b+2: AF_INET / AF_INET6 IP-neighbour classifier ---

    /// Build a synthetic `AF_INET` / `AF_INET6` `RTM_NEWNEIGH` for
    /// ARP/ND snooping tests. `bridge_ifindex` must match the bridge
    /// stored in the cache (not a bridge port — `AF_INET` /
    /// `AF_INET6` neighbours sit on the bridge itself).
    fn ip_neigh_msg(
        family: AddressFamily,
        bridge_ifindex: u32,
        state: NeighbourState,
        flags: NeighbourFlags,
        mac: Option<[u8; 6]>,
        ip: Option<IpAddr>,
    ) -> NeighbourMessage {
        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family,
            ifindex: bridge_ifindex,
            state,
            flags,
            kind: netlink_packet_route::route::RouteType::Unspec,
        };
        if let Some(bytes) = mac {
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(bytes.to_vec()));
        }
        if let Some(addr) = ip {
            let na = match addr {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            };
            msg.attributes.push(NeighbourAttribute::Destination(na));
        }
        msg
    }

    #[test]
    fn classify_inet_emits_ip_added_for_known_bridge() {
        // cache_for builds br100 with bridge ifindex 99.
        let cache = cache_for(100, /* vxlan */ 11, /* port */ 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            Some(v4),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::IpAdded { vni, mac, ip } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]);
                assert_eq!(ip, v4);
            }
            other => panic!("expected IpAdded, got {other:?}"),
        }
    }

    #[test]
    fn classify_inet_drops_vlan_aware_bridge_until_vlan_identity_exists() {
        let mut cache = cache_for(100, 11, 22);
        cache.bridges.get_mut("br100").unwrap().vlan_filtering = true;
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            Some("192.0.2.10".parse().unwrap()),
        );

        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_vlan_upper_emits_ip_added() {
        let cache = vlan_upper_cache();
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            44,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            Some(v4),
        );

        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");

        match obs {
            LocalMacObservation::IpAdded { vni, mac, ip } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]);
                assert_eq!(ip, v4);
            }
            other => panic!("expected IpAdded, got {other:?}"),
        }
    }

    #[test]
    fn classify_inet6_vlan_upper_emits_ip_added() {
        let cache = vlan_upper_cache();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet6,
            45,
            NeighbourState::Stale,
            NeighbourFlags::empty(),
            Some([0xBB; 6]),
            Some(v6),
        );

        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");

        assert!(
            matches!(obs, LocalMacObservation::IpAdded { vni, ip, .. } if vni.as_u32() == 200 && ip == v6),
            "unexpected observation: {obs:?}"
        );
    }

    #[test]
    fn classify_inet_vlan_upper_unknown_mapping_drops() {
        let cache = vlan_upper_cache();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            46,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            Some("192.0.2.10".parse().unwrap()),
        );

        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet6_emits_ip_added() {
        let cache = cache_for(100, 11, 22);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet6,
            99,
            NeighbourState::Stale,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v6),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::IpAdded { ip, .. } if ip == v6));
    }

    #[test]
    fn classify_inet_del_emits_ip_removed_regardless_of_state() {
        // A deletion is meaningful even if the entry was in a
        // transient state — RTM_DELNEIGH skips the validity check.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_FAILED),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        let obs = classify_neigh(NeighEventKind::Del, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::IpRemoved { .. }));
    }

    #[test]
    fn classify_inet_del_uses_cached_mac_when_kernel_omits_lladdr() {
        // Linux can emit bridge-neighbour deletes as only
        // `Deleted 192.0.2.10 dev br100 FAILED`, with no `NDA_LLADDR`.
        // The notify loop supplies the MAC remembered from IpAdded so
        // the originator can withdraw the exact `(MAC, IP)` Type 2.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_FAILED),
            NeighbourFlags::empty(),
            None,
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::Del, &msg, &cache).is_none());
        assert_eq!(ip_neighbour_cache_key(&msg), Some((99, v4)));

        let cached_mac = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
        let obs = classify_ip_neighbour_delete_with_cached_mac(&msg, &cache, cached_mac)
            .expect("cached delete should classify");
        assert!(
            matches!(
                obs,
                LocalMacObservation::IpRemoved { vni, mac, ip }
                    if vni.as_u32() == 100 && mac == cached_mac && ip == v4
            ),
            "unexpected observation: {obs:?}"
        );
    }

    #[test]
    fn classify_inet_del_on_vlan_upper_uses_cached_mac() {
        let cache = vlan_upper_cache();
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            44,
            NeighbourState::Other(NUD_FAILED),
            NeighbourFlags::empty(),
            None,
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::Del, &msg, &cache).is_none());
        assert_eq!(ip_neighbour_cache_key(&msg), Some((44, v4)));

        let cached_mac = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
        let obs = classify_ip_neighbour_delete_with_cached_mac(&msg, &cache, cached_mac)
            .expect("cached delete should classify");

        assert!(
            matches!(
                obs,
                LocalMacObservation::IpRemoved { vni, mac, ip }
                    if vni.as_u32() == 100 && mac == cached_mac && ip == v4
            ),
            "unexpected observation: {obs:?}"
        );
    }

    #[test]
    fn classify_inet_drops_incomplete_state() {
        // NUD_INCOMPLETE = 0x01, not in NUD_VALID_MASK.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(0x01),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_accepts_noarp_permanent_combined_state() {
        // EVPN-suppression entries land with NUD_NOARP | NUD_PERMANENT
        // (the same combined bitmask we use for our own AF_BRIDGE
        // programming). Comes through as NeighbourState::Other(0xC0).
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_NOARP | NUD_PERMANENT),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(matches!(
            classify_neigh(NeighEventKind::New, &msg, &cache),
            Some(LocalMacObservation::IpAdded { .. })
        ));
    }

    /// Regression: `NUD_STALE | NUD_PROBE` represents the kernel
    /// actively re-probing a stale entry — the binding is not
    /// freshly confirmed, just the kernel's previous belief. Acting
    /// on it would produce origination thrash. Earlier validity
    /// check accepted this combination because at least one valid
    /// bit was set; the explicit invalid mask rejects it.
    #[test]
    fn classify_inet_drops_stale_with_probe_bit() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_STALE | NUD_PROBE),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    /// Regression: same shape — `NUD_REACHABLE | NUD_DELAY` means
    /// the kernel has scheduled revalidation against a previously-
    /// reachable entry. Drop until the next steady state.
    #[test]
    fn classify_inet_drops_reachable_with_delay_bit() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_REACHABLE | NUD_DELAY),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_ext_learned_echo() {
        // NTF_EXT_LEARNED guard applies to all families — kernel echo
        // of routes we ourselves programmed must not surface upward.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::ExtLearned,
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_unknown_bridge_ifindex() {
        // ifindex 555 is neither a known bridge nor port.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            555,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_message_without_destination() {
        let cache = cache_for(100, 11, 22);
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            None,
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_message_without_mac() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            None,
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    // --- IP advertisability filter ---
    //
    // Per ADR-0054 §1, the classifier is the boundary that decides
    // what shape of (IP, MAC) binding becomes an EVPN candidate.
    // These tests pin which IPs the filter accepts and rejects.

    /// Helper — runs an `AF_INET` / `AF_INET6` classifier message
    /// with the given IP and asserts whether the classifier emits or
    /// drops.
    fn assert_classify_inet(ip_str: &str, expect_emitted: bool) {
        let cache = cache_for(100, 11, 22);
        let ip: IpAddr = ip_str.parse().unwrap();
        let family = match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        let msg = ip_neigh_msg(
            family,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(ip),
        );
        let got = classify_neigh(NeighEventKind::New, &msg, &cache);
        if expect_emitted {
            assert!(
                matches!(got, Some(LocalMacObservation::IpAdded { .. })),
                "expected IpAdded for {ip_str}, got {got:?}"
            );
        } else {
            assert!(got.is_none(), "expected drop for {ip_str}, got {got:?}");
        }
    }

    #[test]
    fn classify_accepts_ipv4_global_unicast() {
        assert_classify_inet("192.0.2.10", true);
    }

    #[test]
    fn classify_drops_ipv4_unspecified() {
        assert_classify_inet("0.0.0.0", false);
    }

    #[test]
    fn classify_drops_ipv4_multicast() {
        assert_classify_inet("224.0.0.1", false);
    }

    #[test]
    fn classify_drops_ipv4_broadcast() {
        assert_classify_inet("255.255.255.255", false);
    }

    #[test]
    fn classify_drops_ipv4_link_local_apipa() {
        assert_classify_inet("169.254.1.1", false);
    }

    #[test]
    fn classify_drops_ipv4_loopback() {
        assert_classify_inet("127.0.0.1", false);
    }

    #[test]
    fn classify_accepts_ipv6_global_unicast() {
        assert_classify_inet("2001:db8::1", true);
    }

    #[test]
    fn classify_drops_ipv6_unspecified() {
        assert_classify_inet("::", false);
    }

    #[test]
    fn classify_drops_ipv6_loopback() {
        assert_classify_inet("::1", false);
    }

    #[test]
    fn classify_drops_ipv6_multicast() {
        assert_classify_inet("ff02::1", false);
    }

    #[test]
    fn classify_drops_ipv6_link_local() {
        assert_classify_inet("fe80::1", false);
    }

    /// Filter applies on the delete edge too — if the domain
    /// shouldn't see an `IpAdded` for a non-advertisable IP, it
    /// shouldn't see an `IpRemoved` either. Otherwise a domain
    /// layer that filtered `IpAdded` would still get spurious
    /// `IpRemoved` events for IPs it never registered.
    #[test]
    fn classify_drops_non_advertisable_ip_on_delete() {
        let cache = cache_for(100, 11, 22);
        let bad: IpAddr = "fe80::1".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet6,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(bad),
        );
        assert!(classify_neigh(NeighEventKind::Del, &msg, &cache).is_none());
    }

    /// Pins `RTNLGRP_NEIGH` to its `<linux/rtnetlink.h>` enum value `3`,
    /// not the legacy `RTMGRP_NEIGH` bitmask `4`. v0.14.x shipped `4`
    /// here, which subscribed to `RTNLGRP_TC` instead and silently lost
    /// every neighbour notification (caught by the M37 origination
    /// smoke). The constant pin guards against the same regression.
    #[test]
    fn rtnlgrp_neigh_constant_matches_kernel_enum_value() {
        assert_eq!(RTNLGRP_NEIGH, 3);
    }

    /// Same enum-vs-bitmask pin for the slice 6a route subscriptions.
    /// `RTNLGRP_IPV4_ROUTE = 7`, `RTNLGRP_IPV6_ROUTE = 11` per
    /// `<linux/rtnetlink.h>`. The initial draft mistakenly used `5`
    /// (`RTNLGRP_IPV4_IFADDR`) and `7` (which is the correct IPv4
    /// route value): the subscription on `5` silently delivered
    /// address events while the route events disappeared, and the
    /// M39 smoke's tightened withdraw timeout caught the regression
    /// — exactly the pattern the existing `RTNLGRP_NEIGH = 3 vs 4`
    /// fix already documents. This pin is the structural guard
    /// against repeating the off-by-one.
    #[test]
    fn route_rtnlgrp_constants_match_kernel_enum_values() {
        assert_eq!(RTNLGRP_IPV4_ROUTE, 7);
        assert_eq!(RTNLGRP_IPV6_ROUTE, 11);
    }

    // --- Slice 6a: RTNLGRP_IPV4/6_ROUTE classifier (`classify_route`) ---

    fn route_msg(
        family: AddressFamily,
        table: u8,
        protocol: RouteProtocol,
        kind: RouteType,
    ) -> RouteMessage {
        use netlink_packet_route::route::{RouteFlags, RouteHeader, RouteScope};
        let mut msg = RouteMessage::default();
        msg.header = RouteHeader {
            address_family: family,
            destination_prefix_length: 24,
            source_prefix_length: 0,
            tos: 0,
            table,
            protocol,
            scope: RouteScope::Universe,
            kind,
            flags: RouteFlags::empty(),
        };
        msg
    }

    /// The happy path: a connected route in a custom VRF table fires
    /// the wake. Slice 6a's reconcile pass will see the change on the
    /// next coalesce window.
    #[test]
    fn classify_route_wakes_on_connected_route_in_custom_table() {
        let msg = route_msg(
            AddressFamily::Inet,
            100,
            RouteProtocol::Kernel,
            RouteType::Unicast,
        );
        assert!(classify_route(&msg, RouteEventKind::New));
        assert!(classify_route(&msg, RouteEventKind::Del));
    }

    /// Manual `ip route add ... proto static` or `proto boot` in a
    /// custom table also fires — operators sometimes pin a tenant
    /// prefix via a static, and slice 6a's dump-side classifier keeps
    /// both protocols.
    #[test]
    fn classify_route_wakes_on_static_and_boot_protocols() {
        let static_msg = route_msg(
            AddressFamily::Inet,
            100,
            RouteProtocol::Static,
            RouteType::Unicast,
        );
        let boot_msg = route_msg(
            AddressFamily::Inet,
            100,
            RouteProtocol::Boot,
            RouteType::Unicast,
        );
        assert!(classify_route(&static_msg, RouteEventKind::New));
        assert!(classify_route(&boot_msg, RouteEventKind::New));
    }

    /// `apply_add_ip_route` uses `RTPROT_BGP`; every install would
    /// echo back on `RTNLGRP_IPV4_ROUTE` and re-trigger a reconcile if
    /// we didn't drop the protocol here. Same for the rest of the
    /// active-routing-daemon set.
    #[test]
    fn classify_route_drops_routing_daemon_protocols() {
        for proto in [
            RouteProtocol::Bgp,
            RouteProtocol::Zebra,
            RouteProtocol::Ospf,
            RouteProtocol::Bird,
            RouteProtocol::Isis,
            RouteProtocol::Rip,
            RouteProtocol::Babel,
            RouteProtocol::Eigrp,
        ] {
            let msg = route_msg(AddressFamily::Inet, 100, proto, RouteType::Unicast);
            assert!(
                !classify_route(&msg, RouteEventKind::New),
                "expected drop for protocol {proto:?}, got wake"
            );
        }
    }

    /// The main / local / default / unspec tables are not IP-VRFs.
    /// System route churn would otherwise spam wakes. Custom table id
    /// 100 + the `RT_TABLE_COMPAT = 252` sentinel (used by the kernel
    /// when the real table id ≥ 256) must still pass.
    #[test]
    fn classify_route_drops_reserved_tables() {
        for reserved in [0u8, 253, 254, 255] {
            let msg = route_msg(
                AddressFamily::Inet,
                reserved,
                RouteProtocol::Kernel,
                RouteType::Unicast,
            );
            assert!(
                !classify_route(&msg, RouteEventKind::New),
                "expected drop for reserved table {reserved}, got wake"
            );
        }
        // RT_TABLE_COMPAT (252) is the sentinel for table_id ≥ 256
        // and must still pass — the real table id lives in
        // RouteAttribute::Table and resolves to a real IP-VRF in the
        // dump-side classifier.
        let compat = route_msg(
            AddressFamily::Inet,
            252,
            RouteProtocol::Kernel,
            RouteType::Unicast,
        );
        assert!(classify_route(&compat, RouteEventKind::New));
    }

    /// `ip addr add 192.0.2.1/24 dev lo-vrf1` emits both an
    /// `RTN_UNICAST` connected row AND `RTN_LOCAL` / `RTN_BROADCAST`
    /// helpers. Slice 6a's observer only cares about the unicast row;
    /// firing on every helper would double every observation event.
    #[test]
    fn classify_route_drops_non_unicast_route_types() {
        for kind in [
            RouteType::Local,
            RouteType::Broadcast,
            RouteType::Multicast,
            RouteType::BlackHole,
            RouteType::Unreachable,
            RouteType::Prohibit,
            RouteType::Throw,
            RouteType::Anycast,
            RouteType::Nat,
        ] {
            let msg = route_msg(AddressFamily::Inet, 100, RouteProtocol::Kernel, kind);
            assert!(
                !classify_route(&msg, RouteEventKind::New),
                "expected drop for kind {kind:?}, got wake"
            );
        }
    }

    /// IPv6 path. Same classifier rules — the family bit on the
    /// header doesn't change anything; the wake is family-agnostic.
    #[test]
    fn classify_route_passes_ipv6_unicast_in_custom_table() {
        let msg = route_msg(
            AddressFamily::Inet6,
            100,
            RouteProtocol::Kernel,
            RouteType::Unicast,
        );
        assert!(classify_route(&msg, RouteEventKind::New));
        assert!(classify_route(&msg, RouteEventKind::Del));
    }

    // --- FDB-drift reconcile-wake classifier (`classify_fdb_drift`) ---

    /// `bridge fdb del <mac> dev vxlan100` (or a flush sweeping the
    /// VXLAN port) must wake the reconcile actor — a programmed
    /// remote-MAC row vanished and only a re-diff can repair it.
    #[test]
    fn fdb_drift_wakes_on_delete_on_managed_vxlan_port() {
        let cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            11,
            NeighbourFlags::ExtLearned,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_fdb_drift(&msg, &cache));
    }

    #[test]
    fn fdb_drift_wakes_on_delete_on_known_svd_vxlan_port() {
        let mut cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        cache.svd_vxlan_ifindexes.insert(33);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            33,
            NeighbourFlags::ExtLearned,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_fdb_drift(&msg, &cache));
    }

    /// A delete on a local AC port is a kernel age-out, already
    /// surfaced as `LocalMacObservation::Aged` to the originator —
    /// not programmed-state drift, so no reconcile wake.
    #[test]
    fn fdb_drift_ignores_delete_on_ac_port() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(!classify_fdb_drift(&msg, &cache));
    }

    /// Non-bridge families and unmanaged ifindexes stay quiet — IP
    /// neighbour churn must not turn into reconcile dumps.
    #[test]
    fn fdb_drift_ignores_foreign_family_and_unmanaged_port() {
        let cache = cache_for(100, 11, 22);
        let inet = neigh_msg(
            AddressFamily::Inet,
            11,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(!classify_fdb_drift(&inet, &cache));
        let unmanaged = neigh_msg(
            AddressFamily::Bridge,
            77,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(!classify_fdb_drift(&unmanaged, &cache));
    }

    // --- Link-drift reconcile-wake classifier (`classify_link_event`) ---

    fn link_msg(ifindex: u32, controller: Option<u32>, kind: Option<InfoKind>) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        if let Some(master) = controller {
            msg.attributes.push(LinkAttribute::Controller(master));
        }
        if let Some(kind) = kind {
            msg.attributes
                .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(kind)]));
        }
        msg
    }

    /// `bridge link set dev eth0 flood on` / an external port-state
    /// write emits `RTM_NEWLINK` for the port — the exact surface the
    /// BUM-filter and AC-gate diffs enforce, so it must wake.
    #[test]
    fn link_event_wakes_on_managed_bridge_port_and_vxlan_port() {
        let cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        assert!(classify_link_event(&link_msg(22, Some(99), None), &cache));
        assert!(classify_link_event(&link_msg(11, Some(99), None), &cache));
    }

    #[test]
    fn link_event_wakes_on_known_svd_vxlan_port() {
        let mut cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        cache.svd_vxlan_ifindexes.insert(33);
        assert!(classify_link_event(&link_msg(33, Some(99), None), &cache));
    }

    /// Changes on the VNI-resolved bridge itself (ifindex 99 in the
    /// fixture) wake, as does a brand-new port being enslaved to it.
    #[test]
    fn link_event_wakes_on_managed_bridge_and_new_enslavement() {
        let cache = cache_for(100, 11, 22);
        assert!(classify_link_event(&link_msg(99, None, None), &cache));
        // New AC port (ifindex unknown to the cache) enslaved to the
        // managed bridge.
        assert!(classify_link_event(&link_msg(33, Some(99), None), &cache));
    }

    /// VXLAN-kind links wake regardless of cache state — the
    /// create/enslave events of topology bring-up arrive before the
    /// cache knows the ifindex.
    #[test]
    fn link_event_wakes_on_vxlan_kind_link() {
        let cache = LinkCache::default();
        assert!(classify_link_event(
            &link_msg(44, None, Some(InfoKind::Vxlan)),
            &cache
        ));
    }

    /// Container-runtime churn must stay quiet: veths without a
    /// master, veths enslaved to a VNI-less bridge, and non-VXLAN
    /// link creation are not EVPN surface.
    #[test]
    fn link_event_ignores_unmanaged_links() {
        let mut cache = cache_for(100, 11, 22);
        // docker0-shaped bridge: known to the inventory, no VXLAN.
        cache.bridges.insert(
            "docker0".to_string(),
            BridgeLink {
                ifindex: 50,
                vxlan_attach_count: 0,
                ..BridgeLink::default()
            },
        );
        // Bare veth.
        assert!(!classify_link_event(&link_msg(60, None, None), &cache));
        // veth enslaved to the VNI-less bridge.
        assert!(!classify_link_event(&link_msg(60, Some(50), None), &cache));
        // The VNI-less bridge itself flapping operstate.
        assert!(!classify_link_event(&link_msg(50, None, None), &cache));
        // Non-VXLAN link creation (a new bridge with no VXLAN yet).
        assert!(!classify_link_event(
            &link_msg(61, None, Some(InfoKind::Bridge)),
            &cache
        ));
    }
}
