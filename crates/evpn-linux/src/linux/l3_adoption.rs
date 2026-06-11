//! ADR-0079 L3 adoption-candidate dump — the read side of the
//! crash-restart sweep for Gate 9 symmetric-IRB kernel state.
//!
//! Walks three kernel surfaces for rows carrying our ownership
//! markers (written by `super::l3`, see the ADR-0079 marker table):
//!
//! 1. **VRF routes** — `RTM_GETROUTE` walk (IPv4 + IPv6) keeping rows
//!    whose table is a configured `[[evpn_ip_vrfs]]` `table_id` AND
//!    proto is `RTPROT_BGP` AND the onlink flag is set. Note the
//!    slice-6a observation classifier (`super::routes::classify`)
//!    deliberately *drops* `RTPROT_BGP` rows — that path feeds
//!    local-route origination and must never re-originate our own
//!    installs. Adoption wants exactly the rows origination rejects,
//!    so this is a separate walk with its own classifier, not a new
//!    arm on `classify`.
//! 2. **L3 neighbors** — `RTM_GETNEIGH` per address family (Inet,
//!    Inet6), keeping rows on managed L3VXLAN ifindexes whose state
//!    has `NUD_PERMANENT` and whose flags carry `NTF_EXT_LEARNED`,
//!    and whose `NDA_PROTOCOL` — when present — is `RTPROT_BGP`
//!    (ADR-0082; absence is accepted this release as the pre-stamp
//!    legacy shape).
//! 3. **L3VXLAN FDB rows** — `AF_BRIDGE` `RTM_GETNEIGH`, keeping
//!    `extern_learn` + permanent-state rows on managed L3VXLAN
//!    ifindexes. The existing bridge-FDB snapshot (`super::fdb`)
//!    keys by VNI through bridge-enslaved VXLAN ports; L3VXLANs are
//!    enslaved to a VRF, not a bridge, so they never appear in that
//!    cache — this filter keys by ifindex instead.
//!
//! Each row→candidate decision is a pure function over the netlink
//! message plus the configured-table / managed-ifindex maps, so the
//! marker matching unit-tests without a netns — same split
//! `super::routes` uses for its `classify`.
//!
//! Any sub-dump failure returns `None`: the reconcile actor must
//! retry on a later pass rather than latch its one-shot sweep onto a
//! partial kernel view (a missing sub-dump would silently shrink the
//! adopted set and strand the unseen rows forever).

use std::collections::HashMap;
use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol,
};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use rustbgpd_evpn::ip_vrf::{IpVrfId, IpVrfTable};
use rustbgpd_evpn::{EvpnIpPrefixValue, MacAddress};

use crate::error::DataplaneError;
use crate::l3_adoption::{AdoptedL3Route, L3AdoptionDump};

use super::ip_vrf;
use super::routes::{
    IpVrfRoutingResolution, extract_output_ifindex, extract_prefix, extract_table_id,
};

/// `NUD_PERMANENT` — non-aging neighbor entry. Mirrors the private
/// constant in `super::l3` (the write side); both halves of the
/// marker must read the same bit.
const NUD_PERMANENT: u16 = 0x80;

/// Verdict for one kernel route row against the ADR-0079 VRF-route
/// marker (`RTPROT_BGP` + onlink, in a configured `table_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAdoptionVerdict {
    /// Not in a configured IP-VRF table, or missing the marker pair —
    /// foreign state, never touched.
    NotOurs,
    /// Marker matched but the row lacks a gateway, output ifindex, or
    /// parseable destination — we cannot construct the symmetric
    /// `RemoveRemoteIpRoute` op, so the caller debug-logs and skips
    /// (our write side always emits all three, so this shape is
    /// kernel/parser drift, not a row we produced).
    MarkedButUnusable,
    /// Adoptable crash leftover.
    Candidate {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
        route: AdoptedL3Route,
    },
}

/// Pure route-row classifier. The dump loop translates each
/// `RouteMessage` through here; unit tests drive it directly against
/// synthesized messages.
#[must_use]
pub(crate) fn classify_adoption_route(
    msg: &RouteMessage,
    tables: &HashMap<u32, IpVrfId>,
) -> RouteAdoptionVerdict {
    let table_id = extract_table_id(msg);
    let Some(vrf_id) = tables.get(&table_id).copied() else {
        return RouteAdoptionVerdict::NotOurs; // not a configured IP-VRF table
    };
    if msg.header.protocol != netlink_packet_route::route::RouteProtocol::Bgp
        || !msg.header.flags.contains(RouteFlags::Onlink)
    {
        // The marker is the *pair*: proto bgp alone could be a
        // co-resident daemon's route (an unsupported deployment, but
        // fail safe); onlink alone is any operator onlink route.
        return RouteAdoptionVerdict::NotOurs;
    }
    let (Some(prefix), Some(next_hop), Some(l3vxlan_ifindex)) = (
        extract_prefix(msg),
        extract_gateway(msg),
        extract_output_ifindex(msg),
    ) else {
        return RouteAdoptionVerdict::MarkedButUnusable;
    };
    RouteAdoptionVerdict::Candidate {
        vrf_id,
        prefix,
        route: AdoptedL3Route {
            table_id,
            l3vxlan_ifindex,
            next_hop,
        },
    }
}

/// Pure L3-neighbor classifier: keep rows on a managed L3VXLAN
/// ifindex whose state carries `NUD_PERMANENT` and whose flags carry
/// `NTF_EXT_LEARNED` — exactly what `super::l3::apply_add_l3_neighbor`
/// writes — and whose `NDA_PROTOCOL`, when present, is `RTPROT_BGP`
/// (the ADR-0082 ownership stamp the same write side emits). A row
/// stamped with any other protocol value is provably another
/// controller's (zebra stamps `RTPROT_ZEBRA`) and is never adopted; a
/// stamp-less row stays adoptable this release (stamp-or-legacy
/// migration window, ADR-0082 decision 4 — rows installed by
/// pre-stamp rustbgpd versions carry no protocol attribute).
/// Returns the `(ifindex, next_hop) → vrf_id` pair the
/// adoption dump records, or `None` for foreign / unmanaged rows.
#[must_use]
pub(crate) fn classify_adoption_neighbor(
    msg: &NeighbourMessage,
    managed_l3vxlan: &HashMap<u32, IpVrfId>,
) -> Option<((u32, IpAddr), IpVrfId)> {
    let ifindex = msg.header.ifindex;
    let vrf_id = managed_l3vxlan.get(&ifindex).copied()?;
    if !state_has_permanent(msg.header.state)
        || !msg.header.flags.contains(NeighbourFlags::ExtLearned)
    {
        return None;
    }
    if extract_protocol(msg).is_some_and(|p| p != RouteProtocol::Bgp) {
        return None;
    }
    let next_hop = msg.attributes.iter().find_map(|attr| match attr {
        NeighbourAttribute::Destination(NeighbourAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
        NeighbourAttribute::Destination(NeighbourAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
        _ => None,
    })?;
    Some(((ifindex, next_hop), vrf_id))
}

/// Pure L3VXLAN-FDB classifier: keep `AF_BRIDGE` rows on a managed
/// L3VXLAN ifindex with the `extern_learn` flag and permanent state —
/// what `super::l3::apply_add_l3vxlan_fdb` writes
/// (`NUD_NOARP | NUD_PERMANENT`, `NTF_SELF | NTF_EXT_LEARNED`). The
/// `NTF_SELF` bit is not re-checked here: an L3VXLAN has no bridge
/// master, so every row in its own FDB dump is a self row by
/// construction, and `extern_learn` is the discriminating half of the
/// marker.
///
/// The ADR-0082 protocol check runs in *prefer* mode only: mainline
/// `AF_BRIDGE` never stores `NDA_PROTOCOL`, so requiring the stamp
/// would make FDB adoption permanently empty. If a future kernel
/// returns the attribute, a value ≠ `RTPROT_BGP` disqualifies the row
/// (provably another controller's); absence keeps today's flag-based
/// rule — zero behavior change on current kernels.
#[must_use]
pub(crate) fn classify_adoption_l3vxlan_fdb(
    msg: &NeighbourMessage,
    managed_l3vxlan: &HashMap<u32, IpVrfId>,
) -> Option<((u32, MacAddress), IpVrfId)> {
    if msg.header.family != AddressFamily::Bridge {
        return None;
    }
    let ifindex = msg.header.ifindex;
    let vrf_id = managed_l3vxlan.get(&ifindex).copied()?;
    if !state_has_permanent(msg.header.state)
        || !msg.header.flags.contains(NeighbourFlags::ExtLearned)
    {
        return None;
    }
    if extract_protocol(msg).is_some_and(|p| p != RouteProtocol::Bgp) {
        return None;
    }
    let router_mac = msg.attributes.iter().find_map(|attr| match attr {
        NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(bytes);
            Some(MacAddress::new(arr))
        }
        _ => None,
    })?;
    Some(((ifindex, router_mac), vrf_id))
}

/// `NDA_PROTOCOL` value from the dumped neighbour message, if the
/// kernel returned one. IP neighbors store and echo it since Linux
/// 5.0; `AF_BRIDGE` FDB rows never carry it on mainline kernels.
fn extract_protocol(msg: &NeighbourMessage) -> Option<RouteProtocol> {
    msg.attributes.iter().find_map(|attr| match attr {
        NeighbourAttribute::Protocol(p) => Some(*p),
        _ => None,
    })
}

/// `true` when the `ndm_state` bitmask includes `NUD_PERMANENT`.
/// Mirrors `super::fdb::decode_state`'s handling of the combined
/// `NUD_NOARP | NUD_PERMANENT` shape iproute2 (and we) write — the
/// crate's enum only represents single-bit states, so the combined
/// mask arrives through the `Other` escape hatch.
fn state_has_permanent(state: NeighbourState) -> bool {
    match state {
        NeighbourState::Permanent => true,
        NeighbourState::Other(bits) => bits & NUD_PERMANENT != 0,
        _ => false,
    }
}

/// Gateway address from the first `RouteAttribute::Gateway`. The
/// observation path (`super::routes`) never needs the gateway, so
/// this lives with the adoption walk that does.
fn extract_gateway(msg: &RouteMessage) -> Option<IpAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Gateway(RouteAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
        RouteAttribute::Gateway(RouteAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
        _ => None,
    })
}

/// Walk all three kernel surfaces and collect marker-matching rows.
///
/// Returns `Some(empty)` immediately when no IP-VRFs are configured
/// (the zero-cost RR-only / L2-only path — same short-circuit as
/// `dump_ip_vrf_routes`). Returns `None` when *any* sub-dump fails so
/// the caller never acts on a partial kernel view; failures are
/// logged here with the failing surface named.
pub(crate) async fn dump_l3_adoption_candidates(
    handle: &Handle,
    ip_vrfs: &IpVrfTable,
) -> Option<L3AdoptionDump> {
    if ip_vrfs.is_empty() {
        return Some(L3AdoptionDump::default());
    }
    // Resolve table_id → vrf and vrf → L3VXLAN ifindex through the
    // same link-dump + name-resolution pass the slice-6a route
    // observation uses, so "managed device" means the same thing on
    // both paths. A VRF whose L3VXLAN device is currently absent
    // simply contributes no managed ifindex — its neighbor / FDB rows
    // are invisible this pass and a later pass (or the reap's
    // re-dump) picks them up once the device returns.
    let observations = match ip_vrf::dump_ip_vrf_observations(handle).await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, "L3 adoption: ip-vrf link dump failed");
            return None;
        }
    };
    let resolution =
        IpVrfRoutingResolution::from_table(ip_vrfs, &observations.vxlan_name_to_ifindex());
    let managed_l3vxlan: HashMap<u32, IpVrfId> = resolution
        .l3vxlan_ifindexes
        .iter()
        .map(|(vrf_id, ifindex)| (*ifindex, *vrf_id))
        .collect();

    let mut out = L3AdoptionDump::default();
    for version in [IpVersion::V4, IpVersion::V6] {
        if let Err(e) = dump_routes_one_family(handle, version, &resolution.tables, &mut out).await
        {
            tracing::warn!(error = %e, "L3 adoption: route dump failed");
            return None;
        }
    }
    if !managed_l3vxlan.is_empty() {
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            if let Err(e) =
                dump_neighbors_one_family(handle, family, &managed_l3vxlan, &mut out).await
            {
                tracing::warn!(error = %e, "L3 adoption: neighbor dump failed");
                return None;
            }
        }
        if let Err(e) = dump_l3vxlan_fdb(handle, &managed_l3vxlan, &mut out).await {
            tracing::warn!(error = %e, "L3 adoption: L3VXLAN FDB dump failed");
            return None;
        }
    }
    Some(out)
}

async fn dump_routes_one_family(
    handle: &Handle,
    version: IpVersion,
    tables: &HashMap<u32, IpVrfId>,
    out: &mut L3AdoptionDump,
) -> Result<(), DataplaneError> {
    let msg = match version {
        IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
        IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
    };
    let mut stream = handle.route().get(msg).execute();
    while let Some(route_msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("L3 adoption route dump ({version:?}): {e}")))?
    {
        match classify_adoption_route(&route_msg, tables) {
            RouteAdoptionVerdict::Candidate {
                vrf_id,
                prefix,
                route,
            } => {
                out.routes.insert((vrf_id, prefix), route);
            }
            RouteAdoptionVerdict::MarkedButUnusable => {
                // Marker matched but the row is missing the identity
                // a remove op needs. Skipping leaves it in the kernel
                // unmanaged — debug-visible, never silently deleted.
                tracing::debug!(
                    table_id = extract_table_id(&route_msg),
                    "L3 adoption: marker route missing gateway/oif/dst; skipping"
                );
            }
            RouteAdoptionVerdict::NotOurs => {}
        }
    }
    Ok(())
}

async fn dump_neighbors_one_family(
    handle: &Handle,
    family: AddressFamily,
    managed_l3vxlan: &HashMap<u32, IpVrfId>,
    out: &mut L3AdoptionDump,
) -> Result<(), DataplaneError> {
    let mut req = handle.neighbours().get();
    req.message_mut().header.family = family;
    let mut stream = req.execute();
    while let Some(msg) = stream.try_next().await.map_err(|e| {
        DataplaneError::Other(format!("L3 adoption neighbor dump ({family:?}): {e}"))
    })? {
        if let Some((key, vrf_id)) = classify_adoption_neighbor(&msg, managed_l3vxlan) {
            out.neighbors.insert(key, vrf_id);
        }
    }
    Ok(())
}

async fn dump_l3vxlan_fdb(
    handle: &Handle,
    managed_l3vxlan: &HashMap<u32, IpVrfId>,
    out: &mut L3AdoptionDump,
) -> Result<(), DataplaneError> {
    let mut req = handle.neighbours().get();
    req.message_mut().header.family = AddressFamily::Bridge;
    let mut stream = req.execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("L3 adoption fdb dump: {e}")))?
    {
        if let Some((key, vrf_id)) = classify_adoption_l3vxlan_fdb(&msg, managed_l3vxlan) {
            out.l3vxlan_fdb.insert(key, vrf_id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::route::{RouteHeader, RouteProtocol, RouteScope, RouteType};
    use rustbgpd_evpn::Ipv4Prefix;
    use std::net::Ipv4Addr;

    fn vrf_id(n: u32) -> IpVrfId {
        IpVrfId::new(n).unwrap()
    }

    fn tables(entries: &[(u32, u32)]) -> HashMap<u32, IpVrfId> {
        entries.iter().map(|(t, v)| (*t, vrf_id(*v))).collect()
    }

    fn managed(entries: &[(u32, u32)]) -> HashMap<u32, IpVrfId> {
        entries.iter().map(|(i, v)| (*i, vrf_id(*v))).collect()
    }

    /// Marker-shaped route message — proto bgp + onlink in `table`,
    /// with destination / gateway / oif present unless suppressed.
    fn route_msg(
        table: u32,
        proto: RouteProtocol,
        onlink: bool,
        dest: Option<Ipv4Addr>,
        gateway: Option<Ipv4Addr>,
        oif: Option<u32>,
    ) -> RouteMessage {
        let mut msg = RouteMessage::default();
        msg.header = RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: if dest.is_some() { 24 } else { 0 },
            source_prefix_length: 0,
            tos: 0,
            table: u8::try_from(table.min(252)).unwrap_or(252),
            protocol: proto,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: if onlink {
                RouteFlags::Onlink
            } else {
                RouteFlags::empty()
            },
        };
        msg.attributes.push(RouteAttribute::Table(table));
        if let Some(d) = dest {
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(d)));
        }
        if let Some(g) = gateway {
            msg.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet(g)));
        }
        if let Some(idx) = oif {
            msg.attributes.push(RouteAttribute::Oif(idx));
        }
        msg
    }

    fn neigh_msg(
        family: AddressFamily,
        ifindex: u32,
        state: NeighbourState,
        flags: NeighbourFlags,
        dest: Option<Ipv4Addr>,
        lladdr: Option<[u8; 6]>,
    ) -> NeighbourMessage {
        let mut msg = NeighbourMessage::default();
        msg.header.family = family;
        msg.header.ifindex = ifindex;
        msg.header.state = state;
        msg.header.flags = flags;
        if let Some(d) = dest {
            msg.attributes
                .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(d)));
        }
        if let Some(bytes) = lladdr {
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(bytes.to_vec()));
        }
        msg
    }

    // ── route classifier ──

    #[test]
    fn marker_route_in_configured_table_is_candidate() {
        let msg = route_msg(
            201,
            RouteProtocol::Bgp,
            true,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(42),
        );
        let verdict = classify_adoption_route(&msg, &tables(&[(201, 101)]));
        assert_eq!(
            verdict,
            RouteAdoptionVerdict::Candidate {
                vrf_id: vrf_id(101),
                prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
                route: AdoptedL3Route {
                    table_id: 201,
                    l3vxlan_ifindex: 42,
                    next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                },
            },
        );
    }

    #[test]
    fn route_outside_configured_tables_is_not_ours() {
        let msg = route_msg(
            999,
            RouteProtocol::Bgp,
            true,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(42),
        );
        assert_eq!(
            classify_adoption_route(&msg, &tables(&[(201, 101)])),
            RouteAdoptionVerdict::NotOurs,
        );
    }

    #[test]
    fn route_without_onlink_or_without_proto_bgp_is_not_ours() {
        // The marker is the pair — each half alone is foreign.
        let no_onlink = route_msg(
            201,
            RouteProtocol::Bgp,
            false,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(42),
        );
        assert_eq!(
            classify_adoption_route(&no_onlink, &tables(&[(201, 101)])),
            RouteAdoptionVerdict::NotOurs,
        );
        let not_bgp = route_msg(
            201,
            RouteProtocol::Static,
            true,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(42),
        );
        assert_eq!(
            classify_adoption_route(&not_bgp, &tables(&[(201, 101)])),
            RouteAdoptionVerdict::NotOurs,
        );
    }

    #[test]
    fn marker_route_missing_gateway_or_oif_is_unusable_not_foreign() {
        let no_gateway = route_msg(
            201,
            RouteProtocol::Bgp,
            true,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            None,
            Some(42),
        );
        assert_eq!(
            classify_adoption_route(&no_gateway, &tables(&[(201, 101)])),
            RouteAdoptionVerdict::MarkedButUnusable,
        );
        let no_oif = route_msg(
            201,
            RouteProtocol::Bgp,
            true,
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_route(&no_oif, &tables(&[(201, 101)])),
            RouteAdoptionVerdict::MarkedButUnusable,
        );
    }

    // ── neighbor classifier ──

    #[test]
    fn permanent_ext_learned_neighbor_on_managed_ifindex_is_adopted() {
        let msg = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Permanent,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)])),
            Some(((42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), vrf_id(101))),
        );
    }

    #[test]
    fn neighbor_on_unmanaged_ifindex_is_skipped() {
        let msg = neigh_msg(
            AddressFamily::Inet,
            7,
            NeighbourState::Permanent,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)])),
            None
        );
    }

    #[test]
    fn neighbor_missing_either_marker_half_is_skipped() {
        // ext_learn without permanent: kernel-learned-then-flagged
        // shapes are not ours.
        let not_permanent = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Reachable,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&not_permanent, &managed(&[(42, 101)])),
            None,
        );
        // permanent without ext_learn: operator `ip neigh add ...
        // nud permanent` — foreign, preserved.
        let not_ext_learned = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Permanent,
            NeighbourFlags::empty(),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&not_ext_learned, &managed(&[(42, 101)])),
            None,
        );
    }

    // ── ADR-0082 NDA_PROTOCOL ownership stamp (neighbor) ──

    fn with_protocol(mut msg: NeighbourMessage, proto: RouteProtocol) -> NeighbourMessage {
        msg.attributes.push(NeighbourAttribute::Protocol(proto));
        msg
    }

    #[test]
    fn neighbor_with_bgp_protocol_stamp_is_adopted() {
        // A post-ADR-0082 install: the stamp matches our RTPROT_BGP
        // identity, so the row stays a candidate.
        let msg = with_protocol(
            neigh_msg(
                AddressFamily::Inet,
                42,
                NeighbourState::Permanent,
                NeighbourFlags::ExtLearned,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                None,
            ),
            RouteProtocol::Bgp,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)])),
            Some(((42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), vrf_id(101))),
        );
    }

    #[test]
    fn neighbor_with_foreign_protocol_stamp_is_never_adopted() {
        // Flags match ours exactly, but the stamp proves another
        // controller wrote the row (zebra stamps RTPROT_ZEBRA = 11).
        // Same verdict for an arbitrary unassigned protocol value.
        for proto in [RouteProtocol::Zebra, RouteProtocol::Other(150)] {
            let msg = with_protocol(
                neigh_msg(
                    AddressFamily::Inet,
                    42,
                    NeighbourState::Permanent,
                    NeighbourFlags::ExtLearned,
                    Some(Ipv4Addr::new(10, 0, 0, 2)),
                    None,
                ),
                proto,
            );
            assert_eq!(
                classify_adoption_neighbor(&msg, &managed(&[(42, 101)])),
                None,
                "protocol {proto:?} must disqualify the row",
            );
        }
    }

    #[test]
    fn neighbor_without_protocol_stamp_is_adopted_as_legacy() {
        // Rows installed by pre-stamp rustbgpd versions carry no
        // NDA_PROTOCOL; the ADR-0082 decision 4 migration window
        // keeps them adoptable this release (a strict flip is a
        // later, separate release).
        let msg = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Permanent,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)])),
            Some(((42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), vrf_id(101))),
        );
    }

    // ── L3VXLAN FDB classifier ──

    #[test]
    fn ext_learned_permanent_fdb_row_on_managed_ifindex_is_adopted() {
        // The write side sends the combined NUD_NOARP | NUD_PERMANENT
        // bitmask through the `Other` escape hatch — the decode must
        // see the permanent bit inside it.
        let msg = neigh_msg(
            AddressFamily::Bridge,
            42,
            NeighbourState::Other(0xc0), // NUD_NOARP | NUD_PERMANENT
            NeighbourFlags::Own | NeighbourFlags::ExtLearned,
            None,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            Some((
                (42, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
                vrf_id(101),
            )),
        );
    }

    #[test]
    fn fdb_row_without_ext_learn_is_foreign() {
        // Operator `bridge fdb add ... self permanent` — no
        // extern_learn, never adopted.
        let msg = neigh_msg(
            AddressFamily::Bridge,
            42,
            NeighbourState::Other(0xc0),
            NeighbourFlags::Own,
            None,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            None
        );
    }

    #[test]
    fn fdb_row_on_unmanaged_ifindex_is_skipped() {
        // An L2 VXLAN's extern_learn rows share the marker bits but
        // live on a bridge-enslaved ifindex outside the managed
        // L3VXLAN set — they belong to the slice-2 sweep.
        let msg = neigh_msg(
            AddressFamily::Bridge,
            7,
            NeighbourState::Other(0xc0),
            NeighbourFlags::Own | NeighbourFlags::ExtLearned,
            None,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            None
        );
    }

    #[test]
    fn non_bridge_family_message_is_never_an_fdb_row() {
        let msg = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Other(0xc0),
            NeighbourFlags::Own | NeighbourFlags::ExtLearned,
            None,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            None
        );
    }

    // ── ADR-0082 NDA_PROTOCOL prefer mode (L3VXLAN FDB) ──

    #[test]
    fn fdb_row_with_bgp_protocol_stamp_is_adopted() {
        // Prefer mode: if a future FDB-storing kernel echoes our own
        // stamp back, the row stays a candidate.
        let msg = with_protocol(
            neigh_msg(
                AddressFamily::Bridge,
                42,
                NeighbourState::Other(0xc0),
                NeighbourFlags::Own | NeighbourFlags::ExtLearned,
                None,
                Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            ),
            RouteProtocol::Bgp,
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            Some((
                (42, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
                vrf_id(101),
            )),
        );
    }

    #[test]
    fn fdb_row_with_foreign_protocol_stamp_is_foreign() {
        // A stamped value ≠ RTPROT_BGP is provably another
        // controller's row, flags notwithstanding.
        for proto in [RouteProtocol::Zebra, RouteProtocol::Other(150)] {
            let msg = with_protocol(
                neigh_msg(
                    AddressFamily::Bridge,
                    42,
                    NeighbourState::Other(0xc0),
                    NeighbourFlags::Own | NeighbourFlags::ExtLearned,
                    None,
                    Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
                ),
                proto,
            );
            assert_eq!(
                classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
                None,
                "protocol {proto:?} must disqualify the row",
            );
        }
    }

    #[test]
    fn fdb_row_without_protocol_stamp_keeps_flag_based_rule() {
        // Mainline AF_BRIDGE never returns the attribute — the
        // flag-based rule is the only effective one today, so
        // absence must keep adopting (zero behavior change on
        // current kernels).
        let msg = neigh_msg(
            AddressFamily::Bridge,
            42,
            NeighbourState::Other(0xc0),
            NeighbourFlags::Own | NeighbourFlags::ExtLearned,
            None,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            Some((
                (42, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
                vrf_id(101),
            )),
        );
    }
}
