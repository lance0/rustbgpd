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
//!    and whose `NDA_PROTOCOL` is `RTPROT_BGP` (the ADR-0082
//!    ownership stamp; required by default now that the stamp-or-
//!    legacy migration window has closed —
//!    [`ADOPTION_ACCEPT_LEGACY_ENV`] restores legacy acceptance for
//!    skip-version upgrades).
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
use netlink_packet_core::Nla;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHopFlags, RouteProtocol,
};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use rustbgpd_evpn::ip_vrf::{IpVrfId, IpVrfTable};
use rustbgpd_evpn::{EvpnIpPrefixValue, MacAddress};

use crate::error::DataplaneError;
use crate::l3_adoption::{
    AdoptedL3Route, AdoptedL3VxlanFdb, AdoptedL3VxlanFdbTarget, L3AdoptionDump,
};

use super::ip_vrf;
use super::routes::{
    IpVrfRoutingResolution, extract_output_ifindex, extract_prefix, extract_table_id,
};

/// `NUD_PERMANENT` — non-aging neighbor entry. Mirrors the private
/// constant in `super::l3` (the write side); both halves of the
/// marker must read the same bit.
const NUD_PERMANENT: u16 = 0x80;
/// `NDA_NH_ID` (kind = 13). `netlink-packet-route 0.30` exposes it
/// through `NeighbourAttribute::Other(DefaultNla)`.
const NDA_NH_ID: u16 = 13;

/// Escape hatch for the ADR-0082 strict L3-neighbor adoption rule.
/// The stamp-or-legacy migration window (decision 4) closed after
/// v0.38.0 shipped `NDA_PROTOCOL` stamping on every install site:
/// [`classify_adoption_neighbor`] now requires the `RTPROT_BGP` stamp
/// by default, so a stamp-less row — installed by a pre-stamp
/// rustbgpd — is no longer adopted. Setting this to `1` or `true`
/// restores the stamp-or-legacy rule for the run, which a
/// skip-version upgrade (pre-stamp straight to strict, with kernel
/// rows still live) needs for its first boot. Foreign stamps (any
/// value other than `RTPROT_BGP`) disqualify a row in both modes.
const ADOPTION_ACCEPT_LEGACY_ENV: &str = "RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY";

/// Pure core of the [`ADOPTION_ACCEPT_LEGACY_ENV`] switch with the
/// environment value injected, so the parse rule is unit-testable
/// without touching process-global env state. `1` / `true`
/// (ASCII-case-insensitive, surrounding whitespace ignored) enable
/// legacy acceptance; unset, `0`, and `false` keep the strict
/// default; anything else (including set-but-empty, a likely lost
/// value) warns and keeps the strict default.
fn accept_legacy_override(env: Option<&str>) -> bool {
    let Some(raw) = env else {
        return false;
    };
    let value = raw.trim();
    if value.eq_ignore_ascii_case("1") || value.eq_ignore_ascii_case("true") {
        return true;
    }
    if !(value.eq_ignore_ascii_case("0") || value.eq_ignore_ascii_case("false")) {
        tracing::warn!(
            value = %raw,
            "ignoring invalid {ADOPTION_ACCEPT_LEGACY_ENV} (expected 1/true or 0/false)"
        );
    }
    false
}

/// Resolve the effective legacy-acceptance mode, reading
/// [`ADOPTION_ACCEPT_LEGACY_ENV`] once at dataplane construction —
/// never inside the per-row classifier.
pub(super) fn adoption_accept_legacy() -> bool {
    let env = match std::env::var(ADOPTION_ACCEPT_LEGACY_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!("ignoring non-unicode {ADOPTION_ACCEPT_LEGACY_ENV}");
            None
        }
    };
    let accept_legacy = accept_legacy_override(env.as_deref());
    if accept_legacy {
        tracing::warn!(
            "{ADOPTION_ACCEPT_LEGACY_ENV} restores stamp-or-legacy L3 neighbor adoption \
             (ADR-0082 migration escape hatch)"
        );
    }
    accept_legacy
}

/// Verdict for one kernel route row against the ADR-0079 VRF-route
/// marker (`RTPROT_BGP` + onlink, in a configured `table_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    let Some(prefix) = extract_prefix(msg) else {
        return RouteAdoptionVerdict::MarkedButUnusable;
    };
    let Some((next_hops, l3vxlan_ifindex)) = extract_route_targets(msg) else {
        return RouteAdoptionVerdict::MarkedButUnusable;
    };
    let next_hop = next_hops[0];
    RouteAdoptionVerdict::Candidate {
        vrf_id,
        prefix,
        route: AdoptedL3Route {
            table_id,
            l3vxlan_ifindex,
            next_hop,
            next_hops,
        },
    }
}

fn extract_route_targets(msg: &RouteMessage) -> Option<(Vec<IpAddr>, u32)> {
    if let (Some(next_hop), Some(l3vxlan_ifindex)) = (
        super::routes::extract_gateway(msg),
        extract_output_ifindex(msg),
    ) {
        return Some((vec![next_hop], l3vxlan_ifindex));
    }
    let mut out = Vec::new();
    let mut ifindex = None;
    for attr in &msg.attributes {
        let RouteAttribute::MultiPath(hops) = attr else {
            continue;
        };
        for hop in hops {
            if !hop.flags.contains(RouteNextHopFlags::Onlink) {
                return None;
            }
            match ifindex {
                Some(existing) if existing != hop.interface_index => return None,
                Some(_) => {}
                None => ifindex = Some(hop.interface_index),
            }
            let next_hop = hop.attributes.iter().find_map(|attr| match attr {
                RouteAttribute::Gateway(RouteAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
                RouteAttribute::Gateway(RouteAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
                _ => None,
            })?;
            out.push(next_hop);
        }
    }
    out.sort();
    out.dedup();
    if out.len() < 2 {
        return None;
    }
    Some((out, ifindex?))
}

/// Pure L3-neighbor classifier: keep rows on a managed L3VXLAN
/// ifindex whose state carries `NUD_PERMANENT` and whose flags carry
/// `NTF_EXT_LEARNED` — exactly what `super::l3::apply_add_l3_neighbor`
/// writes — and whose `NDA_PROTOCOL` is `RTPROT_BGP` (the ADR-0082
/// ownership stamp the same write side emits). A row stamped with any
/// other protocol value is provably another controller's (zebra
/// stamps `RTPROT_ZEBRA`) and is never adopted. A stamp-less row is
/// no longer adopted by default: the ADR-0082 decision 4
/// stamp-or-legacy migration window closed once v0.38.0 shipped
/// stamping on every install site, so absence now means "not ours".
/// `accept_legacy` (the [`ADOPTION_ACCEPT_LEGACY_ENV`] escape hatch,
/// read once at dataplane construction) restores the old rule for
/// skip-version upgrades whose kernels still hold pre-stamp rows.
/// Returns the `(ifindex, next_hop) → vrf_id` pair the
/// adoption dump records, or `None` for foreign / unmanaged rows.
#[must_use]
pub(crate) fn classify_adoption_neighbor(
    msg: &NeighbourMessage,
    managed_l3vxlan: &HashMap<u32, IpVrfId>,
    accept_legacy: bool,
) -> Option<((u32, IpAddr), IpVrfId)> {
    let ifindex = msg.header.ifindex;
    let vrf_id = managed_l3vxlan.get(&ifindex).copied()?;
    if !state_has_permanent(msg.header.state)
        || !msg.header.flags.contains(NeighbourFlags::ExtLearned)
    {
        return None;
    }
    // Stamp rule: `RTPROT_BGP` is ours; any other stamp is provably
    // another controller's; absence is only ours under the legacy
    // escape hatch (pre-stamp rows, skip-version upgrades).
    let stamp_ok = match extract_protocol(msg) {
        Some(proto) => proto == RouteProtocol::Bgp,
        None => accept_legacy,
    };
    if !stamp_ok {
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
) -> Option<((u32, MacAddress), AdoptedL3VxlanFdb)> {
    if msg.header.family != AddressFamily::Bridge {
        return None;
    }
    let ifindex = msg.header.ifindex;
    let vrf_id = managed_l3vxlan.get(&ifindex).copied()?;
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
    let target = if let Some(nh_id) = extract_nh_id(msg) {
        if !crate::nh_id_alloc::NhIdAllocator::is_l3_nhg(nh_id) {
            return None;
        }
        AdoptedL3VxlanFdbTarget::NexthopGroup { nh_id }
    } else {
        if !state_has_permanent(msg.header.state)
            || !msg.header.flags.contains(NeighbourFlags::ExtLearned)
        {
            return None;
        }
        AdoptedL3VxlanFdbTarget::SingleDst
    };
    Some(((ifindex, router_mac), AdoptedL3VxlanFdb { vrf_id, target }))
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

/// `NDA_NH_ID` from an L3VXLAN FDB row, if present.
fn extract_nh_id(msg: &NeighbourMessage) -> Option<u32> {
    msg.attributes.iter().find_map(|attr| match attr {
        NeighbourAttribute::Other(default_nla)
            if Nla::kind(default_nla) == NDA_NH_ID && Nla::value_len(default_nla) == 4 =>
        {
            let mut bytes = [0u8; 4];
            Nla::emit_value(default_nla, &mut bytes);
            Some(u32::from_ne_bytes(bytes))
        }
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
    accept_legacy: bool,
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
                dump_neighbors_one_family(handle, family, &managed_l3vxlan, accept_legacy, &mut out)
                    .await
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
    accept_legacy: bool,
    out: &mut L3AdoptionDump,
) -> Result<(), DataplaneError> {
    let mut req = handle.neighbours().get();
    req.message_mut().header.family = family;
    let mut stream = req.execute();
    while let Some(msg) = stream.try_next().await.map_err(|e| {
        DataplaneError::Other(format!("L3 adoption neighbor dump ({family:?}): {e}"))
    })? {
        if let Some((key, vrf_id)) =
            classify_adoption_neighbor(&msg, managed_l3vxlan, accept_legacy)
        {
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
        if let Some((key, row)) = classify_adoption_l3vxlan_fdb(&msg, managed_l3vxlan) {
            out.l3vxlan_fdb.insert(key, row);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::DefaultNla;
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteNextHop, RouteProtocol, RouteScope,
        RouteType,
    };
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

    fn adopted_fdb(vrf: u32, target: AdoptedL3VxlanFdbTarget) -> AdoptedL3VxlanFdb {
        AdoptedL3VxlanFdb {
            vrf_id: vrf_id(vrf),
            target,
        }
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

    fn ecmp_route_msg(table: u32, dest: Ipv4Addr, oif: u32, gateways: &[Ipv4Addr]) -> RouteMessage {
        let mut msg = route_msg(table, RouteProtocol::Bgp, true, Some(dest), None, None);
        let hops = gateways
            .iter()
            .map(|gateway| {
                let mut hop = RouteNextHop::default();
                hop.flags = RouteNextHopFlags::Onlink;
                hop.interface_index = oif;
                hop.attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet(*gateway)));
                hop
            })
            .collect();
        msg.attributes.push(RouteAttribute::MultiPath(hops));
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
                    next_hops: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
                },
            },
        );
    }

    #[test]
    fn marker_ecmp_route_in_configured_table_is_candidate() {
        let msg = ecmp_route_msg(
            201,
            Ipv4Addr::new(198, 51, 100, 0),
            42,
            &[Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 2)],
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
                    next_hops: vec![
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                    ],
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
    fn neighbor_on_unmanaged_ifindex_is_skipped() {
        let msg = with_protocol(
            neigh_msg(
                AddressFamily::Inet,
                7,
                NeighbourState::Permanent,
                NeighbourFlags::ExtLearned,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                None,
            ),
            RouteProtocol::Bgp,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)]), false),
            None
        );
    }

    #[test]
    fn neighbor_missing_either_marker_half_is_skipped() {
        // ext_learn without permanent: kernel-learned-then-flagged
        // shapes are not ours — even with our own stamp on the row.
        let not_permanent = with_protocol(
            neigh_msg(
                AddressFamily::Inet,
                42,
                NeighbourState::Reachable,
                NeighbourFlags::ExtLearned,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                None,
            ),
            RouteProtocol::Bgp,
        );
        assert_eq!(
            classify_adoption_neighbor(&not_permanent, &managed(&[(42, 101)]), false),
            None,
        );
        // permanent without ext_learn: operator `ip neigh add ...
        // nud permanent` — foreign, preserved.
        let not_ext_learned = with_protocol(
            neigh_msg(
                AddressFamily::Inet,
                42,
                NeighbourState::Permanent,
                NeighbourFlags::empty(),
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                None,
            ),
            RouteProtocol::Bgp,
        );
        assert_eq!(
            classify_adoption_neighbor(&not_ext_learned, &managed(&[(42, 101)]), false),
            None,
        );
    }

    // ── ADR-0082 NDA_PROTOCOL ownership stamp (neighbor) ──

    fn with_protocol(mut msg: NeighbourMessage, proto: RouteProtocol) -> NeighbourMessage {
        msg.attributes.push(NeighbourAttribute::Protocol(proto));
        msg
    }

    fn with_nh_id(mut msg: NeighbourMessage, nh_id: u32) -> NeighbourMessage {
        msg.attributes
            .push(NeighbourAttribute::Other(DefaultNla::new(
                NDA_NH_ID,
                nh_id.to_ne_bytes().to_vec(),
            )));
        msg
    }

    #[test]
    fn neighbor_with_bgp_protocol_stamp_is_adopted_in_both_modes() {
        // A v0.38.0+ install: the stamp matches our RTPROT_BGP
        // identity, so the row is a candidate under the strict
        // default and under the legacy escape hatch alike.
        for accept_legacy in [false, true] {
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
                classify_adoption_neighbor(&msg, &managed(&[(42, 101)]), accept_legacy),
                Some(((42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), vrf_id(101))),
                "accept_legacy={accept_legacy}",
            );
        }
    }

    #[test]
    fn neighbor_with_foreign_protocol_stamp_is_never_adopted() {
        // Flags match ours exactly, but the stamp proves another
        // controller wrote the row (zebra stamps RTPROT_ZEBRA = 11).
        // Same verdict for an arbitrary unassigned protocol value,
        // and the legacy escape hatch must not weaken it — it only
        // re-admits stamp-LESS rows, never foreign-stamped ones.
        for accept_legacy in [false, true] {
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
                    classify_adoption_neighbor(&msg, &managed(&[(42, 101)]), accept_legacy),
                    None,
                    "protocol {proto:?} must disqualify the row (accept_legacy={accept_legacy})",
                );
            }
        }
    }

    #[test]
    fn neighbor_without_protocol_stamp_is_rejected_by_default() {
        // The ADR-0082 decision 4 migration window closed: every
        // install site has stamped since v0.38.0, so a stamp-less
        // row is no longer provably ours and the strict default
        // classifies it NotOurs (never adopted, never reaped).
        let msg = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Permanent,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)]), false),
            None,
        );
    }

    #[test]
    fn neighbor_without_protocol_stamp_is_adopted_under_the_legacy_hatch() {
        // RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY=1 restores the
        // stamp-or-legacy rule for skip-version upgrades whose
        // kernels still hold pre-stamp rows.
        let msg = neigh_msg(
            AddressFamily::Inet,
            42,
            NeighbourState::Permanent,
            NeighbourFlags::ExtLearned,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
        );
        assert_eq!(
            classify_adoption_neighbor(&msg, &managed(&[(42, 101)]), true),
            Some(((42, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), vrf_id(101))),
        );
    }

    // ── ADOPTION_ACCEPT_LEGACY_ENV parse rule ──

    #[test]
    fn accept_legacy_parse_enables_on_1_and_true() {
        assert!(accept_legacy_override(Some("1")));
        assert!(accept_legacy_override(Some("true")));
        assert!(accept_legacy_override(Some("TRUE")));
        assert!(accept_legacy_override(Some(" 1 ")));
    }

    #[test]
    fn accept_legacy_parse_keeps_strict_on_unset_0_false_and_garbage() {
        assert!(!accept_legacy_override(None));
        assert!(!accept_legacy_override(Some("0")));
        assert!(!accept_legacy_override(Some("false")));
        assert!(!accept_legacy_override(Some("")));
        assert!(!accept_legacy_override(Some("yes")));
        assert!(!accept_legacy_override(Some("garbage")));
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
                adopted_fdb(101, AdoptedL3VxlanFdbTarget::SingleDst),
            )),
        );
    }

    #[test]
    fn fdb_row_with_nhid_records_nexthop_group_target() {
        let msg = with_nh_id(
            neigh_msg(
                AddressFamily::Bridge,
                42,
                NeighbourState::Other(0xc0),
                NeighbourFlags::Own | NeighbourFlags::ExtLearned,
                None,
                Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            ),
            0x6000_0007,
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            Some((
                (42, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
                adopted_fdb(
                    101,
                    AdoptedL3VxlanFdbTarget::NexthopGroup { nh_id: 0x6000_0007 },
                ),
            )),
        );
    }

    #[test]
    fn fdb_nhid_row_uses_l3_nhid_marker_even_when_kernel_drops_flags() {
        let msg = with_nh_id(
            neigh_msg(
                AddressFamily::Bridge,
                42,
                NeighbourState::Other(0),
                NeighbourFlags::Own,
                None,
                Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            ),
            crate::nh_id_alloc::L3_NHG_TAG | 7,
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            Some((
                (42, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
                adopted_fdb(
                    101,
                    AdoptedL3VxlanFdbTarget::NexthopGroup {
                        nh_id: crate::nh_id_alloc::L3_NHG_TAG | 7
                    },
                ),
            )),
        );
    }

    #[test]
    fn fdb_nhid_row_with_non_l3_nhid_is_foreign() {
        let msg = with_nh_id(
            neigh_msg(
                AddressFamily::Bridge,
                42,
                NeighbourState::Other(0xc0),
                NeighbourFlags::Own | NeighbourFlags::ExtLearned,
                None,
                Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            ),
            crate::nh_id_alloc::NHG_TAG | 7,
        );
        assert_eq!(
            classify_adoption_l3vxlan_fdb(&msg, &managed(&[(42, 101)])),
            None
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
                adopted_fdb(101, AdoptedL3VxlanFdbTarget::SingleDst),
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
                adopted_fdb(101, AdoptedL3VxlanFdbTarget::SingleDst),
            )),
        );
    }
}
