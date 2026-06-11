//! RIB → [`RemoteMacTable`] projection.
//!
//! ADR-0054 §1 forbids `crates/evpn-linux` from depending on
//! `crates/rib`, so the daemon — not the dataplane — owns the
//! conversion from RIB best-path EVPN routes into the portable
//! [`RemoteMacTable`] the dataplane consumes. This module is the
//! pure half of that conversion: a free function that takes a small
//! [`ProjectedEvpnRoute`] struct (which the daemon constructs from
//! `EvpnRibRoute` at the call site) and produces the table.
//!
//! Living here in `crates/evpn` rather than `src/` keeps the
//! conversion testable without booting the daemon, and keeps the
//! "domain types live in `crates/evpn`" rule from ADR-0054 §1
//! consistent — the projection is pure domain logic.
//!
//! ## Mobility tie-break
//!
//! Two best-path Type 2 routes can land in the same projection input
//! with the same `(VNI, MAC)` only briefly during MAC mobility
//! transitions, but the function tolerates it deterministically:
//!
//! 1. Higher [`ProjectedEvpnRoute::mobility_sequence`] wins. RFC 7432
//!    §15 puts the higher seq in the more recent advertisement.
//! 2. On equal sequence (or both `None`), the route whose `next_hop`
//!    sorts lower wins. Arbitrary but deterministic — the projection
//!    must always pick the same winner across runs.
//!
//! Routes whose `label1` (the primary MPLS / VNI label) doesn't match
//! any local [`crate::EvpnInstance`] are dropped silently. They
//! belong to other VTEPs' EVIs and the dataplane has no business
//! programming them on this host.

use std::net::IpAddr;

use rustbgpd_wire::{MacAddress, MplsLabel, RouteDistinguisher};
use tracing::warn;

use crate::instance::{EvpnInstanceId, EvpnInstanceTable};
use crate::mac::{RemoteMacEntry, RemoteMacSource, RemoteMacTable};

/// Trimmed best-path EVPN Type 2 record for projection input.
///
/// The daemon translates `EvpnRibRoute` (which lives in `crates/rib`
/// and the EVPN crate cannot reference) into this small portable
/// struct at the call site. Carrying the wire-shaped `RouteDistinguisher`
/// lets the projection log meaningful collision messages without a
/// custom DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedEvpnRoute {
    /// Route Distinguisher of the originating EVI.
    pub rd: RouteDistinguisher,
    /// Advertised MAC.
    pub mac: MacAddress,
    /// Optional host IP carried with the route (Type 2 §7.2).
    pub host_ip: Option<IpAddr>,
    /// Primary MPLS / VNI label. Matched against
    /// [`crate::EvpnInstance`]'s `id` via [`MplsLabel::as_vni`].
    pub label1: MplsLabel,
    /// Resolved next hop — the remote VTEP IP the dataplane will
    /// program as the FDB destination.
    pub next_hop: IpAddr,
    /// MAC mobility sequence (RFC 7432 §15) if the originating route
    /// carried a `MAC Mobility` extended community.
    pub mobility_sequence: Option<u32>,
    /// Ethernet Segment Identifier carried on the Type 2 NLRI.
    /// `EthernetSegmentIdentifier::ZERO` for single-homed CEs;
    /// non-zero when the originator advertises the MAC as part of a
    /// multi-homed segment. The projection layer uses this to look
    /// up aliasing alternatives via the [`crate::AliasIndex`] built
    /// from EAD-per-EVI inputs.
    pub esi: rustbgpd_wire::EthernetSegmentIdentifier,
    /// Ethernet Tag identifying the EVI on the Type 2 NLRI.
    /// Combined with `esi` to key aliasing lookups (RFC 7432 §14
    /// is `(ESI, EthernetTag)`-keyed).
    pub ethernet_tag: rustbgpd_wire::EthernetTagId,
}

/// Trimmed best-path EVPN Type 1 EAD-per-EVI record for projection
/// input. The projection layer uses these to build an
/// [`crate::AliasIndex`] before resolving Type 2 routes; an EAD-per-EVI
/// from a peer signals "this peer can also reach `(esi, eth_tag)`."
///
/// Filtering self-originated entries (next-hop == local VTEP IP) is
/// the caller's responsibility — the projection layer doesn't know
/// which VTEP IP belongs to "us." Doing the filter at the call site
/// keeps this struct purely declarative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectedEvpnEadPerEvi {
    /// Ethernet Segment Identifier the EAD-per-EVI route names.
    pub esi: rustbgpd_wire::EthernetSegmentIdentifier,
    /// Ethernet Tag identifying the EVI.
    pub ethernet_tag: rustbgpd_wire::EthernetTagId,
    /// Next-hop / VTEP IP advertised on the EAD-per-EVI route.
    pub next_hop: IpAddr,
}

/// Build a [`RemoteMacTable`] from a stream of best-path Type 2
/// records.
///
/// Backwards-compat wrapper around
/// [`project_evpn_routes_with_aliases`] for callers that don't yet
/// have an EAD-per-EVI feed. Aliasing alternatives default to
/// empty when no EAD-per-EVI advertisements are supplied.
///
/// The function is pure — no clocks, no I/O, no allocations beyond
/// the returned table. It enforces the mobility tie-break described
/// in the module docs and silently drops routes whose VNI doesn't
/// match a local instance.
///
/// # Panics
///
/// Internally calls [`RemoteMacTableBuilder::insert`], which can only
/// fail on `(VNI, MAC)` collision. The function deduplicates inputs
/// in a `BTreeMap` *before* calling `insert`, so reaching the panic
/// branch indicates a logic bug in this function — never a runtime
/// condition the caller can produce.
///
/// [`RemoteMacTableBuilder::insert`]: crate::RemoteMacTableBuilder::insert
#[must_use]
pub fn project_evpn_routes<I>(instances: &EvpnInstanceTable, routes: I) -> RemoteMacTable
where
    I: IntoIterator<Item = ProjectedEvpnRoute>,
{
    project_evpn_routes_with_aliases(instances, routes, std::iter::empty())
}

/// Build a [`RemoteMacTable`] from Type 2 best paths plus
/// EAD-per-EVI advertisements, populating each entry's
/// `alias_vtep_ips` with the RFC 7432 §14 aliasing alternatives
/// resolved from the EAD-per-EVI feed.
///
/// `ead_per_evi` is the caller's already-self-filtered stream of
/// best-path EAD-per-EVI routes (i.e., self-originated entries
/// removed at the call site). The projection layer uses these to
/// build a [`crate::AliasIndex`] once, then resolves alternatives
/// for every Type 2 with a non-zero ESI.
///
/// Same purity / panic contract as [`project_evpn_routes`].
///
/// # Panics
///
/// Panics under the same logic-bug condition as
/// [`project_evpn_routes`] — the staged `BTreeMap` already dedupes
/// `(VNI, MAC)` keys before calling
/// [`RemoteMacTableBuilder::insert`], so a duplicate-MAC error from
/// the builder indicates a bug in this function, not a runtime
/// condition the caller can produce.
///
/// [`RemoteMacTableBuilder::insert`]: crate::RemoteMacTableBuilder::insert
#[must_use]
pub fn project_evpn_routes_with_aliases<R, A>(
    instances: &EvpnInstanceTable,
    routes: R,
    ead_per_evi: A,
) -> RemoteMacTable
where
    R: IntoIterator<Item = ProjectedEvpnRoute>,
    A: IntoIterator<Item = ProjectedEvpnEadPerEvi>,
{
    // Empty single-active index: `pair_is_single_active` is false for
    // every pair, so every entry takes the pre-ADR-0083 path and the
    // output is bit-identical to the historical behavior.
    project_evpn_routes_with_backup_paths(
        instances,
        routes,
        ead_per_evi,
        &crate::SingleActiveEligibleIndex::new(),
    )
}

/// Build a [`RemoteMacTable`] from Type 2 best paths, all-active
/// EAD-per-EVI aliasing advertisements, and the ADR-0083
/// single-active eligible-set index.
///
/// `ead_per_evi` is the all-active aliasing feed — the caller has
/// already removed self-originated rows *and* rows whose
/// `(next-hop, ESI)` folds single-active (single-active never feeds
/// the ECMP [`crate::AliasIndex`]). `single_active` is the
/// [`crate::SingleActiveEligibleIndex`] built from the same RIB
/// snapshot's EAD-per-ES modes + the full (self-filtered)
/// EAD-per-EVI stream.
///
/// Per staged Type 2 route with a non-zero ESI (ADR-0083 decision 1):
///
/// - **`(next-hop, ESI)` folds single-active, backup derivable** →
///   the entry carries `alias_group_key = (ESI, EthernetTag)` with an
///   *empty* `alias_vtep_ips` (one-member desired membership: the
///   active PE) plus `single_active_backup_vtep_ip = Some(backup)`.
/// - **single-active, no other eligible PE** → de-facto single-homed:
///   plain single-dst entry (no key, no backup) — the NHG indirection
///   buys nothing there.
/// - **all-active (or no EAD-per-ES mode known)** → the existing
///   RFC 7432 §14 aliasing resolution, unchanged.
///
/// Same purity / panic contract as [`project_evpn_routes`].
///
/// # Panics
///
/// Panics under the same logic-bug condition as
/// [`project_evpn_routes`] — the staged `BTreeMap` already dedupes
/// `(VNI, MAC)` keys before calling
/// [`RemoteMacTableBuilder::insert`].
///
/// [`RemoteMacTableBuilder::insert`]: crate::RemoteMacTableBuilder::insert
#[must_use]
pub fn project_evpn_routes_with_backup_paths<R, A>(
    instances: &EvpnInstanceTable,
    routes: R,
    ead_per_evi: A,
    single_active: &crate::SingleActiveEligibleIndex,
) -> RemoteMacTable
where
    R: IntoIterator<Item = ProjectedEvpnRoute>,
    A: IntoIterator<Item = ProjectedEvpnEadPerEvi>,
{
    use std::collections::BTreeMap;

    // Build the aliasing index once. Empty input → empty index;
    // single-homed Type 2 routes resolve to no alternatives even if
    // the index has rows for unrelated ESIs.
    let alias_rows = ead_per_evi.into_iter().map(|e| crate::AliasEadPerEvi {
        esi: e.esi,
        ethernet_tag: e.ethernet_tag,
        vtep_ip: e.next_hop,
    });
    let alias_index = crate::AliasIndex::build(alias_rows);

    // Stage one: collect candidates per (VNI, MAC) and apply the
    // mobility tie-break. The builder rejects duplicates so we resolve
    // races *before* calling insert().
    let mut staged: BTreeMap<(EvpnInstanceId, MacAddress), ProjectedEvpnRoute> = BTreeMap::new();

    for route in routes {
        let Some(vni) = vni_from_label(route.label1) else {
            continue;
        };
        let Some(local_inst) = instances.get(vni) else {
            continue;
        };

        // Skip self-originated Type 2 routes — a route whose next-hop
        // matches our own local VTEP IP for this instance is one we
        // emitted (or will emit) outbound; programming it as a
        // *remote* FDB entry would point traffic for that MAC at
        // ourselves, creating a black hole.
        if route.next_hop == local_inst.local_vtep_ip {
            continue;
        }

        match staged.get_mut(&(vni, route.mac)) {
            None => {
                staged.insert((vni, route.mac), route);
            }
            Some(existing) => {
                if prefer_new(&route, existing) {
                    *existing = route;
                }
            }
        }
    }

    let mut builder = RemoteMacTable::builder();
    for ((vni, mac), route) in staged {
        // ADR-0083 single-active gate: a non-zero-ESI route whose
        // origin `(next-hop, ESI)` pair folds single-active never
        // takes the all-active aliasing path (the single-active bit
        // suppresses ECMP — RFC 7432 §14 vs §8.4). With a derivable
        // backup it carries the one-member group key + backup
        // intent; with no other eligible PE it is de-facto
        // single-homed and keeps today's single-dst shape
        // (decision 1's no-backup fallback).
        if route.esi != rustbgpd_wire::EthernetSegmentIdentifier::ZERO
            && single_active.pair_is_single_active(route.next_hop, route.esi)
        {
            let backup = single_active.backup_pe(route.esi, route.ethernet_tag, route.next_hop);
            let entry = RemoteMacEntry {
                remote_vtep_ip: route.next_hop,
                mobility_sequence: route.mobility_sequence,
                alias_vtep_ips: Vec::new(),
                alias_group_key: backup.map(|_| (route.esi, route.ethernet_tag)),
                single_active_backup_vtep_ip: backup,
                source: RemoteMacSource::EvpnRibBestPath,
            };
            builder
                .insert(vni, mac, entry)
                .expect("staged BTreeMap already deduped (VNI, MAC) keys");
            continue;
        }

        // Resolve aliasing alternatives for non-zero-ESI routes.
        // `alias_resolved_next_hops` returns primary first; we want
        // only the *additional* VTEPs in `alias_vtep_ips`, so trim
        // the primary off the front. Then enforce ADR-0059's
        // same-address-family-per-(ESI, EthernetTag) invariant: an
        // EAD-per-EVI advertised under a different family than the
        // primary is operator misconfiguration — drop it with a
        // warn! per dropped alias so the daemon log surfaces the
        // bad config but the dataplane never sees a mixed-family
        // FDB-NHG member list.
        let alias_vtep_ips: Vec<IpAddr> =
            if route.esi == rustbgpd_wire::EthernetSegmentIdentifier::ZERO {
                Vec::new()
            } else {
                let resolved = crate::alias_resolved_next_hops(
                    route.next_hop,
                    route.esi,
                    route.ethernet_tag,
                    &alias_index,
                );
                let primary_is_v4 = route.next_hop.is_ipv4();
                // resolved[0] is the primary (route.next_hop). Drop it
                // so the field carries only alternatives; then filter
                // any AF-mismatched aliases.
                resolved
                    .into_iter()
                    .skip(1)
                    .filter(|alias_ip| {
                        if alias_ip.is_ipv4() == primary_is_v4 {
                            true
                        } else {
                            warn!(
                                vni = vni.as_u32(),
                                mac = %mac,
                                esi = ?route.esi,
                                ethernet_tag = ?route.ethernet_tag,
                                primary_vtep_ip = %route.next_hop,
                                dropped_vtep_ip = %alias_ip,
                                "evpn: aliasing AF mismatch — dropping alias VTEP \
                                 (ADR-0059 same-family-per-(ESI, EthernetTag) invariant)",
                            );
                            false
                        }
                    })
                    .collect()
            };
        // Aliasing group key — `Some((ESI, EthernetTag))` only when at
        // least one alias VTEP survived; `None` covers ESI == ZERO,
        // ESI != ZERO with no observed aliases, and the post-AF-filter
        // empty case. The "empty list ⇔ key is None" invariant is what
        // the dataplane keys on (ADR-0059 §4).
        let alias_group_key = if alias_vtep_ips.is_empty() {
            None
        } else {
            Some((route.esi, route.ethernet_tag))
        };
        let entry = RemoteMacEntry {
            remote_vtep_ip: route.next_hop,
            mobility_sequence: route.mobility_sequence,
            alias_vtep_ips,
            alias_group_key,
            single_active_backup_vtep_ip: None,
            source: RemoteMacSource::EvpnRibBestPath,
        };
        // Builder rejects duplicates, but we already deduped via
        // BTreeMap above. The Result is here for API symmetry; an
        // Err would indicate a logic bug, not a runtime collision.
        builder
            .insert(vni, mac, entry)
            .expect("staged BTreeMap already deduped (VNI, MAC) keys");
    }
    builder.build()
}

/// Decide whether `new` should displace `existing` for the same
/// `(VNI, MAC)` key. See module docs for the tie-break rule.
fn prefer_new(new: &ProjectedEvpnRoute, existing: &ProjectedEvpnRoute) -> bool {
    // Higher mobility sequence wins. None < Some(0), and Some(N+1) >
    // Some(N) — Option<u32>::cmp gives this ordering naturally.
    match new.mobility_sequence.cmp(&existing.mobility_sequence) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            // Tie on sequence: deterministic by lower next_hop.
            new.next_hop < existing.next_hop
        }
    }
}

/// Convert an MPLS label to a 24-bit VNI per RFC 8365 §5. Returns
/// `None` for labels outside the legal VNI range (0 or > 24-bit). VNI
/// 0 is reserved by RFC 8365 §5; we reject it here so a malformed
/// route doesn't produce an unbuildable [`EvpnInstanceId`].
fn vni_from_label(label: MplsLabel) -> Option<EvpnInstanceId> {
    let raw = label.as_vni();
    if raw == 0 {
        return None;
    }
    EvpnInstanceId::new(raw).ok()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustbgpd_wire::{MacAddress, MplsLabel, RouteDistinguisher};

    use super::*;
    use crate::instance::{EvpnInstance, EvpnInstanceId, EvpnInstanceTable};
    use crate::route_target::RouteTarget;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn label(vni: u32) -> MplsLabel {
        // VXLAN-encapped EVPN puts the full 24-bit VNI directly in
        // the label field (RFC 8365 §5); MplsLabel::as_vni returns
        // self.0, so construct with the raw VNI.
        MplsLabel::new(vni)
    }

    fn rd(asn: u16, val: u32) -> RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        RouteDistinguisher::new(bytes)
    }

    fn local_instance(v: u32) -> EvpnInstance {
        EvpnInstance::new(
            vni(v),
            rd(65001, v),
            vec![RouteTarget::TwoOctetAs {
                asn: 65001,
                value: v,
            }],
            ipa("10.0.0.1"),
            Some(format!("br{v}")),
            false,
        )
        .unwrap()
    }

    fn one_local(v: u32) -> EvpnInstanceTable {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(v)).unwrap();
        t
    }

    fn route(v: u32, m: u8, dst: &str, seq: Option<u32>) -> ProjectedEvpnRoute {
        ProjectedEvpnRoute {
            rd: rd(65002, v),
            mac: mac(m),
            host_ip: None,
            label1: label(v),
            next_hop: ipa(dst),
            mobility_sequence: seq,
            esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
            ethernet_tag: rustbgpd_wire::EthernetTagId(0),
        }
    }

    #[test]
    fn empty_inputs_produce_empty_table() {
        let table = project_evpn_routes(&EvpnInstanceTable::new(), std::iter::empty());
        assert!(table.is_empty());
    }

    #[test]
    fn single_route_round_trips_into_table() {
        let table = project_evpn_routes(&one_local(100), vec![route(100, 1, "10.0.0.2", None)]);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.remote_vtep_ip, ipa("10.0.0.2"));
        assert_eq!(entry.source, RemoteMacSource::EvpnRibBestPath);
    }

    #[test]
    fn route_for_unknown_vni_is_dropped() {
        // VNI 200 has no local instance, so the route is dropped
        // even though it's well-formed.
        let table = project_evpn_routes(&one_local(100), vec![route(200, 1, "10.0.0.2", None)]);
        assert!(table.is_empty());
    }

    #[test]
    fn route_with_zero_label_is_dropped() {
        let bad = ProjectedEvpnRoute {
            label1: MplsLabel::new(0),
            ..route(100, 1, "10.0.0.2", None)
        };
        let table = project_evpn_routes(&one_local(100), vec![bad]);
        assert!(table.is_empty());
    }

    #[test]
    fn higher_mobility_sequence_wins() {
        let routes = vec![
            route(100, 1, "10.0.0.2", Some(1)),
            route(100, 1, "10.0.0.3", Some(5)), // higher seq → wins
            route(100, 1, "10.0.0.4", Some(2)),
        ];
        let table = project_evpn_routes(&one_local(100), routes);
        assert_eq!(
            table.get(vni(100), mac(1)).unwrap().remote_vtep_ip,
            ipa("10.0.0.3")
        );
        assert_eq!(
            table.get(vni(100), mac(1)).unwrap().mobility_sequence,
            Some(5)
        );
    }

    #[test]
    fn equal_seq_breaks_tie_on_lower_next_hop() {
        let routes = vec![
            route(100, 1, "10.0.0.5", Some(3)),
            route(100, 1, "10.0.0.2", Some(3)), // lower next_hop → wins
            route(100, 1, "10.0.0.7", Some(3)),
        ];
        let table = project_evpn_routes(&one_local(100), routes);
        assert_eq!(
            table.get(vni(100), mac(1)).unwrap().remote_vtep_ip,
            ipa("10.0.0.2")
        );
    }

    #[test]
    fn no_seq_at_all_breaks_tie_on_lower_next_hop() {
        let routes = vec![
            route(100, 1, "10.0.0.5", None),
            route(100, 1, "10.0.0.2", None),
        ];
        let table = project_evpn_routes(&one_local(100), routes);
        assert_eq!(
            table.get(vni(100), mac(1)).unwrap().remote_vtep_ip,
            ipa("10.0.0.2")
        );
    }

    #[test]
    fn distinct_macs_in_same_vni_both_land() {
        let routes = vec![
            route(100, 1, "10.0.0.2", None),
            route(100, 2, "10.0.0.3", None),
        ];
        let table = project_evpn_routes(&one_local(100), routes);
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get(vni(100), mac(1)).unwrap().remote_vtep_ip,
            ipa("10.0.0.2")
        );
        assert_eq!(
            table.get(vni(100), mac(2)).unwrap().remote_vtep_ip,
            ipa("10.0.0.3")
        );
    }

    #[test]
    fn same_mac_in_different_vnis_keeps_both() {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(100)).unwrap();
        t.insert(local_instance(200)).unwrap();
        let routes = vec![
            route(100, 1, "10.0.0.2", None),
            route(200, 1, "10.0.0.3", None),
        ];
        let table = project_evpn_routes(&t, routes);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn self_originated_route_is_dropped() {
        // local instance VTEP IP is 10.0.0.1; a route whose next-hop
        // matches our own VTEP must not be programmed as a remote
        // FDB entry (would black-hole traffic for that MAC).
        let table = project_evpn_routes(&one_local(100), vec![route(100, 1, "10.0.0.1", None)]);
        assert!(table.is_empty());
    }

    #[test]
    fn self_filter_does_not_affect_other_vnis_with_same_vtep() {
        // Same MAC+VTEP across two instances; both are local, so both
        // routes drop. Verifies the filter is per-instance.
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(100)).unwrap();
        t.insert(local_instance(200)).unwrap();
        let table = project_evpn_routes(
            &t,
            vec![
                route(100, 1, "10.0.0.1", None),
                route(200, 2, "10.0.0.1", None),
            ],
        );
        assert!(table.is_empty());
    }

    fn route_with_esi(
        v: u32,
        m: u8,
        dst: &str,
        seq: Option<u32>,
        esi: rustbgpd_wire::EthernetSegmentIdentifier,
    ) -> ProjectedEvpnRoute {
        let mut r = route(v, m, dst, seq);
        r.esi = esi;
        r
    }

    fn ead(
        esi: rustbgpd_wire::EthernetSegmentIdentifier,
        eth_tag: u32,
        dst: &str,
    ) -> ProjectedEvpnEadPerEvi {
        ProjectedEvpnEadPerEvi {
            esi,
            ethernet_tag: rustbgpd_wire::EthernetTagId(eth_tag),
            next_hop: ipa(dst),
        }
    }

    fn esi_seed(seed: u8) -> rustbgpd_wire::EthernetSegmentIdentifier {
        rustbgpd_wire::EthernetSegmentIdentifier::new([seed; 10])
    }

    #[test]
    fn aliases_empty_for_zero_esi_routes() {
        let routes = vec![route(100, 1, "10.0.0.2", None)];
        let eads = vec![ead(esi_seed(1), 0, "10.0.0.3")];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_vtep_ips.is_empty());
    }

    #[test]
    fn aliases_populated_for_non_zero_esi_routes() {
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        // Two other PEs advertise EAD-per-EVI for the same segment.
        let eads = vec![
            ead(esi_seed(7), 0, "10.0.0.3"),
            ead(esi_seed(7), 0, "10.0.0.4"),
        ];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        // Primary (10.0.0.2) is in `remote_vtep_ip`, never repeated.
        assert_eq!(entry.remote_vtep_ip, ipa("10.0.0.2"));
        assert_eq!(entry.alias_vtep_ips.len(), 2);
        assert!(entry.alias_vtep_ips.contains(&ipa("10.0.0.3")));
        assert!(entry.alias_vtep_ips.contains(&ipa("10.0.0.4")));
    }

    #[test]
    fn aliases_filter_self_when_eads_include_primary() {
        // A peer advertised EAD-per-EVI for the same `(esi, eth_tag)`
        // and happens to share the Type 2's next-hop (e.g. the same
        // PE advertised both Type 1 and Type 2). The alias list
        // must not duplicate the primary.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let eads = vec![
            ead(esi_seed(7), 0, "10.0.0.2"),
            ead(esi_seed(7), 0, "10.0.0.3"),
        ];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(!entry.alias_vtep_ips.contains(&ipa("10.0.0.2")));
        assert_eq!(entry.alias_vtep_ips, vec![ipa("10.0.0.3")]);
    }

    #[test]
    fn aliases_keyed_on_esi_and_eth_tag_pair() {
        // Two segments, two routes: each only resolves alternatives
        // from the matching segment's EAD-per-EVI rows.
        let routes = vec![
            route_with_esi(100, 1, "10.0.0.2", None, esi_seed(1)),
            route_with_esi(100, 2, "10.0.0.4", None, esi_seed(2)),
        ];
        let eads = vec![
            ead(esi_seed(1), 0, "10.0.0.3"),
            ead(esi_seed(2), 0, "10.0.0.5"),
        ];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let e1 = table.get(vni(100), mac(1)).unwrap();
        let e2 = table.get(vni(100), mac(2)).unwrap();
        assert_eq!(e1.alias_vtep_ips, vec![ipa("10.0.0.3")]);
        assert_eq!(e2.alias_vtep_ips, vec![ipa("10.0.0.5")]);
    }

    #[test]
    fn alias_group_key_none_for_zero_esi() {
        // ESI == ZERO routes never get a group key, regardless of
        // whether unrelated EAD-per-EVI rows happen to be in scope.
        let routes = vec![route(100, 1, "10.0.0.2", None)];
        let eads = vec![ead(esi_seed(1), 0, "10.0.0.3")];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_group_key.is_none());
        assert!(entry.alias_vtep_ips.is_empty());
    }

    #[test]
    fn alias_group_key_populated_when_aliases_observed() {
        // Non-zero ESI + at least one EAD-per-EVI for that segment →
        // group key carries the (ESI, EthernetTag).
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let eads = vec![ead(esi_seed(7), 0, "10.0.0.3")];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(
            entry.alias_group_key,
            Some((esi_seed(7), rustbgpd_wire::EthernetTagId(0))),
        );
        assert!(!entry.alias_vtep_ips.is_empty());
    }

    #[test]
    fn alias_group_key_none_when_nonzero_esi_but_no_aliases() {
        // Non-zero ESI but no EAD-per-EVI observed yet → no key. The
        // dataplane must not pre-create a group for a singleton.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let eads: Vec<ProjectedEvpnEadPerEvi> = Vec::new();
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_group_key.is_none());
        assert!(entry.alias_vtep_ips.is_empty());
    }

    #[test]
    fn mixed_family_aliases_dropped() {
        // IPv4 primary + one IPv4 alias + one IPv6 alias under the
        // same (ESI, EthernetTag) → ADR-0059 invariant drops the v6
        // alias. The v4 alias survives and `alias_group_key` is set.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(9))];
        let eads = vec![
            ead(esi_seed(9), 0, "10.0.0.3"),
            ead(esi_seed(9), 0, "2001:db8::1"),
        ];
        let table = project_evpn_routes_with_aliases(&one_local(100), routes, eads);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.alias_vtep_ips, vec![ipa("10.0.0.3")]);
        assert_eq!(
            entry.alias_group_key,
            Some((esi_seed(9), rustbgpd_wire::EthernetTagId(0))),
        );
    }

    #[test]
    fn project_evpn_routes_legacy_wrapper_yields_empty_aliases() {
        // Backwards-compat: the no-EAD wrapper must produce empty
        // alias lists even for non-zero-ESI routes.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(1))];
        let table = project_evpn_routes(&one_local(100), routes);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_vtep_ips.is_empty());
    }

    // ─── ADR-0083 slice 2: single-active backup-path projection ───

    use crate::aliasing::{EadPerEsMode, SingleActiveEligibleIndex};

    fn sa_index(
        es_rows: &[(u8, &str, bool)],
        evi_rows: &[(u8, u32, &str)],
    ) -> SingleActiveEligibleIndex {
        SingleActiveEligibleIndex::build(
            es_rows
                .iter()
                .map(|&(seed, vtep, single_active)| EadPerEsMode {
                    esi: esi_seed(seed),
                    vtep_ip: ipa(vtep),
                    single_active,
                }),
            evi_rows
                .iter()
                .map(|&(seed, tag, vtep)| crate::AliasEadPerEvi {
                    esi: esi_seed(seed),
                    ethernet_tag: rustbgpd_wire::EthernetTagId(tag),
                    vtep_ip: ipa(vtep),
                }),
        )
    }

    #[test]
    fn single_active_entry_carries_one_member_group_key_and_backup() {
        // Primary 10.0.0.2 + eligible backup 10.0.0.3 on a
        // single-active segment: the entry must carry the
        // `(ESI, EthernetTag)` group key with an EMPTY alias list
        // (one-member desired membership = the active PE) plus the
        // backup intent (ADR-0083 decision 1).
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let index = sa_index(
            &[(7, "10.0.0.2", true), (7, "10.0.0.3", true)],
            &[(7, 0, "10.0.0.2"), (7, 0, "10.0.0.3")],
        );
        // Single-active rows never feed the all-active aliasing feed.
        let table = project_evpn_routes_with_backup_paths(
            &one_local(100),
            routes,
            std::iter::empty(),
            &index,
        );
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.remote_vtep_ip, ipa("10.0.0.2"));
        assert!(
            entry.alias_vtep_ips.is_empty(),
            "single-active membership is one member: the active PE only"
        );
        assert_eq!(
            entry.alias_group_key,
            Some((esi_seed(7), rustbgpd_wire::EthernetTagId(0))),
        );
        assert_eq!(entry.single_active_backup_vtep_ip, Some(ipa("10.0.0.3")));
    }

    #[test]
    fn single_active_backup_is_lowest_non_primary_eligible() {
        let routes = vec![route_with_esi(100, 1, "10.0.0.4", None, esi_seed(7))];
        let index = sa_index(
            &[
                (7, "10.0.0.2", true),
                (7, "10.0.0.3", true),
                (7, "10.0.0.4", true),
            ],
            &[(7, 0, "10.0.0.2"), (7, 0, "10.0.0.3"), (7, 0, "10.0.0.4")],
        );
        let table = project_evpn_routes_with_backup_paths(
            &one_local(100),
            routes,
            std::iter::empty(),
            &index,
        );
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.single_active_backup_vtep_ip, Some(ipa("10.0.0.2")));
    }

    #[test]
    fn single_active_sole_pe_falls_back_to_plain_dst_row() {
        // ADR-0083 decision 1: "Single-active MACs on an ES with no
        // other eligible PE (a de-facto single-homed segment) keep
        // today's single-dst rows; the NHG indirection buys nothing
        // there." No group key, no backup.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let index = sa_index(&[(7, "10.0.0.2", true)], &[(7, 0, "10.0.0.2")]);
        let table = project_evpn_routes_with_backup_paths(
            &one_local(100),
            routes,
            std::iter::empty(),
            &index,
        );
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_group_key.is_none());
        assert!(entry.alias_vtep_ips.is_empty());
        assert!(entry.single_active_backup_vtep_ip.is_none());
    }

    #[test]
    fn single_active_gate_never_consumes_all_active_aliases() {
        // Pathological mixed-mode segment: the primary's pair folds
        // single-active while another PE advertises an all-active
        // EAD-per-EVI for the same key (which therefore appears in
        // the aliasing feed). The single-active bit on the primary's
        // pair is authoritative: no ECMP aliases, and the all-active
        // PE is not eligible as a backup either.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let index = sa_index(
            &[(7, "10.0.0.2", true), (7, "10.0.0.3", false)],
            &[(7, 0, "10.0.0.2"), (7, 0, "10.0.0.3")],
        );
        let eads = vec![ead(esi_seed(7), 0, "10.0.0.3")];
        let table = project_evpn_routes_with_backup_paths(&one_local(100), routes, eads, &index);
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_vtep_ips.is_empty());
        assert!(entry.alias_group_key.is_none());
        assert!(entry.single_active_backup_vtep_ip.is_none());
    }

    #[test]
    fn all_active_entries_unchanged_by_backup_path_projection() {
        // All-active behavior must be bit-identical: the same inputs
        // through the aliasing wrapper and through the backup-path
        // function (with the segment's pairs folding all-active)
        // produce identical tables, with no backup intent.
        let routes = vec![route_with_esi(100, 1, "10.0.0.2", None, esi_seed(7))];
        let eads = vec![
            ead(esi_seed(7), 0, "10.0.0.3"),
            ead(esi_seed(7), 0, "10.0.0.4"),
        ];
        let index = sa_index(
            &[(7, "10.0.0.2", false), (7, "10.0.0.3", false)],
            &[(7, 0, "10.0.0.2"), (7, 0, "10.0.0.3")],
        );
        let via_wrapper =
            project_evpn_routes_with_aliases(&one_local(100), routes.clone(), eads.clone());
        let via_backup_paths =
            project_evpn_routes_with_backup_paths(&one_local(100), routes, eads, &index);
        assert_eq!(via_wrapper, via_backup_paths);
        let entry = via_backup_paths.get(vni(100), mac(1)).unwrap();
        assert!(entry.single_active_backup_vtep_ip.is_none());
        assert_eq!(entry.alias_vtep_ips.len(), 2);
    }

    #[test]
    fn zero_esi_routes_ignore_single_active_index() {
        // ESI == ZERO routes are single-homed regardless of what the
        // index contains for unrelated keys.
        let routes = vec![route(100, 1, "10.0.0.2", None)];
        let index = sa_index(
            &[(7, "10.0.0.2", true), (7, "10.0.0.3", true)],
            &[(7, 0, "10.0.0.2"), (7, 0, "10.0.0.3")],
        );
        let table = project_evpn_routes_with_backup_paths(
            &one_local(100),
            routes,
            std::iter::empty(),
            &index,
        );
        let entry = table.get(vni(100), mac(1)).unwrap();
        assert!(entry.alias_group_key.is_none());
        assert!(entry.single_active_backup_vtep_ip.is_none());
    }

    #[test]
    fn projection_is_deterministic_under_input_reordering() {
        let routes_a = vec![
            route(100, 1, "10.0.0.2", Some(2)),
            route(100, 1, "10.0.0.3", Some(2)),
            route(100, 2, "10.0.0.5", None),
        ];
        let routes_b = vec![
            route(100, 2, "10.0.0.5", None),
            route(100, 1, "10.0.0.3", Some(2)),
            route(100, 1, "10.0.0.2", Some(2)),
        ];
        let a = project_evpn_routes(&one_local(100), routes_a);
        let b = project_evpn_routes(&one_local(100), routes_b);
        assert_eq!(a, b);
    }
}
