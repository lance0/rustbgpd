//! EVPN aliasing resolver for Gate 8b multi-homing (RFC 7432 §14).
//!
//! When a peer announces a Type 2 MAC/IP route with a non-zero
//! Ethernet Segment Identifier, the multi-homed CE the route names
//! is reachable via *all* PEs that announce a Type 1 EAD-per-EVI
//! route for the same `(ESI, Ethernet Tag)`. The receiver should
//! treat those PE next-hops as alternative paths for the MAC, both
//! for ECMP load balancing and for fast failover when the primary
//! path goes away.
//!
//! ## What this module does
//!
//! Pure-logic indexing and portable-intent shaping for aliasing:
//!
//! - Given a stream of `(ESI, EthTag, PE_IP)` tuples extracted
//!   from the receiver's RIB best-path EAD-per-EVI routes, build
//!   an [`AliasIndex`] that answers `vtep_ips_for(esi, eth_tag)`
//!   in O(log n). Self-originated routes are filtered at the
//!   caller (the resolver doesn't know which PE *we* are).
//! - [`alias_resolved_next_hops`] combines a Type 2 route's
//!   primary next-hop with the index's aliasing alternatives,
//!   primary-first and deduped. The projection layer
//!   ([`crate::projection::project_evpn_routes_with_aliases`])
//!   consumes this to populate
//!   [`crate::mac::RemoteMacEntry::alias_vtep_ips`] and
//!   [`crate::mac::RemoteMacEntry::alias_group_key`].
//! - [`group_members`] returns the canonical FDB nexthop group
//!   membership for an entry (`remote_vtep_ip` ∪
//!   `alias_vtep_ips`, sorted + deduped). This is the portable
//!   intent the Linux dataplane will consume in ADR-0059 slice
//!   3+ when it programs FDB nexthop groups via
//!   `RTM_NEWNEXTHOP` + `NHA_FDB`.
//!
//! ## What this module does NOT do
//!
//! - Touch the kernel. FDB nexthop group programming
//!   (`RTM_NEWNEXTHOP` with `NHA_FDB`, `NDA_NH_ID` on the FDB
//!   row) is owned by `crates/evpn-linux` and lives behind
//!   ADR-0059 slices 2-4. Today's `LinuxDataplane` still
//!   programs one `dst` per MAC; the [`group_members`] surface
//!   is the bridge to the future FDB-NHG installer.
//! - Decide best-path among aliased PEs. RFC 7432 §14 describes
//!   the receiver's responsibilities (treat them as ECMP); choice
//!   of policy (round-robin, hash-based, weighted) is a
//!   forwarding-layer decision separate from this control-plane
//!   resolution.
//! - Tie aliasing to DF role. The Non-DF / DF distinction governs
//!   BUM forwarding (Gate 8b BUM-suppression primitive) but does
//!   *not* gate aliasing for known-unicast — both DF and Non-DF
//!   PEs that have a local interface on the segment are valid
//!   aliasing alternatives for known-unicast traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_wire::{EthernetSegmentIdentifier, EthernetTagId};

use crate::mac::RemoteMacEntry;

/// One EAD-per-EVI advertisement, trimmed to the fields the resolver
/// needs. Built by the daemon at the boundary between the RIB's
/// `EvpnRoute::EadPerEvi` and the resolver here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasEadPerEvi {
    /// Ethernet Segment Identifier the EAD-per-EVI route names.
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag identifying the EVI. Always paired with `esi`
    /// because RFC 7432 §14 aliasing is `(ESI, EthTag)`-keyed.
    pub ethernet_tag: EthernetTagId,
    /// Next-hop / VTEP IP advertised on the EAD-per-EVI route. The
    /// resolver dedupes by IP before returning, so the caller
    /// doesn't need to pre-trim duplicate entries.
    pub vtep_ip: IpAddr,
}

/// Built index of `(ESI, EthTag) -> [VTEP IP]` for fast lookup.
///
/// Construction is O(n log n) on the input length; lookups are
/// O(log m) where m is the number of distinct `(ESI, EthTag)`
/// pairs. The index is read-only after `build`; rebuild on every
/// projection pass to stay aligned with the RIB best-path snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AliasIndex {
    by_key: BTreeMap<(EthernetSegmentIdentifier, EthernetTagId), Vec<IpAddr>>,
}

impl AliasIndex {
    /// Empty index. Lookup returns `None` for every key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a stream of EAD-per-EVI advertisements. Single-
    /// homed entries (`ESI == ZERO`) are filtered out — they'd
    /// never resolve aliasing alternatives even if the caller
    /// somehow surfaced them. Duplicate `(ESI, EthTag, VTEP IP)`
    /// triples are deduped to keep the result list minimal.
    #[must_use]
    pub fn build<I>(rows: I) -> Self
    where
        I: IntoIterator<Item = AliasEadPerEvi>,
    {
        let mut staged: BTreeMap<
            (EthernetSegmentIdentifier, EthernetTagId),
            std::collections::BTreeSet<IpAddr>,
        > = BTreeMap::new();

        for row in rows {
            if row.esi == EthernetSegmentIdentifier::ZERO {
                continue;
            }
            staged
                .entry((row.esi, row.ethernet_tag))
                .or_default()
                .insert(row.vtep_ip);
        }

        let by_key = staged
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        Self { by_key }
    }

    /// VTEP IPs that advertise an EAD-per-EVI for `(esi, eth_tag)`.
    /// Returns `None` if there are no aliasing alternatives — the
    /// caller treats that as "use the Type 2's own next-hop only."
    #[must_use]
    pub fn vtep_ips_for(
        &self,
        esi: EthernetSegmentIdentifier,
        eth_tag: EthernetTagId,
    ) -> Option<&[IpAddr]> {
        self.by_key.get(&(esi, eth_tag)).map(Vec::as_slice)
    }

    /// Number of `(ESI, EthTag)` pairs with at least one
    /// aliasing alternative.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// `true` if the index has no aliasing alternatives.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Convenience: combine an Type 2 route's primary next-hop with any
/// aliasing alternatives from the index, deduped. The primary always
/// appears first so callers that don't yet support ECMP get the
/// existing behavior; downstream wiring can take all entries when
/// ready.
#[must_use]
pub fn alias_resolved_next_hops(
    primary_next_hop: IpAddr,
    esi: EthernetSegmentIdentifier,
    eth_tag: EthernetTagId,
    index: &AliasIndex,
) -> Vec<IpAddr> {
    let mut out = vec![primary_next_hop];
    if esi == EthernetSegmentIdentifier::ZERO {
        return out;
    }
    if let Some(aliases) = index.vtep_ips_for(esi, eth_tag) {
        for &ip in aliases {
            if ip != primary_next_hop && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Canonical FDB nexthop group membership for `entry`: the union of
/// `remote_vtep_ip` and `alias_vtep_ips`, sorted by `IpAddr` natural
/// order and deduplicated. This is the set the dataplane keys an
/// FDB nexthop group on (ADR-0059 slice 2+ wiring).
///
/// Returns a single-element `Vec` for single-homed entries (the
/// primary VTEP only). For multi-homed entries the order is stable
/// regardless of how `alias_vtep_ips` was populated — `BTreeSet`
/// gives sort + dedup in one pass so two entries with the same
/// member set always produce the same canonical group, which is
/// what the dataplane needs to spot "membership unchanged" without
/// re-emitting a `NLM_F_REPLACE`.
///
/// Dedup is defensive: the projection layer (`projection.rs`)
/// already prevents the primary from appearing in `alias_vtep_ips`,
/// but future operator-static entries or hand-rolled tests could
/// trip the kernel if duplicates leaked through.
#[must_use]
pub fn group_members(entry: &RemoteMacEntry) -> Vec<IpAddr> {
    let mut set: BTreeSet<IpAddr> = BTreeSet::new();
    set.insert(entry.remote_vtep_ip);
    for ip in &entry.alias_vtep_ips {
        set.insert(*ip);
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_index_resolves_nothing() {
        let idx = AliasIndex::new();
        assert!(idx.is_empty());
        assert!(idx.vtep_ips_for(esi(1), EthernetTagId(0)).is_none());
    }

    #[test]
    fn build_filters_zero_esi() {
        let idx = AliasIndex::build([
            AliasEadPerEvi {
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.1"),
            },
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.2"),
            },
        ]);
        assert_eq!(idx.len(), 1);
        assert_eq!(
            idx.vtep_ips_for(esi(1), EthernetTagId(0)).unwrap().to_vec(),
            vec![ip("10.0.0.2")],
        );
    }

    #[test]
    fn build_dedups_identical_triples() {
        let idx = AliasIndex::build([
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.2"),
            },
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.2"),
            },
        ]);
        assert_eq!(
            idx.vtep_ips_for(esi(1), EthernetTagId(0)).unwrap().to_vec(),
            vec![ip("10.0.0.2")],
        );
    }

    #[test]
    fn build_groups_distinct_pes_under_same_key() {
        let idx = AliasIndex::build([
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(100),
                vtep_ip: ip("10.0.0.2"),
            },
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(100),
                vtep_ip: ip("10.0.0.3"),
            },
        ]);
        let ips = idx
            .vtep_ips_for(esi(1), EthernetTagId(100))
            .unwrap()
            .to_vec();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&ip("10.0.0.2")));
        assert!(ips.contains(&ip("10.0.0.3")));
    }

    #[test]
    fn build_keeps_eth_tags_separate() {
        let idx = AliasIndex::build([
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(100),
                vtep_ip: ip("10.0.0.2"),
            },
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(200),
                vtep_ip: ip("10.0.0.3"),
            },
        ]);
        assert_eq!(
            idx.vtep_ips_for(esi(1), EthernetTagId(100))
                .unwrap()
                .to_vec(),
            vec![ip("10.0.0.2")],
        );
        assert_eq!(
            idx.vtep_ips_for(esi(1), EthernetTagId(200))
                .unwrap()
                .to_vec(),
            vec![ip("10.0.0.3")],
        );
    }

    #[test]
    fn resolved_next_hops_zero_esi_returns_primary_only() {
        let idx = AliasIndex::build([AliasEadPerEvi {
            esi: esi(1),
            ethernet_tag: EthernetTagId(0),
            vtep_ip: ip("10.0.0.5"),
        }]);
        let nhs = alias_resolved_next_hops(
            ip("10.0.0.1"),
            EthernetSegmentIdentifier::ZERO,
            EthernetTagId(0),
            &idx,
        );
        assert_eq!(nhs, vec![ip("10.0.0.1")]);
    }

    #[test]
    fn resolved_next_hops_appends_unique_alias_ips() {
        let idx = AliasIndex::build([
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.2"),
            },
            AliasEadPerEvi {
                esi: esi(1),
                ethernet_tag: EthernetTagId(0),
                vtep_ip: ip("10.0.0.3"),
            },
        ]);
        let nhs = alias_resolved_next_hops(ip("10.0.0.2"), esi(1), EthernetTagId(0), &idx);
        // Primary first, then aliases minus the primary.
        assert_eq!(nhs[0], ip("10.0.0.2"));
        assert_eq!(nhs.len(), 2);
        assert!(nhs.contains(&ip("10.0.0.3")));
    }

    #[test]
    fn resolved_next_hops_dedupes_primary_against_alias() {
        // Primary is also in the alias list; result must dedupe.
        let idx = AliasIndex::build([AliasEadPerEvi {
            esi: esi(1),
            ethernet_tag: EthernetTagId(0),
            vtep_ip: ip("10.0.0.2"),
        }]);
        let nhs = alias_resolved_next_hops(ip("10.0.0.2"), esi(1), EthernetTagId(0), &idx);
        assert_eq!(nhs, vec![ip("10.0.0.2")]);
    }

    #[test]
    fn resolved_next_hops_no_aliases_returns_primary_only() {
        let idx = AliasIndex::new();
        let nhs = alias_resolved_next_hops(ip("10.0.0.2"), esi(1), EthernetTagId(0), &idx);
        assert_eq!(nhs, vec![ip("10.0.0.2")]);
    }

    fn entry_with_aliases(primary: &str, aliases: &[&str]) -> RemoteMacEntry {
        RemoteMacEntry {
            remote_vtep_ip: ip(primary),
            mobility_sequence: None,
            alias_vtep_ips: aliases.iter().map(|s| ip(s)).collect(),
            alias_group_key: None,
            source: crate::mac::RemoteMacSource::EvpnRibBestPath,
        }
    }

    #[test]
    fn group_members_returns_primary_only_when_no_aliases() {
        let entry = entry_with_aliases("10.0.0.2", &[]);
        assert_eq!(group_members(&entry), vec![ip("10.0.0.2")]);
    }

    #[test]
    fn group_members_combines_primary_and_aliases_sorted() {
        // Insert in non-sorted order; output must be IpAddr-sorted.
        let entry = entry_with_aliases("10.0.0.5", &["10.0.0.3", "10.0.0.7"]);
        assert_eq!(
            group_members(&entry),
            vec![ip("10.0.0.3"), ip("10.0.0.5"), ip("10.0.0.7")],
        );
    }

    #[test]
    fn group_members_dedupes_primary_in_alias_list() {
        // Defensive: if the primary leaks into alias_vtep_ips (shouldn't
        // happen via projection, but could via operator-static or
        // hand-rolled construction), group_members must still emit a
        // single canonical membership set.
        let entry = entry_with_aliases("10.0.0.2", &["10.0.0.2", "10.0.0.3"]);
        assert_eq!(group_members(&entry), vec![ip("10.0.0.2"), ip("10.0.0.3")],);
    }
}
