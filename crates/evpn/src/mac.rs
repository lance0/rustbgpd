//! Remote-MAC table and local-MAC observation types — Gate 7b dataplane domain.
//!
//! ADR-0054 §2 requires the dataplane crate to consume *portable domain
//! objects* describing remote-MAC intent, not raw `rustbgpd_wire::EvpnRoute`
//! values. This module is that domain surface.
//!
//! [`RemoteMacTable`] is the **complete** desired set of remote MACs the
//! dataplane should program for this VTEP. The dataplane crate computes
//! create/update/delete by diffing the table against its kernel snapshot
//! and previously-applied state — there is no delta stream.
//!
//! [`LocalMacObservation`] flows the other direction: the Linux dataplane
//! emits learn/age events for MACs it sees on bridge ports, and the
//! domain layer decides whether they cause Type 2 origination, withdrawal,
//! or hold-down. Gate 7b only carries the observation type; consumption
//! is a follow-up.
//!
//! ## Mobility key choice
//!
//! Keys are `(EvpnInstanceId, MacAddress)`. RFC 7432 §15 distinguishes
//! MAC moves *within* an EVI by mobility-sequence comparison; the table
//! keeps a single best-path entry per `(VNI, MAC)`. VLAN-aware bundle
//! support (where keys widen to `(VNI, VLAN, MAC)`) is deferred until
//! the `EvpnInstance` schema gains a `vlan` field — see ADR-0054 §4.
//!
//! ## Why a builder
//!
//! [`RemoteMacTableBuilder`] returns `Err(DuplicateMac)` on collision
//! rather than silently overwriting. The daemon-side projection from
//! RIB best-paths is the only caller; surfacing collisions as a typed
//! error forces the projection to resolve mobility races deterministically
//! before the dataplane sees inconsistent intent.
//!
//! ## Reference
//!
//! - ADR-0054 §2 (Dataplane input is a coalescing snapshot channel)
//! - ADR-0054 §5 (Local MACs observed; remote MACs programmed)
//! - RFC 7432 §15 (MAC mobility procedures)

use std::collections::BTreeMap;
use std::net::IpAddr;

pub use rustbgpd_wire::MacAddress;

use crate::EvpnInstanceId;

/// How a remote-MAC entry came to be in the table.
///
/// Carrying the source on every entry lets future filters (e.g., refuse
/// to program operator-static remotes until learned remotes drain) be
/// added without a schema change. Gate 7b populates only [`Self::EvpnRibBestPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteMacSource {
    /// Selected by the RIB as the best-path EVPN Type 2 route.
    EvpnRibBestPath,
    /// Operator-supplied static remote MAC (reserved; no producer in Gate 7b).
    OperatorStatic,
}

/// One remote-MAC desired-state entry.
///
/// `mobility_sequence` echoes RFC 7432 §15's MAC Mobility extended
/// community when present on the originating route; the dataplane
/// records it on apply so a later snapshot whose sequence is *lower*
/// can be detected as a stale race and corrected against the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoteMacEntry {
    /// Remote VTEP IP — the destination of the VXLAN-encapped frames
    /// the kernel will forward to.
    pub remote_vtep_ip: IpAddr,
    /// MAC mobility sequence number (RFC 7432 §15) if the originating
    /// route carried a `MAC Mobility` extended community.
    pub mobility_sequence: Option<u32>,
    /// Aliasing alternative VTEP IPs for this MAC (RFC 7432 §14).
    /// Populated by the projection layer when the originating Type 2
    /// route carries a non-zero ESI and other peers have advertised
    /// EAD-per-EVI routes for the same `(ESI, EthernetTag)` — those
    /// peers' next-hops appear here so the dataplane can ECMP / fail
    /// over without waiting for the primary's `MP_UNREACH_NLRI`.
    /// Empty for single-homed routes (ESI == ZERO) and for
    /// multi-homed routes with no aliasing alternatives observed.
    /// `remote_vtep_ip` is **never** included here — the primary
    /// stays in the dedicated field and `alias_vtep_ips` carries
    /// only the *additional* VTEPs.
    pub alias_vtep_ips: Vec<IpAddr>,
    /// How this entry came to be desired.
    pub source: RemoteMacSource,
}

/// Complete desired-state table of remote MACs for this VTEP.
///
/// Snapshot semantics: the dataplane treats the table as authoritative
/// and reconciles the kernel toward it. There is no notion of "this
/// entry is new" or "this entry is being withdrawn" — that's the
/// dataplane's diff output, not table state.
///
/// `BTreeMap` is deliberate: ordered iteration produces deterministic
/// diff output and makes property tests reproducible. The cost of the
/// `BTreeMap` over a `HashMap` is negligible at expected operator scale.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteMacTable {
    entries: BTreeMap<(EvpnInstanceId, MacAddress), RemoteMacEntry>,
}

impl RemoteMacTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a fresh builder.
    #[must_use]
    pub fn builder() -> RemoteMacTableBuilder {
        RemoteMacTableBuilder::default()
    }

    /// Number of `(VNI, MAC)` entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no remote MACs are programmed for any instance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a single entry.
    #[must_use]
    pub fn get(&self, vni: EvpnInstanceId, mac: MacAddress) -> Option<&RemoteMacEntry> {
        self.entries.get(&(vni, mac))
    }

    /// Iterate entries in deterministic `(VNI, MAC)` ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (&(EvpnInstanceId, MacAddress), &RemoteMacEntry)> {
        self.entries.iter()
    }

    /// Iterate entries scoped to one EVPN instance.
    pub fn iter_instance(
        &self,
        vni: EvpnInstanceId,
    ) -> impl Iterator<Item = (MacAddress, &RemoteMacEntry)> {
        self.entries
            .iter()
            .filter_map(move |(&(v, m), e)| (v == vni).then_some((m, e)))
    }
}

/// Building block for [`RemoteMacTable`]. Rejects duplicate `(VNI, MAC)`
/// at insert time so the projection caller surfaces mobility races
/// rather than silently dropping one of two competing best paths.
#[derive(Debug, Default)]
pub struct RemoteMacTableBuilder {
    entries: BTreeMap<(EvpnInstanceId, MacAddress), RemoteMacEntry>,
}

impl RemoteMacTableBuilder {
    /// Insert a new `(VNI, MAC)` → entry mapping.
    ///
    /// # Errors
    /// Returns [`RemoteMacTableBuilderError::DuplicateMac`] when the
    /// `(VNI, MAC)` pair is already present.
    pub fn insert(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        entry: RemoteMacEntry,
    ) -> Result<(), RemoteMacTableBuilderError> {
        if self.entries.contains_key(&(vni, mac)) {
            return Err(RemoteMacTableBuilderError::DuplicateMac { vni, mac });
        }
        self.entries.insert((vni, mac), entry);
        Ok(())
    }

    /// Finalize and consume the builder.
    #[must_use]
    pub fn build(self) -> RemoteMacTable {
        RemoteMacTable {
            entries: self.entries,
        }
    }
}

/// Errors produced by [`RemoteMacTableBuilder::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RemoteMacTableBuilderError {
    /// Two routes resolved to the same `(VNI, MAC)` during a single
    /// projection pass — the projection must pick a winner before
    /// handing the table to the dataplane.
    #[error("duplicate remote MAC {mac} in VNI {vni}")]
    DuplicateMac {
        /// VNI the collision occurred in.
        vni: EvpnInstanceId,
        /// Conflicting MAC.
        mac: MacAddress,
    },
}

/// Upward-flowing event from the Linux dataplane describing local
/// kernel state changes that may turn into Type 2 originations.
///
/// Two flavors share the channel because they originate from the
/// same `RTNLGRP_NEIGH` subscription, just on different families:
///
/// - **MAC observations** (`Learned` / `Aged`) come from `AF_BRIDGE`
///   FDB notifications — kernel learning a MAC on a non-VXLAN bridge
///   port. These drive **MAC-only** Type 2 origination per Gate
///   7b+1.
/// - **IP observations** (`IpAdded` / `IpRemoved`) come from
///   `AF_INET` / `AF_INET6` neighbour notifications on the bridge
///   ifindex itself — kernel observing an `(IP, MAC)` binding via
///   ARP / ND. These pair with a known MAC to produce **MAC+IP**
///   Type 2 origination per Gate 7b+2 (RFC 7432 §7.2; RFC 9135 §4.4
///   permits MAC-only and MAC+IP routes for the same MAC to coexist).
///
/// The classifier in `crates/evpn-linux::linux::notify` is the single
/// place that maps raw `RTM_NEWNEIGH` / `RTM_DELNEIGH` messages to
/// these typed variants; the daemon-side originator decides what to
/// do with each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMacObservation {
    /// Kernel learned a new local MAC on a bridge port belonging to
    /// the named EVPN instance.
    Learned {
        /// VNI of the learning instance.
        vni: EvpnInstanceId,
        /// Newly-learned MAC.
        mac: MacAddress,
        /// Bridge-port ifindex the kernel saw the MAC on.
        ifindex: u32,
    },
    /// Previously-observed local MAC aged out or was deleted by the
    /// operator.
    Aged {
        /// VNI of the instance the MAC was last observed in.
        vni: EvpnInstanceId,
        /// MAC that disappeared.
        mac: MacAddress,
    },
    /// Kernel learned an `(IP, MAC)` binding for a host on this
    /// bridge — the result of ARP (IPv4) or ND (IPv6) snooping when
    /// the bridge has `neigh_suppress on`. Pairs with a `Learned`
    /// MAC observation to drive a MAC+IP Type 2 origination.
    IpAdded {
        /// VNI of the bridge whose neighbour table the binding
        /// appeared in.
        vni: EvpnInstanceId,
        /// MAC half of the binding.
        mac: MacAddress,
        /// IP half of the binding (IPv4 or IPv6).
        ip: IpAddr,
    },
    /// Previously-observed `(IP, MAC)` binding aged out or was
    /// deleted. Triggers withdrawal of the MAC+IP Type 2 origination
    /// while leaving the MAC-only origination (if any) intact —
    /// per RFC 9135 §4.4 they're independent advertisements.
    IpRemoved {
        /// VNI of the bridge whose neighbour table the binding was
        /// in.
        vni: EvpnInstanceId,
        /// MAC half of the binding that disappeared.
        mac: MacAddress,
        /// IP half of the binding that disappeared.
        ip: IpAddr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).expect("test VNI")
    }

    fn mac(byte: u8) -> MacAddress {
        MacAddress::new([byte, byte, byte, byte, byte, byte])
    }

    fn entry(remote: &str) -> RemoteMacEntry {
        RemoteMacEntry {
            remote_vtep_ip: remote.parse().unwrap(),
            mobility_sequence: None,
            alias_vtep_ips: Vec::new(),
            source: RemoteMacSource::EvpnRibBestPath,
        }
    }

    #[test]
    fn builder_rejects_duplicate_vni_mac() {
        let mut b = RemoteMacTable::builder();
        b.insert(vni(100), mac(1), entry("10.0.0.2")).unwrap();
        let err = b.insert(vni(100), mac(1), entry("10.0.0.3")).unwrap_err();
        assert_eq!(
            err,
            RemoteMacTableBuilderError::DuplicateMac {
                vni: vni(100),
                mac: mac(1),
            }
        );
    }

    #[test]
    fn builder_accepts_same_mac_in_different_vnis() {
        let mut b = RemoteMacTable::builder();
        b.insert(vni(100), mac(1), entry("10.0.0.2")).unwrap();
        b.insert(vni(200), mac(1), entry("10.0.0.3")).unwrap();
        assert_eq!(b.build().len(), 2);
    }

    #[test]
    fn iteration_is_deterministic_vni_ascending() {
        let mut b = RemoteMacTable::builder();
        b.insert(vni(300), mac(3), entry("10.0.0.4")).unwrap();
        b.insert(vni(100), mac(1), entry("10.0.0.2")).unwrap();
        b.insert(vni(200), mac(2), entry("10.0.0.3")).unwrap();
        let table = b.build();
        let order: Vec<u32> = table.iter().map(|((v, _), _)| v.as_u32()).collect();
        assert_eq!(order, vec![100, 200, 300]);
    }

    #[test]
    fn iter_instance_filters_to_one_vni() {
        let mut b = RemoteMacTable::builder();
        b.insert(vni(100), mac(1), entry("10.0.0.2")).unwrap();
        b.insert(vni(100), mac(2), entry("10.0.0.3")).unwrap();
        b.insert(vni(200), mac(1), entry("10.0.0.4")).unwrap();
        let table = b.build();
        let macs: Vec<u8> = table
            .iter_instance(vni(100))
            .map(|(m, _)| m.octets()[0])
            .collect();
        assert_eq!(macs, vec![1, 2]);
    }

    #[test]
    fn get_returns_inserted_entry() {
        let mut b = RemoteMacTable::builder();
        b.insert(vni(100), mac(1), entry("10.0.0.2")).unwrap();
        let table = b.build();
        let got = table.get(vni(100), mac(1)).unwrap();
        assert_eq!(got.remote_vtep_ip.to_string(), "10.0.0.2");
        assert!(table.get(vni(100), mac(2)).is_none());
    }

    #[test]
    fn empty_table_predicates() {
        let table = RemoteMacTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn local_mac_observation_variants_carry_expected_fields() {
        let learned = LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(7),
            ifindex: 42,
        };
        let aged = LocalMacObservation::Aged {
            vni: vni(100),
            mac: mac(7),
        };
        assert_ne!(learned, aged);
    }
}
