//! Ethernet Segment domain types — Gate 8 multihoming foundation.
//!
//! An Ethernet Segment (ES, RFC 7432 §5) is a set of Ethernet links
//! shared by a CE that is multihomed to two or more PEs. The set is
//! identified by a 10-byte Ethernet Segment Identifier (ESI). All PEs
//! reachable on the same ES advertise the same ESI; downstream EVPN
//! state — Type 1 EAD-per-ES, Type 1 EAD-per-EVI, Type 4 ES route,
//! and the per-`(ESI, VNI)` Designated Forwarder (DF) election —
//! keys off it.
//!
//! This module is the **declarative** ESI surface: what an operator
//! tells the daemon about the local PE's ES participation. The
//! origination state machines (slice 2) produce wire-shaped Type 1/4
//! routes from this; the daemon-side orchestrator (slice 3) gathers
//! peer ES routes from the RIB and runs the [`crate::df_election`]
//! state machine to compute per-`(ESI, VNI)` roles.
//!
//! ## Scope (Gate 8 — observable, not enforcing)
//!
//! The DF role this gate computes is **observable only** — surfaced
//! via Prometheus, gRPC, and CLI. No FDB suppression, no
//! split-horizon enforcement, no aliasing-driven backup paths.
//! Forwarding-blocking enforcement is Gate 8b. Decoupling lets us
//! lock election correctness against RFC 7432 §8.5 + RFC 8584 §3
//! cases without touching FDB semantics. See ADR-0057.
//!
//! ## Reference
//!
//! - RFC 7432 §5 — ESI shape and types 0–5
//! - RFC 7432 §7.1 — Type 1 EAD-per-ES + per-EVI NLRI
//! - RFC 7432 §7.4 — Type 4 ES route NLRI
//! - RFC 7432 §8.5 — Default DF election (service carving)
//! - RFC 8584 §3 — DF election extensions, algorithm negotiation

use std::collections::BTreeSet;
use std::net::IpAddr;

use rustbgpd_wire::EthernetSegmentIdentifier;

use crate::EvpnInstanceId;

/// One operator-configured Ethernet Segment on this PE.
///
/// Identifies a set of CE-facing links that this PE shares with one
/// or more other PEs. The ESI is a 10-byte value the operator
/// supplies literally — auto-derivation from LACP / STP is a
/// config-time helper deferred past Gate 8 (the wire format already
/// supports types 1 / 2; the daemon just doesn't fill them in
/// automatically yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetSegment {
    /// 10-byte ESI per RFC 7432 §5.
    pub esi: EthernetSegmentIdentifier,
    /// VNIs this ES is a member of. Each member VNI emits its own
    /// Type 1 EAD-per-EVI route and runs its own slot in the per-ESI
    /// service-carving DF election.
    pub member_vnis: BTreeSet<EvpnInstanceId>,
    /// DF preference value carried in the DF Election extended
    /// community (RFC 8584 §3.1). Higher wins. Default value is
    /// derived per the implementation's policy (see daemon config
    /// layer); the domain type just carries whatever the operator /
    /// daemon chose.
    pub df_preference: u32,
    /// DF election algorithm this PE proposes for this ES per
    /// RFC 8584 §3. The election state machine handles
    /// algorithm-mismatch tiebreak.
    pub df_algorithm: DfAlgorithm,
    /// Multi-homing redundancy mode signaled in the ESI Label
    /// extended community on the Type 1 EAD-per-ES route.
    pub redundancy_mode: RedundancyMode,
    /// IP this PE will use as the originator address in the Type 4
    /// ES route. Typically equals the EVPN instance's local VTEP IP,
    /// but kept separable so a future multi-loopback design (e.g.,
    /// per-fabric-VRF originator IPs) doesn't have to refactor.
    pub originator_ip: IpAddr,
}

/// Ethernet Segment redundancy mode (RFC 7432 §14.1).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RedundancyMode {
    /// All PEs attached to the ES may forward known unicast to/from
    /// the CE for the VLAN. This is rustbgpd's historical default.
    #[default]
    AllActive,
    /// Only the active PE forwards traffic to/from the ES for the
    /// VLAN. Remote PEs must not use all-active aliasing ECMP for
    /// this ES.
    SingleActive,
}

impl RedundancyMode {
    /// `true` when the ESI Label extended community's Single-Active
    /// flag must be set.
    #[must_use]
    pub const fn is_single_active(self) -> bool {
        matches!(self, Self::SingleActive)
    }

    /// Operator-facing config string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllActive => "all-active",
            Self::SingleActive => "single-active",
        }
    }
}

/// DF election algorithm (RFC 7432 §8.5, RFC 8584 §3, RFC 9785 §4.1).
///
/// Per RFC 8584 / RFC 9785 negotiation, all candidates must
/// advertise the same algorithm or the election falls back to
/// `DefaultModulo` service carving.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DfAlgorithm {
    /// RFC 7432 §8.5 — service carving. Sort candidate PEs by
    /// originator IP ascending; the candidate at index
    /// `vni mod candidate_count` is the DF for that VNI. Algorithm
    /// ID 0 in the DF Election extcomm.
    #[default]
    DefaultModulo,
    /// RFC 8584 §3 — Highest Random Weight. Algorithm ID 1.
    HighestRandomWeight,
    /// RFC 9785 — Highest-Preference. Algorithm ID 2.
    HighestPreference,
    /// RFC 9785 — Lowest-Preference. Algorithm ID 3.
    LowestPreference,
}

impl DfAlgorithm {
    /// Wire-side algorithm ID per RFC 8584 §3.1's DF Election extcomm,
    /// used by the Type 4 origination/decode path. Negotiation is
    /// unanimous-or-`DefaultModulo` (see
    /// [`crate::df_election`]); the ID is not a mismatch tiebreak.
    #[must_use]
    pub const fn algorithm_id(self) -> u8 {
        match self {
            Self::DefaultModulo => 0,
            Self::HighestRandomWeight => 1,
            Self::HighestPreference => 2,
            Self::LowestPreference => 3,
        }
    }

    /// Decode an algorithm ID byte from the wire. Unknown IDs map to
    /// [`Self::DefaultModulo`] under RFC 8584's "fall back to default"
    /// rule when peers can't agree on a non-default algorithm.
    #[must_use]
    pub const fn from_algorithm_id(id: u8) -> Self {
        match id {
            1 => Self::HighestRandomWeight,
            2 => Self::HighestPreference,
            3 => Self::LowestPreference,
            _ => Self::DefaultModulo,
        }
    }
}

/// The role this PE plays for one `(ESI, VNI)` pair after running
/// DF election. `Df` means "I forward BUM traffic for this VNI on
/// this ES"; `NonDf` means "another PE handles BUM, I'm a backup."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DfRole {
    /// This PE is the Designated Forwarder.
    Df,
    /// Another PE is the Designated Forwarder.
    NonDf,
}

impl DfRole {
    /// `true` if this PE is the DF.
    #[must_use]
    pub const fn is_df(self) -> bool {
        matches!(self, Self::Df)
    }

    /// Lowercase string for telemetry / CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Df => "df",
            Self::NonDf => "nondf",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id_roundtrips() {
        for alg in [
            DfAlgorithm::DefaultModulo,
            DfAlgorithm::HighestRandomWeight,
            DfAlgorithm::HighestPreference,
            DfAlgorithm::LowestPreference,
        ] {
            assert_eq!(DfAlgorithm::from_algorithm_id(alg.algorithm_id()), alg);
        }
    }

    #[test]
    fn unknown_algorithm_id_falls_back_to_default() {
        // RFC 8584 §3 — peers that can't agree on a non-default
        // algorithm fall back to default-modulo. Unknown IDs (255,
        // 99, etc.) decode to DefaultModulo so the local PE doesn't
        // crash on a future RFC's algorithm.
        for id in [4u8, 99, 200, 255] {
            assert_eq!(
                DfAlgorithm::from_algorithm_id(id),
                DfAlgorithm::DefaultModulo
            );
        }
    }

    #[test]
    fn df_role_is_df_predicate() {
        assert!(DfRole::Df.is_df());
        assert!(!DfRole::NonDf.is_df());
    }

    #[test]
    fn df_role_as_str_matches_telemetry_convention() {
        assert_eq!(DfRole::Df.as_str(), "df");
        assert_eq!(DfRole::NonDf.as_str(), "nondf");
    }

    #[test]
    fn algorithm_default_is_modulo() {
        assert_eq!(DfAlgorithm::default(), DfAlgorithm::DefaultModulo);
    }

    #[test]
    fn algorithm_ord_matches_id_ord() {
        // Ord on the enum follows declaration order, which matches
        // algorithm_id ordering. Pin that invariant so future
        // algorithm additions don't accidentally reorder telemetry or
        // debug output.
        let mut algs = vec![
            DfAlgorithm::LowestPreference,
            DfAlgorithm::DefaultModulo,
            DfAlgorithm::HighestPreference,
            DfAlgorithm::HighestRandomWeight,
        ];
        algs.sort();
        assert_eq!(
            algs,
            vec![
                DfAlgorithm::DefaultModulo,
                DfAlgorithm::HighestRandomWeight,
                DfAlgorithm::HighestPreference,
                DfAlgorithm::LowestPreference,
            ]
        );
    }

    #[test]
    fn redundancy_mode_strings_match_config_surface() {
        assert_eq!(RedundancyMode::AllActive.as_str(), "all-active");
        assert_eq!(RedundancyMode::SingleActive.as_str(), "single-active");
        assert!(!RedundancyMode::AllActive.is_single_active());
        assert!(RedundancyMode::SingleActive.is_single_active());
    }
}
