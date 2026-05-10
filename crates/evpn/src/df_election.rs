//! Designated Forwarder election state machine — Gate 8.
//!
//! Pure-function state machine implementing RFC 7432 §8.5 service
//! carving plus RFC 8584 §3 algorithm negotiation. Lives in
//! `crates/evpn` for the same reasons the local-MAC originator does:
//! deterministic, no I/O, no tokio, testable on macOS dev builds.
//!
//! The daemon-side orchestrator (slice 3 in `src/evpn_segment.rs`)
//! gathers candidate PEs from the RIB's Type 4 ES routes, calls
//! [`DfElection::run`], and reads the per-`(ESI, VNI)` `DfRole` map
//! to drive observability. Forwarding-blocking enforcement is Gate
//! 8b — see ADR-0057 for the scope split.
//!
//! # Algorithm
//!
//! For each member VNI of the ES, RFC 7432 §8.5 service carving
//! computes:
//!
//! 1. Sort the candidate PE list by **originator IP** ascending.
//! 2. The candidate at index `vni mod candidate_count` is the DF
//!    for that VNI; all others are `NonDf`.
//!
//! That's it. The algebra is intentionally simple — it's deterministic,
//! requires no shared state between PEs, and the only input PEs need
//! to agree on is the candidate set (which they already see via the
//! RIB's reflected Type 4 ES routes).
//!
//! # Algorithm negotiation (RFC 8584 §3)
//!
//! Each PE proposes an algorithm in its Type 4 ES route's DF
//! Election extcomm. If all candidates propose the same algorithm,
//! that algorithm runs. If they disagree, the **lowest algorithm
//! ID** wins (RFC 8584 §3) — peers fall back to a common floor.
//! `DefaultModulo` (ID 0) is the universal floor, so heterogeneous
//! deployments converge on it deterministically.
//!
//! Gate 8 only implements `DefaultModulo`. The other variants are
//! reserved at the type level (see [`crate::segment::DfAlgorithm`])
//! so the wire-side codec is forward-compat, but
//! [`DfElection::run`] returns
//! [`DfElectionError::AlgorithmNotImplemented`] if negotiation
//! settles on `HighestRandomWeight` or `PreferenceBased`. That's a
//! deliberate decision: implementing them now without a use case
//! would be untested code. The error is typed so the daemon can
//! surface it at config-validation time and degrade gracefully (log
//! + skip the ES rather than panic).

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::EthernetSegmentIdentifier;

use crate::EvpnInstanceId;
use crate::segment::{DfAlgorithm, DfRole};

/// One PE's proposal in the candidate set for a given ESI.
///
/// Daemon-side orchestrator builds these from the RIB's Type 4 ES
/// routes (one candidate per peer Type 4) plus a synthetic
/// "ourselves" entry from local config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DfCandidate {
    /// The PE's originator IP from its Type 4 ES route.
    pub originator_ip: IpAddr,
    /// DF preference value the PE proposed (RFC 8584 §3.1).
    /// Reserved for use under non-default algorithms; `DefaultModulo`
    /// ignores this field.
    pub df_preference: u32,
    /// DF election algorithm the PE proposed.
    pub df_algorithm: DfAlgorithm,
}

/// Election driver scoped to one Ethernet Segment.
///
/// Stateless apart from the operator-supplied member-VNI list. The
/// caller hands a fresh candidate set to [`Self::run`] on each
/// invocation; results are derived purely from those inputs.
#[derive(Debug, Clone)]
pub struct DfElection {
    esi: EthernetSegmentIdentifier,
    member_vnis: Vec<EvpnInstanceId>,
}

impl DfElection {
    /// Build an election driver for one ESI + its member VNIs.
    ///
    /// The member-VNI list is sorted into a stable order so the
    /// resulting `BTreeMap<VNI, DfRole>` ordering is deterministic
    /// even if the operator config came in with a different order.
    #[must_use]
    pub fn new(
        esi: EthernetSegmentIdentifier,
        member_vnis: impl IntoIterator<Item = EvpnInstanceId>,
    ) -> Self {
        let mut vnis: Vec<_> = member_vnis.into_iter().collect();
        vnis.sort();
        vnis.dedup();
        Self {
            esi,
            member_vnis: vnis,
        }
    }

    /// ESI this election runs for.
    #[must_use]
    pub fn esi(&self) -> EthernetSegmentIdentifier {
        self.esi
    }

    /// Member VNIs in canonical order.
    #[must_use]
    pub fn member_vnis(&self) -> &[EvpnInstanceId] {
        &self.member_vnis
    }

    /// Run the election. Returns the per-VNI `DfRole` for the local
    /// PE (identified by `local_originator_ip` — must be one of the
    /// candidates).
    ///
    /// # Panics
    ///
    /// Internal invariant assertion: the empty-candidate guard at
    /// the top of the function ensures the subsequent `.min()` call
    /// cannot return `None`. The `expect` is unreachable in
    /// practice; it documents the invariant for the reader.
    ///
    /// # Errors
    ///
    /// - [`DfElectionError::EmptyCandidateSet`] if `candidates` is
    ///   empty (every ESI has at least one candidate — the local PE).
    /// - [`DfElectionError::LocalNotInCandidates`] if
    ///   `local_originator_ip` doesn't appear in the candidate set
    ///   (programmer bug; the orchestrator must include the local PE
    ///   in the set it passes in).
    /// - [`DfElectionError::DuplicateOriginator`] if two candidates
    ///   share the same originator IP. RFC 7432 §8.5 implicitly
    ///   assumes uniqueness — collisions break service carving's
    ///   deterministic split.
    /// - [`DfElectionError::AlgorithmNotImplemented`] if negotiation
    ///   settles on an algorithm other than `DefaultModulo`. Gate 8
    ///   ships only the default; non-default IDs surface here so the
    ///   caller can degrade gracefully (log + skip vs. panic).
    pub fn run(
        &self,
        candidates: &[DfCandidate],
        local_originator_ip: IpAddr,
    ) -> Result<BTreeMap<EvpnInstanceId, DfRole>, DfElectionError> {
        if candidates.is_empty() {
            return Err(DfElectionError::EmptyCandidateSet);
        }

        // Validate uniqueness on originator IP — RFC 7432 §8.5 keys
        // service carving on a sorted IP list, and a duplicate IP
        // would silently break the deterministic split (two
        // candidates would collapse into one slot).
        let mut sorted = candidates.to_vec();
        sorted.sort_by_key(|c| c.originator_ip);
        for window in sorted.windows(2) {
            if window[0].originator_ip == window[1].originator_ip {
                return Err(DfElectionError::DuplicateOriginator(
                    window[0].originator_ip,
                ));
            }
        }

        // Negotiate algorithm. RFC 8584 §3: lowest algorithm ID
        // among the candidates wins. `DefaultModulo` is ID 0 and the
        // universal floor — heterogeneous deployments converge here.
        let agreed = sorted
            .iter()
            .map(|c| c.df_algorithm)
            .min()
            .expect("non-empty after EmptyCandidateSet guard");
        if agreed != DfAlgorithm::DefaultModulo {
            return Err(DfElectionError::AlgorithmNotImplemented(agreed));
        }

        // Locate the local PE's slot in the sorted candidate list.
        let local_slot = sorted
            .iter()
            .position(|c| c.originator_ip == local_originator_ip)
            .ok_or(DfElectionError::LocalNotInCandidates(local_originator_ip))?;

        // Service carving: candidate at index `vni mod n` is DF for
        // that VNI. RFC 7432 §8.5.
        let n = sorted.len();
        let mut roles = BTreeMap::new();
        for &vni in &self.member_vnis {
            let winner_slot = (vni.as_u32() as usize) % n;
            let role = if winner_slot == local_slot {
                DfRole::Df
            } else {
                DfRole::NonDf
            };
            roles.insert(vni, role);
        }
        Ok(roles)
    }
}

/// Errors raised by [`DfElection::run`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DfElectionError {
    /// The candidate list was empty. Every ESI has at least one
    /// candidate (the local PE); an empty list means the orchestrator
    /// forgot to include itself.
    #[error("DF election candidate set is empty (orchestrator must include the local PE)")]
    EmptyCandidateSet,
    /// The `local_originator_ip` argument doesn't appear in the
    /// candidate set. Indicates the orchestrator built a candidate
    /// list that excluded the local PE — programmer bug.
    #[error("local originator IP {0} not present in DF election candidates")]
    LocalNotInCandidates(IpAddr),
    /// Two candidates share the same originator IP. RFC 7432 §8.5
    /// service carving's determinism depends on uniqueness.
    #[error("two DF election candidates share originator IP {0}")]
    DuplicateOriginator(IpAddr),
    /// Negotiation settled on an algorithm Gate 8 doesn't implement.
    /// Caller should log the ESI + the algorithm and skip
    /// origination for this ES.
    #[error(
        "DF election algorithm {0:?} is reserved but not implemented (Gate 8 ships DefaultModulo only)"
    )]
    AlgorithmNotImplemented(DfAlgorithm),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn candidate(ip_str: &str, alg: DfAlgorithm) -> DfCandidate {
        DfCandidate {
            originator_ip: ip(ip_str),
            df_preference: 32_768,
            df_algorithm: alg,
        }
    }

    #[test]
    fn single_pe_is_df_for_all_vnis() {
        // The trivial case: one candidate, all VNIs → DF.
        let election = DfElection::new(esi(1), [vni(100), vni(200), vni(300)]);
        let local = ip("10.0.0.1");
        let candidates = vec![candidate("10.0.0.1", DfAlgorithm::DefaultModulo)];
        let roles = election.run(&candidates, local).expect("run succeeds");
        assert_eq!(roles.len(), 3);
        for role in roles.values() {
            assert!(role.is_df(), "single PE must be DF for every VNI");
        }
    }

    #[test]
    fn two_pe_modulo_split_canonical() {
        // Two candidates sorted by IP: 10.0.0.1 (slot 0), 10.0.0.2 (slot 1).
        // VNI 100 → slot 100 % 2 = 0 → 10.0.0.1 wins.
        // VNI 101 → slot 101 % 2 = 1 → 10.0.0.2 wins.
        // Local PE is 10.0.0.1: DF for 100, NonDF for 101.
        let election = DfElection::new(esi(1), [vni(100), vni(101)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
        ];
        let roles_a = election
            .run(&candidates, ip("10.0.0.1"))
            .expect("run succeeds");
        let roles_b = election
            .run(&candidates, ip("10.0.0.2"))
            .expect("run succeeds");
        assert_eq!(roles_a[&vni(100)], DfRole::Df);
        assert_eq!(roles_a[&vni(101)], DfRole::NonDf);
        assert_eq!(roles_b[&vni(100)], DfRole::NonDf);
        assert_eq!(roles_b[&vni(101)], DfRole::Df);
    }

    #[test]
    fn three_pe_modulo_carving_distributes_evenly() {
        // VNIs 10, 11, 12 across 3 PEs at .1/.2/.3.
        // 10 % 3 = 1 → .2, 11 % 3 = 2 → .3, 12 % 3 = 0 → .1.
        let election = DfElection::new(esi(1), [vni(10), vni(11), vni(12)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.3", DfAlgorithm::DefaultModulo),
        ];
        let r1 = election.run(&candidates, ip("10.0.0.1")).unwrap();
        let r2 = election.run(&candidates, ip("10.0.0.2")).unwrap();
        let r3 = election.run(&candidates, ip("10.0.0.3")).unwrap();
        assert_eq!(r1[&vni(10)], DfRole::NonDf);
        assert_eq!(r2[&vni(10)], DfRole::Df);
        assert_eq!(r3[&vni(10)], DfRole::NonDf);
        assert_eq!(r1[&vni(11)], DfRole::NonDf);
        assert_eq!(r2[&vni(11)], DfRole::NonDf);
        assert_eq!(r3[&vni(11)], DfRole::Df);
        assert_eq!(r1[&vni(12)], DfRole::Df);
        assert_eq!(r2[&vni(12)], DfRole::NonDf);
        assert_eq!(r3[&vni(12)], DfRole::NonDf);
    }

    #[test]
    fn pe_leaves_redistributes_correctly() {
        // Start: 3 PEs, VNI 12 belongs to .1 (slot 0, 12 % 3 = 0).
        // After .3 leaves: 2 PEs, VNI 12 → slot 12 % 2 = 0 → still .1.
        // VNI 11: was on .3 (slot 2, 11 % 3 = 2). After leave: slot
        //         11 % 2 = 1 → .2 picks up.
        let election = DfElection::new(esi(1), [vni(11), vni(12)]);

        let three = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.3", DfAlgorithm::DefaultModulo),
        ];
        let r2_three = election.run(&three, ip("10.0.0.2")).unwrap();
        assert_eq!(r2_three[&vni(11)], DfRole::NonDf, "before leave");
        assert_eq!(r2_three[&vni(12)], DfRole::NonDf, "before leave");

        let two = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
        ];
        let r2_two = election.run(&two, ip("10.0.0.2")).unwrap();
        assert_eq!(
            r2_two[&vni(11)],
            DfRole::Df,
            "after .3 leaves, .2 picks up VNI 11"
        );
        assert_eq!(r2_two[&vni(12)], DfRole::NonDf, "VNI 12 stays on .1");
    }

    #[test]
    fn input_ordering_does_not_affect_output() {
        // Service carving sorts internally — caller's input order
        // shouldn't change the DF assignment.
        let election = DfElection::new(esi(1), [vni(7), vni(8)]);
        let local = ip("10.0.0.1");
        let forward = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.3", DfAlgorithm::DefaultModulo),
        ];
        let reverse = vec![
            candidate("10.0.0.3", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
        ];
        assert_eq!(
            election.run(&forward, local).unwrap(),
            election.run(&reverse, local).unwrap(),
        );
    }

    #[test]
    fn empty_candidates_errors() {
        let election = DfElection::new(esi(1), [vni(100)]);
        assert!(matches!(
            election.run(&[], ip("10.0.0.1")),
            Err(DfElectionError::EmptyCandidateSet),
        ));
    }

    #[test]
    fn local_not_in_candidates_errors() {
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.3", DfAlgorithm::DefaultModulo),
        ];
        let err = election.run(&candidates, ip("10.0.0.1")).unwrap_err();
        match err {
            DfElectionError::LocalNotInCandidates(addr) => {
                assert_eq!(addr, ip("10.0.0.1"));
            }
            other => panic!("expected LocalNotInCandidates, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_originator_errors() {
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
        ];
        let err = election.run(&candidates, ip("10.0.0.1")).unwrap_err();
        match err {
            DfElectionError::DuplicateOriginator(addr) => {
                assert_eq!(addr, ip("10.0.0.1"));
            }
            other => panic!("expected DuplicateOriginator, got {other:?}"),
        }
    }

    #[test]
    fn mixed_algorithms_settles_on_lowest_id() {
        // RFC 8584 §3: lowest algorithm ID wins. DefaultModulo is 0,
        // which always wins over any other proposal. Election runs.
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::HighestRandomWeight),
        ];
        let roles = election
            .run(&candidates, ip("10.0.0.1"))
            .expect("DefaultModulo ID 0 wins; election runs");
        // VNI 100 → slot 100 % 2 = 0 → .1.
        assert_eq!(roles[&vni(100)], DfRole::Df);
    }

    #[test]
    fn unanimous_non_default_algorithm_returns_not_implemented() {
        // All candidates propose HighestRandomWeight. Negotiation
        // settles there; Gate 8 doesn't implement it; typed error
        // surfaces. Caller (orchestrator) is expected to log + skip
        // origination for this ES.
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::HighestRandomWeight),
            candidate("10.0.0.2", DfAlgorithm::HighestRandomWeight),
        ];
        let err = election.run(&candidates, ip("10.0.0.1")).unwrap_err();
        match err {
            DfElectionError::AlgorithmNotImplemented(alg) => {
                assert_eq!(alg, DfAlgorithm::HighestRandomWeight);
            }
            other => panic!("expected AlgorithmNotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn unanimous_preference_based_returns_not_implemented() {
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::PreferenceBased),
            candidate("10.0.0.2", DfAlgorithm::PreferenceBased),
        ];
        let err = election.run(&candidates, ip("10.0.0.1")).unwrap_err();
        match err {
            DfElectionError::AlgorithmNotImplemented(alg) => {
                assert_eq!(alg, DfAlgorithm::PreferenceBased);
            }
            other => panic!("expected AlgorithmNotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn member_vnis_dedupe_on_construction() {
        // Caller might pass an iterator with duplicates (e.g.,
        // overlapping config sources). Dedup so the resulting role
        // map has one entry per VNI.
        let election = DfElection::new(esi(1), [vni(100), vni(100), vni(200)]);
        assert_eq!(election.member_vnis(), &[vni(100), vni(200)]);
    }

    #[test]
    fn ipv6_originators_sort_canonically() {
        // Sort uses IpAddr's PartialOrd; v4 < v6. Mixed candidate
        // lists are uncommon but should still produce a deterministic
        // ordering — pin it.
        let election = DfElection::new(esi(1), [vni(100)]);
        let v4 = candidate("10.0.0.1", DfAlgorithm::DefaultModulo);
        let v6 = candidate("2001:db8::1", DfAlgorithm::DefaultModulo);
        let candidates = vec![v6, v4];
        let roles = election.run(&candidates, ip("10.0.0.1")).unwrap();
        // v4 sorts before v6 in IpAddr's PartialOrd, so .1 is slot 0.
        // VNI 100 → 100 % 2 = 0 → .1 wins.
        assert_eq!(roles[&vni(100)], DfRole::Df);
        let roles_v6 = election.run(&candidates, ip("2001:db8::1")).unwrap();
        assert_eq!(roles_v6[&vni(100)], DfRole::NonDf);
    }

    #[test]
    fn empty_member_vnis_yields_empty_roles() {
        // ES with no member VNIs is degenerate but legal config —
        // election runs and produces an empty role map.
        let election = DfElection::new(esi(1), Vec::<EvpnInstanceId>::new());
        let candidates = vec![candidate("10.0.0.1", DfAlgorithm::DefaultModulo)];
        let roles = election.run(&candidates, ip("10.0.0.1")).unwrap();
        assert!(roles.is_empty());
    }

    #[test]
    fn ipv4_orderings_check_octet_by_octet() {
        // Confirm the IpAddr sort uses canonical big-endian octet
        // comparison: 10.0.0.10 sorts after 10.0.0.2, not before
        // (string sort would invert this).
        //
        // Use VNI 200 (200 % 2 = 0 → first slot) so the sorted-first
        // candidate wins. RFC 8365 §5 reserves VNI 0; we can't use
        // it as a member.
        let election = DfElection::new(esi(1), [vni(200)]);
        let candidates = vec![
            candidate("10.0.0.10", DfAlgorithm::DefaultModulo),
            candidate("10.0.0.2", DfAlgorithm::DefaultModulo),
        ];
        // After sort: .2 (slot 0), .10 (slot 1).
        // VNI 200 → 200 % 2 = 0 → .2 wins.
        let roles_2 = election.run(&candidates, ip("10.0.0.2")).unwrap();
        let roles_10 = election.run(&candidates, ip("10.0.0.10")).unwrap();
        assert_eq!(roles_2[&vni(200)], DfRole::Df);
        assert_eq!(roles_10[&vni(200)], DfRole::NonDf);
    }

    #[test]
    fn esi_accessor_returns_construction_value() {
        let id = esi(0xAB);
        let election = DfElection::new(id, [vni(100)]);
        assert_eq!(election.esi(), id);
    }

    /// Smoke that the underlying IPv4 octet ordering rule we depend
    /// on is what `IpAddr` actually does. Defensive — if std ever
    /// changed `Ord` semantics on `Ipv4Addr` this test would surface
    /// the regression at the dependency layer.
    #[test]
    fn ipv4_addr_ord_is_octet_canonical() {
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let b: IpAddr = Ipv4Addr::new(10, 0, 0, 10).into();
        assert!(a < b);
    }
}
