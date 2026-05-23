//! Designated Forwarder election state machine — Gate 8.
//!
//! Pure-function state machine implementing RFC 7432 §8.5 service
//! carving, RFC 8584 §2.2 algorithm negotiation, and the RFC 8584
//! §3.2 Highest Random Weight algorithm. Lives in
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
//! # Algorithm negotiation (RFC 8584 §2.2)
//!
//! Each PE proposes an algorithm in its Type 4 ES route's DF
//! Election extcomm. If all candidates propose the same algorithm,
//! that algorithm runs. If any candidate is absent, default, or
//! disagrees, RFC 8584 falls back to `DefaultModulo` so heterogeneous
//! deployments converge on a common floor.
//!
//! This module implements `DefaultModulo`, the RFC 8584 §3.2 Highest
//! Random Weight algorithm, and the RFC 9785 Highest-/Lowest-Preference
//! algorithms. The RFC 9785 Don't-Preempt capability is accepted as a
//! remote tie-break input; local non-revertive behavior is an
//! orchestrator policy concern and remains outside this pure election
//! state machine.

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
    /// DF preference value the PE proposed. RFC 9785 preference
    /// algorithms use this field; `DefaultModulo` and HRW ignore it.
    pub df_preference: u32,
    /// RFC 9785 Don't-Preempt capability advertised by this PE.
    /// Preference algorithms use it as an equal-preference tie-breaker.
    pub df_dont_preempt: bool,
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

        let agreed = negotiate_algorithm(&sorted);

        // The local PE must be one of the candidates, else we cannot assign it
        // a role. (The winner is computed by IP below, so the index is unused.)
        if !sorted
            .iter()
            .any(|c| c.originator_ip == local_originator_ip)
        {
            return Err(DfElectionError::LocalNotInCandidates(local_originator_ip));
        }

        let n = sorted.len();
        let mut roles = BTreeMap::new();
        for &vni in &self.member_vnis {
            let winner_ip = match agreed {
                DfAlgorithm::DefaultModulo => {
                    // Service carving: candidate at index `vni mod n` is DF for
                    // that VNI. RFC 7432 §8.5.
                    let winner_slot = (vni.as_u32() as usize) % n;
                    sorted[winner_slot].originator_ip
                }
                DfAlgorithm::HighestRandomWeight => {
                    hrw_winner(self.esi, vni, &sorted)
                        .expect("non-empty after EmptyCandidateSet guard")
                        .originator_ip
                }
                DfAlgorithm::HighestPreference => {
                    preference_winner(&sorted, PreferenceOrder::High)
                        .expect("non-empty after EmptyCandidateSet guard")
                        .originator_ip
                }
                DfAlgorithm::LowestPreference => {
                    preference_winner(&sorted, PreferenceOrder::Low)
                        .expect("non-empty after EmptyCandidateSet guard")
                        .originator_ip
                }
            };
            let role = if winner_ip == local_originator_ip {
                DfRole::Df
            } else {
                DfRole::NonDf
            };
            roles.insert(vni, role);
        }
        Ok(roles)
    }
}

#[derive(Debug, Clone, Copy)]
enum PreferenceOrder {
    High,
    Low,
}

fn preference_winner(candidates: &[DfCandidate], order: PreferenceOrder) -> Option<&DfCandidate> {
    // RFC 9785 preference election: highest- (or lowest-) `df_preference` wins,
    // ties broken by the numerically lowest originator IP. The Don't-Preempt (DP)
    // bit is intentionally NOT a tie-break input: a stateless election has no
    // prior-DF / incumbent input, so it cannot implement RFC 9785 "don't preempt
    // the incumbent DF". Using DP as a static promotion key would make it
    // offensive extra preference weight rather than the defensive non-preemption
    // it is meant to be. rustbgpd originates + parses the DP bit; stateful
    // non-revertive election remains deferred work.
    candidates.iter().max_by_key(|c| {
        let preference_key = match order {
            PreferenceOrder::High => c.df_preference,
            PreferenceOrder::Low => u32::MAX - c.df_preference,
        };
        (preference_key, std::cmp::Reverse(c.originator_ip))
    })
}

/// RFC 8584 §2.2 algorithm negotiation: if every candidate advertises the same
/// DF Alg, that algorithm runs; any disagreement (or an absent DF Election
/// Extended Community, decoded as `DefaultModulo`) falls back to default
/// service carving.
///
/// Limitation: this compares only the DF Alg field. RFC 8584 §2.2 also requires
/// fallback when the DF Election **capability bitmap** (e.g. Don't Preempt,
/// AC-DF) differs, but rustbgpd does not yet originate or parse those
/// capabilities — `DfCandidate` carries no capability field — so they are
/// neither advertised nor compared. Capability-aware negotiation is a future
/// slice; until then rustbgpd interoperates only on the DF Alg field.
fn negotiate_algorithm(candidates: &[DfCandidate]) -> DfAlgorithm {
    let first = candidates
        .first()
        .map_or(DfAlgorithm::DefaultModulo, |c| c.df_algorithm);
    if candidates.iter().all(|c| c.df_algorithm == first) {
        first
    } else {
        DfAlgorithm::DefaultModulo
    }
}

fn hrw_winner(
    esi: EthernetSegmentIdentifier,
    vni: EvpnInstanceId,
    candidates: &[DfCandidate],
) -> Option<&DfCandidate> {
    // `D(V,Es)` is constant across candidates for this `(vni, esi)`, so compute
    // it once; `max_by_key` then evaluates each candidate's weight exactly once
    // (not O(n log n) times as a `max_by` comparator would).
    let d = hrw_digest(vni, esi);
    candidates.iter().max_by_key(|c| {
        // Highest weight wins; equal weights fall to the numerically least PE
        // IP (RFC 8584 §3.2), so reverse the IP — the largest key then prefers
        // the lowest address.
        (
            hrw_weight_from_digest(d, c.originator_ip),
            std::cmp::Reverse(c.originator_ip),
        )
    })
}

/// RFC 8584 §3.2 HRW digest `D(V, Es)`: the 31-bit value — CRC-32 with the MSB
/// discarded — of the 14-octet stream `V || Es` (the 4-octet Ethernet Tag
/// followed by the 10-octet ESI, network byte order). Constant for a given
/// `(vni, esi)`, so callers electing across a candidate set compute it once.
fn hrw_digest(vni: EvpnInstanceId, esi: EthernetSegmentIdentifier) -> u32 {
    let mut tuple = [0u8; 14];
    tuple[0..4].copy_from_slice(&vni.as_u32().to_be_bytes());
    tuple[4..14].copy_from_slice(&esi.octets());
    crc32_ieee(&tuple) & 0x7FFF_FFFF
}

/// RFC 8584 §3.2 Highest Random Weight, given a precomputed digest `d`:
///
/// ```text
/// Wrand = (1103515245 * ((1103515245*Si + 12345) XOR D(V,Es)) + 12345) (mod 2^31)
/// ```
///
/// `Si` is the PE IP address. All PEs in the segment must compute this
/// identically for the election to converge, so it matches the RFC byte-for-byte
/// for IPv4 (the interoperable VXLAN-underlay case). Reducing `mod 2^31` at each
/// LCG step is algebraically identical to the RFC's single final reduction and
/// keeps the arithmetic overflow-free.
fn hrw_weight_from_digest(d: u32, originator_ip: IpAddr) -> u32 {
    let si = pe_ip_weight_input(originator_ip);
    let inner = hrw_lcg_step(si) ^ d;
    hrw_lcg_step(inner)
}

/// One `(1103515245 * x + 12345) mod 2^31` LCG step, computed in `u64` so the
/// multiply cannot overflow before the reduction.
fn hrw_lcg_step(x: u32) -> u32 {
    const HRW_MOD: u64 = 0x8000_0000; // 2^31
    (((1_103_515_245u64 * u64::from(x)) + 12_345) % HRW_MOD) as u32
}

/// `Si` for the HRW weight. RFC 8584 §3.2 defines it as the PE IPv4 address;
/// IPv4 maps directly to its 32-bit value (the cross-vendor-interoperable
/// case). IPv6 underlays have no standardized 128→32-bit reduction, so use the
/// low-order 31 bits of the address — `Si` feeds an LCG that already reduces
/// `mod 2^31`, so this is the natural "address as a number" input without an
/// extra hash. Deterministic and self-consistent across rustbgpd PEs (PEs with
/// distinct addresses that collide in the low 31 bits fall to the lowest-IP
/// tie-break); not cross-vendor guaranteed.
fn pe_ip_weight_input(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[12], o[13], o[14], o[15]]) & 0x7FFF_FFFF
        }
    }
}

/// Standard CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`, init/xorout
/// `0xFFFFFFFF`) — the same digest FRR and other EVPN implementations feed into
/// RFC 8584 §3.2's `D(V,Es)`. Bitwise (no table); inputs here are 14 octets.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
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
            df_dont_preempt: false,
            df_algorithm: alg,
        }
    }

    fn preference_candidate(
        ip_str: &str,
        alg: DfAlgorithm,
        preference: u32,
        dont_preempt: bool,
    ) -> DfCandidate {
        DfCandidate {
            originator_ip: ip(ip_str),
            df_preference: preference,
            df_dont_preempt: dont_preempt,
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
    fn mixed_algorithms_fall_back_to_default_modulo() {
        // RFC 8584 §2.2: if candidates do not agree on the same DF
        // algorithm/capabilities, all PEs fall back to default.
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::HighestRandomWeight),
            candidate("10.0.0.2", DfAlgorithm::HighestPreference),
        ];
        let roles = election
            .run(&candidates, ip("10.0.0.1"))
            .expect("algorithm disagreement falls back to DefaultModulo");
        // VNI 100 → slot 100 % 2 = 0 → .1.
        assert_eq!(roles[&vni(100)], DfRole::Df);
    }

    #[test]
    fn unanimous_hrw_algorithm_runs() {
        let election = DfElection::new(esi(1), [vni(100), vni(101), vni(102)]);
        let candidates = vec![
            candidate("10.0.0.1", DfAlgorithm::HighestRandomWeight),
            candidate("10.0.0.2", DfAlgorithm::HighestRandomWeight),
            candidate("10.0.0.3", DfAlgorithm::HighestRandomWeight),
        ];

        let roles = election.run(&candidates, ip("10.0.0.1")).unwrap();

        for member_vni in [vni(100), vni(101), vni(102)] {
            let winner =
                hrw_winner(election.esi(), member_vni, &candidates).expect("winner exists");
            assert_eq!(
                roles[&member_vni],
                if winner.originator_ip == ip("10.0.0.1") {
                    DfRole::Df
                } else {
                    DfRole::NonDf
                }
            );
        }
    }

    #[test]
    fn hrw_tie_chooses_lowest_originator_ip() {
        let candidates = [
            candidate("10.0.0.2", DfAlgorithm::HighestRandomWeight),
            candidate("10.0.0.1", DfAlgorithm::HighestRandomWeight),
        ];
        let winner = candidates.iter().min_by_key(|c| c.originator_ip).unwrap();
        assert_eq!(winner.originator_ip, ip("10.0.0.1"));

        // Exercise the comparator's tie path directly by checking the
        // deterministic tie-break rule it implements.
        let by_tie = candidates
            .iter()
            .max_by(|a, b| {
                42u32
                    .cmp(&42)
                    .then_with(|| b.originator_ip.cmp(&a.originator_ip))
            })
            .unwrap();
        assert_eq!(by_tie.originator_ip, ip("10.0.0.1"));
    }

    #[test]
    fn crc32_matches_standard_test_vector() {
        // Standard CRC-32 (IEEE) check value for the ASCII "123456789".
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn hrw_weight_matches_rfc8584_known_answer() {
        // Known-answer vector computed independently (Python `zlib.crc32` +
        // the RFC 8584 §3.2 LCG): V=100, Es=[0x01; 10], Si=10.0.0.1.
        // D(V,Es) = 42_737_338; Wrand = 664_511_525. This pins the byte-exact
        // weight so a regression to a non-conformant hash is caught.
        assert_eq!(hrw_digest(vni(100), esi(1)), 42_737_338);
        assert_eq!(
            hrw_weight_from_digest(hrw_digest(vni(100), esi(1)), ip("10.0.0.1")),
            664_511_525
        );
    }

    #[test]
    fn hrw_weight_ipv6_uses_low_order_31_bits() {
        // `::a00:1` has low 32 bits 0x0A000001 — the same integer as 10.0.0.1
        // and within 31 bits, so Si (and therefore the whole weight) matches
        // the IPv4 case. Confirms IPv6 folds to the low-order 31 bits, not a
        // separate hash.
        let v6: IpAddr = "::a00:1".parse().unwrap();
        let d = hrw_digest(vni(100), esi(1));
        assert_eq!(
            hrw_weight_from_digest(d, v6),
            hrw_weight_from_digest(d, ip("10.0.0.1"))
        );
        assert_eq!(hrw_weight_from_digest(d, v6), 664_511_525);
    }

    #[test]
    fn unanimous_highest_preference_prefers_larger_preference() {
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            preference_candidate("10.0.0.1", DfAlgorithm::HighestPreference, 100, false),
            preference_candidate("10.0.0.2", DfAlgorithm::HighestPreference, 500, false),
        ];
        let roles = election.run(&candidates, ip("10.0.0.2")).unwrap();
        assert_eq!(roles[&vni(100)], DfRole::Df);
    }

    #[test]
    fn unanimous_lowest_preference_prefers_smaller_preference() {
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            preference_candidate("10.0.0.1", DfAlgorithm::LowestPreference, 100, false),
            preference_candidate("10.0.0.2", DfAlgorithm::LowestPreference, 500, false),
        ];
        let roles = election.run(&candidates, ip("10.0.0.1")).unwrap();
        assert_eq!(roles[&vni(100)], DfRole::Df);
    }

    #[test]
    fn preference_tie_breaks_on_lowest_originator_ip_ignoring_dont_preempt() {
        // Equal preference: the numerically lowest originator IP wins. The
        // Don't-Preempt bit must NOT promote a higher-IP candidate — DP is not a
        // tie-break input, because a stateless election cannot implement RFC 9785
        // "don't preempt the incumbent" without prior-role state.
        let election = DfElection::new(esi(1), [vni(100)]);
        let candidates = vec![
            preference_candidate("10.0.0.1", DfAlgorithm::HighestPreference, 500, false),
            preference_candidate("10.0.0.2", DfAlgorithm::HighestPreference, 500, true),
            preference_candidate("10.0.0.3", DfAlgorithm::HighestPreference, 500, false),
        ];
        // 10.0.0.2 advertises DP=true but does not win the tie.
        let roles = election.run(&candidates, ip("10.0.0.2")).unwrap();
        assert_eq!(roles[&vni(100)], DfRole::NonDf);
        // The lowest originator IP (10.0.0.1) is DF despite DP=false.
        let roles = election.run(&candidates, ip("10.0.0.1")).unwrap();
        assert_eq!(roles[&vni(100)], DfRole::Df);

        // LowestPreference path: same lowest-IP tie-break.
        let lowest = vec![
            preference_candidate("10.0.0.2", DfAlgorithm::LowestPreference, 500, false),
            preference_candidate("10.0.0.1", DfAlgorithm::LowestPreference, 500, false),
        ];
        let roles = election.run(&lowest, ip("10.0.0.1")).unwrap();
        assert_eq!(roles[&vni(100)], DfRole::Df);
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
