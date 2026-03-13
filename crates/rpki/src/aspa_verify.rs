//! ASPA upstream path verification per draft-ietf-sidrops-aspa-verification.
//!
//! Implements the upstream verification algorithm only. Downstream verification
//! (for routes from providers) requires per-peer relationship configuration and
//! is deferred.

use rustbgpd_wire::{AsPath, AsPathSegment, AspaValidation};

use crate::aspa::{AspaTable, ProviderAuth};

/// Compress an `AS_PATH` into a flat list of ASNs with consecutive duplicates
/// removed (`AS_PATH` preload compression per the ASPA verification spec).
///
/// Returns `None` if any `AS_SET` segment is encountered (`AS_SET` makes the
/// path unverifiable).
fn compress_as_path(path: &AsPath) -> Option<Vec<u32>> {
    let mut result = Vec::new();
    for segment in &path.segments {
        match segment {
            AsPathSegment::AsSet(_) => return None,
            AsPathSegment::AsSequence(asns) => {
                for &asn in asns {
                    if result.last() != Some(&asn) {
                        result.push(asn);
                    }
                }
            }
        }
    }
    Some(result)
}

/// Verify an `AS_PATH` using upstream ASPA verification.
///
/// The compressed path is indexed as `hop[0]` = neighbor AS (closest),
/// `hop[N-1]` = origin AS (farthest). The algorithm walks from origin
/// upward checking that each hop is an authorized provider of the
/// previous hop.
///
/// Returns:
/// - `Valid` — all hops have authorized provider relationships
/// - `Invalid` — at least one hop has a proven non-provider relationship
/// - `Unknown` — verification incomplete due to missing ASPA records
#[must_use]
pub fn verify_upstream(path: &AsPath, table: &AspaTable) -> AspaValidation {
    let Some(compressed) = compress_as_path(path) else {
        return AspaValidation::Invalid; // AS_SET present
    };

    // Empty or single-hop paths are trivially valid (no hops to verify).
    if compressed.len() <= 1 {
        return AspaValidation::Valid;
    }

    // Walk from origin (last element) toward neighbor (first element).
    // For each pair (customer, provider), check authorization.
    // compressed[0] = neighbor, compressed[N-1] = origin
    // Pairs: (origin, origin-1), (origin-1, origin-2), ..., (1, 0)
    // i.e. (compressed[i], compressed[i-1]) for i from N-1 down to 1
    let mut has_no_attestation = false;

    for i in (1..compressed.len()).rev() {
        let customer = compressed[i];
        let provider = compressed[i - 1];

        match table.authorized(customer, provider) {
            ProviderAuth::ProviderPlus => {
                // This hop is authorized, continue up-ramp.
            }
            ProviderAuth::NotProviderPlus => {
                // Proven non-provider relationship — path is invalid.
                return AspaValidation::Invalid;
            }
            ProviderAuth::NoAttestation => {
                // Cannot verify this hop — mark as incomplete.
                has_no_attestation = true;
            }
        }
    }

    if has_no_attestation {
        AspaValidation::Unknown
    } else {
        AspaValidation::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aspa::AspaRecord;
    use rustbgpd_wire::AsPathSegment;

    fn make_path(asns: &[u32]) -> AsPath {
        AsPath {
            segments: vec![AsPathSegment::AsSequence(asns.to_vec())],
        }
    }

    fn make_table(records: Vec<(u32, Vec<u32>)>) -> AspaTable {
        AspaTable::new(
            records
                .into_iter()
                .map(|(customer, providers)| AspaRecord {
                    customer_asn: customer,
                    provider_asns: providers,
                })
                .collect(),
        )
    }

    #[test]
    fn empty_path_is_valid() {
        let table = make_table(vec![]);
        let path = AsPath { segments: vec![] };
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn single_hop_is_valid() {
        let table = make_table(vec![]);
        let path = make_path(&[65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn as_set_is_invalid() {
        let table = make_table(vec![]);
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001]),
                AsPathSegment::AsSet(vec![65002, 65003]),
            ],
        };
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Invalid);
    }

    #[test]
    fn valid_two_hop_chain() {
        // 65001 (origin) → 65002 (neighbor)
        // 65001 says 65002 is its provider
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn valid_three_hop_chain() {
        // 65001 (origin) → 65002 → 65003 (neighbor)
        // 65001 says 65002 is provider, 65002 says 65003 is provider
        let table = make_table(vec![(65001, vec![65002]), (65002, vec![65003])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn invalid_unauthorized_hop() {
        // 65001 (origin) → 65002 (neighbor)
        // 65001 has ASPA but 65002 is NOT in its provider set
        let table = make_table(vec![(65001, vec![65099])]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Invalid);
    }

    #[test]
    fn unknown_missing_attestation() {
        // 65001 (origin) → 65002 (neighbor)
        // No ASPA record for 65001
        let table = make_table(vec![]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Unknown);
    }

    #[test]
    fn invalid_middle_hop_unauthorized() {
        // 65001 → 65002 → 65003
        // 65001 says 65002 is provider (ok)
        // 65002 has ASPA but 65003 is NOT in it (invalid)
        let table = make_table(vec![(65001, vec![65002]), (65002, vec![65099])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Invalid);
    }

    #[test]
    fn unknown_partial_attestation() {
        // 65001 → 65002 → 65003
        // 65001 says 65002 is provider (ok)
        // No ASPA for 65002 (unknown)
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Unknown);
    }

    #[test]
    fn consecutive_duplicates_compressed() {
        // AS prepending: 65001 65001 65001 → 65002
        // Should compress to just [65002, 65001]
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65002, 65001, 65001, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn invalid_trumps_unknown() {
        // 65001 → 65002 → 65003
        // No ASPA for 65001 (would be unknown)
        // 65002 has ASPA but 65003 not in it (invalid)
        // Invalid wins over unknown
        let table = make_table(vec![(65002, vec![65099])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Invalid);
    }

    #[test]
    fn four_hop_valid_chain() {
        // 65001 → 65002 → 65003 → 65004
        let table = make_table(vec![
            (65001, vec![65002]),
            (65002, vec![65003]),
            (65003, vec![65004]),
        ]);
        let path = make_path(&[65004, 65003, 65002, 65001]);
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }

    #[test]
    fn multiple_segments_treated_as_sequence() {
        // Two AS_SEQUENCE segments concatenated
        let table = make_table(vec![(65001, vec![65002])]);
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65002]),
                AsPathSegment::AsSequence(vec![65001]),
            ],
        };
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Valid);
    }
}
