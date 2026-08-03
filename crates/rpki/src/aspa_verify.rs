//! ASPA path verification per draft-ietf-sidrops-aspa-verification.
//!
//! Implements upstream and downstream verification, with the verification
//! direction selected from the locally configured BGP Role when available.

use rustbgpd_wire::{AsPath, AsPathSegment, AspaValidation, AspaValidationContext, BgpRole};

use crate::aspa::{AspaTable, ProviderAuth};

/// Proven customer/provider pair that made an ASPA path invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AspaInvalidHop {
    pub customer_asn: u32,
    pub provider_asn: u32,
}

/// ASPA verdict plus the first proven `NotProviderPlus` hop, when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AspaVerificationResult {
    pub state: AspaValidation,
    pub invalid_hop: Option<AspaInvalidHop>,
}

impl AspaVerificationResult {
    pub(crate) const fn state(state: AspaValidation) -> Self {
        Self {
            state,
            invalid_hop: None,
        }
    }

    const fn invalid(customer_asn: u32, provider_asn: u32) -> Self {
        Self {
            state: AspaValidation::Invalid,
            invalid_hop: Some(AspaInvalidHop {
                customer_asn,
                provider_asn,
            }),
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationDirection {
    Upstream,
    Downstream,
}

fn direction_for_role(role: Option<BgpRole>) -> VerificationDirection {
    match role {
        Some(BgpRole::Customer) => VerificationDirection::Downstream,
        // Provider / RouteServer / RouteServerClient / Peer — and any role
        // added to the registry later — get the upstream procedure, the
        // same conservative behavior as an unconfigured role.
        _ => VerificationDirection::Upstream,
    }
}

fn leftmost_as_matches_neighbor(hops: &[u32], neighbor_asn: Option<u32>) -> bool {
    match neighbor_asn {
        Some(asn) => hops.first().is_some_and(|leftmost| *leftmost == asn),
        None => true,
    }
}

/// Verify an `AS_PATH` using the role-aware ASPA procedures from
/// `draft-ietf-sidrops-aspa-verification-27` §5.4 and §5.5.
///
/// With no configured role, rustbgpd uses upstream verification; the session
/// boundary independently enforces the current draft's first-AS precondition.
/// When the local role is [`BgpRole::Customer`], routes are treated as received
/// from a provider and downstream verification is applied.
#[must_use]
pub fn verify(path: &AsPath, table: &AspaTable, context: AspaValidationContext) -> AspaValidation {
    verify_detailed(path, table, context).state
}

/// Verify an `AS_PATH`, retaining the first `NotProviderPlus` hop. Invalid
/// structural/precondition outcomes deliberately carry no pair.
#[must_use]
pub fn verify_detailed(
    path: &AsPath,
    table: &AspaTable,
    context: AspaValidationContext,
) -> AspaVerificationResult {
    match direction_for_role(context.local_role) {
        VerificationDirection::Upstream => {
            verify_upstream_with_context_detailed(path, table, context)
        }
        VerificationDirection::Downstream => verify_downstream_detailed(path, table, context),
    }
}

/// Verify an `AS_PATH` using upstream ASPA verification per
/// `draft-ietf-sidrops-aspa-verification-27` §5.4.
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
///
/// # Equivalence to the §5.3 bounds-checker form
///
/// The spec describes the algorithm in §5.3 as a bounds-check that
/// computes `max_up_ramp` (treating `NoAttestation` as optimistic-pass)
/// and `min_up_ramp` (strict) walking from origin toward neighbor. For
/// *upstream* verification (§5.4 with `max_down_ramp = min_down_ramp =
/// 0`) the bounds form collapses into the pairwise walk here, because:
///
/// - "any pair `NotProviderPlus`" ⇔ "`max_up_ramp > 0`" — `max_up_ramp`
///   stops walking at the first confirmed-bad edge from origin, so it
///   reaches 0 iff no such edge exists.
/// - "any pair `NoAttestation` and no pair `NotProviderPlus`" ⇔
///   "`min_up_ramp > 0` and `max_up_ramp == 0`" — `min_up_ramp` stops
///   at any non-`ProviderPlus`.
/// - "every pair `ProviderPlus`" ⇔ "`min_up_ramp == 0`".
///
/// This equivalence is empirically verified by the
/// `spike_bounds_equivalence_on_synthetic_corpus` test in this
/// module, which exhaustively cross-products distinct-ASN paths of
/// length 2..=5
/// drawn from a 6-ASN pool with every per-pair attestation state
/// combination (≈ 69k cases). The bounds-checker reference impl
/// `verify_upstream_bounds_v25` lives in the test module as a
/// regression oracle: any future divergence (e.g. a spec revision
/// that introduces a non-zero `max_down_ramp`) fires the corpus test.
#[must_use]
pub fn verify_upstream(path: &AsPath, table: &AspaTable) -> AspaValidation {
    verify_upstream_with_context_detailed(path, table, AspaValidationContext::default()).state
}

fn verify_upstream_with_context_detailed(
    path: &AsPath,
    table: &AspaTable,
    context: AspaValidationContext,
) -> AspaVerificationResult {
    let Some(compressed) = compress_as_path(path) else {
        return AspaVerificationResult::state(AspaValidation::Invalid); // AS_SET present
    };

    // Empty AS_PATH is Invalid per spec step 1.
    if compressed.is_empty() {
        return AspaVerificationResult::state(AspaValidation::Invalid);
    }

    if !context.first_as_check_exempt
        && !leftmost_as_matches_neighbor(&compressed, context.neighbor_asn)
    {
        return AspaVerificationResult::state(AspaValidation::Invalid);
    }

    // Single-hop path: only origin AS, no pairs to verify → Valid.
    if compressed.len() == 1 {
        return AspaVerificationResult::state(AspaValidation::Valid);
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
                return AspaVerificationResult::invalid(customer, provider);
            }
            ProviderAuth::NoAttestation => {
                // Cannot verify this hop — mark as incomplete.
                has_no_attestation = true;
            }
        }
    }

    if has_no_attestation {
        AspaVerificationResult::state(AspaValidation::Unknown)
    } else {
        AspaVerificationResult::state(AspaValidation::Valid)
    }
}

fn verify_downstream_detailed(
    path: &AsPath,
    table: &AspaTable,
    context: AspaValidationContext,
) -> AspaVerificationResult {
    let Some(compressed) = compress_as_path(path) else {
        return AspaVerificationResult::state(AspaValidation::Invalid); // AS_SET present
    };

    if compressed.is_empty() {
        return AspaVerificationResult::state(AspaValidation::Invalid);
    }

    // Downstream verification always enforces the leftmost-AS precondition:
    // the only role that reaches this path is `Customer` (route received from
    // a provider, which prepends its ASN), and the route-server-client
    // exemption never applies downstream — an RS-client uses upstream
    // verification. `direction_for_role` is the single source of that mapping.
    if !leftmost_as_matches_neighbor(&compressed, context.neighbor_asn) {
        return AspaVerificationResult::state(AspaValidation::Invalid);
    }

    if compressed.len() == 1 {
        return AspaVerificationResult::state(AspaValidation::Valid);
    }

    let origin_to_neighbor: Vec<u32> = compressed.iter().rev().copied().collect();
    let n = origin_to_neighbor.len();
    let (max_up, invalid_hop) = ramp_up_bound(&origin_to_neighbor, table, BoundMode::Max);
    let (min_up, _) = ramp_up_bound(&origin_to_neighbor, table, BoundMode::Min);
    let max_down = ramp_down_bound(&origin_to_neighbor, table, BoundMode::Max);
    let min_down = ramp_down_bound(&origin_to_neighbor, table, BoundMode::Min);

    if max_up + max_down < n {
        AspaVerificationResult {
            state: AspaValidation::Invalid,
            // The downstream Invalid inequality guarantees that the max-up
            // walk encountered `NotProviderPlus`; there is no max-down
            // fallback because it would report a different traversal.
            invalid_hop,
        }
    } else if min_up + min_down < n {
        AspaVerificationResult::state(AspaValidation::Unknown)
    } else {
        AspaVerificationResult::state(AspaValidation::Valid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundMode {
    Max,
    Min,
}

fn ramp_up_bound(
    origin_to_neighbor: &[u32],
    table: &AspaTable,
    mode: BoundMode,
) -> (usize, Option<AspaInvalidHop>) {
    let n = origin_to_neighbor.len();
    for i in 0..n.saturating_sub(1) {
        let customer = origin_to_neighbor[i];
        let provider = origin_to_neighbor[i + 1];
        let auth = table.authorized(customer, provider);
        if stops_ramp(auth, mode) {
            return (
                i + 1,
                (auth == ProviderAuth::NotProviderPlus).then_some(AspaInvalidHop {
                    customer_asn: customer,
                    provider_asn: provider,
                }),
            );
        }
    }
    (n, None)
}

fn ramp_down_bound(origin_to_neighbor: &[u32], table: &AspaTable, mode: BoundMode) -> usize {
    let n = origin_to_neighbor.len();
    for j in (1..n).rev() {
        let customer = origin_to_neighbor[j];
        let provider = origin_to_neighbor[j - 1];
        if stops_ramp(table.authorized(customer, provider), mode) {
            return n - j;
        }
    }
    n
}

fn stops_ramp(auth: ProviderAuth, mode: BoundMode) -> bool {
    match mode {
        BoundMode::Max => auth == ProviderAuth::NotProviderPlus,
        BoundMode::Min => auth != ProviderAuth::ProviderPlus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aspa::AspaRecord;
    use rustbgpd_wire::{AsPathSegment, AspaValidationContext, BgpRole};

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

    fn context(local_role: Option<BgpRole>, neighbor_asn: u32) -> AspaValidationContext {
        AspaValidationContext {
            neighbor_asn: Some(neighbor_asn),
            local_role,
            first_as_check_exempt: matches!(local_role, Some(BgpRole::RouteServerClient)),
        }
    }

    /// Red proof: choosing the last/swapped hop or attaching one to any other
    /// outcome breaks an exact pair/no-pair assertion.
    #[test]
    fn detailed_result_reports_only_first_not_provider_hop() {
        let all_bad = make_table(vec![(1, vec![99]), (2, vec![99]), (3, vec![99])]);
        let path = make_path(&[3, 2, 1]);
        let expected = Some(AspaInvalidHop {
            customer_asn: 1,
            provider_asn: 2,
        });
        assert_eq!(
            verify_detailed(&path, &all_bad, context(None, 3)),
            AspaVerificationResult {
                state: AspaValidation::Invalid,
                invalid_hop: expected,
            }
        );
        assert_eq!(
            verify_detailed(&path, &all_bad, context(Some(BgpRole::Customer), 3)),
            AspaVerificationResult {
                state: AspaValidation::Invalid,
                invalid_hop: expected,
            }
        );

        let empty = make_table(vec![]);
        let valid = make_table(vec![(1, vec![2])]);
        let as_set = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![2, 1])],
        };
        for result in [
            verify_detailed(&make_path(&[2, 1]), &valid, context(None, 2)),
            verify_detailed(&make_path(&[2, 1]), &empty, context(None, 2)),
            verify_detailed(&as_set, &empty, context(None, 2)),
            verify_detailed(&make_path(&[]), &empty, context(None, 2)),
            verify_detailed(&make_path(&[2, 1]), &empty, context(None, 9)),
        ] {
            assert_eq!(result.invalid_hop, None, "state={:?}", result.state);
        }
    }

    #[test]
    fn empty_path_is_invalid() {
        let table = make_table(vec![]);
        let path = AsPath { segments: vec![] };
        assert_eq!(verify_upstream(&path, &table), AspaValidation::Invalid);
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
    fn roleless_context_preserves_upstream_behavior() {
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(
            verify(&path, &table, AspaValidationContext::default()),
            AspaValidation::Valid
        );
    }

    #[test]
    fn upstream_first_as_mismatch_is_invalid() {
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(
            verify(
                &path,
                &table,
                AspaValidationContext {
                    neighbor_asn: Some(65099),
                    local_role: Some(BgpRole::Provider),
                    first_as_check_exempt: false,
                },
            ),
            AspaValidation::Invalid
        );
    }

    #[test]
    fn upstream_route_server_client_exempts_first_as_check() {
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65002, 65001]);
        assert_eq!(
            verify(
                &path,
                &table,
                context(Some(BgpRole::RouteServerClient), 65099)
            ),
            AspaValidation::Valid
        );
    }

    #[test]
    fn downstream_valid_when_ramps_cover_path() {
        let table = make_table(vec![(65001, vec![65002]), (65002, vec![65003])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(
            verify(&path, &table, context(Some(BgpRole::Customer), 65003)),
            AspaValidation::Valid
        );
    }

    #[test]
    fn downstream_unknown_when_only_min_bounds_fail() {
        let table = make_table(vec![(65001, vec![65002])]);
        let path = make_path(&[65004, 65003, 65002, 65001]);
        assert_eq!(
            verify(&path, &table, context(Some(BgpRole::Customer), 65004)),
            AspaValidation::Unknown
        );
    }

    #[test]
    fn downstream_invalid_when_max_bounds_do_not_cover_path() {
        let table = make_table(vec![(65001, vec![65099]), (65004, vec![65099])]);
        let path = make_path(&[65004, 65003, 65002, 65001]);
        assert_eq!(
            verify(&path, &table, context(Some(BgpRole::Customer), 65004)),
            AspaValidation::Invalid
        );
    }

    #[test]
    fn downstream_first_as_mismatch_is_invalid() {
        let table = make_table(vec![(65001, vec![65002]), (65002, vec![65003])]);
        let path = make_path(&[65003, 65002, 65001]);
        assert_eq!(
            verify(&path, &table, context(Some(BgpRole::Customer), 65099)),
            AspaValidation::Invalid
        );
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

    fn nist_brio_common_demo_table() -> AspaTable {
        // NIST-BRIO b7.1.2, commit 23ee402f (2025-08-08):
        // brio-examples/demo-aspa-upstream/{exp13,exp46,exp79}.brio_rc.script
        // and brio-examples/demo-aspa-downstream/{exp1,exp14}.brio_rc.script
        // and brio-examples/demo-aspa-downstream/exp57.README.tpl.md.
        // AS 65060's record is the AS0-only "no providers" attestation,
        // encoded exactly as the cache scripts send it (`addASPA 65060 0`).
        make_table(vec![
            (65000, vec![65020, 65030]),
            (65010, vec![65040]),
            (65020, vec![65050]),
            (65030, vec![65050, 65060]),
            (65060, vec![0]),
        ])
    }

    fn nist_brio_exp910_table() -> AspaTable {
        // NIST-BRIO b7.1.2, commit 23ee402f (2025-08-08):
        // brio-examples/demo-aspa-downstream/exp910.README.tpl.md.
        make_table(vec![
            (65000, vec![65020, 65030]),
            (65010, vec![65040]),
            (65020, vec![65050]),
        ])
    }

    fn assert_nist_brio_case(
        table: &AspaTable,
        local_role: Option<BgpRole>,
        neighbor_asn: u32,
        as_path: &[u32],
        expected: AspaValidation,
    ) {
        assert_eq!(
            verify(
                &make_path(as_path),
                table,
                context(local_role, neighbor_asn)
            ),
            expected,
            "neighbor={neighbor_asn} role={local_role:?} path={as_path:?}"
        );
        assert_eq!(
            verify_detailed(
                &make_path(as_path),
                table,
                context(local_role, neighbor_asn)
            )
            .state,
            expected,
            "detailed neighbor={neighbor_asn} role={local_role:?} path={as_path:?}"
        );
    }

    #[test]
    fn nist_brio_exp13_upstream_vectors() {
        let table = nist_brio_common_demo_table();
        let upstream = Some(BgpRole::Provider);

        // BRIO exp13 bundles upstream examples #1, #2, and #3:
        // F C A => Valid, D C A => Invalid, D F C A => Unknown.
        assert_nist_brio_case(
            &table,
            upstream,
            65050,
            &[65050, 65020, 65000],
            AspaValidation::Valid,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65030,
            &[65030, 65020, 65000],
            AspaValidation::Invalid,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65030,
            &[65030, 65050, 65020, 65000],
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn nist_brio_exp46_upstream_vectors() {
        let table = nist_brio_common_demo_table();
        let upstream = Some(BgpRole::Provider);

        // BRIO exp46 bundles upstream examples #4, #5, and #6, received
        // by C: D E B => Unknown, A D E B => Invalid, A D G E B =>
        // Invalid (G's AS0-only ASPA proves the G→D hop unauthorized).
        assert_nist_brio_case(
            &table,
            upstream,
            65030,
            &[65030, 65040, 65010],
            AspaValidation::Unknown,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65000,
            &[65000, 65030, 65040, 65010],
            AspaValidation::Invalid,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65000,
            &[65000, 65030, 65060, 65040, 65010],
            AspaValidation::Invalid,
        );
    }

    #[test]
    fn nist_brio_exp79_upstream_vectors() {
        let table = nist_brio_common_demo_table();
        let upstream = Some(BgpRole::Provider);

        // BRIO exp79 bundles upstream examples #7, #8, and #9, received
        // by D: A C F => Invalid, A C F G => Invalid (AS0-only ASPA on
        // G), E B => Valid.
        assert_nist_brio_case(
            &table,
            upstream,
            65000,
            &[65000, 65020, 65050],
            AspaValidation::Invalid,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65000,
            &[65000, 65020, 65050, 65060],
            AspaValidation::Invalid,
        );
        assert_nist_brio_case(
            &table,
            upstream,
            65040,
            &[65040, 65010],
            AspaValidation::Valid,
        );
    }

    #[test]
    fn nist_brio_downstream_vectors() {
        let table = nist_brio_common_demo_table();
        let downstream = Some(BgpRole::Customer);

        // BRIO downstream exp1: E G F C A => Unknown.
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65060, 65050, 65020, 65000],
            AspaValidation::Unknown,
        );

        // BRIO downstream exp57 examples #5, #6, and #7:
        // C F D G => Unknown, D G E B => Valid, C D G E B => Invalid.
        assert_nist_brio_case(
            &table,
            downstream,
            65020,
            &[65020, 65050, 65030, 65060],
            AspaValidation::Unknown,
        );
        assert_nist_brio_case(
            &table,
            downstream,
            65030,
            &[65030, 65060, 65040, 65010],
            AspaValidation::Valid,
        );
        assert_nist_brio_case(
            &table,
            downstream,
            65020,
            &[65020, 65030, 65060, 65040, 65010],
            AspaValidation::Invalid,
        );
    }

    #[test]
    fn nist_brio_exp8_downstream_vector() {
        // BRIO downstream exp8: D receives F C A from its provider F =>
        // Valid (a pure up-ramp seen from the down side). exp8's cache
        // script carries a subset of the common demo table; the extra
        // rows (B, G) name ASes absent from this path and cannot change
        // the verdict.
        let table = nist_brio_common_demo_table();
        assert_nist_brio_case(
            &table,
            Some(BgpRole::Customer),
            65050,
            &[65050, 65020, 65000],
            AspaValidation::Valid,
        );
    }

    #[test]
    fn nist_brio_exp14_downstream_vectors() {
        let table = nist_brio_common_demo_table();
        let downstream = Some(BgpRole::Customer);

        // BRIO exp14 bundles downstream examples received by B from its
        // provider E (#1, E G F C A => Unknown, is already pinned by the
        // exp1 vector above): E G D A => Valid, E D C A => Unknown,
        // E G D C A => Invalid.
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65060, 65030, 65000],
            AspaValidation::Valid,
        );
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65030, 65020, 65000],
            AspaValidation::Unknown,
        );
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65060, 65030, 65020, 65000],
            AspaValidation::Invalid,
        );
    }

    #[test]
    fn nist_brio_exp910_downstream_limit_vectors() {
        let table = nist_brio_exp910_table();
        let downstream = Some(BgpRole::Customer);

        // BRIO exp910 documents forged-origin / forged-segment paths that
        // remain ASPA-Valid. These pin the expected limitation rather than a
        // stronger security claim.
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65000],
            AspaValidation::Valid,
        );
        assert_nist_brio_case(
            &table,
            downstream,
            65040,
            &[65040, 65020, 65000],
            AspaValidation::Valid,
        );
    }

    // ----------------------------------------------------------------
    // Bounds-checker equivalence spike (draft-ietf-sidrops-aspa-
    // verification-25 §5.3 / §5.4).
    //
    // The production `verify_upstream` is a pairwise walk: any
    // `NotProviderPlus` → Invalid; any `NoAttestation` (and no
    // `NotProviderPlus`) → Unknown; otherwise Valid.
    //
    // Draft v25 §5.3 specifies the algorithm in a bounds-checker form:
    // walk from origin toward neighbor twice, computing `max_up_ramp`
    // (treating `NoAttestation` as optimistic-pass) and `min_up_ramp`
    // (strict, only `ProviderPlus` passes). For *upstream* §5.4 the
    // verdict is:
    //
    //   max_up_ramp > 0  → Invalid  (confirmed bad edge in the path)
    //   min_up_ramp > 0  → Unknown  (no confirmed bad, but missing data)
    //   min_up_ramp == 0 → Valid    (every edge fully attested)
    //
    // The hypothesis is that these two formulations are semantically
    // equivalent for upstream (where the §5.4 simplification
    // `max_down_ramp = min_down_ramp = 0` collapses the bounds check
    // into the pairwise walk). The corpus test below is the empirical
    // proof on a synthesized exhaustive cross product of small inputs.
    // If it ever fails on a future draft revision or a refactor, the
    // spike has caught a real divergence and the failing case prints.
    // ----------------------------------------------------------------

    /// Faithful transcription of draft v25 §5.3-5.4 upstream
    /// verification in the bounds-checker form. Used as a regression
    /// oracle against the production pairwise walk. NOT for production
    /// use — `verify_upstream` is the authoritative entry point.
    fn verify_upstream_bounds_v25(path: &AsPath, table: &AspaTable) -> AspaValidation {
        let Some(hops) = compress_as_path(path) else {
            return AspaValidation::Invalid;
        };

        if hops.is_empty() {
            return AspaValidation::Invalid;
        }
        if hops.len() == 1 {
            return AspaValidation::Valid;
        }

        let n = hops.len();

        // max_up_ramp: walking from origin (hops[n-1]) toward neighbor
        // (hops[0]), how far can we walk treating `NoAttestation` as
        // optimistic-pass? Stops at the first confirmed-bad edge.
        let mut max_up_ramp = n - 1;
        for i in (1..n).rev() {
            let customer = hops[i];
            let provider = hops[i - 1];
            match table.authorized(customer, provider) {
                ProviderAuth::ProviderPlus | ProviderAuth::NoAttestation => {
                    max_up_ramp = i - 1;
                }
                ProviderAuth::NotProviderPlus => break,
            }
        }

        // min_up_ramp: same walk, but only `ProviderPlus` passes. Stops
        // at the first non-`ProviderPlus` edge (missing OR bad).
        let mut min_up_ramp = n - 1;
        for i in (1..n).rev() {
            let customer = hops[i];
            let provider = hops[i - 1];
            match table.authorized(customer, provider) {
                ProviderAuth::ProviderPlus => {
                    min_up_ramp = i - 1;
                }
                ProviderAuth::NoAttestation | ProviderAuth::NotProviderPlus => break,
            }
        }

        // §5.4 upstream verdict (with max_down_ramp = min_down_ramp = 0).
        if max_up_ramp > 0 {
            AspaValidation::Invalid
        } else if min_up_ramp > 0 {
            AspaValidation::Unknown
        } else {
            AspaValidation::Valid
        }
    }

    /// Per-pair attestation state used to synthesize an `AspaTable`
    /// that produces a chosen `ProviderAuth` verdict at each edge of
    /// a path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PairState {
        /// Customer attests provider as upstream.
        Pp,
        /// Customer attests SOMEONE ELSE as upstream (provider is not in the set).
        Npp,
        /// No ASPA record exists for this customer.
        NoAtt,
    }

    /// Build an `AspaTable` whose `authorized(hops[i], hops[i-1])`
    /// matches `states[i-1]` for every pair in the path. Requires
    /// `hops` to have distinct ASNs (else a single customer ASN could
    /// be constrained inconsistently across pairs).
    ///
    /// For `Npp`, fabricates an ASPA record for the customer that
    /// lists an out-of-pool ASN (`99`) so that the actual provider is
    /// proven absent.
    fn build_table_from_states(hops: &[u32], states: &[PairState]) -> AspaTable {
        assert_eq!(states.len() + 1, hops.len());
        // Distinct-ASN precondition keeps the table construction sound.
        let mut sorted = hops.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), hops.len(), "hops must have distinct ASNs");

        let mut records = Vec::new();
        for (i, state) in states.iter().enumerate() {
            let customer = hops[i + 1];
            let provider = hops[i];
            match state {
                PairState::Pp => records.push(AspaRecord {
                    customer_asn: customer,
                    provider_asns: vec![provider],
                }),
                PairState::Npp => records.push(AspaRecord {
                    customer_asn: customer,
                    // ASN 99 is outside the test ASN pool {1..=6}, so it
                    // cannot accidentally equal the actual provider.
                    provider_asns: vec![99],
                }),
                PairState::NoAtt => {}
            }
        }
        make_table(
            records
                .into_iter()
                .map(|r| (r.customer_asn, r.provider_asns))
                .collect(),
        )
    }

    /// Enumerate all length-`k` permutations of distinct ASNs drawn
    /// from `pool`. Recursive, returns vectors of length `k`.
    fn distinct_paths(pool: &[u32], k: usize) -> Vec<Vec<u32>> {
        fn recurse(pool: &[u32], k: usize, prefix: &mut Vec<u32>, out: &mut Vec<Vec<u32>>) {
            if prefix.len() == k {
                out.push(prefix.clone());
                return;
            }
            for &asn in pool {
                if !prefix.contains(&asn) {
                    prefix.push(asn);
                    recurse(pool, k, prefix, out);
                    prefix.pop();
                }
            }
        }
        let mut out = Vec::new();
        recurse(pool, k, &mut Vec::new(), &mut out);
        out
    }

    /// Enumerate all `3^n` state-combinations of length `n`.
    fn all_state_combos(n: usize) -> Vec<Vec<PairState>> {
        let mut out = Vec::new();
        // `n` is small (≤ 4 for the spike corpus); fold rather than `pow`
        // sidesteps the usize→u32 cast that would trigger clippy.
        let total: usize = (0..n).fold(1, |acc, _| acc * 3);
        for mask in 0..total {
            let mut combo = Vec::with_capacity(n);
            let mut m = mask;
            for _ in 0..n {
                combo.push(match m % 3 {
                    0 => PairState::Pp,
                    1 => PairState::Npp,
                    _ => PairState::NoAtt,
                });
                m /= 3;
            }
            out.push(combo);
        }
        out
    }

    #[test]
    fn spike_bounds_equivalence_on_synthetic_corpus() {
        // Pool of 6 ASNs; paths of length 2..=5 with all distinct ASNs;
        // every possible per-pair state combination. Cross product
        // size: P(6,2)·3 + P(6,3)·9 + P(6,4)·27 + P(6,5)·81 ≈ 69k cases.
        let pool: Vec<u32> = (1..=6).collect();
        let mut cases_checked = 0usize;
        for path_len in 2..=5 {
            let paths = distinct_paths(&pool, path_len);
            let combos = all_state_combos(path_len - 1);
            for hops in &paths {
                for states in &combos {
                    let table = build_table_from_states(hops, states);
                    let path = make_path(hops);
                    let prod = verify_upstream(&path, &table);
                    let detailed = verify_detailed(&path, &table, AspaValidationContext::default());
                    let refr = verify_upstream_bounds_v25(&path, &table);
                    assert_eq!(
                        prod, refr,
                        "divergence: hops={hops:?} states={states:?} \
                         prod={prod:?} ref={refr:?}"
                    );
                    assert_eq!(detailed.state, prod, "detailed verdict drifted");
                    cases_checked += 1;
                }
            }
        }
        // Sanity: corpus is the expected size.
        // P(6,2)=30·3=90; P(6,3)=120·9=1080; P(6,4)=360·27=9720;
        // P(6,5)=720·81=58320. Total = 69210.
        assert_eq!(cases_checked, 69210, "corpus size drifted");
    }

    #[test]
    fn spike_bounds_equivalence_on_edge_lengths() {
        // Length 1 (no pairs) and the empty-path / AS_SET / consecutive-
        // duplicate edge cases are covered by the existing simple tests
        // and by both impls' early returns. Re-check them here through
        // the reference oracle to pin the contract.
        let empty_table = make_table(vec![]);

        let empty_path = AsPath { segments: vec![] };
        assert_eq!(
            verify_upstream(&empty_path, &empty_table),
            verify_upstream_bounds_v25(&empty_path, &empty_table),
        );

        let single = make_path(&[1]);
        assert_eq!(
            verify_upstream(&single, &empty_table),
            verify_upstream_bounds_v25(&single, &empty_table),
        );

        let as_set = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![1]),
                AsPathSegment::AsSet(vec![2, 3]),
            ],
        };
        assert_eq!(
            verify_upstream(&as_set, &empty_table),
            verify_upstream_bounds_v25(&as_set, &empty_table),
        );

        // Consecutive duplicates collapse to one ASN under compression;
        // both impls share `compress_as_path`, so equivalence here is
        // structural rather than algorithmic — but worth pinning.
        let prepended = make_path(&[2, 1, 1, 1]);
        let pp_table = make_table(vec![(1, vec![2])]);
        assert_eq!(
            verify_upstream(&prepended, &pp_table),
            verify_upstream_bounds_v25(&prepended, &pp_table),
        );
    }

    #[test]
    fn spike_draft_v25_examples() {
        // A handful of named cases drawn from draft v25 §5.4 prose,
        // each spelled out for human-readable debugging if the corpus
        // test ever fires.

        // (a) Two-hop fully attested upstream: Valid.
        {
            let table = make_table(vec![(1, vec![2])]);
            let path = make_path(&[2, 1]); // neighbor=2, origin=1
            assert_eq!(
                verify_upstream_bounds_v25(&path, &table),
                AspaValidation::Valid
            );
        }
        // (b) Two-hop with NotProviderPlus: Invalid.
        {
            let table = make_table(vec![(1, vec![99])]); // 1 says 99 is its provider, not 2
            let path = make_path(&[2, 1]);
            assert_eq!(
                verify_upstream_bounds_v25(&path, &table),
                AspaValidation::Invalid
            );
        }
        // (c) Two-hop with NoAttestation: Unknown.
        {
            let table = make_table(vec![]);
            let path = make_path(&[2, 1]);
            assert_eq!(
                verify_upstream_bounds_v25(&path, &table),
                AspaValidation::Unknown
            );
        }
        // (d) Three-hop with NoAttestation in the middle, ProviderPlus
        //     elsewhere — bounds reach origin-side but not all the way:
        //     Unknown (matches production).
        {
            let table = make_table(vec![(1, vec![2])]); // (3,2) has no attestation
            let path = make_path(&[3, 2, 1]); // neighbor=3 → 2 → origin=1
            assert_eq!(
                verify_upstream_bounds_v25(&path, &table),
                AspaValidation::Unknown
            );
        }
        // (e) Three-hop with NotProviderPlus at neighbor side and
        //     NoAttestation at origin side — Invalid still wins.
        {
            let table = make_table(vec![(2, vec![99])]); // (2,3) is NotProviderPlus
            let path = make_path(&[3, 2, 1]); // no ASPA for 1; bad edge (2→3)
            assert_eq!(
                verify_upstream_bounds_v25(&path, &table),
                AspaValidation::Invalid
            );
        }
    }
}
