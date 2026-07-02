//! Best-path selection per RFC 4271 §9.1.2.
//!
//! Uses deterministic MED (always-compare) for simplicity, matching `GoBGP`.

use std::cmp::Ordering;

use rustbgpd_wire::{AsPath, AspaValidation, RpkiValidation};

use crate::route::Route;

/// Numeric preference for RPKI validation state: higher = more preferred.
fn rpki_preference(v: RpkiValidation) -> u8 {
    match v {
        RpkiValidation::Valid => 2,
        RpkiValidation::NotFound => 1,
        RpkiValidation::Invalid => 0,
    }
}

/// Numeric preference for ASPA path verification state: higher = more preferred.
fn aspa_preference(v: AspaValidation) -> u8 {
    match v {
        AspaValidation::Valid => 2,
        AspaValidation::Unknown => 1,
        AspaValidation::Invalid => 0,
    }
}

/// Three-tier stale ranking: fresh (0) > GR-stale (1) > LLGR-stale (2).
/// Lower value = more preferred.
fn stale_rank(route: &Route) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

/// The decisive step in a best-path comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BestPathReason {
    /// Step 0: non-stale preferred over stale (RFC 4724 / RFC 9494).
    StalePreference,
    /// Step 0.5: RPKI validation preference (`Valid` > `NotFound` > `Invalid`).
    RpkiPreference,
    /// Step 0.7: ASPA path verification preference (Valid > Unknown > Invalid).
    AspaPreference,
    /// Step 1: higher `LOCAL_PREF` wins.
    HigherLocalPref,
    /// Step 2: shorter `AS_PATH` wins.
    ShorterAsPath,
    /// Step 3: lower ORIGIN type wins (IGP < EGP < Incomplete).
    LowerOrigin,
    /// Step 4: lower MED wins (deterministic / always-compare).
    LowerMed,
    /// Step 5: eBGP preferred over iBGP.
    EbgpOverIbgp,
    /// Step 5.3 (RFC 9107 ORR only): lower vantage interior cost to
    /// `NEXT_HOP` wins; a known cost beats an unknown one. Never produced
    /// by the Loc-RIB ladder (`best_path_cmp_with_reason` carries no
    /// vantage costs) — only [`best_path_cmp_orr_with_reason`] yields it.
    OrrInteriorCost,
    /// Step 5.5: shorter `CLUSTER_LIST` wins (RFC 4456).
    ShorterClusterList,
    /// Step 5.6: lower `ORIGINATOR_ID` wins (RFC 4456).
    LowerOriginatorId,
    /// Step 6: lower peer address (final tiebreaker).
    LowerPeerAddress,
    /// EVPN Type 2 only: higher MAC Mobility sequence number wins, with
    /// sticky-MAC preservation (RFC 7432 §15.1).
    EvpnMacMobility,
}

impl BestPathReason {
    /// Stable `snake_case` identifier for this step (the string behind
    /// `Display` — usable where a `&'static str` code is required).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StalePreference => "stale_preference",
            Self::RpkiPreference => "rpki_preference",
            Self::AspaPreference => "aspa_preference",
            Self::HigherLocalPref => "higher_local_pref",
            Self::ShorterAsPath => "shorter_as_path",
            Self::LowerOrigin => "lower_origin",
            Self::LowerMed => "lower_med",
            Self::EbgpOverIbgp => "ebgp_over_ibgp",
            Self::OrrInteriorCost => "orr_interior_cost",
            Self::ShorterClusterList => "shorter_cluster_list",
            Self::LowerOriginatorId => "lower_originator_id",
            Self::LowerPeerAddress => "lower_peer_address",
            Self::EvpnMacMobility => "evpn_mac_mobility",
        }
    }
}

impl std::fmt::Display for BestPathReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Compare two routes and return the decisive reason.
///
/// Same logic as [`best_path_cmp`] but also returns which step broke the tie.
#[must_use]
pub fn best_path_cmp_with_reason(a: &Route, b: &Route) -> (Ordering, BestPathReason) {
    let cmp = stale_rank(a).cmp(&stale_rank(b));
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::StalePreference);
    }

    let cmp = rpki_preference(b.validation_state).cmp(&rpki_preference(a.validation_state));
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::RpkiPreference);
    }

    let cmp = aspa_preference(b.aspa_state).cmp(&aspa_preference(a.aspa_state));
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::AspaPreference);
    }

    let cmp = b.local_pref().cmp(&a.local_pref());
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::HigherLocalPref);
    }

    let a_len = a.as_path().map_or(0, AsPath::len);
    let b_len = b.as_path().map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::ShorterAsPath);
    }

    let cmp = a.origin().cmp(&b.origin());
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::LowerOrigin);
    }

    let cmp = a.med().cmp(&b.med());
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::LowerMed);
    }

    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::EbgpOverIbgp);
    }

    let cmp = a.cluster_list().len().cmp(&b.cluster_list().len());
    if cmp != Ordering::Equal {
        return (cmp, BestPathReason::ShorterClusterList);
    }

    if let (Some(a_oid), Some(b_oid)) = (a.originator_id(), b.originator_id()) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return (cmp, BestPathReason::LowerOriginatorId);
        }
    }

    (a.peer.cmp(&b.peer), BestPathReason::LowerPeerAddress)
}

/// Compare two routes under RFC 9107 ORR and return the decisive reason.
///
/// Same ordering as [`best_path_cmp_orr`], derived by composition rather
/// than a third hand-maintained ladder: the plain reason ladder decides
/// unless its decisive step is one of the tiebreakers *below* the ORR
/// interior-cost step (`CLUSTER_LIST`, `ORIGINATOR_ID`, peer address) —
/// in that case the vantage cost gets first shot and, when decisive,
/// yields [`BestPathReason::OrrInteriorCost`].
#[must_use]
pub fn best_path_cmp_orr_with_reason(
    a: &Route,
    b: &Route,
    cost_a: Option<u64>,
    cost_b: Option<u64>,
) -> (Ordering, BestPathReason) {
    let (ord, reason) = best_path_cmp_with_reason(a, b);
    let below_orr_step = matches!(
        reason,
        BestPathReason::ShorterClusterList
            | BestPathReason::LowerOriginatorId
            | BestPathReason::LowerPeerAddress
    );
    if ord != Ordering::Equal && !below_orr_step {
        return (ord, reason);
    }
    let cost_cmp = match (cost_a, cost_b) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    if cost_cmp != Ordering::Equal {
        return (cost_cmp, BestPathReason::OrrInteriorCost);
    }
    (ord, reason)
}

/// Render an ORR vantage cost for explain output: the interior metric,
/// or `unreachable` when the vantage has no known cost to the next-hop.
fn orr_cost_str(cost: Option<u64>) -> String {
    cost.map_or_else(|| "unreachable".to_string(), |c| c.to_string())
}

/// Render the compared vantage costs behind a decisive
/// [`BestPathReason::OrrInteriorCost`], `a`'s cost on the left —
/// e.g. `"orr_cost 12 < 40"` or `"orr_cost 12 < unreachable"` (RFC 9107
/// §3.1: an unknown metric-to-next-hop is least preferred).
///
/// Explain-only, like [`best_path_reason_detail`] — the costs live on
/// the ORR distribution path, not on [`Route`], so they are passed in.
#[must_use]
pub fn orr_interior_cost_detail(cost_a: Option<u64>, cost_b: Option<u64>) -> String {
    let symbol = match (cost_a, cost_b) {
        (Some(x), Some(y)) => cmp_symbol(&x, &y),
        (Some(_), None) => "<",
        (None, Some(_)) => ">",
        (None, None) => "=",
    };
    format!(
        "orr_cost {} {symbol} {}",
        orr_cost_str(cost_a),
        orr_cost_str(cost_b)
    )
}

/// Relational symbol for a compared pair, read left-to-right:
/// `a < b`, `a = b`, or `a > b`.
fn cmp_symbol<T: Ord>(a: &T, b: &T) -> &'static str {
    match a.cmp(b) {
        Ordering::Less => "<",
        Ordering::Equal => "=",
        Ordering::Greater => ">",
    }
}

/// Operator-facing name for a route's stale tier (see [`stale_rank`]).
fn stale_tier_name(route: &Route) -> &'static str {
    match stale_rank(route) {
        0 => "fresh",
        1 => "gr_stale",
        _ => "llgr_stale",
    }
}

/// Render the compared values behind a decisive [`BestPathReason`] for
/// the pair `(a, b)`, e.g. `"local_pref 100 < 200"` — `a`'s value on
/// the left, `b`'s on the right.
///
/// Explain-only: this allocates per call and exists solely for the
/// on-demand `ExplainBestPath` query. It must never be called from the
/// live comparator path ([`best_path_cmp`] stays allocation-free).
#[must_use]
pub fn best_path_reason_detail(reason: BestPathReason, a: &Route, b: &Route) -> String {
    match reason {
        BestPathReason::StalePreference => {
            format!(
                "stale_tier {} vs {}",
                stale_tier_name(a),
                stale_tier_name(b)
            )
        }
        BestPathReason::RpkiPreference => {
            format!("rpki {} vs {}", a.validation_state, b.validation_state)
        }
        BestPathReason::AspaPreference => {
            format!("aspa {} vs {}", a.aspa_state, b.aspa_state)
        }
        BestPathReason::HigherLocalPref => {
            let (x, y) = (a.local_pref(), b.local_pref());
            format!("local_pref {x} {} {y}", cmp_symbol(&x, &y))
        }
        BestPathReason::ShorterAsPath => {
            let x = a.as_path().map_or(0, AsPath::len);
            let y = b.as_path().map_or(0, AsPath::len);
            format!("as_path_len {x} {} {y}", cmp_symbol(&x, &y))
        }
        BestPathReason::LowerOrigin => {
            format!("origin {} vs {}", a.origin(), b.origin()).to_ascii_lowercase()
        }
        BestPathReason::LowerMed => {
            let (x, y) = (a.med(), b.med());
            format!("med {x} {} {y}", cmp_symbol(&x, &y))
        }
        BestPathReason::EbgpOverIbgp => {
            let kind = |ebgp: bool| if ebgp { "ebgp" } else { "ibgp" };
            format!("{} vs {}", kind(a.is_ebgp()), kind(b.is_ebgp()))
        }
        BestPathReason::ShorterClusterList => {
            let (x, y) = (a.cluster_list().len(), b.cluster_list().len());
            format!("cluster_list_len {x} {} {y}", cmp_symbol(&x, &y))
        }
        BestPathReason::LowerOriginatorId => match (a.originator_id(), b.originator_id()) {
            (Some(x), Some(y)) => format!("originator_id {x} {} {y}", cmp_symbol(&x, &y)),
            // Defensive: the comparator only returns this reason when
            // both routes carry ORIGINATOR_ID.
            _ => "originator_id absent".to_string(),
        },
        BestPathReason::LowerPeerAddress => {
            format!(
                "peer {} {} {}",
                a.peer,
                cmp_symbol(&a.peer, &b.peer),
                b.peer
            )
        }
        // Not produced by the unicast ladder; EVPN MAC mobility carries
        // its sequence in EVPN-specific route state, not on `Route`.
        BestPathReason::EvpnMacMobility => "mac_mobility_sequence".to_string(),
        // Not produced by `best_path_cmp_with_reason` either — the
        // vantage costs live on the ORR distribution path, not on
        // `Route`; callers with costs use `orr_interior_cost_detail`.
        BestPathReason::OrrInteriorCost => "orr_interior_cost_to_next_hop".to_string(),
    }
}

/// How a candidate relates to the best route under the ADR-0066
/// equal-cost (ECMP) grouping rules — the "multipath cut".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathEligibility {
    /// Not co-installable with the best route under any setting.
    None,
    /// Co-installable under the strict default (exact `AS_PATH` match).
    Eligible,
    /// Co-installable only with multipath-relax (`AS_PATH` length match,
    /// ADR-0066 / FRR `as-path multipath-relax`).
    RelaxOnly,
}

impl std::fmt::Display for MultipathEligibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Eligible => write!(f, "eligible"),
            Self::RelaxOnly => write!(f, "relax_only"),
        }
    }
}

/// Classify `other`'s ECMP grouping vs `best` under both the strict
/// default and multipath-relax.
///
/// Explain-only enrichment for the `ExplainBestPath` point query. The
/// live multipath cut keeps using [`multipath_equal`] with the
/// operator's actual per-table `relax` knob; this reports both answers
/// because the explain query does not know which knob a given FIB table
/// uses.
#[must_use]
pub fn multipath_eligibility(best: &Route, other: &Route) -> MultipathEligibility {
    if multipath_equal(best, other, false) {
        MultipathEligibility::Eligible
    } else if multipath_equal(best, other, true) {
        MultipathEligibility::RelaxOnly
    } else {
        MultipathEligibility::None
    }
}

/// Compare two routes for best-path selection.
///
/// The preferred route sorts `Less`. Decision steps (RFC 4271 §9.1.2):
/// 0. Non-stale preferred over stale (RFC 4724 / RFC 9494 three-tier)
/// 0.5. RPKI validation: Valid > `NotFound` > Invalid (RFC 6811)
/// 0.7. ASPA path verification: Valid > Unknown > Invalid
/// 1. Highest `LOCAL_PREF` (default 100)
/// 2. Shortest `AS_PATH` length (default 0)
/// 3. Lowest ORIGIN — IGP < EGP < INCOMPLETE
/// 4. Lowest MED (default 0; always-compare / deterministic MED)
/// 5. eBGP over iBGP
///    5.3. ORR interior cost (RFC 9107) — [`best_path_cmp_orr`] only;
///    this comparator never runs it
///    5.5. Shortest `CLUSTER_LIST` length (RFC 4456 §9)
///    5.6. Lowest `ORIGINATOR_ID` (RFC 4456 §9) — only when both present
/// 6. Lowest peer address (tiebreaker)
#[must_use]
pub fn best_path_cmp(a: &Route, b: &Route) -> Ordering {
    cmp_chain(a, b, None)
}

/// Compare two routes under RFC 9107 Optimal Route Reflection.
///
/// The standard [`best_path_cmp`] chain with one extra step between
/// step 5 (eBGP over iBGP) and step 5.5 (`CLUSTER_LIST`): the
/// configured vantage's interior (SPF) cost to each route's `NEXT_HOP`.
/// Lower cost wins; a known cost beats an unknown one (RFC 9107 §3.1:
/// an unknown metric-to-next-hop MUST be least preferred); equal or
/// both-unknown falls through to `CLUSTER_LIST`.
#[must_use]
pub fn best_path_cmp_orr(
    a: &Route,
    b: &Route,
    cost_a: Option<u64>,
    cost_b: Option<u64>,
) -> Ordering {
    cmp_chain(a, b, Some((cost_a, cost_b)))
}

/// The shared decision chain behind [`best_path_cmp`] (`orr_costs =
/// None`) and [`best_path_cmp_orr`] (`orr_costs = Some(..)`).
fn cmp_chain(a: &Route, b: &Route, orr_costs: Option<(Option<u64>, Option<u64>)>) -> Ordering {
    // 0. Three-tier stale demotion: fresh > GR-stale > LLGR-stale (RFC 4724 + RFC 9494)
    let cmp = stale_rank(a).cmp(&stale_rank(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 0.5. RPKI validation: Valid > NotFound > Invalid (higher preference wins)
    let cmp = rpki_preference(b.validation_state).cmp(&rpki_preference(a.validation_state));
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 0.7. ASPA path verification: Valid > Unknown > Invalid
    let cmp = aspa_preference(b.aspa_state).cmp(&aspa_preference(a.aspa_state));
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 1. Highest LOCAL_PREF wins → reverse comparison
    let cmp = b.local_pref().cmp(&a.local_pref());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 2. Shortest AS_PATH
    let a_len = a.as_path().map_or(0, AsPath::len);
    let b_len = b.as_path().map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 3. Lowest ORIGIN (IGP=0 < EGP=1 < Incomplete=2)
    let cmp = a.origin().cmp(&b.origin());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 4. Lowest MED (always-compare / deterministic)
    let cmp = a.med().cmp(&b.med());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5. eBGP over iBGP (only RouteOrigin::Ebgp gets preference here;
    //    RouteOrigin::Local sorts equal to iBGP — local routes win via
    //    LOCAL_PREF or shorter AS_PATH, not an explicit origin preference)
    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5.3. RFC 9107 ORR interior cost to NEXT_HOP — only when the
    //      caller supplies vantage costs (the Loc-RIB never does).
    //      Lower cost wins; Some beats None (unknown metric MUST be
    //      least preferred); equal or both-None falls through.
    if let Some((cost_a, cost_b)) = orr_costs {
        let cmp = match (cost_a, cost_b) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    // 5.5. Shortest CLUSTER_LIST length (RFC 4456 §9)
    let cmp = a.cluster_list().len().cmp(&b.cluster_list().len());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5.6. Lowest ORIGINATOR_ID (RFC 4456 §9) — only when both present
    if let (Some(a_oid), Some(b_oid)) = (a.originator_id(), b.originator_id()) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    // 6. Lowest peer address (final tiebreaker)
    a.peer.cmp(&b.peer)
}

/// Whether `other` is co-installable with the best route `best` as an
/// equal-cost (ECMP) sibling.
///
/// Two paths group together iff they tie on every decision step *above* the
/// next-hop-distinguishing tiebreakers — stale tier, RPKI, ASPA, `LOCAL_PREF`,
/// `AS_PATH`, `ORIGIN`, `MED` — **and** are the same eBGP/iBGP class (a group is
/// never mixed; forwarding across an eBGP and an iBGP path at once is not a
/// thing operators expect). The tiebreakers `best_path_cmp` applies below this
/// point (`CLUSTER_LIST` length, `ORIGINATOR_ID`, peer address) are deliberately
/// *not* compared: those exist precisely to pick one winner among otherwise
/// co-equal paths, which are exactly the paths we want to bundle.
///
/// `AS_PATH` is compared for **full equality** (not just length) — the
/// conservative `maximum-paths` default (matches FRR without
/// `as-path multipath-relax`). Loosening to length-only is an explicit opt-in
/// knob, not the default behavior.
///
/// iBGP grouping is well-defined here despite the lack of an IGP: `best_path_cmp`
/// has no IGP-metric step (the daemon carries a directly-usable next-hop and does
/// no recursive resolution) — the metric step is absent except under RFC 9107
/// ORR, where `best_path_cmp_orr` compares the configured vantage's SPF cost to
/// `NEXT_HOP` at distribution time (never here or in the Loc-RIB) — so iBGP
/// equal-cost is fully determined by the BGP decision chain above.
///
/// Locally injected (controller) routes never participate in maximum-paths — they
/// install as the single best path — so a `RouteOrigin::Local` on either side
/// disqualifies grouping (see `same_multipath_class`).
#[must_use]
pub fn multipath_equal(best: &Route, other: &Route, relax: bool) -> bool {
    // `relax` is ADR-0066 multipath-relax (FRR's `bgp bestpath as-path
    // multipath-relax`): group by AS_PATH *length* rather than an exact AS_PATH
    // match, so equal-length paths through different ASes co-install as ECMP.
    // Off by default — the strict path compares the full AS_PATH.
    let as_path_equal = if relax {
        best.as_path().map_or(0, AsPath::len) == other.as_path().map_or(0, AsPath::len)
    } else {
        best.as_path() == other.as_path()
    };
    stale_rank(best) == stale_rank(other)
        && rpki_preference(best.validation_state) == rpki_preference(other.validation_state)
        && aspa_preference(best.aspa_state) == aspa_preference(other.aspa_state)
        && best.local_pref() == other.local_pref()
        && as_path_equal
        && best.origin() == other.origin()
        && best.med() == other.med()
        && same_multipath_class(best, other)
}

/// ADR-0068 weighted multipath: normalize a multipath group's next-hop weights
/// from their Link Bandwidth Extended Communities.
///
/// Returns one kernel weight (`1..=256`) per input, in order. Weighting applies
/// only when `weighted` is on **and** every next-hop carries a finite, positive
/// bandwidth; otherwise every next-hop gets weight `1` (equal cost — the
/// ADR-0066 default, byte-for-byte). The largest bandwidth maps to 256 and the
/// rest scale in proportion, so the kernel distributes traffic by the bandwidth
/// ratio. The all-or-nothing rule avoids inventing a bandwidth for a path that
/// never advertised one.
#[must_use]
pub(crate) fn link_bandwidth_weights(weighted: bool, bandwidths: &[Option<f32>]) -> Vec<u16> {
    let all_present = !bandwidths.is_empty()
        && bandwidths
            .iter()
            .all(|b| b.is_some_and(|v| v.is_finite() && v > 0.0));
    if !weighted || !all_present {
        return vec![1; bandwidths.len()];
    }
    let max = bandwidths
        .iter()
        .map(|b| b.unwrap_or(0.0))
        .fold(0.0_f32, f32::max);
    bandwidths
        .iter()
        .map(|b| {
            // Clamped to [1, 256]: the cast is exact and non-negative.
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "weights are clamped to the positive u16 ECMP range before casting"
            )]
            let weight = (b.unwrap_or(0.0) / max * 256.0).round().clamp(1.0, 256.0) as u16;
            weight
        })
        .collect()
}

/// eBGP groups only with eBGP and iBGP only with iBGP. `RouteOrigin::Local`
/// (controller-injected) routes are *not* part of maximum-paths, so any Local on
/// either side returns `false` — `best.is_ebgp() == other.is_ebgp()` would wrongly
/// treat Local and iBGP as the same "not-eBGP" class and co-install them.
fn same_multipath_class(a: &Route, b: &Route) -> bool {
    use crate::route::RouteOrigin;
    matches!(
        (&a.origin_type, &b.origin_type),
        (RouteOrigin::Ebgp, RouteOrigin::Ebgp) | (RouteOrigin::Ibgp, RouteOrigin::Ibgp)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

    use super::*;
    use crate::route::{Route, RouteOrigin};

    fn base_route(peer: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(peer),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(peer),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    fn with_local_pref(mut r: Route, lp: u32) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::LocalPref(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::LocalPref(lp));
        r
    }

    fn with_as_path(mut r: Route, asns: Vec<u32>) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::AsPath(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }));
        r
    }

    fn with_origin(mut r: Route, origin: Origin) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::Origin(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::Origin(origin));
        r
    }

    fn with_med(mut r: Route, med: u32) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::Med(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::Med(med));
        r
    }

    const fn with_ibgp(mut r: Route) -> Route {
        r.origin_type = RouteOrigin::Ibgp;
        r
    }

    const fn with_local(mut r: Route) -> Route {
        r.origin_type = RouteOrigin::Local;
        r
    }

    // --- multipath_equal tests ---

    #[test]
    fn multipath_equal_true_for_co_equal_paths_differing_only_on_tiebreakers() {
        // Same LP/AS_PATH/ORIGIN/MED/class; differ only on peer + next-hop
        // (the tiebreakers we deliberately ignore) → co-installable.
        let best = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let other = base_route(Ipv4Addr::new(1, 0, 0, 2));
        assert!(multipath_equal(&best, &other, false));
    }

    #[test]
    fn multipath_equal_false_on_local_pref() {
        let best = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let other = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert!(!multipath_equal(&best, &other, false));
        // Relax only touches AS_PATH — LOCAL_PREF still disqualifies.
        assert!(!multipath_equal(&best, &other, true));
    }

    #[test]
    fn multipath_equal_false_on_as_path_length() {
        let best = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 1)), vec![65001]);
        let other = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 2)), vec![65001, 65002]);
        assert!(!multipath_equal(&best, &other, false));
        // Different *lengths* never group, even with relax.
        assert!(!multipath_equal(&best, &other, true));
    }

    #[test]
    fn multipath_equal_exact_as_path_strict_vs_relax() {
        // Equal length, different ASNs: strict mode refuses (exact AS_PATH);
        // multipath-relax groups them (ADR-0066, FRR's as-path multipath-relax).
        let best = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 1)), vec![65001, 65010]);
        let other = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 2)), vec![65001, 65020]);
        assert!(!multipath_equal(&best, &other, false));
        assert!(multipath_equal(&best, &other, true));
    }

    #[test]
    fn multipath_equal_false_on_origin_and_med() {
        let best = base_route(Ipv4Addr::new(1, 0, 0, 1));
        assert!(!multipath_equal(
            &best,
            &with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Egp),
            false
        ));
        assert!(!multipath_equal(
            &best,
            &with_med(base_route(Ipv4Addr::new(1, 0, 0, 2)), 50),
            false
        ));
    }

    #[test]
    fn multipath_equal_false_mixing_ebgp_and_ibgp() {
        // Groups are homogeneous: never bundle an eBGP path with an iBGP path.
        let ebgp = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let ibgp = with_ibgp(base_route(Ipv4Addr::new(1, 0, 0, 2)));
        assert!(!multipath_equal(&ebgp, &ibgp, false));
        // Relax does not cross the eBGP/iBGP class boundary.
        assert!(!multipath_equal(&ebgp, &ibgp, true));
    }

    #[test]
    fn multipath_equal_false_for_local_routes() {
        // Controller-injected (Local) routes are not part of maximum-paths.
        // The class guard must not treat Local and iBGP as the same "not-eBGP"
        // class (the bug `is_ebgp() == is_ebgp()` had), nor group two Locals.
        let ibgp = with_ibgp(base_route(Ipv4Addr::new(1, 0, 0, 1)));
        let local1 = with_local(base_route(Ipv4Addr::new(1, 0, 0, 2)));
        let local2 = with_local(base_route(Ipv4Addr::new(1, 0, 0, 3)));
        assert!(!multipath_equal(&local1, &ibgp, false));
        assert!(!multipath_equal(&ibgp, &local1, false));
        assert!(!multipath_equal(&local1, &local2, false));
    }

    // --- Decision step tests ---

    #[test]
    fn higher_local_pref_wins() {
        let a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn shorter_as_path_wins() {
        let a = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 1)), vec![65001]);
        let b = with_as_path(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![65001, 65002, 65003],
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_origin_wins() {
        let a = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 1)), Origin::Igp);
        let b = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Egp);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_med_wins() {
        let a = with_med(base_route(Ipv4Addr::new(1, 0, 0, 1)), 50);
        let b = with_med(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_peer_addr_tiebreaks() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn equal_routes_same_peer() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        assert_eq!(best_path_cmp(&a, &b), Ordering::Equal);
    }

    #[test]
    fn local_pref_beats_shorter_as_path() {
        let a = with_as_path(
            with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200),
            vec![65001, 65002, 65003],
        );
        let b = with_as_path(
            with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100),
            vec![65001],
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn default_local_pref_when_absent() {
        // Route with no LOCAL_PREF attribute should default to 100
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        Arc::make_mut(&mut a.attributes).retain(|a| !matches!(a, PathAttribute::LocalPref(_)));
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        // Same local_pref, same as_path, same origin, no MED → peer tiebreak
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn ebgp_beats_ibgp() {
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.origin_type = RouteOrigin::Ebgp;
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.origin_type = RouteOrigin::Ibgp;
        // eBGP route wins even though peer address is lower
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn ebgp_ibgp_same_both_ebgp_falls_through() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        // Both eBGP — falls through to peer tiebreaker
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn non_stale_beats_stale() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        b.is_stale = true;
        // Non-stale (a) preferred over stale (b)
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn stale_demotion_beats_local_pref() {
        // A stale route with higher LOCAL_PREF should lose to a non-stale route
        let mut a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        a.is_stale = true;
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Greater);
    }

    #[test]
    fn igp_beats_incomplete() {
        let a = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 1)), Origin::Igp);
        let b = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Incomplete);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    fn with_cluster_list(mut r: Route, ids: Vec<Ipv4Addr>) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::ClusterList(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::ClusterList(ids));
        r
    }

    fn with_originator_id(mut r: Route, id: Ipv4Addr) -> Route {
        Arc::make_mut(&mut r.attributes).retain(|a| !matches!(a, PathAttribute::OriginatorId(_)));
        Arc::make_mut(&mut r.attributes).push(PathAttribute::OriginatorId(id));
        r
    }

    #[test]
    fn shorter_cluster_list_wins() {
        let a = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![Ipv4Addr::new(10, 0, 0, 1)],
        );
        let b = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        // a has shorter CLUSTER_LIST, wins despite higher peer address
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn lower_originator_id_wins() {
        let a = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let b = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        // a has lower ORIGINATOR_ID, wins despite higher peer address
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn cluster_list_beats_originator_id() {
        // Shorter CLUSTER_LIST should win even if ORIGINATOR_ID is higher
        let a = with_originator_id(
            with_cluster_list(
                base_route(Ipv4Addr::new(1, 0, 0, 1)),
                vec![Ipv4Addr::new(10, 0, 0, 1)],
            ),
            Ipv4Addr::new(10, 0, 0, 99),
        );
        let b = with_originator_id(
            with_cluster_list(
                base_route(Ipv4Addr::new(1, 0, 0, 1)),
                vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            ),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn originator_id_only_when_both_present() {
        // When only one route has ORIGINATOR_ID, it should fall through
        let a = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 99),
        );
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        // ORIGINATOR_ID tiebreaker skipped (b has none), falls to peer address
        // b has lower peer → b wins
        assert_eq!(best_path_cmp(&a, &b), Ordering::Greater);
    }

    #[test]
    fn rpki_valid_beats_not_found() {
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.validation_state = RpkiValidation::Valid;
        let b = base_route(Ipv4Addr::new(1, 0, 0, 2)); // NotFound (default)
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn rpki_not_found_beats_invalid() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1)); // NotFound (default)
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.validation_state = RpkiValidation::Invalid;
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn rpki_valid_beats_invalid() {
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.validation_state = RpkiValidation::Valid;
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.validation_state = RpkiValidation::Invalid;
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn rpki_tie_falls_through_to_local_pref() {
        // Both Valid — should fall through to LOCAL_PREF
        let mut a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        a.validation_state = RpkiValidation::Valid;
        let mut b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        b.validation_state = RpkiValidation::Valid;
        // a has higher LP → a wins
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn rpki_beats_local_pref() {
        // Valid with lower LOCAL_PREF beats NotFound with higher LOCAL_PREF
        let mut a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 50);
        a.validation_state = RpkiValidation::Valid;
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 200);
        // a is Valid, b is NotFound → a wins despite lower LP
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn stale_beats_rpki() {
        // Stale demotion (step 0) takes precedence over RPKI (step 0.5)
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.validation_state = RpkiValidation::Valid;
        a.is_stale = true;
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.validation_state = RpkiValidation::Invalid;
        b.is_stale = false;
        // b is non-stale → b wins despite Invalid RPKI
        assert_eq!(best_path_cmp(&a, &b), Ordering::Greater);
    }

    // --- direct ASPA / stale-tier ordering + reason-vs-ordering guards ---

    #[test]
    fn aspa_ordering_valid_unknown_invalid() {
        // Direct ASPA ladder step: Valid > Unknown > Invalid. Same peer so
        // only the ASPA state can decide.
        let mut valid = base_route(Ipv4Addr::new(1, 0, 0, 1));
        valid.aspa_state = AspaValidation::Valid;
        let unknown = base_route(Ipv4Addr::new(1, 0, 0, 1)); // Unknown (default)
        let mut invalid = base_route(Ipv4Addr::new(1, 0, 0, 1));
        invalid.aspa_state = AspaValidation::Invalid;
        assert_eq!(best_path_cmp(&valid, &unknown), Ordering::Less);
        assert_eq!(best_path_cmp(&unknown, &invalid), Ordering::Less);
        assert_eq!(best_path_cmp(&valid, &invalid), Ordering::Less);
    }

    #[test]
    fn stale_tier_fresh_gr_llgr() {
        // Three-tier stale demotion: fresh > GR-stale > LLGR-stale.
        let fresh = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let mut gr = base_route(Ipv4Addr::new(1, 0, 0, 1));
        gr.is_stale = true;
        let mut llgr = base_route(Ipv4Addr::new(1, 0, 0, 1));
        llgr.is_llgr_stale = true;
        assert_eq!(best_path_cmp(&fresh, &gr), Ordering::Less);
        assert_eq!(best_path_cmp(&gr, &llgr), Ordering::Less);
        assert_eq!(best_path_cmp(&fresh, &llgr), Ordering::Less);
    }

    #[test]
    fn with_reason_ordering_matches_plain_cmp_at_every_step() {
        // best_path_cmp_with_reason(..).0 must equal best_path_cmp(..) at
        // every decisive ladder step, and report the right reason. Guards
        // against the two (currently hand-maintained) ladders drifting.
        let p1 = Ipv4Addr::new(1, 0, 0, 1);
        let p2 = Ipv4Addr::new(1, 0, 0, 2);

        let mut stale_a = base_route(p1);
        stale_a.is_stale = true;
        let mut rpki_a = base_route(p1);
        rpki_a.validation_state = RpkiValidation::Invalid;
        let mut aspa_a = base_route(p1);
        aspa_a.aspa_state = AspaValidation::Invalid;
        let mut ebgp_b = base_route(p2);
        ebgp_b.origin_type = RouteOrigin::Ibgp;

        // One decisive pair per ladder step.
        let cases: Vec<(&str, Route, Route, BestPathReason)> = vec![
            (
                "stale",
                stale_a,
                base_route(p2),
                BestPathReason::StalePreference,
            ),
            (
                "rpki",
                rpki_a,
                base_route(p2),
                BestPathReason::RpkiPreference,
            ),
            (
                "aspa",
                aspa_a,
                base_route(p2),
                BestPathReason::AspaPreference,
            ),
            (
                "local_pref",
                with_local_pref(base_route(p1), 50),
                with_local_pref(base_route(p2), 200),
                BestPathReason::HigherLocalPref,
            ),
            (
                "as_path",
                with_as_path(base_route(p1), vec![65001, 65002]),
                with_as_path(base_route(p2), vec![65001]),
                BestPathReason::ShorterAsPath,
            ),
            (
                "origin",
                with_origin(base_route(p1), Origin::Egp),
                with_origin(base_route(p2), Origin::Igp),
                BestPathReason::LowerOrigin,
            ),
            (
                "med",
                with_med(base_route(p1), 100),
                with_med(base_route(p2), 50),
                BestPathReason::LowerMed,
            ),
            ("ebgp", base_route(p1), ebgp_b, BestPathReason::EbgpOverIbgp),
            (
                "cluster",
                with_cluster_list(
                    base_route(p1),
                    vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
                ),
                with_cluster_list(base_route(p2), vec![Ipv4Addr::new(10, 0, 0, 1)]),
                BestPathReason::ShorterClusterList,
            ),
            (
                "originator",
                with_originator_id(base_route(p1), Ipv4Addr::new(10, 0, 0, 9)),
                with_originator_id(base_route(p2), Ipv4Addr::new(10, 0, 0, 1)),
                BestPathReason::LowerOriginatorId,
            ),
            (
                "peer",
                base_route(p1),
                base_route(p2),
                BestPathReason::LowerPeerAddress,
            ),
        ];

        for (label, a, b, expected) in cases {
            let (ord, reason) = best_path_cmp_with_reason(&a, &b);
            assert_eq!(ord, best_path_cmp(&a, &b), "ordering drift at step {label}");
            assert_eq!(reason, expected, "wrong decisive reason at step {label}");
            let (rev, rev_reason) = best_path_cmp_with_reason(&b, &a);
            assert_eq!(
                rev,
                best_path_cmp(&b, &a),
                "reverse ordering drift at step {label}"
            );
            assert_eq!(rev_reason, expected, "reverse reason drift at step {label}");
        }
    }

    // --- RFC 9107 ORR interior-cost step (best_path_cmp_orr) ---

    #[test]
    fn orr_cost_only_breaks_ties_below_step5() {
        // Steps 0-5 all outrank the ORR interior cost. A higher
        // LOCAL_PREF wins regardless of a worse — or unknown — cost.
        let a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(
            best_path_cmp_orr(&a, &b, Some(1000), Some(0)),
            Ordering::Less
        );
        assert_eq!(best_path_cmp_orr(&a, &b, None, Some(0)), Ordering::Less);
        assert_eq!(best_path_cmp_orr(&b, &a, Some(0), None), Ordering::Greater);

        // Step 5 (eBGP over iBGP) also sits above the cost step.
        let ebgp = base_route(Ipv4Addr::new(1, 0, 0, 2));
        let ibgp = with_ibgp(base_route(Ipv4Addr::new(1, 0, 0, 1)));
        assert_eq!(
            best_path_cmp_orr(&ibgp, &ebgp, Some(0), Some(1000)),
            Ordering::Greater
        );
    }

    #[test]
    fn orr_unknown_cost_least_preferred() {
        // RFC 9107 §3.1: an unknown metric-to-next-hop MUST be least
        // preferred — a known cost wins even against a lower peer
        // address (a is the higher-peer route here).
        let a = base_route(Ipv4Addr::new(1, 0, 0, 2));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        assert_eq!(best_path_cmp_orr(&a, &b, Some(500), None), Ordering::Less);
        assert_eq!(
            best_path_cmp_orr(&b, &a, None, Some(500)),
            Ordering::Greater
        );
        // And among known costs, the lower one wins.
        assert_eq!(best_path_cmp_orr(&a, &b, Some(5), Some(10)), Ordering::Less);
        assert_eq!(
            best_path_cmp_orr(&a, &b, Some(10), Some(5)),
            Ordering::Greater
        );
    }

    #[test]
    fn orr_equal_costs_fall_through_to_cluster_list() {
        // Equal known costs — and both-unknown — fall through to the
        // CLUSTER_LIST step: the shorter list wins despite a's higher
        // peer address.
        let a = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![Ipv4Addr::new(10, 0, 0, 1)],
        );
        let b = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        assert_eq!(best_path_cmp_orr(&a, &b, Some(7), Some(7)), Ordering::Less);
        assert_eq!(best_path_cmp_orr(&a, &b, None, None), Ordering::Less);
        // The fall-through outcome matches the plain comparator.
        assert_eq!(best_path_cmp_orr(&a, &b, None, None), best_path_cmp(&a, &b));
    }

    // --- RFC 9107 ORR reason ladder (best_path_cmp_orr_with_reason) ---

    #[test]
    fn orr_with_reason_winner_by_cost_yields_orr_interior_cost() {
        // Attributes tie down to the cost step; the lower cost wins and
        // the decisive reason is OrrInteriorCost with the right detail.
        let a = base_route(Ipv4Addr::new(1, 0, 0, 2));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, Some(12), Some(40));
        assert_eq!(ord, Ordering::Less);
        assert_eq!(reason, BestPathReason::OrrInteriorCost);
        assert_eq!(
            orr_interior_cost_detail(Some(12), Some(40)),
            "orr_cost 12 < 40"
        );

        // Known beats unknown (RFC 9107 §3.1).
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, Some(12), None);
        assert_eq!(ord, Ordering::Less);
        assert_eq!(reason, BestPathReason::OrrInteriorCost);
        assert_eq!(
            orr_interior_cost_detail(Some(12), None),
            "orr_cost 12 < unreachable"
        );
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, None, Some(12));
        assert_eq!(ord, Ordering::Greater);
        assert_eq!(reason, BestPathReason::OrrInteriorCost);
        assert_eq!(
            orr_interior_cost_detail(None, Some(12)),
            "orr_cost unreachable > 12"
        );
    }

    #[test]
    fn orr_with_reason_cost_tie_falls_through_to_next_step() {
        // Equal (and both-unknown) costs fall through to CLUSTER_LIST —
        // the same next step the plain ladder would use.
        let a = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![Ipv4Addr::new(10, 0, 0, 1)],
        );
        let b = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, Some(7), Some(7));
        assert_eq!(ord, Ordering::Less);
        assert_eq!(reason, BestPathReason::ShorterClusterList);
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, None, None);
        assert_eq!(ord, Ordering::Less);
        assert_eq!(reason, BestPathReason::ShorterClusterList);
    }

    #[test]
    fn orr_with_reason_steps_above_cost_still_decide() {
        // A step above 5.3 (LOCAL_PREF) outranks even a wildly better
        // cost, and the reason names that step.
        let a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        let (ord, reason) = best_path_cmp_orr_with_reason(&a, &b, Some(1000), Some(0));
        assert_eq!(ord, Ordering::Less);
        assert_eq!(reason, BestPathReason::HigherLocalPref);
    }

    #[test]
    fn orr_with_reason_ordering_matches_cmp_orr() {
        // Drift guard: the composed reason ladder must agree with the
        // hot-path ORR comparator at every cost combination over pairs
        // that tie above, at, and below the cost step.
        let pairs = [
            (
                base_route(Ipv4Addr::new(1, 0, 0, 1)),
                base_route(Ipv4Addr::new(1, 0, 0, 2)),
            ),
            (
                with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200),
                with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100),
            ),
            (
                with_cluster_list(
                    base_route(Ipv4Addr::new(1, 0, 0, 2)),
                    vec![Ipv4Addr::new(10, 0, 0, 1)],
                ),
                with_cluster_list(
                    base_route(Ipv4Addr::new(1, 0, 0, 1)),
                    vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
                ),
            ),
        ];
        let costs = [None, Some(0_u64), Some(7), Some(1000)];
        for (a, b) in &pairs {
            for &ca in &costs {
                for &cb in &costs {
                    let (ord, _) = best_path_cmp_orr_with_reason(a, b, ca, cb);
                    assert_eq!(ord, best_path_cmp_orr(a, b, ca, cb));
                    let (rev, _) = best_path_cmp_orr_with_reason(b, a, cb, ca);
                    assert_eq!(rev, best_path_cmp_orr(b, a, cb, ca));
                }
            }
        }
    }

    // --- best_path_reason_detail (explain-only compared-values render) ---

    #[test]
    fn reason_detail_renders_compared_values_per_step() {
        let p1 = Ipv4Addr::new(1, 0, 0, 1);
        let p2 = Ipv4Addr::new(1, 0, 0, 2);

        let mut stale = base_route(p1);
        stale.is_stale = true;
        assert_eq!(
            best_path_reason_detail(BestPathReason::StalePreference, &stale, &base_route(p2)),
            "stale_tier gr_stale vs fresh"
        );

        let mut rpki = base_route(p1);
        rpki.validation_state = RpkiValidation::Invalid;
        assert_eq!(
            best_path_reason_detail(BestPathReason::RpkiPreference, &rpki, &base_route(p2)),
            "rpki invalid vs not_found"
        );

        let mut aspa = base_route(p1);
        aspa.aspa_state = AspaValidation::Invalid;
        assert_eq!(
            best_path_reason_detail(BestPathReason::AspaPreference, &aspa, &base_route(p2)),
            "aspa invalid vs unknown"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::HigherLocalPref,
                &with_local_pref(base_route(p1), 100),
                &with_local_pref(base_route(p2), 200),
            ),
            "local_pref 100 < 200"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::ShorterAsPath,
                &with_as_path(base_route(p1), vec![65001, 65002, 65003]),
                &with_as_path(base_route(p2), vec![65001]),
            ),
            "as_path_len 3 > 1"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::LowerOrigin,
                &with_origin(base_route(p1), Origin::Incomplete),
                &with_origin(base_route(p2), Origin::Igp),
            ),
            "origin incomplete vs igp"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::LowerMed,
                &with_med(base_route(p1), 100),
                &with_med(base_route(p2), 50),
            ),
            "med 100 > 50"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::EbgpOverIbgp,
                &with_ibgp(base_route(p1)),
                &base_route(p2),
            ),
            "ibgp vs ebgp"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::ShorterClusterList,
                &with_cluster_list(
                    base_route(p1),
                    vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
                ),
                &with_cluster_list(base_route(p2), vec![Ipv4Addr::new(10, 0, 0, 1)]),
            ),
            "cluster_list_len 2 > 1"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::LowerOriginatorId,
                &with_originator_id(base_route(p1), Ipv4Addr::new(10, 0, 0, 9)),
                &with_originator_id(base_route(p2), Ipv4Addr::new(10, 0, 0, 1)),
            ),
            "originator_id 10.0.0.9 > 10.0.0.1"
        );

        assert_eq!(
            best_path_reason_detail(
                BestPathReason::LowerPeerAddress,
                &base_route(p2),
                &base_route(p1)
            ),
            "peer 1.0.0.2 > 1.0.0.1"
        );
    }

    #[test]
    fn reason_detail_missing_med_renders_as_zero() {
        // Deterministic / always-compare MED treats an absent MED as 0
        // (matching `Route::med()`); the detail must show that, so an
        // operator sees why a MED-less path beat a MED-carrying one.
        let no_med = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let med50 = with_med(base_route(Ipv4Addr::new(1, 0, 0, 2)), 50);
        // The MED-less route wins (0 < 50) under always-compare.
        assert_eq!(best_path_cmp(&no_med, &med50), Ordering::Less);
        let (_, reason) = best_path_cmp_with_reason(&no_med, &med50);
        assert_eq!(reason, BestPathReason::LowerMed);
        assert_eq!(
            best_path_reason_detail(reason, &no_med, &med50),
            "med 0 < 50"
        );
    }

    // --- multipath_eligibility (explain-only ECMP-cut classification) ---

    #[test]
    fn multipath_eligibility_strict_relax_and_none() {
        // Co-equal paths differing only on peer/next-hop: strict-eligible.
        let best = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let sibling = base_route(Ipv4Addr::new(1, 0, 0, 2));
        assert_eq!(
            multipath_eligibility(&best, &sibling),
            MultipathEligibility::Eligible
        );

        // Equal AS_PATH length, different ASNs: groups only with relax.
        let best = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 1)), vec![65001, 65010]);
        let relax_only = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 2)), vec![65001, 65020]);
        assert_eq!(
            multipath_eligibility(&best, &relax_only),
            MultipathEligibility::RelaxOnly
        );

        // LOCAL_PREF difference disqualifies under both modes.
        let best = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let worse = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(
            multipath_eligibility(&best, &worse),
            MultipathEligibility::None
        );

        // eBGP/iBGP class mixing never groups.
        let ebgp = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let ibgp = with_ibgp(base_route(Ipv4Addr::new(1, 0, 0, 2)));
        assert_eq!(
            multipath_eligibility(&ebgp, &ibgp),
            MultipathEligibility::None
        );
    }

    #[test]
    fn multipath_eligibility_display_labels() {
        assert_eq!(MultipathEligibility::None.to_string(), "none");
        assert_eq!(MultipathEligibility::Eligible.to_string(), "eligible");
        assert_eq!(MultipathEligibility::RelaxOnly.to_string(), "relax_only");
    }

    // --- ADR-0068 link_bandwidth_weights ---

    #[test]
    fn link_bw_weights_disabled_is_all_equal() {
        let bws = [Some(40e9), Some(10e9)];
        assert_eq!(link_bandwidth_weights(false, &bws), vec![1, 1]);
    }

    #[test]
    fn link_bw_weights_proportional_when_all_present() {
        // 40G / 20G / 10G → max 40G maps to 256, the rest scale by ratio.
        let bws = [Some(40e9), Some(20e9), Some(10e9)];
        assert_eq!(link_bandwidth_weights(true, &bws), vec![256, 128, 64]);
    }

    #[test]
    fn link_bw_weights_all_or_nothing_on_missing() {
        // One path without a Link Bandwidth community ⇒ whole group equal-cost.
        let bws = [Some(40e9), None, Some(10e9)];
        assert_eq!(link_bandwidth_weights(true, &bws), vec![1, 1, 1]);
    }

    #[test]
    fn link_bw_weights_reject_non_finite_and_non_positive() {
        assert_eq!(
            link_bandwidth_weights(true, &[Some(10e9), Some(f32::NAN)]),
            vec![1, 1]
        );
        assert_eq!(
            link_bandwidth_weights(true, &[Some(10e9), Some(f32::INFINITY)]),
            vec![1, 1]
        );
        assert_eq!(
            link_bandwidth_weights(true, &[Some(10e9), Some(0.0)]),
            vec![1, 1]
        );
        assert_eq!(
            link_bandwidth_weights(true, &[Some(10e9), Some(-5.0)]),
            vec![1, 1]
        );
    }

    #[test]
    fn link_bw_weights_equal_bandwidth_is_uniform() {
        // Equal bandwidth ⇒ equal (max) weight; ratio 1:1 distributes evenly.
        assert_eq!(
            link_bandwidth_weights(true, &[Some(10e9), Some(10e9)]),
            vec![256, 256]
        );
    }

    #[test]
    fn link_bw_weights_clamps_extreme_ratio_to_one() {
        // A bandwidth ratio beyond 256:1 saturates the low end at weight 1.
        assert_eq!(
            link_bandwidth_weights(true, &[Some(1e12), Some(1.0)]),
            vec![256, 1]
        );
    }

    #[test]
    fn link_bw_weights_empty_input() {
        assert_eq!(link_bandwidth_weights(true, &[]), Vec::<u16>::new());
    }
}

#[cfg(test)]
mod proptests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use proptest::prelude::*;
    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

    use super::*;
    use crate::route::{Route, RouteOrigin};

    fn arb_origin() -> impl Strategy<Value = Origin> {
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete),
        ]
    }

    fn arb_route_origin() -> impl Strategy<Value = RouteOrigin> {
        prop_oneof![
            Just(RouteOrigin::Ebgp),
            Just(RouteOrigin::Ibgp),
            Just(RouteOrigin::Local),
        ]
    }

    fn arb_stale_tier() -> impl Strategy<Value = (bool, bool)> {
        // (is_stale, is_llgr_stale): fresh, GR-stale, LLGR-stale.
        prop_oneof![
            Just((false, false)),
            Just((true, false)),
            Just((false, true)),
        ]
    }

    fn arb_rpki() -> impl Strategy<Value = rustbgpd_wire::RpkiValidation> {
        use rustbgpd_wire::RpkiValidation as V;
        prop_oneof![Just(V::Valid), Just(V::NotFound), Just(V::Invalid)]
    }

    fn arb_aspa() -> impl Strategy<Value = rustbgpd_wire::AspaValidation> {
        use rustbgpd_wire::AspaValidation as V;
        prop_oneof![Just(V::Valid), Just(V::Unknown), Just(V::Invalid)]
    }

    fn arb_route() -> impl Strategy<Value = Route> {
        (
            1u8..=4,                                   // peer last octet
            0u32..=500,                                // local_pref
            prop::collection::vec(1u32..=65535, 0..5), // as_path ASNs
            arb_origin(),
            0u32..=1000,                   // MED
            arb_route_origin(),            // origin_type
            proptest::option::of(1u8..=4), // originator_id last octet
            0u8..=3,                       // cluster_list length
            arb_stale_tier(),
            arb_rpki(),
            arb_aspa(),
        )
            .prop_map(
                |(
                    peer_oct,
                    lp,
                    asns,
                    origin,
                    med,
                    origin_type,
                    oid_oct,
                    cl_len,
                    (is_stale, is_llgr_stale),
                    validation_state,
                    aspa_state,
                )| {
                    let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
                    let mut attributes = vec![
                        PathAttribute::LocalPref(lp),
                        PathAttribute::AsPath(AsPath {
                            segments: if asns.is_empty() {
                                vec![]
                            } else {
                                vec![AsPathSegment::AsSequence(asns)]
                            },
                        }),
                        PathAttribute::Origin(origin),
                        PathAttribute::Med(med),
                    ];
                    if let Some(oct) = oid_oct {
                        attributes.push(PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, oct)));
                    }
                    if cl_len > 0 {
                        let ids: Vec<Ipv4Addr> =
                            (1..=cl_len).map(|i| Ipv4Addr::new(10, 0, i, 1)).collect();
                        attributes.push(PathAttribute::ClusterList(ids));
                    }
                    Route {
                        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                        next_hop: IpAddr::V4(peer),
                        link_local_next_hop: None,
                        next_hop_scope: None,
                        peer: IpAddr::V4(peer),
                        attributes: Arc::new(attributes),
                        received_at: Instant::now(),
                        origin_type,
                        peer_router_id: Ipv4Addr::UNSPECIFIED,
                        is_stale,
                        is_llgr_stale,
                        path_id: 0,
                        validation_state,
                        aspa_state,
                        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
                    }
                },
            )
    }

    /// Verbatim fixture copy of `best_path_cmp` as it stood BEFORE the
    /// `cmp_chain` refactor (the ORR arc) — the oracle for
    /// `best_path_cmp_unchanged_without_orr`. Do not "fix" or refactor
    /// this copy; its value is that it never changes.
    fn legacy_best_path_cmp(a: &Route, b: &Route) -> Ordering {
        let cmp = stale_rank(a).cmp(&stale_rank(b));
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = rpki_preference(b.validation_state).cmp(&rpki_preference(a.validation_state));
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = aspa_preference(b.aspa_state).cmp(&aspa_preference(a.aspa_state));
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = b.local_pref().cmp(&a.local_pref());
        if cmp != Ordering::Equal {
            return cmp;
        }
        let a_len = a.as_path().map_or(0, AsPath::len);
        let b_len = b.as_path().map_or(0, AsPath::len);
        let cmp = a_len.cmp(&b_len);
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = a.origin().cmp(&b.origin());
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = a.med().cmp(&b.med());
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = b.is_ebgp().cmp(&a.is_ebgp());
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = a.cluster_list().len().cmp(&b.cluster_list().len());
        if cmp != Ordering::Equal {
            return cmp;
        }
        if let (Some(a_oid), Some(b_oid)) = (a.originator_id(), b.originator_id()) {
            let cmp = a_oid.cmp(&b_oid);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
        a.peer.cmp(&b.peer)
    }

    proptest! {
        /// The `cmp_chain` refactor property: with no ORR costs the
        /// public comparator is behavior-identical to the pre-refactor
        /// chain (`legacy_best_path_cmp`, a verbatim fixture copy),
        /// over the generated route corpus.
        #[test]
        fn best_path_cmp_unchanged_without_orr(a in arb_route(), b in arb_route()) {
            prop_assert_eq!(best_path_cmp(&a, &b), legacy_best_path_cmp(&a, &b));
        }

        /// With both costs unknown the ORR comparator degenerates to
        /// the standard chain — the both-None fall-through is total.
        #[test]
        fn orr_both_unknown_matches_plain_cmp(a in arb_route(), b in arb_route()) {
            prop_assert_eq!(best_path_cmp_orr(&a, &b, None, None), best_path_cmp(&a, &b));
        }

        /// The explain-only ladder (`best_path_cmp_with_reason`) must
        /// agree with the hot-path comparator on arbitrary inputs —
        /// the randomized counterpart of the per-step agreement matrix
        /// in `with_reason_ordering_matches_plain_cmp_at_every_step`.
        #[test]
        fn with_reason_agrees_with_plain_cmp(a in arb_route(), b in arb_route()) {
            let (ord, _) = best_path_cmp_with_reason(&a, &b);
            prop_assert_eq!(ord, best_path_cmp(&a, &b));
        }

        #[test]
        fn antisymmetry(a in arb_route(), b in arb_route()) {
            let ab = best_path_cmp(&a, &b);
            let ba = best_path_cmp(&b, &a);
            prop_assert_eq!(ab, ba.reverse());
        }

        #[test]
        fn transitivity(a in arb_route(), b in arb_route(), c in arb_route()) {
            use std::cmp::Ordering::*;
            let ab = best_path_cmp(&a, &b);
            let bc = best_path_cmp(&b, &c);
            let ac = best_path_cmp(&a, &c);
            if ab == Less && bc == Less {
                prop_assert_eq!(ac, Less);
            }
            if ab == Greater && bc == Greater {
                prop_assert_eq!(ac, Greater);
            }
        }

        #[test]
        fn totality(a in arb_route(), b in arb_route()) {
            let result = best_path_cmp(&a, &b);
            prop_assert!(matches!(result, std::cmp::Ordering::Less | std::cmp::Ordering::Equal | std::cmp::Ordering::Greater));
        }
    }
}
