//! Receive-side feasibility from RFC 8955 section 6 and RFC 9117 section 4.
//!
//! This module borrows route facts; the manager owns retention, dependency
//! revisions, bounded traversal, and publication of completed results.

use std::net::{IpAddr, Ipv4Addr};
use std::ops::ControlFlow;

use rustbgpd_wire::{
    AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, Ipv4Prefix, Ipv6Prefix, Prefix,
};

use crate::route::{FlowSpecRoute, Route, RouteOrigin};

/// Completed validation result. Pending work is tracked separately by its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Feasibility {
    /// Explicit local origination, not a claim of received-route validation.
    Local,
    /// All receive-side checks completed against the same dependency revision.
    Feasible,
    /// Retained for diagnosis and revalidation, but ineligible for selection.
    Infeasible(InfeasibleReason),
}

/// The first failed receive-side check, in validation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InfeasibleReason {
    MissingDestination,
    NonzeroDestinationOffset,
    NoCoveringUnicast,
    MissingAsPath,
    UnsupportedAsPath,
    OriginatorMismatch,
    LeftmostAsMismatch,
    UnknownNeighborAs,
    ConflictingMoreSpecific,
}

impl InfeasibleReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingDestination => "missing_destination",
            Self::NonzeroDestinationOffset => "nonzero_destination_offset",
            Self::NoCoveringUnicast => "no_covering_unicast",
            Self::MissingAsPath => "missing_as_path",
            Self::UnsupportedAsPath => "unsupported_as_path",
            Self::OriginatorMismatch => "originator_mismatch",
            Self::LeftmostAsMismatch => "leftmost_as_mismatch",
            Self::UnknownNeighborAs => "unknown_neighbor_as",
            Self::ConflictingMoreSpecific => "conflicting_more_specific",
        }
    }
}

/// State after the destination, covering route, originator, and path checks.
///
/// Each visit checks one retained received candidate, allowing the actor to
/// bound work even when a single rule covers the entire unicast table. The
/// caller must discard this state if a relevant dependency changes, and call
/// `finish` only after every relevant candidate in that revision was visited.
#[derive(Debug)]
pub(crate) struct MoreSpecificCheck {
    destination: Prefix,
    best_neighbor_as: u32,
    local_as: u32,
    failure: Option<InfeasibleReason>,
}

impl MoreSpecificCheck {
    /// Visit a received candidate, including losing Add-Path candidates.
    /// Returns `Break` when a failure makes the remaining walk unnecessary.
    pub(crate) fn visit(&mut self, candidate: &Route) -> ControlFlow<InfeasibleReason> {
        if let Some(reason) = self.failure {
            return ControlFlow::Break(reason);
        }
        // Rule (c) concerns received routes strictly more specific than the
        // FlowSpec destination, not than its possibly shorter covering route.
        if candidate.origin_type == RouteOrigin::Local
            || candidate.prefix.prefix_len() <= self.destination.prefix_len()
            || !covers(self.destination, candidate.prefix)
        {
            return ControlFlow::Continue(());
        }
        let reason = match neighboring_as(candidate, self.local_as) {
            Ok(asn) if asn == self.best_neighbor_as => return ControlFlow::Continue(()),
            Ok(_) => InfeasibleReason::ConflictingMoreSpecific,
            Err(_) => InfeasibleReason::UnknownNeighborAs,
        };
        self.failure = Some(reason);
        ControlFlow::Break(reason)
    }

    /// Complete a walk; this does not establish that its dependency revision is
    /// still current. The manager must check that before publishing the result.
    pub(crate) fn finish(self) -> Feasibility {
        self.failure
            .map_or(Feasibility::Feasible, Feasibility::Infeasible)
    }
}

/// Begin validation against the selected longest-covering unicast route.
///
/// `Break` carries an immediately completed result; `Continue` requires a
/// bounded walk over all retained received more-specific unicast candidates.
/// Local injection is trusted origination. Received routes require a cover,
/// including the empty-path iBGP case (the conservative ADR-0135 choice).
pub(crate) fn begin(
    flow: &FlowSpecRoute,
    best_match: Option<&Route>,
    local_as: u32,
) -> ControlFlow<Feasibility, MoreSpecificCheck> {
    if flow.origin_type == RouteOrigin::Local {
        return ControlFlow::Break(Feasibility::Local);
    }
    match prepare(flow, best_match, local_as) {
        Ok(check) => ControlFlow::Continue(check),
        Err(reason) => ControlFlow::Break(Feasibility::Infeasible(reason)),
    }
}

fn prepare(
    flow: &FlowSpecRoute,
    best_match: Option<&Route>,
    local_as: u32,
) -> Result<MoreSpecificCheck, InfeasibleReason> {
    let destination = flow
        .rule
        .components
        .iter()
        .find_map(|component| match component {
            FlowSpecComponent::DestinationPrefix(prefix) => Some(prefix),
            _ => None,
        })
        .ok_or(InfeasibleReason::MissingDestination)?;
    if matches!(destination, FlowSpecPrefix::V6(prefix) if prefix.offset != 0) {
        return Err(InfeasibleReason::NonzeroDestinationOffset);
    }
    let destination = flow
        .rule
        .destination_prefix()
        .ok_or(InfeasibleReason::MissingDestination)?;
    let best = best_match
        .filter(|route| covers(route.prefix, destination))
        .ok_or(InfeasibleReason::NoCoveringUnicast)?;
    let flow_head = sequence_head(flow.as_path())?;
    let local_domain = flow.origin_type == RouteOrigin::Ibgp && flow_head.is_none();
    if !local_domain
        && originator(flow.originator_id(), flow.peer)
            != originator(best.originator_id(), best.peer)
    {
        return Err(InfeasibleReason::OriginatorMismatch);
    }
    let best_neighbor_as = neighboring_as(best, local_as)?;
    if flow.origin_type == RouteOrigin::Ebgp {
        let flow_as = flow_head.ok_or(InfeasibleReason::UnknownNeighborAs)?;
        // Section 4.2 requires a real leftmost AS_SEQUENCE AS, so a local
        // covering route's synthetic local-AS identity cannot satisfy it.
        let best_as = sequence_head(best.as_path())?.ok_or(InfeasibleReason::UnknownNeighborAs)?;
        if flow_as != best_as {
            return Err(InfeasibleReason::LeftmostAsMismatch);
        }
    }
    Ok(MoreSpecificCheck {
        destination,
        best_neighbor_as,
        local_as,
        failure: None,
    })
}

fn originator(id: Option<Ipv4Addr>, peer: IpAddr) -> IpAddr {
    id.map_or(peer, IpAddr::V4)
}

/// Preserve the distinction between an absent attribute and a genuinely empty
/// path. `AS_SET` has no leftmost ASN; never flatten it through `AsPath::asns`.
fn sequence_head(path: Option<&AsPath>) -> Result<Option<u32>, InfeasibleReason> {
    let path = path.ok_or(InfeasibleReason::MissingAsPath)?;
    for segment in &path.segments {
        match segment {
            AsPathSegment::AsSequence(asns) if !asns.is_empty() => {}
            AsPathSegment::AsSequence(_) | AsPathSegment::AsSet(_) => {
                return Err(InfeasibleReason::UnsupportedAsPath);
            }
        }
    }
    Ok(match path.segments.first() {
        Some(AsPathSegment::AsSequence(asns)) => asns.first().copied(),
        _ => None,
    })
}

fn neighboring_as(route: &Route, local_as: u32) -> Result<u32, InfeasibleReason> {
    // Local API injection need not carry an AS_PATH attribute at all.
    if route.origin_type == RouteOrigin::Local && route.as_path().is_none() {
        return Ok(local_as);
    }
    match sequence_head(route.as_path())? {
        Some(asn) => Ok(asn),
        None if route.origin_type != RouteOrigin::Ebgp => Ok(local_as),
        None => Err(InfeasibleReason::UnknownNeighborAs),
    }
}

fn covers(cover: Prefix, destination: Prefix) -> bool {
    match (cover, destination) {
        (Prefix::V4(cover), Prefix::V4(destination)) => {
            cover.len <= destination.len && Ipv4Prefix::new(destination.addr, cover.len) == cover
        }
        (Prefix::V6(cover), Prefix::V6(destination)) => {
            cover.len <= destination.len && Ipv6Prefix::new(destination.addr, cover.len) == cover
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustbgpd_wire::{Afi, Ipv6PrefixOffset, PathAttribute};

    use super::*;
    use crate::test_support::{make_flowspec_route, make_route};

    const LOCAL_AS: u32 = 64512;
    const SOURCE_AS: u32 = 64496;

    fn path(asns: &[u32]) -> PathAttribute {
        PathAttribute::AsPath(AsPath {
            segments: if asns.is_empty() {
                Vec::new()
            } else {
                vec![AsPathSegment::AsSequence(asns.to_vec())]
            },
        })
    }

    fn fixture() -> (FlowSpecRoute, Route) {
        let peer = Ipv4Addr::new(198, 51, 100, 1);
        let mut flow = make_flowspec_route(peer);
        flow.attributes.push(path(&[SOURCE_AS]));
        let mut cover = make_route(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 0, 0), 16), peer);
        cover.attributes = Arc::new(vec![path(&[SOURCE_AS])]);
        (flow, cover)
    }

    fn evaluate(flow: &FlowSpecRoute, cover: Option<&Route>, candidates: &[Route]) -> Feasibility {
        match begin(flow, cover, LOCAL_AS) {
            ControlFlow::Break(result) => result,
            ControlFlow::Continue(mut check) => {
                for candidate in candidates {
                    if check.visit(candidate).is_break() {
                        break;
                    }
                }
                check.finish()
            }
        }
    }

    fn invalid(reason: InfeasibleReason) -> Feasibility {
        Feasibility::Infeasible(reason)
    }

    #[test]
    fn covering_route_and_equal_originator_are_feasible() {
        let (flow, cover) = fixture();
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);
    }

    #[test]
    fn originator_is_attribute_or_transport_address_not_router_id_or_next_hop() {
        let (mut flow, mut cover) = fixture();
        cover.peer = "2001:db8::1".parse().unwrap();
        cover.next_hop = flow.peer;
        cover.peer_router_id = flow.peer_router_id;
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::OriginatorMismatch)
        );

        let id = Ipv4Addr::new(203, 0, 113, 1);
        flow.attributes.push(PathAttribute::OriginatorId(id));
        Arc::make_mut(&mut cover.attributes).push(PathAttribute::OriginatorId(id));
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);

        // Attribute identity and the same direct peer address denote the same
        // originator; their encoding provenance must not create a mismatch.
        flow.attributes.pop();
        flow.peer = IpAddr::V4(id);
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);
    }

    #[test]
    fn ebgp_compares_actual_leftmost_sequence_as() {
        let (mut flow, mut cover) = fixture();
        flow.attributes = vec![path(&[SOURCE_AS, 64498])];
        cover.attributes = Arc::new(vec![path(&[SOURCE_AS, 64499])]);
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);
        cover.attributes = Arc::new(vec![path(&[64497, SOURCE_AS])]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::LeftmostAsMismatch)
        );
    }

    #[test]
    fn empty_ibgp_path_relaxes_only_originator_matching() {
        let (mut flow, mut cover) = fixture();
        flow.origin_type = RouteOrigin::Ibgp;
        flow.attributes = vec![path(&[])];
        cover.peer = "198.51.100.2".parse().unwrap();
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);
        assert_eq!(
            evaluate(&flow, None, &[]),
            invalid(InfeasibleReason::NoCoveringUnicast)
        );

        let mut conflict = cover.clone();
        conflict.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25));
        conflict.attributes = Arc::new(vec![path(&[64497])]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[conflict]),
            invalid(InfeasibleReason::ConflictingMoreSpecific)
        );

        flow.attributes.clear();
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::MissingAsPath)
        );
    }

    #[test]
    fn absent_and_empty_ebgp_paths_never_compare_equal() {
        let (mut flow, mut cover) = fixture();
        flow.attributes.clear();
        cover.attributes = Arc::new(vec![]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::MissingAsPath)
        );

        flow.attributes = vec![path(&[])];
        cover.attributes = Arc::new(vec![path(&[])]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::UnknownNeighborAs)
        );
    }

    #[test]
    fn unordered_and_empty_segments_are_not_sequence_heads() {
        let (mut flow, cover) = fixture();
        for segments in [
            vec![AsPathSegment::AsSet(vec![SOURCE_AS])],
            vec![AsPathSegment::AsSequence(vec![])],
            vec![
                AsPathSegment::AsSequence(vec![SOURCE_AS]),
                AsPathSegment::AsSet(vec![64497]),
            ],
        ] {
            flow.attributes = vec![PathAttribute::AsPath(AsPath { segments })];
            assert_eq!(
                evaluate(&flow, Some(&cover), &[]),
                invalid(InfeasibleReason::UnsupportedAsPath)
            );
        }
    }

    #[test]
    fn cover_must_contain_destination_in_the_same_family() {
        let (flow, mut cover) = fixture();
        for prefix in [
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25)),
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 1, 0, 0), 16)),
            Prefix::V6(Ipv6Prefix::new("::".parse().unwrap(), 0)),
        ] {
            cover.prefix = prefix;
            assert_eq!(
                evaluate(&flow, Some(&cover), &[]),
                invalid(InfeasibleReason::NoCoveringUnicast)
            );
        }
    }

    #[test]
    fn losing_add_path_more_specific_invalidates_but_unrelated_prefixes_do_not() {
        let (flow, cover) = fixture();
        let mut candidate = cover.clone();
        candidate.path_id = 7;
        candidate.attributes = Arc::new(vec![path(&[64497]), PathAttribute::LocalPref(0)]);
        for prefix in [
            // More specific than the cover is insufficient: it must be more
            // specific than the FlowSpec destination (192.0.2.0/24).
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 3, 0), 25)),
            Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64)),
        ] {
            candidate.prefix = prefix;
            assert_eq!(
                evaluate(&flow, Some(&cover), std::slice::from_ref(&candidate)),
                Feasibility::Feasible
            );
        }
        candidate.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25));
        assert_eq!(
            evaluate(&flow, Some(&cover), std::slice::from_ref(&candidate)),
            invalid(InfeasibleReason::ConflictingMoreSpecific)
        );
        // Withdrawing only the losing candidate restores feasibility.
        assert_eq!(evaluate(&flow, Some(&cover), &[]), Feasibility::Feasible);
    }

    #[test]
    fn local_domain_unicast_paths_share_local_as_identity() {
        let (mut flow, mut cover) = fixture();
        flow.origin_type = RouteOrigin::Ibgp;
        flow.attributes = vec![path(&[])];
        cover.origin_type = RouteOrigin::Ibgp;
        cover.attributes = Arc::new(vec![path(&[])]);
        let mut child = cover.clone();
        child.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25));
        child.peer = "198.51.100.2".parse().unwrap();
        assert_eq!(
            evaluate(&flow, Some(&cover), std::slice::from_ref(&child)),
            Feasibility::Feasible
        );
        child.attributes = Arc::new(vec![path(&[SOURCE_AS])]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[child]),
            invalid(InfeasibleReason::ConflictingMoreSpecific)
        );
    }

    #[test]
    fn unknown_received_neighbor_as_is_not_ignored() {
        let (flow, cover) = fixture();
        let mut child = cover.clone();
        child.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25));
        child.attributes = Arc::new(vec![]);
        assert_eq!(
            evaluate(&flow, Some(&cover), std::slice::from_ref(&child)),
            invalid(InfeasibleReason::UnknownNeighborAs)
        );
        // Locally originated unicast is not a received candidate in rule (c).
        child.origin_type = RouteOrigin::Local;
        assert_eq!(
            evaluate(&flow, Some(&cover), &[child]),
            Feasibility::Feasible
        );
    }

    #[test]
    fn ipv6_offset_and_absent_destination_have_different_reasons() {
        let (mut flow, mut cover) = fixture();
        flow.afi = Afi::Ipv6;
        cover.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));
        flow.rule.components.clear();
        assert_eq!(
            evaluate(&flow, Some(&cover), &[]),
            invalid(InfeasibleReason::MissingDestination)
        );
        for (offset, expected) in [
            (0, Feasibility::Feasible),
            (16, invalid(InfeasibleReason::NonzeroDestinationOffset)),
        ] {
            flow.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
                Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48),
                    offset,
                },
            ))];
            assert_eq!(evaluate(&flow, Some(&cover), &[]), expected);
        }
        flow.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
            Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48),
                offset: 0,
            },
        ))];
        let mut child = cover.clone();
        child.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:1:8000::".parse().unwrap(), 49));
        child.attributes = Arc::new(vec![path(&[64497])]);
        assert_eq!(
            evaluate(&flow, Some(&cover), &[child]),
            invalid(InfeasibleReason::ConflictingMoreSpecific)
        );
    }

    #[test]
    fn local_injection_is_distinct_from_rfc_validated_receipt() {
        let (mut flow, _) = fixture();
        flow.origin_type = RouteOrigin::Local;
        flow.attributes.clear();
        flow.rule.components.clear();
        assert_eq!(evaluate(&flow, None, &[]), Feasibility::Local);
    }

    #[test]
    fn incremental_failure_is_sticky_across_visits() {
        let (flow, cover) = fixture();
        let ControlFlow::Continue(mut check) = begin(&flow, Some(&cover), LOCAL_AS) else {
            panic!("fixture must require a more-specific scan");
        };
        let mut child = cover.clone();
        child.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25));
        assert!(check.visit(&child).is_continue());
        child.attributes = Arc::new(vec![path(&[64497])]);
        assert_eq!(
            check.visit(&child),
            ControlFlow::Break(InfeasibleReason::ConflictingMoreSpecific)
        );
        assert_eq!(
            check.visit(&cover),
            ControlFlow::Break(InfeasibleReason::ConflictingMoreSpecific)
        );
        assert_eq!(
            check.finish(),
            invalid(InfeasibleReason::ConflictingMoreSpecific)
        );
    }
}
