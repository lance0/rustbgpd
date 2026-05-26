//! rustbgpd-policy — Policy engine
//!
//! Route filtering, matching, and attribute modification.
//! Supports prefix lists, community matching, and route modifications.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

/// Policy engine core — match, modify, and filter routes.
pub mod engine;

pub use engine::{
    AsPathRegex, CommunityMatch, NamedPolicy, NeighborSetMatch, NextHopAction, Policy,
    PolicyAction, PolicyChain, PolicyEvaluation, PolicyResult, PolicyStatement, RouteContext,
    RouteModifications, RouteType, apply_modifications, evaluate_chain,
    evaluate_chain_with_attribution, evaluate_policy, parse_community_match,
};
