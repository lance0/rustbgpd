//! The typed, compiled policy IR (ADR-0096).
//!
//! This is the single evaluation representation every policy frontend
//! compiles into: TOML statement chains today (`crate::compile`), the
//! `.rpol` language in a later slice. It is a **public, analyzable**
//! surface (ADR-0096 Decision 3) because four consumers introspect it:
//! the `requires_*` hot-path gates (IR analyses below), the ADR-0076
//! live-impact planner (structural diff), explain rendering, and
//! `rbgp policy test`.
//!
//! Match *data* lives outside the expression tree in indexed,
//! `Arc`-shared structures ([`crate::sets`]); expression nodes
//! reference them by [`SetId`] / [`RegexId`] into the owning
//! [`CompiledChain`]'s tables. Guards are side-effect-free, so
//! And-children may be (and are, at compile time) ordered by static
//! cost class without changing results.
//!
//! Spans and term names are optional carriers for the future `.rpol`
//! frontend; the TOML compiler leaves term names empty.

use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_wire::{AspaValidation, Prefix, RpkiValidation};

use crate::engine::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, PolicyAction, RouteModifications, RouteType,
};
use crate::sets::{CommunitySet, PrefixSet};

/// Index of a match set within its owning [`CompiledChain`]'s table
/// (`prefix_sets` or `community_sets`, per the referencing node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetId(pub u32);

/// Index of a compiled AS-path regex within its owning
/// [`CompiledChain`]'s `as_path_regexes` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexId(pub u32);

/// An inclusive comparison against an unsigned attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// Value must be `>=` the operand.
    Ge(u32),
    /// Value must be `<=` the operand.
    Le(u32),
}

/// A typed match expression — the guard side of a [`Term`].
///
/// Every node is a pure, side-effect-free predicate over a
/// `RouteContext`. Semantics mirror the legacy `PolicyStatement`
/// matcher exactly (pinned by the golden corpus in
/// `engine/tests/ir_parity.rs`):
///
/// - Prefix nodes never match a prefixless route (e.g. BGP-LS NLRIs).
/// - [`Cmp`] on `LocalPref` / `Med` sees the RFC 4271 implicit defaults
///   (`LOCAL_PREF` 100, `MED` 0) when the attribute is absent.
/// - `RouteTypeIs` / `EvpnRouteTypeIs` / `NextHopEq` never match when
///   the corresponding context field is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchExpr {
    /// Always matches (an unconditional term).
    True,
    /// The route's prefix is a member of an indexed prefix set.
    PrefixInSet(SetId),
    /// The route's prefix matches one inline `(prefix, ge, le)` triple
    /// (see [`crate::sets::prefix_entry_matches`]). Single-prefix
    /// matches stay inline rather than paying a set indirection.
    PrefixEq {
        /// The covering prefix; candidates are masked at its length.
        prefix: Prefix,
        /// Minimum candidate prefix length (inclusive).
        ge: Option<u8>,
        /// Maximum candidate prefix length (inclusive).
        le: Option<u8>,
    },
    /// Any route community satisfies this single criterion.
    CommunityContains(CommunityMatch),
    /// Any route community satisfies any criterion in an indexed set.
    CommunityInSet(SetId),
    /// The rendered `AS_PATH` string matches a compiled regex.
    AsPathMatches(RegexId),
    /// Comparison against the `AS_PATH` ASN count.
    AsPathLen(Cmp),
    /// Comparison against `LOCAL_PREF` (implicit default 100).
    LocalPref(Cmp),
    /// Comparison against `MED` (implicit default 0).
    Med(Cmp),
    /// The route's next-hop equals this address.
    NextHopEq(IpAddr),
    /// The evaluation peer matches a neighbor set (address, ASN, or
    /// peer-group membership — OR within the set). Boxed: the set is
    /// three `Vec`s (72 bytes) and would otherwise dominate every
    /// `MatchExpr`'s size — And-children are walked as a contiguous
    /// `Vec`, so small nodes are cache locality.
    NeighborIn(Box<NeighborSetMatch>),
    /// The route's source class equals this type.
    RouteTypeIs(RouteType),
    /// The route is an EVPN NLRI of this route type (RFC 7432 §7).
    EvpnRouteTypeIs(u8),
    /// RPKI origin validation state equals this state (RFC 6811).
    RpkiIs(RpkiValidation),
    /// ASPA path verification state equals this state.
    AspaIs(AspaValidation),
    /// All children match (empty = true).
    And(Vec<MatchExpr>),
    /// Any child matches (empty = false).
    Or(Vec<MatchExpr>),
    /// The child does not match.
    Not(Box<MatchExpr>),
}

impl MatchExpr {
    /// Static evaluation cost class, used to order And-children
    /// cheapest-first at compile time (mirroring the legacy matcher's
    /// tiers): scalar comparisons (0) < prefix (1) < neighbor-set (2) <
    /// community probe/scan (3) < AS-path regex (4). Compound nodes
    /// take their most expensive descendant.
    #[must_use]
    pub fn cost_class(&self) -> u8 {
        match self {
            MatchExpr::True
            | MatchExpr::AsPathLen(_)
            | MatchExpr::LocalPref(_)
            | MatchExpr::Med(_)
            | MatchExpr::NextHopEq(_)
            | MatchExpr::RouteTypeIs(_)
            | MatchExpr::EvpnRouteTypeIs(_)
            | MatchExpr::RpkiIs(_)
            | MatchExpr::AspaIs(_) => 0,
            MatchExpr::PrefixInSet(_) | MatchExpr::PrefixEq { .. } => 1,
            MatchExpr::NeighborIn(_) => 2,
            MatchExpr::CommunityContains(_) | MatchExpr::CommunityInSet(_) => 3,
            MatchExpr::AsPathMatches(_) => 4,
            MatchExpr::Not(inner) => inner.cost_class(),
            MatchExpr::And(children) | MatchExpr::Or(children) => {
                children.iter().map(Self::cost_class).max().unwrap_or(0)
            }
        }
    }

    /// Depth-first structural walk: does any node (including `self`)
    /// satisfy `pred`? This is the primitive the `requires_*` analyses
    /// build on.
    pub fn any_node(&self, pred: &impl Fn(&MatchExpr) -> bool) -> bool {
        if pred(self) {
            return true;
        }
        match self {
            MatchExpr::And(children) | MatchExpr::Or(children) => {
                children.iter().any(|child| child.any_node(pred))
            }
            MatchExpr::Not(inner) => inner.any_node(pred),
            _ => false,
        }
    }
}

/// What a matched term does with the route.
///
/// Chain continuation semantics live at the *chain* level, matching
/// today's GoBGP-style rules: within a policy the first matching term
/// decides; across the chain a `Permit` accumulates its modifications
/// and evaluation continues to the next policy, while a `Deny`
/// terminates the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermAction {
    /// Accept the route, contributing these attribute modifications.
    Permit(RouteModifications),
    /// Reject the route (terminates chain evaluation; contributes no
    /// modifications).
    Deny,
}

/// One guarded action inside a [`CompiledPolicy`] — the compiled form
/// of a TOML `PolicyStatement` or (later) an `.rpol` `term` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    /// Term name for explain surfaces. `None` for TOML statements
    /// (they are unnamed); the `.rpol` frontend populates it.
    pub name: Option<String>,
    /// The match guard; [`MatchExpr::True`] for an unconditional term.
    pub guard: MatchExpr,
    /// The action taken when the guard matches.
    pub action: TermAction,
}

/// Which frontend produced a compiled policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicySource {
    /// Compiled from a TOML `PolicyStatement` chain.
    Toml,
}

/// One compiled policy: ordered terms with first-match-wins semantics
/// and a default action when no term matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// Configured policy name (`None` for inline / anonymous policies);
    /// carried for chain attribution.
    pub name: Option<String>,
    /// Ordered terms; the first whose guard matches decides.
    pub terms: Vec<Term>,
    /// Action when no term matches.
    pub default_action: PolicyAction,
    /// The frontend this policy was compiled from.
    pub source: PolicySource,
}

/// A compiled policy chain plus the indexed match data its expression
/// nodes reference.
///
/// The set tables are `Arc`-shared with the [`crate::sets::SetStore`]
/// that interned them, so identical set data is stored once across
/// policies and chains. [`SetId`] / [`RegexId`] values index these
/// tables; constructing a chain whose nodes reference out-of-range ids
/// is a compiler bug (the evaluator indexes directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledChain {
    /// Policies evaluated in order (`GoBGP` chain semantics: permits
    /// accumulate modifications and continue; a deny terminates).
    pub policies: Vec<CompiledPolicy>,
    /// Prefix sets referenced by [`MatchExpr::PrefixInSet`].
    pub prefix_sets: Vec<Arc<PrefixSet>>,
    /// Community sets referenced by [`MatchExpr::CommunityInSet`].
    pub community_sets: Vec<Arc<CommunitySet>>,
    /// Compiled regexes referenced by [`MatchExpr::AsPathMatches`].
    pub as_path_regexes: Vec<Arc<AsPathRegex>>,
}

impl CompiledChain {
    /// An empty chain (matches an empty `PolicyChain`: implicit permit).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            policies: Vec::new(),
            prefix_sets: Vec::new(),
            community_sets: Vec::new(),
            as_path_regexes: Vec::new(),
        }
    }

    /// Whether evaluating this chain needs the rendered `AS_PATH`
    /// string — true iff some guard contains an
    /// [`MatchExpr::AsPathMatches`] node ([`MatchExpr::AsPathLen`] uses
    /// the cheap ASN count instead and does not count here).
    #[must_use]
    pub fn requires_as_path_string(&self) -> bool {
        self.any_guard_node(&|expr| matches!(expr, MatchExpr::AsPathMatches(_)))
    }

    /// Whether evaluating this chain depends on RPKI origin-validation
    /// state (any [`MatchExpr::RpkiIs`] node).
    #[must_use]
    pub fn requires_rpki_validation(&self) -> bool {
        self.any_guard_node(&|expr| matches!(expr, MatchExpr::RpkiIs(_)))
    }

    /// Whether evaluating this chain depends on ASPA path-validation
    /// state (any [`MatchExpr::AspaIs`] node).
    #[must_use]
    pub fn requires_aspa_validation(&self) -> bool {
        self.any_guard_node(&|expr| matches!(expr, MatchExpr::AspaIs(_)))
    }

    /// Whether evaluating this chain depends on any external validation
    /// cache (RPKI or ASPA).
    #[must_use]
    pub fn requires_validation_state(&self) -> bool {
        self.requires_rpki_validation() || self.requires_aspa_validation()
    }

    /// Does any guard node across all policies satisfy `pred`?
    fn any_guard_node(&self, pred: &impl Fn(&MatchExpr) -> bool) -> bool {
        self.policies
            .iter()
            .flat_map(|policy| policy.terms.iter())
            .any(|term| term.guard.any_node(pred))
    }
}
