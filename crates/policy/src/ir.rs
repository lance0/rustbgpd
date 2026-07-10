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
    AsPathRegex, CommunityMatch, NeighborSetMatch, PolicyAction, RouteFamily, RouteModifications,
    RouteType,
};
use crate::sets::{AsnSet, CommunitySet, PrefixSet};

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
/// - Prefix nodes (`PrefixEq` / `PrefixNe` / `PrefixInSet`) never match
///   a prefixless route (e.g. BGP-LS / RTC NLRIs) — `!=` mirrors `==`.
/// - [`Cmp`] on `LocalPref` / `Med` sees the RFC 4271 implicit defaults
///   (`LOCAL_PREF` 100, `MED` 0) when the attribute is absent.
/// - `RouteTypeIs` / `EvpnRouteTypeIs` / `NextHopEq` and their `Ne`
///   siblings (`RouteTypeNe` / `EvpnRouteTypeNe` / `NextHopNe`) never
///   match when the corresponding context field is `None` (`!=` mirrors
///   `==`: an absent attribute satisfies neither).
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
    /// The route's prefix does **not** match this `(prefix, ge, le)`
    /// triple. Unlike `Not(PrefixEq{…})`, this never matches a
    /// prefixless route (BGP-LS / RTC NLRIs): `!=` mirrors `==`, so an
    /// absent prefix satisfies neither.
    PrefixNe {
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
    /// The route's origin AS (last ASN of the rightmost non-empty
    /// `AS_SEQUENCE`) equals this ASN. Never matches when the origin is
    /// absent (empty or `AS_SET`-only path).
    OriginAsEq(u32),
    /// The route's origin AS differs from this ASN. Unlike
    /// `Not(OriginAsEq(_))`, this never matches when the origin is
    /// absent — `!=` mirrors `==`, so an absent origin satisfies
    /// neither.
    OriginAsNe(u32),
    /// The route's origin AS is a member of an indexed ASN set. Never
    /// matches when the origin is absent.
    OriginAsInSet(SetId),
    /// The evaluation peer's ASN is a member of an indexed ASN set.
    /// Never matches when the peer ASN is unknown. Reads peer identity,
    /// so it counts toward [`CompiledChain::requires_peer_context`].
    PeerAsInSet(SetId),
    /// Comparison against `LOCAL_PREF` (implicit default 100).
    LocalPref(Cmp),
    /// Comparison against `MED` (implicit default 0).
    Med(Cmp),
    /// The route's next-hop equals this address.
    NextHopEq(IpAddr),
    /// The route's next-hop equals the evaluation peer's address
    /// (strict next-hop, `.rpol` `route.next-hop == peer.address`).
    /// Never matches when either side is unknown. Reads peer identity,
    /// so it counts toward [`CompiledChain::requires_peer_context`]:
    /// on an export chain the verdict is per-target-peer and the peer
    /// must not join an update group.
    NextHopEqPeer,
    /// The route's next-hop differs from this address. Unlike
    /// `Not(NextHopEq(_))`, this never matches when the next-hop is
    /// absent — `!=` mirrors `==`, so an absent attribute satisfies
    /// neither.
    NextHopNe(IpAddr),
    /// The route's next-hop differs from the evaluation peer's address
    /// (strict next-hop `!=`, `.rpol` `route.next-hop != peer.address`).
    /// Never matches when either side is unknown. Like
    /// [`NextHopEqPeer`](Self::NextHopEqPeer) it reads peer identity, so
    /// it counts toward [`CompiledChain::requires_peer_context`].
    NextHopNePeer,
    /// The evaluation peer matches a neighbor set (address, ASN, or
    /// peer-group membership — OR within the set). Boxed: the set is
    /// three `Vec`s (72 bytes) and would otherwise dominate every
    /// `MatchExpr`'s size — And-children are walked as a contiguous
    /// `Vec`, so small nodes are cache locality.
    NeighborIn(Box<NeighborSetMatch>),
    /// The route's source class equals this type.
    RouteTypeIs(RouteType),
    /// The route's source class differs from this type. Unlike
    /// `Not(RouteTypeIs(_))`, this never matches when the route-type is
    /// absent — `!=` mirrors `==`.
    RouteTypeNe(RouteType),
    /// The route is an EVPN NLRI of this route type (RFC 7432 §7).
    EvpnRouteTypeIs(u8),
    /// The route is an EVPN NLRI whose route type differs from this one.
    /// Unlike `Not(EvpnRouteTypeIs(_))`, this never matches a non-EVPN
    /// (absent evpn-route-type) route — `!=` mirrors `==`.
    EvpnRouteTypeNe(u8),
    /// The route's typed AFI/SAFI family equals this one (`.rpol`
    /// `route.family == evpn`, LAN-295). Route-context-only: it reads
    /// no peer identity, so it does NOT count toward
    /// [`CompiledChain::requires_peer_context`] and never disqualifies
    /// a peer from update-group sharing. `.rpol`-only — the TOML
    /// frontend has no family match field (same posture as strict
    /// next-hop).
    FamilyIs(RouteFamily),
    /// The route's typed family differs from this one. Unlike
    /// `Not(FamilyIs(_))`, this never matches a context without typed
    /// family knowledge — `!=` mirrors `==`.
    FamilyNe(RouteFamily),
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
            | MatchExpr::OriginAsEq(_)
            | MatchExpr::OriginAsNe(_)
            | MatchExpr::LocalPref(_)
            | MatchExpr::Med(_)
            | MatchExpr::NextHopEq(_)
            | MatchExpr::NextHopEqPeer
            | MatchExpr::NextHopNe(_)
            | MatchExpr::NextHopNePeer
            | MatchExpr::RouteTypeIs(_)
            | MatchExpr::RouteTypeNe(_)
            | MatchExpr::EvpnRouteTypeIs(_)
            | MatchExpr::EvpnRouteTypeNe(_)
            | MatchExpr::FamilyIs(_)
            | MatchExpr::FamilyNe(_)
            | MatchExpr::RpkiIs(_)
            | MatchExpr::AspaIs(_) => 0,
            MatchExpr::PrefixInSet(_)
            | MatchExpr::PrefixEq { .. }
            | MatchExpr::PrefixNe { .. }
            // ASN-set membership is one hash probe against an indexed
            // table — cheaper than a community scan, comparable to the
            // prefix probe tier.
            | MatchExpr::OriginAsInSet(_)
            | MatchExpr::PeerAsInSet(_) => 1,
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
    /// The guard matched: apply these modifications and continue to the
    /// next term of the *same* policy (Junos-style modify-and-continue).
    ///
    /// This is the `.rpol` frontend's term-fallthrough carrier — a term
    /// body that executes `set`/`add`/`remove` actions but ends without
    /// an `accept`/`reject` verdict lowers to `Continue`. Continue
    /// modifications accumulate policy-locally and are merged into the
    /// policy's eventual `Permit` decision (its own modifications win
    /// on scalar conflicts, matching chain merge semantics); a later
    /// `Deny` discards them. The TOML frontend never emits this
    /// variant.
    Continue(RouteModifications),
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
    /// Compiled from `.rpol` source (the language frontend,
    /// [`crate::rpol`]).
    Rpol,
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
    /// ASN sets referenced by [`MatchExpr::OriginAsInSet`] /
    /// [`MatchExpr::PeerAsInSet`].
    pub asn_sets: Vec<Arc<AsnSet>>,
    /// Compiled regexes referenced by [`MatchExpr::AsPathMatches`].
    pub as_path_regexes: Vec<Arc<AsPathRegex>>,
    /// Source names of `prefix_sets` entries (same indexing), for
    /// explain rendering. `None` for sets the frontend had no name for
    /// (the TOML compiler; inline data). Participates in `PartialEq`
    /// like everything else here: renaming a set changes chain
    /// identity, which is honest — the rename is a config change.
    pub prefix_set_names: Vec<Option<String>>,
    /// Source names of `community_sets` entries (same indexing).
    pub community_set_names: Vec<Option<String>>,
    /// Source names of `asn_sets` entries (same indexing).
    pub asn_set_names: Vec<Option<String>>,
    /// The local speaker's ASN, stamped at attach time by the config
    /// chain resolver — the value `.rpol` `prepend as self` resolves
    /// to (LAN-296, see [`crate::engine::PrependAs`]). Carried on the
    /// chain rather than the per-route context because it is
    /// config-constant (`[global] asn`) and rides with the policy into
    /// every evaluation path (live distribution, import, explain
    /// dry-runs) without per-site plumbing. `None` for chains compiled
    /// outside a daemon config (standalone `rbgp policy check`, unit
    /// tests) unless the harness provides one — `prepend as self` then
    /// fails closed. Participates in `PartialEq` like everything else:
    /// deterministic from config, so unchanged reloads still diff as
    /// no-ops.
    pub local_asn: Option<u32>,
}

impl CompiledChain {
    /// An empty chain (matches an empty `PolicyChain`: implicit permit).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            policies: Vec::new(),
            prefix_sets: Vec::new(),
            community_sets: Vec::new(),
            asn_sets: Vec::new(),
            as_path_regexes: Vec::new(),
            prefix_set_names: Vec::new(),
            community_set_names: Vec::new(),
            asn_set_names: Vec::new(),
            local_asn: None,
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

    /// Whether evaluating this chain depends on the evaluation peer's
    /// identity (any [`MatchExpr::NeighborIn`] node — peer address,
    /// ASN, or peer-group matching — a strict-next-hop
    /// [`MatchExpr::NextHopEqPeer`] / [`MatchExpr::NextHopNePeer`]
    /// node, a [`MatchExpr::PeerAsInSet`] membership probe, or a
    /// peer-derived `prepend as peer` action, LAN-296 — the last is
    /// defense in depth: export attachment rejects it outright).
    /// Content-equal chains with
    /// such a guard can still yield peer-different verdicts, so
    /// update-group fingerprinting must not group peers that share one.
    /// `prepend as self` / `prepend as origin` are chain/route-context
    /// only and deliberately do NOT count here. Import chains are
    /// evaluated per-session and are unaffected by this flag.
    #[must_use]
    pub fn requires_peer_context(&self) -> bool {
        self.any_guard_node(&|expr| {
            matches!(
                expr,
                MatchExpr::NeighborIn(_)
                    | MatchExpr::NextHopEqPeer
                    | MatchExpr::NextHopNePeer
                    | MatchExpr::PeerAsInSet(_)
            )
        }) || self.peer_prepend_action().is_some()
    }

    /// The first `prepend as peer` action in the chain, as the owning
    /// `(policy-name, term-name)` pair for diagnostics — `None` when
    /// the chain carries no peer-derived prepend.
    ///
    /// Direction legality (LAN-296): such an action is import-only. On
    /// an export chain it would prepend the *receiving* peer's own ASN
    /// — dropped by the receiver as an own-AS loop (RFC 4271 §9.1.2) —
    /// so the config chain resolver rejects export attachment using
    /// this probe (see [`crate::engine::PrependAs`] for the decision
    /// note and the FRR/BIRD comparison).
    #[must_use]
    pub fn peer_prepend_action(&self) -> Option<(Option<&str>, Option<&str>)> {
        use crate::engine::PrependAs;
        for policy in &self.policies {
            for term in &policy.terms {
                let mods = match &term.action {
                    TermAction::Permit(mods) | TermAction::Continue(mods) => mods,
                    TermAction::Deny => continue,
                };
                if matches!(mods.as_path_prepend_computed, Some((PrependAs::PeerAs, _))) {
                    return Some((policy.name.as_deref(), term.name.as_deref()));
                }
            }
        }
        None
    }

    /// Does any guard node across all policies satisfy `pred`?
    fn any_guard_node(&self, pred: &impl Fn(&MatchExpr) -> bool) -> bool {
        self.policies
            .iter()
            .flat_map(|policy| policy.terms.iter())
            .any(|term| term.guard.any_node(pred))
    }
}
