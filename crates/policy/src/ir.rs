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

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_wire::{AspaValidation, Prefix, RpkiValidation};

use crate::datasets::{DatasetHandle, DatasetKind};
use crate::engine::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, PolicyAction, RouteFamily, RouteModifications,
    RouteType,
};
use crate::sets::{AsnSet, CommunitySet, PrefixSet};

/// Index of a match set within its owning [`CompiledChain`]'s table
/// (`prefix_sets` or `community_sets`, per the referencing node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetId(pub u32);

/// Index of a dataset binding within its owning [`CompiledChain`]'s
/// `datasets` table (LAN-305).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetId(pub u32);

/// What a [`MatchExpr::InDataset`] guard probes against the pinned
/// dataset snapshot — the dataset mirror of the per-kind `*InSet`
/// nodes (LAN-305). Kind agreement (an ASN probe against an asn-set
/// dataset, …) is a typecheck guarantee; the evaluator fails closed on
/// a mismatch, like every compiler-bug rail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatasetProbe {
    /// `route.prefix in <dataset>` (prefix-set kind).
    Prefix,
    /// `route.origin-as in <dataset>` (asn-set kind). Never matches
    /// when the origin is absent, mirroring [`MatchExpr::OriginAsInSet`].
    OriginAs,
    /// `peer.asn in <dataset>` (asn-set kind). Reads peer identity, so
    /// it counts toward [`CompiledChain::requires_peer_context`].
    PeerAs,
    /// A community-list `in <dataset>` (community-set kind) — the
    /// OR-any criteria semantics of [`MatchExpr::CommunityInSet`].
    Community,
    /// `<binding> in <dataset>` (asn-set kind): one frame load plus
    /// one hash probe, mirroring [`MatchExpr::LocalInAsnSet`].
    LocalAsn {
        /// Frame slot to read.
        slot: u8,
        /// The binding name as written (explain rendering; equality
        /// participant like set names).
        name: Box<str>,
    },
    /// `<binding> in <dataset>` (community-set kind): probes the
    /// standard partition by raw `u32`, mirroring
    /// [`MatchExpr::LocalInCommunitySet`].
    LocalCommunity {
        /// Frame slot to read.
        slot: u8,
        /// The binding name as written.
        name: Box<str>,
    },
    /// `<parameter> in <dataset>` (asn-set kind). Unlike parameter
    /// probes against in-language sets — which fold to their truth
    /// value at compile time — dataset content is external and swaps
    /// at runtime, so the probe stays a runtime probe of the constant.
    ConstAsn(u32),
    /// `<parameter> in <dataset>` (community-set kind): standard
    /// partition probe of the constant.
    ConstCommunity(u32),
}

/// One dataset binding in a [`CompiledChain`]'s `datasets` table: the
/// declared name and kind plus the shared live handle the evaluator
/// pins snapshots from.
///
/// **Equality is (name, kind) only** — deliberately excluding the
/// handle and its content. This is ADR-0103 Decision 5.3 ("data diffs
/// as data"): a dataset content swap must not make the referencing
/// chain diff as changed (no spurious live-impact classification, no
/// counter reset), while renaming or re-kinding a dataset is a source
/// change that honestly does.
#[derive(Debug, Clone)]
pub struct DatasetSlot {
    /// The declared dataset name.
    pub name: Arc<str>,
    /// The declared kind.
    pub kind: DatasetKind,
    /// The live handle; `Arc`-shared with the daemon's dataset
    /// registry so content swaps are visible to installed chains
    /// without reinstalling them.
    pub handle: Arc<DatasetHandle>,
}

impl PartialEq for DatasetSlot {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.kind == other.kind
    }
}

impl Eq for DatasetSlot {}

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

/// A checked `u32` arithmetic operator (LAN-299, ADR-0103 Decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    /// `+` — checked; overflow is an evaluation error.
    Add,
    /// `-` — checked; underflow is an evaluation error.
    Sub,
    /// `*` — checked; overflow is an evaluation error.
    Mul,
    /// `/` — checked; division by zero is an evaluation error.
    Div,
    /// `%` — checked; modulo by zero is an evaluation error.
    Rem,
}

impl ArithOp {
    /// The source spelling.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            ArithOp::Add => "+",
            ArithOp::Sub => "-",
            ArithOp::Mul => "*",
            ArithOp::Div => "/",
            ArithOp::Rem => "%",
        }
    }
}

/// A `u32`-typed context field readable as a value-expression operand
/// (LAN-299). Absent-value semantics per field, mirroring today's
/// comparison defaults where a documented default exists:
///
/// - [`LocalPref`](Self::LocalPref) / [`Med`](Self::Med): the RFC 4271
///   implicit defaults (100 / 0) when the attribute is absent — the
///   same values plain comparisons already see.
/// - [`AsPathLen`](Self::AsPathLen): always present (0 for an empty
///   path).
/// - [`OriginAs`](Self::OriginAs) / [`PeerAsn`](Self::PeerAsn): no
///   default exists. An absent value makes the whole expression
///   unresolvable — an **evaluation error** (uniform Deny, ADR-0103
///   Decision 4), mirroring how computed prepend operands fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueField {
    /// `route.local-pref` (absent → 100).
    LocalPref,
    /// `route.med` (absent → 0).
    Med,
    /// `route.as-path.len`.
    AsPathLen,
    /// `route.origin-as` (absent → evaluation error).
    OriginAs,
    /// `peer.asn` (absent → evaluation error). Reads peer identity, so
    /// a chain whose value expressions contain it counts toward
    /// [`CompiledChain::requires_peer_context`].
    PeerAsn,
}

impl ValueField {
    /// The `.rpol` source spelling (also the explain rendering).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ValueField::LocalPref => "route.local-pref",
            ValueField::Med => "route.med",
            ValueField::AsPathLen => "route.as-path.len",
            ValueField::OriginAs => "route.origin-as",
            ValueField::PeerAsn => "peer.asn",
        }
    }
}

/// A compiled `u32` value expression (LAN-299): checked arithmetic over
/// constants, context fields, and the bounded builtins. Evaluated per
/// route by `eval_value` (`crate::eval`); any checked-arithmetic
/// failure or absent operand is an evaluation error that resolves the
/// route as Deny (ADR-0103 Decision 4). Constant subtrees are folded at
/// compile time (with checked ops); a constant expression that cannot
/// fold safely is left in place and fails per route, closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueExpr {
    /// A constant (literal, parameter, or folded subtree).
    Const(u32),
    /// A `u32` context field read.
    Field(ValueField),
    /// A `let`-binding read (LAN-302): one indexed load from the
    /// evaluation frame ([`TermAction::Bind`] wrote the slot earlier in
    /// the same walk — definite assignment is a compile-time guarantee).
    /// `name` is the source binding name, carried for explain rendering
    /// and eval-error logs; it participates in equality like set names
    /// do (renaming a binding is a source change).
    Local {
        /// Frame slot index (< `LOCAL_FRAME_SLOTS`).
        slot: u8,
        /// The binding name as written.
        name: Box<str>,
    },
    /// A checked binary arithmetic operation.
    Binary {
        /// The operator.
        op: ArithOp,
        /// Left operand.
        lhs: Box<ValueExpr>,
        /// Right operand.
        rhs: Box<ValueExpr>,
    },
    /// `min(a, b)`.
    Min(Box<ValueExpr>, Box<ValueExpr>),
    /// `max(a, b)`.
    Max(Box<ValueExpr>, Box<ValueExpr>),
    /// `clamp(x, lo, hi)` — `lo > hi` is a compile error when statically
    /// known, an evaluation error otherwise.
    Clamp(Box<ValueExpr>, Box<ValueExpr>, Box<ValueExpr>),
}

impl ValueExpr {
    /// Does any node satisfy `pred`? The value-expression sibling of
    /// [`MatchExpr::any_node`], used by the `requires_*` analyses.
    pub fn any_node(&self, pred: &impl Fn(&ValueExpr) -> bool) -> bool {
        if pred(self) {
            return true;
        }
        match self {
            ValueExpr::Const(_) | ValueExpr::Field(_) | ValueExpr::Local { .. } => false,
            ValueExpr::Binary { lhs, rhs, .. }
            | ValueExpr::Min(lhs, rhs)
            | ValueExpr::Max(lhs, rhs) => lhs.any_node(pred) || rhs.any_node(pred),
            ValueExpr::Clamp(x, lo, hi) => {
                x.any_node(pred) || lo.any_node(pred) || hi.any_node(pred)
            }
        }
    }

    /// Whether evaluating this expression reads the evaluation peer's
    /// identity (a [`ValueField::PeerAsn`] operand).
    #[must_use]
    pub fn reads_peer(&self) -> bool {
        self.any_node(&|node| matches!(node, ValueExpr::Field(ValueField::PeerAsn)))
    }
}

impl fmt::Display for ValueExpr {
    /// Render in `.rpol` surface syntax with minimal parentheses
    /// (`*`/`/`/`%` bind tighter than `+`/`-`), for explain traces and
    /// eval-error logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn binding(expr: &ValueExpr) -> u8 {
            match expr {
                ValueExpr::Binary {
                    op: ArithOp::Add | ArithOp::Sub,
                    ..
                } => 0,
                ValueExpr::Binary { .. } => 1,
                _ => 2,
            }
        }
        fn render(expr: &ValueExpr, f: &mut fmt::Formatter<'_>, min_binding: u8) -> fmt::Result {
            let paren = binding(expr) < min_binding;
            if paren {
                write!(f, "(")?;
            }
            match expr {
                ValueExpr::Const(value) => write!(f, "{value}")?,
                ValueExpr::Field(field) => write!(f, "{}", field.as_str())?,
                ValueExpr::Local { name, .. } => write!(f, "{name}")?,
                ValueExpr::Binary { op, lhs, rhs } => {
                    let this = binding(expr);
                    render(lhs, f, this)?;
                    write!(f, " {} ", op.symbol())?;
                    // Right side binds one tighter so `a - (b - c)`
                    // keeps its parentheses.
                    render(rhs, f, this + 1)?;
                }
                ValueExpr::Min(a, b) => {
                    write!(f, "min(")?;
                    render(a, f, 0)?;
                    write!(f, ", ")?;
                    render(b, f, 0)?;
                    write!(f, ")")?;
                }
                ValueExpr::Max(a, b) => {
                    write!(f, "max(")?;
                    render(a, f, 0)?;
                    write!(f, ", ")?;
                    render(b, f, 0)?;
                    write!(f, ")")?;
                }
                ValueExpr::Clamp(x, lo, hi) => {
                    write!(f, "clamp(")?;
                    render(x, f, 0)?;
                    write!(f, ", ")?;
                    render(lo, f, 0)?;
                    write!(f, ", ")?;
                    render(hi, f, 0)?;
                    write!(f, ")")?;
                }
            }
            if paren {
                write!(f, ")")?;
            }
            Ok(())
        }
        render(self, f, 0)
    }
}

/// What a compiled `for` loop iterates (LAN-303, ADR-0103 Decision 3).
/// Every source is finite by construction: route attribute lists are
/// wire-bounded and set snapshots are load-bounded; the evaluator
/// additionally enforces the per-loop iteration cap and fuel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopSource {
    /// `route.communities` — the route's standard (RFC 1997)
    /// communities as raw `u32` values, in attribute order. Large and
    /// extended communities are not `u32`-shaped and do not iterate in
    /// this slice (ADR-0103 Decision 2 value model).
    Communities,
    /// `route.as-path` — every ASN in wire order (segments in order,
    /// ASNs within each segment in stored order, prepend duplicates
    /// included; `AS_SET` members yielded individually — see
    /// `rustbgpd_wire::AsPath::asns`). A route without an `AS_PATH`
    /// iterates zero times.
    AsPath,
    /// A named `asn-set` — members in canonical order (the interned
    /// sorted, deduplicated representation), so iteration order is
    /// deterministic across compiles and insertion orders.
    AsnSet(SetId),
}

impl LoopSource {
    /// The `.rpol` source spelling for attribute sources (set sources
    /// render by set name via the chain tables).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LoopSource::Communities => "route.communities",
            LoopSource::AsPath => "route.as-path",
            LoopSource::AsnSet(_) => "<asn-set>",
        }
    }
}

/// A compiled `for` loop (LAN-303): bind each element of `source` to
/// frame slot `slot` and walk `body` per iteration. The loop is one IR
/// term inside its policy (the term grid stays a function of the
/// source — ADR-0103 Decision 6.1); body terms live here, outside the
/// policy's term/counter grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForEachNode {
    /// What to iterate.
    pub source: LoopSource,
    /// Frame slot the loop variable occupies (a fresh value is written
    /// per iteration; the slot follows LAN-302 scope reuse rules).
    pub slot: u8,
    /// The loop variable name as written, for explain rendering.
    pub var: Box<str>,
    /// Body terms, walked per iteration with loop semantics:
    /// [`TermAction::Permit`]/[`TermAction::Deny`] terminate the policy
    /// exactly as in an `if` body, [`TermAction::Continue`] accumulates
    /// staged modifications, [`TermAction::Break`] exits this loop,
    /// [`TermAction::ContinueLoop`] skips to the next iteration, and
    /// nested [`TermAction::ForEach`] terms recurse (nesting depth is
    /// typecheck-capped).
    pub body: Vec<Term>,
}

/// Comparison operator of a [`MatchExpr::ValueCmp`] guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueCmpOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `>=`
    Ge,
    /// `<=`
    Le,
}

impl ValueCmpOp {
    /// The source spelling.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            ValueCmpOp::Eq => "==",
            ValueCmpOp::Ne => "!=",
            ValueCmpOp::Ge => ">=",
            ValueCmpOp::Le => "<=",
        }
    }
}

/// A comparison between two value expressions (LAN-299) — the compiled
/// form of any `.rpol` comparison containing arithmetic or a builtin.
/// Boxed behind [`MatchExpr::ValueCmp`] so plain guard nodes keep their
/// size. Unlike the plain scalar nodes, an unresolvable operand here
/// (absent origin/peer ASN, checked-arithmetic failure) is an
/// **evaluation error**, not a non-match: the route is denied
/// (ADR-0103 Decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCmpNode {
    /// The comparison operator.
    pub op: ValueCmpOp,
    /// Left value expression.
    pub lhs: ValueExpr,
    /// Right value expression.
    pub rhs: ValueExpr,
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
    /// A comparison between two `u32` value expressions (LAN-299) —
    /// any `.rpol` comparison containing arithmetic or a builtin. An
    /// unresolvable operand or checked-arithmetic failure during
    /// evaluation is an evaluation error: the route is denied
    /// (ADR-0103 Decision 4), unlike the never-match semantics of the
    /// plain scalar nodes above.
    ValueCmp(Box<ValueCmpNode>),
    /// A `let`/loop binding's `u32` value is a member of an indexed
    /// ASN set (LAN-303, `.rpol` `<binding> in <asn-set>`). One frame
    /// load plus one hash probe; an unwritten frame is the fail-closed
    /// [`EvalErrorKind`](crate::eval::EvalErrorKind) compiler-bug rail,
    /// like every `Local` read.
    LocalInAsnSet {
        /// Frame slot to read.
        slot: u8,
        /// The binding name as written (explain rendering; participates
        /// in equality like set names do).
        name: Box<str>,
        /// The probed set (indexes [`CompiledChain::asn_sets`]).
        set: SetId,
    },
    /// A binding's `u32` value matches a community set's **standard**
    /// members (LAN-303, `.rpol` `<binding> in <community-set>` where
    /// the binding iterates `route.communities`). Standard communities
    /// are raw `u32` values, so this is one hash probe against the
    /// set's standard partition; large/extended members of the set are
    /// not `u32`-comparable and never match a binding.
    LocalInCommunitySet {
        /// Frame slot to read.
        slot: u8,
        /// The binding name as written.
        name: Box<str>,
        /// The probed set (indexes [`CompiledChain::community_sets`]).
        set: SetId,
    },
    /// A membership probe against a generation-pinned external dataset
    /// (LAN-305, ADR-0103 Decision 8.5). `id` indexes
    /// [`CompiledChain::datasets`]; the evaluator resolves it against
    /// the snapshot frame pinned once at walk start, so every probe in
    /// one walk sees the same generation. Semantics per probe form
    /// mirror the corresponding `*InSet` node exactly — the same
    /// indexed structures do the matching.
    InDataset {
        /// What is probed.
        probe: DatasetProbe,
        /// The dataset (indexes [`CompiledChain::datasets`]).
        id: DatasetId,
    },
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
            | MatchExpr::AspaIs(_)
            // Straight-line checked arithmetic over scalars — the
            // cheap tier, like the comparisons it generalizes.
            | MatchExpr::ValueCmp(_) => 0,
            MatchExpr::PrefixInSet(_)
            | MatchExpr::PrefixEq { .. }
            | MatchExpr::PrefixNe { .. }
            // ASN-set membership is one hash probe against an indexed
            // table — cheaper than a community scan, comparable to the
            // prefix probe tier.
            | MatchExpr::OriginAsInSet(_)
            | MatchExpr::PeerAsInSet(_)
            // A binding probe (LAN-303) is one frame load + one hash
            // probe — the same tier, for both set kinds (the community
            // form probes one partition by value, never scanning the
            // route's lists).
            | MatchExpr::LocalInAsnSet { .. }
            | MatchExpr::LocalInCommunitySet { .. } => 1,
            // Dataset probes cost what the same-kind set probe costs
            // (same structures); the community form scans the route's
            // lists (tier 3), everything else is a hash probe (tier 1).
            MatchExpr::InDataset { probe, .. } => match probe {
                DatasetProbe::Community => 3,
                _ => 1,
            },
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
    /// Evaluate `expr` and write the result into frame slot `slot` — a
    /// lowered `.rpol` `let` statement (LAN-302, ADR-0103 Decision 2).
    /// Like [`Continue`](Self::Continue) it never decides: the walk
    /// keeps going. The initializer is **eager**: it evaluates whenever
    /// the walk reaches this term (its guard is the enclosing branch
    /// condition — `True` for a term-body `let`), used or not, and any
    /// evaluation error denies the route on the uniform eval-error
    /// rail. Slots are statically allocated per source term; bindings
    /// are immutable in the language, so a slot is written once per
    /// scope activation (sibling scopes may reuse slots — never live
    /// simultaneously). `name` is carried for explain rendering. The
    /// TOML frontend never emits this variant, and `apply` targets are
    /// rejected at typecheck when they declare bindings, so it never
    /// appears inside an inlined predicate.
    Bind {
        /// Frame slot to write (< `LOCAL_FRAME_SLOTS`).
        slot: u8,
        /// The source binding name, for explain surfaces.
        name: Box<str>,
        /// The initializer (a checked value expression).
        expr: ValueExpr,
    },
    /// A bounded `for` loop (LAN-303, ADR-0103 Decision 3): iterate
    /// the node's finite source, binding each element and walking the
    /// body terms per iteration. Never decides by itself — a body
    /// verdict decides the policy; otherwise the walk continues past
    /// the loop. Runtime-metered: each iteration decrements the
    /// per-evaluation fuel and counts against the per-loop cap
    /// (`MAX_LOOP_ITERATIONS`); exhaustion of either is an evaluation
    /// error on the uniform Deny rail. `.rpol`-only — the TOML
    /// frontend never emits this variant.
    ForEach(Box<ForEachNode>),
    /// `break` — exit the innermost enclosing loop; the walk continues
    /// after it. Only valid inside a [`ForEach`](Self::ForEach) body
    /// (the typechecker rejects it elsewhere); reaching one at policy
    /// level is the fail-closed compiler-bug rail.
    Break,
    /// `continue` — skip to the enclosing loop's next iteration. Same
    /// placement rules as [`Break`](Self::Break).
    ContinueLoop,
    /// `add`/`remove community <binding>` (LAN-303): stage the
    /// binding's `u32` value as a standard-community add/remove at
    /// execution time — inside a loop this resolves per iteration, so
    /// a scrub loop stages each matched community individually. Like
    /// [`Continue`](Self::Continue) it never decides. The staged value
    /// lands in the ordinary literal modification lists, so downstream
    /// consumers only ever see concrete values (the LAN-296/LAN-299
    /// discipline).
    CommunityVar {
        /// True for `add`, false for `remove`.
        add: bool,
        /// Frame slot holding the community value.
        slot: u8,
        /// The binding name as written, for explain surfaces.
        name: Box<str>,
    },
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

impl Term {
    /// Does any term — this one or, recursively, any
    /// [`TermAction::ForEach`] body term — satisfy `pred`? The
    /// primitive the chain-level `requires_*` analyses walk with, so
    /// guards and actions inside loop bodies participate exactly like
    /// top-level ones (LAN-303).
    pub fn any_term(&self, pred: &impl Fn(&Term) -> bool) -> bool {
        if pred(self) {
            return true;
        }
        match &self.action {
            TermAction::ForEach(node) => node.body.iter().any(|term| term.any_term(pred)),
            _ => false,
        }
    }
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
    /// carried for chain attribution. Shared with each attributed
    /// evaluation so the live metrics path does not allocate one owned
    /// policy label per route.
    pub name: Option<Arc<str>>,
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
    /// External dataset bindings referenced by
    /// [`MatchExpr::InDataset`] nodes, indexed by [`DatasetId`]
    /// (LAN-305). Unlike the set tables — which carry every definition
    /// in the source file — only datasets some guard actually
    /// references get a slot, so this table *is* the chain's dataset
    /// dependency list (the `requires_*`-style scoping input for
    /// swap-time refresh). Slot equality is (name, kind), never
    /// content: a content swap does not change chain identity.
    pub datasets: Vec<DatasetSlot>,
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
            datasets: Vec::new(),
            local_asn: None,
        }
    }

    /// Whether some guard probes the named external dataset (LAN-305)
    /// — the scoping predicate for swap-time refresh: a dataset
    /// content swap refreshes exactly the peers whose chains satisfy
    /// this, mirroring the RPKI/ASPA cache-update pattern.
    #[must_use]
    pub fn references_dataset(&self, name: &str) -> bool {
        self.datasets.iter().any(|slot| &*slot.name == name)
    }

    /// The datasets this chain's guards reference, in [`DatasetId`]
    /// order.
    pub fn referenced_datasets(&self) -> impl Iterator<Item = &DatasetSlot> {
        self.datasets.iter()
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
    /// node, a [`MatchExpr::PeerAsInSet`] membership probe, a
    /// `peer.asn` operand inside a value expression — guard
    /// [`MatchExpr::ValueCmp`] or a computed `set` value, LAN-299 — or
    /// a peer-derived `prepend as peer` action, LAN-296 — the last is
    /// defense in depth: export attachment rejects it outright).
    /// Content-equal chains with
    /// such a guard can still yield peer-different verdicts, so
    /// update-group fingerprinting must not group peers that share one.
    /// `prepend as self` / `prepend as origin` are chain/route-context
    /// only and deliberately do NOT count here; arithmetic over route
    /// fields alone likewise never disqualifies grouping. Import
    /// chains are evaluated per-session and are unaffected by this
    /// flag.
    #[must_use]
    pub fn requires_peer_context(&self) -> bool {
        self.any_guard_node(&|expr| match expr {
            MatchExpr::NeighborIn(_)
            | MatchExpr::NextHopEqPeer
            | MatchExpr::NextHopNePeer
            | MatchExpr::PeerAsInSet(_)
            | MatchExpr::InDataset {
                probe: DatasetProbe::PeerAs,
                ..
            } => true,
            MatchExpr::ValueCmp(node) => node.lhs.reads_peer() || node.rhs.reads_peer(),
            _ => false,
        }) || self.peer_prepend_action().is_some()
            || self.any_action_mods(&|mods| {
                [&mods.set_local_pref_computed, &mods.set_med_computed]
                    .into_iter()
                    .flatten()
                    .any(|expr| expr.reads_peer())
            })
            // A `let` initializer reading `peer.asn` (LAN-302)
            // evaluates eagerly per route — an unknown peer ASN even
            // denies — so the binding alone makes verdicts
            // peer-dependent, whether or not the value is read.
            || self.any_term_node(
                &|term| matches!(&term.action, TermAction::Bind { expr, .. } if expr.reads_peer()),
            )
    }

    /// Whether evaluating this chain needs the typed `AS_PATH` on the
    /// route context — true iff some term (loop bodies included)
    /// iterates `route.as-path` (LAN-303, [`LoopSource::AsPath`]).
    /// Construction sites that leave [`crate::engine::RouteContext::as_path`]
    /// `None` make such loops iterate zero times, so callers with a
    /// typed path in hand should always pass it.
    #[must_use]
    pub fn requires_as_path_asns(&self) -> bool {
        self.any_term_node(&|term| {
            matches!(
                &term.action,
                TermAction::ForEach(node) if node.source == LoopSource::AsPath
            )
        })
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
        let carries_peer_prepend = |term: &Term| {
            let (TermAction::Permit(mods) | TermAction::Continue(mods)) = &term.action else {
                return false;
            };
            matches!(mods.as_path_prepend_computed, Some((PrependAs::PeerAs, _)))
        };
        for policy in &self.policies {
            for term in &policy.terms {
                // Attribute a hit inside a loop body to the enclosing
                // top-level term — that is the name explain and the
                // attach-time rejection render.
                if term.any_term(&carries_peer_prepend) {
                    return Some((policy.name.as_deref(), term.name.as_deref()));
                }
            }
        }
        None
    }

    /// Does any term across all policies — recursing into
    /// [`TermAction::ForEach`] bodies (LAN-303) — satisfy `pred`?
    fn any_term_node(&self, pred: &impl Fn(&Term) -> bool) -> bool {
        self.policies
            .iter()
            .flat_map(|policy| policy.terms.iter())
            .any(|term| term.any_term(pred))
    }

    /// Does any guard node across all policies satisfy `pred`?
    fn any_guard_node(&self, pred: &impl Fn(&MatchExpr) -> bool) -> bool {
        self.any_term_node(&|term| term.guard.any_node(pred))
    }

    /// Do any term's action modifications (Permit or Continue) across
    /// all policies satisfy `pred`?
    fn any_action_mods(&self, pred: &impl Fn(&RouteModifications) -> bool) -> bool {
        self.any_term_node(&|term| match &term.action {
            TermAction::Permit(mods) | TermAction::Continue(mods) => pred(mods),
            _ => false,
        })
    }
}
