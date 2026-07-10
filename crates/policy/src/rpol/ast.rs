//! The spanned `.rpol` AST — the parser's output, the typechecker's
//! and lowerer's input.
//!
//! Every node that can appear in a diagnostic carries a [`Span`].
//! Literals are already value-parsed (the parser validates ranges and
//! address syntax so later passes never re-parse text).

use std::net::IpAddr;

use rustbgpd_wire::{LargeCommunity, Prefix};

use crate::engine::CommunityMatch;

use super::diag::{Span, Spanned};

/// A parsed `.rpol` source file.
#[derive(Debug, Default)]
pub struct SourceFile {
    /// `prefix-set` definitions.
    pub prefix_sets: Vec<PrefixSetDef>,
    /// `community-set` definitions.
    pub community_sets: Vec<CommunitySetDef>,
    /// `asn-set` definitions.
    pub asn_sets: Vec<AsnSetDef>,
    /// `policy` definitions, in source order.
    pub policies: Vec<PolicyDef>,
    /// `test` blocks.
    pub tests: Vec<TestDef>,
}

/// `prefix-set NAME { entries }`.
#[derive(Debug)]
pub struct PrefixSetDef {
    /// Set name.
    pub name: Spanned<String>,
    /// Member prefixes with optional ge/le bounds.
    pub entries: Vec<PrefixEntryAst>,
}

/// One prefix-set member: `10.0.0.0/8 ge 24 le 28`.
#[derive(Debug)]
pub struct PrefixEntryAst {
    /// The member prefix.
    pub prefix: Prefix,
    /// Minimum candidate length (inclusive).
    pub ge: Option<u8>,
    /// Maximum candidate length (inclusive).
    pub le: Option<u8>,
}

/// `asn-set NAME { 64500, 64501, ... }`.
#[derive(Debug)]
pub struct AsnSetDef {
    /// Set name.
    pub name: Spanned<String>,
    /// Member ASNs (u32 literals; range-checked at parse).
    pub entries: Vec<Spanned<u32>>,
}

/// `community-set NAME { literals }`.
#[derive(Debug)]
pub struct CommunitySetDef {
    /// Set name.
    pub name: Spanned<String>,
    /// Member community literals (standard / large / RT / RO mixed).
    pub entries: Vec<Spanned<CommunityLit>>,
}

/// A community literal of any of the three kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityLit {
    /// `65000:100` or a well-known name (`NO_EXPORT`, …) — RFC 1997.
    Standard(u32),
    /// `65000:1:2` / `LC:65000:1:2` — RFC 8092.
    Large(LargeCommunity),
    /// `RT:65001:100` / `RO:...` — RFC 4360 Route Target / Route Origin.
    Ext {
        /// True for Route Target (sub-type 0x02), false for Route
        /// Origin (sub-type 0x03).
        route_target: bool,
        /// Global administrator (ASN, or an IPv4 address as u32).
        global: u32,
        /// Local administrator.
        local: u32,
        /// True when the global admin was written as a dotted-quad
        /// IPv4 address (selects the type 0x01 wire encoding).
        ipv4_admin: bool,
    },
    /// A well-known extended community by raw 8-byte value —
    /// `OV_VALID` / `OV_NOT_FOUND` / `OV_INVALID` (RFC 8097
    /// origin-validation state). The name is resolved at parse time;
    /// matching and add/remove operate on the exact wire value.
    ExtRaw(u64),
}

/// The community kind named by an action or fixture keyword
/// (`community` / `large-community` / `ext-community`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityKind {
    /// Standard (RFC 1997).
    Standard,
    /// Large (RFC 8092).
    Large,
    /// Extended (RFC 4360 RT/RO).
    Ext,
}

impl CommunityLit {
    /// The literal's kind.
    #[must_use]
    pub fn kind(self) -> CommunityKind {
        match self {
            CommunityLit::Standard(_) => CommunityKind::Standard,
            CommunityLit::Large(_) => CommunityKind::Large,
            CommunityLit::Ext { .. } | CommunityLit::ExtRaw(_) => CommunityKind::Ext,
        }
    }

    /// The equivalent match criterion (encoding-agnostic for RT/RO).
    #[must_use]
    pub fn to_match(self) -> CommunityMatch {
        match self {
            CommunityLit::Standard(value) => CommunityMatch::Standard { value },
            CommunityLit::Large(lc) => CommunityMatch::LargeCommunity {
                global_admin: lc.global_admin,
                local_data1: lc.local_data1,
                local_data2: lc.local_data2,
            },
            CommunityLit::Ext {
                route_target: true,
                global,
                local,
                ..
            } => CommunityMatch::RouteTarget { global, local },
            CommunityLit::Ext {
                route_target: false,
                global,
                local,
                ..
            } => CommunityMatch::RouteOrigin { global, local },
            CommunityLit::ExtRaw(raw) => CommunityMatch::ExactExt(raw),
        }
    }
}

/// `policy NAME(params) { terms }`.
#[derive(Debug)]
pub struct PolicyDef {
    /// Policy name.
    pub name: Spanned<String>,
    /// Declared parameters (all `u32` in V1).
    pub params: Vec<Spanned<String>>,
    /// Named terms, in source order.
    pub terms: Vec<TermDef>,
}

/// `term NAME { statements }`.
#[derive(Debug)]
pub struct TermDef {
    /// Term name (carried into the IR for explain).
    pub name: Spanned<String>,
    /// Body statements, in source order.
    pub stmts: Vec<Stmt>,
}

/// A term-body statement.
#[derive(Debug)]
pub enum Stmt {
    /// `if <expr> { actions } [else { actions }]`.
    If(IfStmt),
    /// A bare action executed unconditionally.
    Action(ActionStmt),
}

/// `if <cond> { then } [else { otherwise }]`. Bodies are flat action
/// lists — V1 has no nested `if`.
#[derive(Debug)]
pub struct IfStmt {
    /// The guard expression.
    pub cond: Expr,
    /// Actions when the guard matches.
    pub then_actions: Vec<ActionStmt>,
    /// Actions when it does not (optional `else`).
    pub else_actions: Option<Vec<ActionStmt>>,
    /// Span of the `if` keyword + condition.
    pub span: Span,
}

/// A `u32`-valued argument position: literal or parameter reference.
#[derive(Debug, Clone)]
pub enum U32Arg {
    /// Integer literal.
    Lit(u32, Span),
    /// Reference to a policy parameter (resolved by the typechecker,
    /// substituted at instantiation).
    Param(Spanned<String>),
}

impl U32Arg {
    /// The argument's source span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            U32Arg::Lit(_, span) => *span,
            U32Arg::Param(name) => name.span,
        }
    }
}

/// An action statement inside a term or `if` body.
#[derive(Debug)]
pub enum ActionStmt {
    /// `accept` — terminal permit.
    Accept(Span),
    /// `reject` — terminal deny.
    Reject(Span),
    /// `set local-pref <u32>`.
    SetLocalPref(U32Arg, Span),
    /// `set med <u32>`.
    SetMed(U32Arg, Span),
    /// `set next-hop <ip|self>`.
    SetNextHop(NextHopArg, Span),
    /// `add`/`remove` `community`/`large-community`/`ext-community`.
    Community {
        /// True for `add`, false for `remove`.
        add: bool,
        /// The kind keyword written (must match the literal's kind).
        kind: CommunityKind,
        /// The community literal.
        lit: Spanned<CommunityLit>,
        /// Whole-statement span.
        span: Span,
    },
    /// `prepend as <asn> <count>`.
    Prepend {
        /// ASN to prepend.
        asn: U32Arg,
        /// Number of copies (1–255, checked by the typechecker).
        count: U32Arg,
        /// Whole-statement span.
        span: Span,
    },
}

impl ActionStmt {
    /// The action's source span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            ActionStmt::Accept(span)
            | ActionStmt::Reject(span)
            | ActionStmt::SetLocalPref(_, span)
            | ActionStmt::SetMed(_, span)
            | ActionStmt::SetNextHop(_, span)
            | ActionStmt::Community { span, .. }
            | ActionStmt::Prepend { span, .. } => *span,
        }
    }
}

/// `set next-hop` operand.
#[derive(Debug)]
pub enum NextHopArg {
    /// `self` — rewrite to the local address.
    Self_(Span),
    /// A specific address.
    Addr(IpAddr, Span),
}

/// The context object a field path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRoot {
    /// `route.` — the route under evaluation.
    Route,
    /// `peer.` — the evaluation peer.
    Peer,
}

/// A dotted field path: `route.local-pref`, `route.as-path.len`,
/// `peer.asn`. Segments are contextual identifiers resolved by the
/// typechecker.
#[derive(Debug, Clone)]
pub struct FieldPath {
    /// `route` or `peer`.
    pub root: FieldRoot,
    /// Dotted segments after the root.
    pub segs: Vec<Spanned<String>>,
    /// Span of the whole path.
    pub span: Span,
}

impl FieldPath {
    /// The path rendered back to source form (`route.local-pref`).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = match self.root {
            FieldRoot::Route => String::from("route"),
            FieldRoot::Peer => String::from("peer"),
        };
        for seg in &self.segs {
            out.push('.');
            out.push_str(&seg.node);
        }
        out
    }
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `>=`
    Ge,
    /// `<=`
    Le,
}

/// A comparison right-hand side, resolved by the typechecker against
/// the field's type.
#[derive(Debug, Clone)]
pub enum Rhs {
    /// Integer literal.
    Int(u32, Span),
    /// Bare identifier: a policy parameter or an enum member
    /// (`valid`, `internal`, …).
    Ident(Spanned<String>),
    /// IP address literal.
    Ip(IpAddr, Span),
    /// Prefix literal.
    Prefix(Prefix, Span),
    /// String literal (peer-group names).
    Str(Spanned<String>),
    /// Community literal (never valid in a comparison — accepted so
    /// the typechecker can point at `has`/`in` instead).
    Community(Spanned<CommunityLit>),
    /// A field path on the right-hand side. The only accepted
    /// field-vs-field comparison is strict next-hop
    /// (`route.next-hop == peer.address`); the typechecker rejects
    /// everything else with a spanned diagnostic.
    Field(FieldPath),
}

impl Rhs {
    /// The operand's source span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Rhs::Int(_, span) | Rhs::Ip(_, span) | Rhs::Prefix(_, span) => *span,
            Rhs::Ident(s) | Rhs::Str(s) => s.span,
            Rhs::Community(lit) => lit.span,
            Rhs::Field(path) => path.span,
        }
    }

    /// Short description for type-mismatch diagnostics.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Rhs::Int(..) => "integer",
            Rhs::Ident(_) => "identifier",
            Rhs::Ip(..) => "IP address",
            Rhs::Prefix(..) => "prefix",
            Rhs::Str(_) => "string",
            Rhs::Community(_) => "community literal",
            Rhs::Field(_) => "field reference",
        }
    }
}

/// A boolean guard expression.
#[derive(Debug)]
pub enum Expr {
    /// `a || b`
    Or(Box<Expr>, Box<Expr>),
    /// `a && b`
    And(Box<Expr>, Box<Expr>),
    /// `!a`
    Not(Box<Expr>, Span),
    /// `field <op> rhs`
    Cmp {
        /// Left-hand field.
        field: FieldPath,
        /// The operator.
        op: CmpOp,
        /// Right-hand operand.
        rhs: Rhs,
        /// Whole-comparison span.
        span: Span,
    },
    /// `field in set-name`
    In {
        /// Left-hand field (`route.prefix` or a community list).
        field: FieldPath,
        /// The referenced set.
        set: Spanned<String>,
    },
    /// `field has <community literal>`
    Has {
        /// Left-hand community-list field.
        field: FieldPath,
        /// The community literal to probe for.
        lit: Spanned<CommunityLit>,
    },
    /// `route.as-path matches "regex"`
    Matches {
        /// Left-hand field (must be `route.as-path`).
        field: FieldPath,
        /// The Cisco-style regex pattern.
        pattern: Spanned<String>,
    },
    /// `route.as-path contains <asn>`
    Contains {
        /// Left-hand field (must be `route.as-path`).
        field: FieldPath,
        /// The ASN to look for (boundary-anchored).
        asn: U32Arg,
    },
    /// `apply(policy)` / `apply(policy(args))` — policy-as-predicate.
    Apply {
        /// The referenced policy.
        policy: Spanned<String>,
        /// Instantiation arguments.
        args: Vec<U32Arg>,
        /// Whole-call span.
        span: Span,
    },
}

impl Expr {
    /// The expression's source span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Expr::Or(l, r) | Expr::And(l, r) => l.span().to(r.span()),
            Expr::Not(_, span) | Expr::Cmp { span, .. } | Expr::Apply { span, .. } => *span,
            Expr::In { field, set } => field.span.to(set.span),
            Expr::Has { field, lit } => field.span.to(lit.span),
            Expr::Matches { field, pattern } => field.span.to(pattern.span),
            Expr::Contains { field, asn } => field.span.to(asn.span()),
        }
    }
}

/// `test NAME { route {...} [peer {...}] expect ... }`.
#[derive(Debug)]
pub struct TestDef {
    /// Test name.
    pub name: Spanned<String>,
    /// The route fixture.
    pub route: Vec<RouteField>,
    /// Optional peer fixture.
    pub peer: Vec<PeerField>,
    /// Expectations, in order.
    pub expects: Vec<ExpectDef>,
}

/// One field of a `route { ... }` fixture.
#[derive(Debug)]
pub enum RouteField {
    /// `prefix 10.0.0.0/24`
    Prefix(Prefix, Span),
    /// `communities [65000:100, ...]` (standard).
    Communities(Vec<Spanned<CommunityLit>>, Span),
    /// `large-communities [...]`.
    LargeCommunities(Vec<Spanned<CommunityLit>>, Span),
    /// `ext-communities [...]`.
    ExtCommunities(Vec<Spanned<CommunityLit>>, Span),
    /// `as-path "65001 65002"`.
    AsPath(Spanned<String>),
    /// `next-hop 10.0.0.1`.
    NextHop(IpAddr, Span),
    /// `local-pref 200`.
    LocalPref(u32, Span),
    /// `med 50`.
    Med(u32, Span),
    /// `rpki valid|invalid|not-found`.
    Rpki(Spanned<String>),
    /// `aspa valid|invalid|unknown`.
    Aspa(Spanned<String>),
    /// `route-type local|internal|external`.
    RouteType(Spanned<String>),
    /// `evpn-route-type 2`.
    EvpnRouteType(u32, Span),
    /// `family ipv4-unicast|evpn|...` (LAN-295).
    Family(Spanned<String>),
}

/// One field of a `peer { ... }` fixture.
#[derive(Debug)]
pub enum PeerField {
    /// `address 10.0.0.1`.
    Address(IpAddr),
    /// `asn 65001`.
    Asn(u32),
    /// `group "leaf"`.
    Group(Spanned<String>),
}

/// `expect policy(args) == accept|reject [with assertions]`.
#[derive(Debug)]
pub struct ExpectDef {
    /// The policy under test.
    pub policy: Spanned<String>,
    /// Instantiation arguments (literals only in `expect`).
    pub args: Vec<Spanned<u32>>,
    /// True for `accept`, false for `reject`.
    pub accept: bool,
    /// `with` attribute assertions.
    pub with: Vec<WithAssertion>,
    /// Whole-expect span.
    pub span: Span,
}

/// One `with` assertion — checked against the evaluation result's
/// modifications.
#[derive(Debug)]
pub enum WithAssertion {
    /// `local-pref 200` — `set_local_pref == Some(200)`.
    LocalPref(u32),
    /// `med 50`.
    Med(u32),
    /// `next-hop 10.0.0.1` / `next-hop self`.
    NextHop(NextHopArg),
    /// `community 65001:999` (any kind) — present in the adds.
    Community(Spanned<CommunityLit>),
    /// `prepend as 65001 3`.
    Prepend(u32, u32),
}
