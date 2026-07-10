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
    /// `import "path"` declarations (LAN-300), in source order.
    /// Consumed by the module resolver ([`super::modules`]); the merged
    /// compilation unit it produces carries none.
    pub imports: Vec<Spanned<String>>,
    /// `prefix-set` definitions.
    pub prefix_sets: Vec<PrefixSetDef>,
    /// `community-set` definitions.
    pub community_sets: Vec<CommunitySetDef>,
    /// `asn-set` definitions.
    pub asn_sets: Vec<AsnSetDef>,
    /// `dataset` declarations (LAN-305), in source order.
    pub datasets: Vec<DatasetDecl>,
    /// `fn` definitions (LAN-304), in source order.
    pub fns: Vec<FnDef>,
    /// `policy` definitions, in source order.
    pub policies: Vec<PolicyDef>,
    /// `test` blocks.
    pub tests: Vec<TestDef>,
}

/// `fn NAME(params) -> u32 { lets… result }` — a pure user-defined
/// value function (LAN-304, ADR-0103 Decision 2). Bodies are
/// expression-shaped: `let` bindings followed by exactly one result
/// expression — no verdicts, actions, `if`, or loops. Functions are
/// closed over nothing (no `route.`/`peer.` reads inside bodies; every
/// input arrives as a parameter — enforced by the typechecker), so
/// they are pure functions of their arguments, and calls fully inline
/// at lowering (no runtime call frames).
#[derive(Debug)]
pub struct FnDef {
    /// Function name. `fn` is a top-level contextual identifier
    /// (ADR-0103 Decision 2.2), not a reserved word.
    pub name: Spanned<String>,
    /// Declared parameters (all `u32` this slice).
    pub params: Vec<Spanned<String>>,
    /// Body `let` bindings, in source order.
    pub lets: Vec<FnLet>,
    /// The result expression (the body's last — and only — expression).
    pub result: ValueExprAst,
}

/// One `let <name> = <expr>` inside a function body (LAN-304).
#[derive(Debug)]
pub struct FnLet {
    /// The binding name (may shadow a parameter or earlier binding).
    pub name: Spanned<String>,
    /// The initializer.
    pub init: ValueExprAst,
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

/// `dataset <kind> NAME` (LAN-305) — declares an external dataset:
/// a named set whose members come from an operator-maintained file
/// (bound to a path by the daemon's `[policy.datasets]` config)
/// instead of source text. Declaration only: kind and name are
/// compile-time knowledge, content is a runtime snapshot. Datasets
/// share the flat set namespace — a dataset and a set with the same
/// name is a compile error.
#[derive(Debug)]
pub struct DatasetDecl {
    /// Dataset name.
    pub name: Spanned<String>,
    /// Declared kind (which probe positions accept it and how its
    /// file parses).
    pub kind: crate::datasets::DatasetKind,
    /// Span of the kind keyword, for diagnostics.
    pub kind_span: Span,
}

/// One member of a `test`-block `dataset NAME { ... }` override
/// (LAN-305): the literal forms are token-distinguishable, so the
/// parser accepts any of them and the typechecker pins the member
/// kinds against the declared dataset kind.
#[derive(Debug)]
pub enum DatasetEntryAst {
    /// A prefix entry with optional `ge`/`le`.
    Prefix(PrefixEntryAst),
    /// A bare u32 ASN.
    Asn(u32),
    /// A community literal of any kind.
    Community(CommunityLit),
}

/// `dataset NAME { members }` inside a `test` block (LAN-305): the
/// test's content for a declared dataset — tests never read operator
/// files, so a test whose policy probes a dataset must provide the
/// snapshot it runs against.
#[derive(Debug)]
pub struct TestDatasetDef {
    /// The declared dataset this overrides.
    pub name: Spanned<String>,
    /// Members, parsed with the same literal parsers set definitions
    /// use.
    pub entries: Vec<Spanned<DatasetEntryAst>>,
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
    /// `for <var> in <source> { statements }` (LAN-303). Legal in term
    /// bodies and (nested, depth-capped) in loop bodies; `if` bodies
    /// stay flat action lists (the V1 rule).
    For(ForStmt),
}

/// `for <var> in <source> { body }` — a bounded loop (LAN-303). `for`
/// is a statement-initial contextual identifier (ADR-0103 Decision
/// 2.2): statement position previously admitted no bare identifier but
/// `let`, so consuming it is purely additive.
#[derive(Debug)]
pub struct ForStmt {
    /// The loop variable: an immutable `u32` binding scoped to the
    /// body, fresh per iteration.
    pub var: Spanned<String>,
    /// What to iterate.
    pub source: ForSource,
    /// Body statements — the term-body statement grammar plus
    /// `break`/`continue` and nested `for`.
    pub body: Vec<Stmt>,
    /// Span of `for <var> in <source>`.
    pub span: Span,
}

/// A loop's iteration source as parsed: a `route.`/`peer.` field path
/// or a named set. The typechecker restricts these to the finite
/// `u32`-valued sources (`route.communities`, `route.as-path`,
/// `asn-set` names).
#[derive(Debug)]
pub enum ForSource {
    /// `route.<field>` (or `peer.<field>`, rejected at typecheck).
    Field(FieldPath),
    /// A named set.
    Set(Spanned<String>),
}

impl ForSource {
    /// The source's span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            ForSource::Field(path) => path.span,
            ForSource::Set(name) => name.span,
        }
    }
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

/// A `u32` value expression (LAN-299): checked arithmetic over
/// literals, parameters, u32-typed context fields, and the bounded
/// builtins (`min`/`max`/`clamp`). Appears in `set local-pref`/`set
/// med` value positions and on either side of a comparison; the
/// typechecker enforces u32 operand typing, the lowerer
/// constant-folds (with checked ops) into [`crate::ir::ValueExpr`].
#[derive(Debug, Clone)]
pub enum ValueExprAst {
    /// Integer literal.
    Lit(u32, Span),
    /// Parameter reference (bare identifier in a value position).
    Ident(Spanned<String>),
    /// A `route.`/`peer.` field read (u32-typed fields only, checked
    /// by the typechecker).
    Field(FieldPath),
    /// A checked binary arithmetic operation.
    Binary {
        /// The operator.
        op: crate::ir::ArithOp,
        /// Left operand.
        lhs: Box<ValueExprAst>,
        /// Right operand.
        rhs: Box<ValueExprAst>,
        /// Whole-expression span.
        span: Span,
    },
    /// A builtin call: `min(a, b)`, `max(a, b)`, `clamp(x, lo, hi)`.
    /// The name is contextual (a parameter named `min` used bare keeps
    /// its parameter meaning); the typechecker validates name and
    /// arity.
    Call {
        /// The builtin name as written.
        name: Spanned<String>,
        /// Argument expressions.
        args: Vec<ValueExprAst>,
        /// Whole-call span.
        span: Span,
    },
}

impl ValueExprAst {
    /// The expression's source span.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            ValueExprAst::Lit(_, span)
            | ValueExprAst::Binary { span, .. }
            | ValueExprAst::Call { span, .. } => *span,
            ValueExprAst::Ident(name) => name.span,
            ValueExprAst::Field(path) => path.span,
        }
    }
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

/// The `prepend as <operand>` argument (LAN-296): a literal/parameter
/// ASN or a computed operand.
#[derive(Debug)]
pub enum PrependAsArg {
    /// Literal ASN or parameter reference (`prepend as 65001 3`,
    /// `prepend as n 3`). A bare identifier `origin` that is **not** a
    /// declared parameter of the enclosing policy also arrives here
    /// and denotes the origin operand (see [`Self::operand`]) — the
    /// grammar-evolution rules (ADR-0103 Decision 2) forbid reserving
    /// `origin`, so a parameter of that name keeps its existing
    /// meaning.
    Value(U32Arg),
    /// `prepend as self <count>` — the local speaker's ASN.
    SelfAs,
    /// `prepend as peer <count>` — the evaluation peer's ASN
    /// (import-only; rejected on export attachment).
    Peer,
}

impl PrependAsArg {
    /// The computed operand this argument denotes, or `None` for the
    /// literal/parameter form. `is_param` answers whether a name is a
    /// declared parameter of the enclosing policy — the single
    /// decision point shared by the typechecker and the lowerer, so
    /// the two passes cannot disagree about an `origin` identifier.
    pub fn operand(&self, is_param: impl Fn(&str) -> bool) -> Option<crate::engine::PrependAs> {
        match self {
            PrependAsArg::SelfAs => Some(crate::engine::PrependAs::LocalAs),
            PrependAsArg::Peer => Some(crate::engine::PrependAs::PeerAs),
            PrependAsArg::Value(U32Arg::Param(name))
                if name.node == "origin" && !is_param(&name.node) =>
            {
                Some(crate::engine::PrependAs::OriginAs)
            }
            PrependAsArg::Value(_) => None,
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
    /// `set local-pref <value-expr>` (a plain literal or parameter is
    /// the degenerate expression).
    SetLocalPref(ValueExprAst, Span),
    /// `set med <value-expr>`.
    SetMed(ValueExprAst, Span),
    /// `set next-hop <ip|self>`.
    SetNextHop(NextHopArg, Span),
    /// `add`/`remove` `community`/`large-community`/`ext-community`.
    Community {
        /// True for `add`, false for `remove`.
        add: bool,
        /// The kind keyword written (must match the literal's kind).
        kind: CommunityKind,
        /// The community literal or a `u32` binding reference
        /// (LAN-303).
        arg: CommunityArg,
        /// Whole-statement span.
        span: Span,
    },
    /// `prepend as <asn|self|peer|origin> <count>`.
    Prepend {
        /// ASN to prepend: literal/parameter, or a computed operand
        /// (LAN-296).
        asn: PrependAsArg,
        /// Number of copies (1–255, checked by the typechecker).
        count: U32Arg,
        /// Whole-statement span.
        span: Span,
    },
    /// `break` (LAN-303): exit the innermost enclosing loop. A
    /// statement-position contextual identifier like `let`; the
    /// typechecker rejects it outside a loop body.
    Break(Span),
    /// `continue` (LAN-303): skip to the enclosing loop's next
    /// iteration. Same placement rules as `break`.
    Continue(Span),
    /// `let <name> = <value-expr>` (LAN-302): an immutable, lexically
    /// scoped `u32` binding, legal in statement position — a term body
    /// or an `if`/`else` body. `let` is a contextual identifier
    /// (statement position admits no other bare identifier), not a
    /// reserved word — ADR-0103 Decision 2.2. Parsed alongside actions
    /// because statement position is exactly where actions live;
    /// the typechecker scopes it and the lowerer emits a `Bind` term.
    Let {
        /// The binding name.
        name: Spanned<String>,
        /// The initializer (a checked u32 value expression).
        init: ValueExprAst,
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
            | ActionStmt::Prepend { span, .. }
            | ActionStmt::Break(span)
            | ActionStmt::Continue(span)
            | ActionStmt::Let { span, .. } => *span,
        }
    }
}

/// The operand of an `add`/`remove` community action: a literal, or a
/// binding reference (LAN-303) whose `u32` value stages per execution
/// — the scrub-loop form `remove community <loop-var>`. Bindings are
/// standard-kind only (the u32 value model).
#[derive(Debug)]
pub enum CommunityArg {
    /// A community literal of the action's kind.
    Lit(Spanned<CommunityLit>),
    /// A `let`/loop binding or policy parameter (standard communities
    /// only; parameters resolve to literals at compile time).
    Var(Spanned<String>),
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
    /// `<binding> in set-name` (LAN-303): a `u32` binding (loop
    /// variable or `let`) probed against an `asn-set`, or — when the
    /// binding carries a standard community — a `community-set`'s
    /// standard members. Parameters are compile-time constants and
    /// fold to a constant truth value at lowering.
    IdentIn {
        /// The binding or parameter name.
        ident: Spanned<String>,
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
    /// A comparison containing arithmetic or a builtin on either side
    /// (LAN-299): `route.med + 50 >= p`, `route.as-path.len * 10 >=
    /// route.med`, `route.med == min(a, b)`. Plain comparisons keep
    /// the [`Cmp`](Self::Cmp) shape (and its never-match absent
    /// semantics); this shape evaluates checked, and an unresolvable
    /// operand denies the route (ADR-0103 Decision 4).
    ValueCmp {
        /// Left value expression.
        lhs: ValueExprAst,
        /// The operator.
        op: CmpOp,
        /// Right value expression.
        rhs: ValueExprAst,
        /// Whole-comparison span.
        span: Span,
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
            Expr::Not(_, span)
            | Expr::Cmp { span, .. }
            | Expr::ValueCmp { span, .. }
            | Expr::Apply { span, .. } => *span,
            Expr::In { field, set } => field.span.to(set.span),
            Expr::IdentIn { ident, set } => ident.span.to(set.span),
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
    /// `dataset NAME { ... }` content overrides (LAN-305), before the
    /// fixture.
    pub datasets: Vec<TestDatasetDef>,
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
    /// `local-as 64512` — the session's local speaker ASN, backing the
    /// `prepend as self` operand (LAN-296). In the daemon this comes
    /// from `[global] asn` at chain attach; a test fixture states it
    /// explicitly (omitted ⇒ `prepend as self` fails closed).
    LocalAs(u32),
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
