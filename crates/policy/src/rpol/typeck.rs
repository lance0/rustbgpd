//! The `.rpol` typechecker: name resolution, per-field operator/type
//! rules, parameter scoping, `apply` DAG validation, and did-you-mean
//! suggestions. Runs on the full AST even after parse errors, so one
//! `check` reports as much as possible.
//!
//! The type universe is fixed (ADR-0096 Decision 4): bool (guards),
//! u32 (`local-pref`, `med`, `as-path.len`, `peer.asn`,
//! `evpn-route-type`, parameters), prefix, the three community kinds,
//! as-path, the `rpki`/`aspa`/`route-type` enums, IP addresses, and
//! strings (regexes, peer groups). Inference is trivial by design —
//! every field has a known type and every operator a fixed signature.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::engine::AsPathRegex;
use crate::eval::checked_arith;
use crate::ir::ValueField;

use super::ast::{
    ActionStmt, CmpOp, CommunityKind, Expr, FieldPath, FieldRoot, PolicyDef, PrependAsArg, Rhs,
    RouteField, SourceFile, Stmt, U32Arg, ValueExprAst,
};
use super::diag::{Diagnostic, Span, Spanned, closest};

/// A resolved route/peer context field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Field {
    Prefix,
    Communities,
    LargeCommunities,
    ExtCommunities,
    AsPath,
    AsPathLen,
    OriginAs,
    LocalPref,
    Med,
    NextHop,
    Rpki,
    Aspa,
    RouteType,
    EvpnRouteType,
    Family,
    PeerAddress,
    PeerAsn,
    PeerGroup,
}

const ROUTE_FIELDS: &[(&str, Field)] = &[
    ("prefix", Field::Prefix),
    ("communities", Field::Communities),
    ("large-communities", Field::LargeCommunities),
    ("ext-communities", Field::ExtCommunities),
    ("as-path", Field::AsPath),
    ("origin-as", Field::OriginAs),
    ("local-pref", Field::LocalPref),
    ("med", Field::Med),
    ("next-hop", Field::NextHop),
    ("rpki", Field::Rpki),
    ("aspa", Field::Aspa),
    ("route-type", Field::RouteType),
    ("evpn-route-type", Field::EvpnRouteType),
    ("family", Field::Family),
];

const PEER_FIELDS: &[(&str, Field)] = &[
    ("address", Field::PeerAddress),
    ("asn", Field::PeerAsn),
    ("group", Field::PeerGroup),
];

/// Maximum `apply` composition depth (LAN-290). The DAG check rules
/// out recursion, but a linear chain of applies still nests: lowering
/// inlines each `apply` recursively, and every level embeds the
/// applied policy's predicate at least twice (once positive, once
/// negated for the default-permit arm), so inlined size doubles per
/// level and useful compositions are intrinsically shallow — 8 already
/// allows a 256× multiplier, generous for human-written policy stacks
/// (typical depth 2–3). rpol files arrive via SIGHUP overlay at
/// runtime, so an unbounded chain is a config-triggered stack overflow
/// in the lowering recursion.
const MAX_APPLY_DEPTH: u32 = 8;

/// Maximum IR guard nodes one policy may expand to through `apply`
/// inlining (LAN-290). `apply(p)` inlines `p`'s decision as a
/// predicate at every use site (quadratic in `p`'s decision-term
/// count — see `lower::accept_predicate`), so a wide apply DAG
/// multiplies nodes exponentially even within the depth limit. Bounds
/// compile-time work and compiled-chain memory; a typical
/// human-written guard is under ten nodes.
const MAX_APPLY_EXPANSION: u64 = 100_000;

/// Maximum worst-case per-route evaluation steps for one policy
/// (ADR-0103 Decision 3, `MAX_EVAL_COST`). Computed in the same
/// Kahn-ordered DP as the apply bounds: every guard node — including
/// each value-expression operator and builtin (LAN-299) — and every
/// action's value operators count one step, apply targets contribute
/// their inlined predicate cost. Straight-line programs whose bound
/// fits need no runtime fuel (fuel starts at loop back-edges,
/// LAN-303); a program whose bound exceeds this is rejected with a
/// diagnostic naming the policy.
const MAX_EVAL_COST: u64 = 1_000_000;

/// The value-expression builtins (LAN-299) and their arities.
const VALUE_BUILTINS: &[(&str, usize)] = &[("min", 2), ("max", 2), ("clamp", 3)];

/// Enum members per enum-typed field, in language spelling.
pub(super) const RPKI_MEMBERS: &[&str] = &["valid", "invalid", "not-found"];
pub(super) const ASPA_MEMBERS: &[&str] = &["valid", "invalid", "unknown"];
pub(super) const ROUTE_TYPE_MEMBERS: &[&str] = &["local", "internal", "external"];
/// The closed route-family set (LAN-295) — one spelling per
/// [`crate::engine::RouteFamily`] variant.
pub(super) const FAMILY_MEMBERS: &[&str] = &[
    "ipv4-unicast",
    "ipv6-unicast",
    "ipv4-labeled-unicast",
    "ipv6-labeled-unicast",
    "vpnv4",
    "vpnv6",
    "ipv4-flowspec",
    "ipv6-flowspec",
    "evpn",
    "rtc",
    "bgp-ls",
    "bgp-ls-vpn",
];

/// Resolve a dotted field path to a [`Field`], or a diagnostic with a
/// suggestion.
pub(super) fn resolve_field(path: &FieldPath) -> Result<Field, Diagnostic> {
    let (table, root_name) = match path.root {
        FieldRoot::Route => (ROUTE_FIELDS, "route"),
        FieldRoot::Peer => (PEER_FIELDS, "peer"),
    };
    let first = &path.segs[0];
    let Some(&(_, field)) = table.iter().find(|(name, _)| *name == first.node) else {
        let mut diag = Diagnostic::new(
            first.span,
            format!("unknown field `{root_name}.{}`", first.node),
            format!("`{root_name}` has no field `{}`", first.node),
        );
        if let Some(suggestion) = closest(&first.node, table.iter().map(|(name, _)| *name)) {
            diag = diag.with_note(format!("did you mean `{root_name}.{suggestion}`?"));
        }
        return Err(diag);
    };
    match path.segs.len() {
        1 => Ok(field),
        2 if field == Field::AsPath && path.segs[1].node == "len" => Ok(Field::AsPathLen),
        _ => {
            let extra = &path.segs[1];
            Err(Diagnostic::new(
                extra.span,
                format!("field `{}` has no sub-field `{}`", first.node, extra.node),
                "unexpected sub-field",
            )
            .with_note("the only sub-field is `route.as-path.len`"))
        }
    }
}

/// The u32-typed [`ValueField`] a resolved field reads as a
/// value-expression operand (LAN-299), or `None` for non-u32 fields.
/// The single decision point shared by the typechecker and the
/// lowerer, so the two passes cannot disagree about which fields are
/// arithmetic operands.
pub(super) fn value_field_of(field: Field) -> Option<ValueField> {
    match field {
        Field::LocalPref => Some(ValueField::LocalPref),
        Field::Med => Some(ValueField::Med),
        Field::AsPathLen => Some(ValueField::AsPathLen),
        Field::OriginAs => Some(ValueField::OriginAs),
        Field::PeerAsn => Some(ValueField::PeerAsn),
        _ => None,
    }
}

/// Typecheck a parsed source file. Returns every diagnostic found.
#[must_use]
pub fn typecheck(file: &SourceFile) -> Vec<Diagnostic> {
    let mut checker = Checker {
        file,
        diags: Vec::new(),
    };
    checker.check_declarations();
    for policy in &file.policies {
        checker.check_policy(policy);
    }
    checker.check_apply_dag();
    checker.check_apply_bounds();
    checker.check_tests();
    checker.diags
}

struct Checker<'a> {
    file: &'a SourceFile,
    diags: Vec<Diagnostic>,
}

impl Checker<'_> {
    fn policy(&self, name: &str) -> Option<&PolicyDef> {
        self.file.policies.iter().find(|p| p.name.node == name)
    }

    fn duplicate_check<'n>(
        &mut self,
        kind: &str,
        names: impl IntoIterator<Item = &'n Spanned<String>>,
    ) {
        let mut seen: HashMap<&str, Span> = HashMap::new();
        for name in names {
            if let Some(&first) = seen.get(name.node.as_str()) {
                self.diags.push(
                    Diagnostic::new(
                        name.span,
                        format!("duplicate {kind} `{}`", name.node),
                        format!("`{}` is already defined", name.node),
                    )
                    .with_label(first, "first definition is here"),
                );
            } else {
                seen.insert(&name.node, name.span);
            }
        }
    }

    fn check_declarations(&mut self) {
        self.duplicate_check("prefix-set", self.file.prefix_sets.iter().map(|s| &s.name));
        self.duplicate_check(
            "community-set",
            self.file.community_sets.iter().map(|s| &s.name),
        );
        self.duplicate_check("asn-set", self.file.asn_sets.iter().map(|s| &s.name));
        self.duplicate_check("policy", self.file.policies.iter().map(|p| &p.name));
        self.duplicate_check("test", self.file.tests.iter().map(|t| &t.name));
    }

    // ── policies ────────────────────────────────────────────────────

    fn check_policy(&mut self, policy: &PolicyDef) {
        self.duplicate_check("parameter", policy.params.iter());
        self.duplicate_check("term", policy.terms.iter().map(|t| &t.name));
        let params: Vec<&str> = policy.params.iter().map(|p| p.node.as_str()).collect();
        for term in &policy.terms {
            let mut terminated: Option<Span> = None;
            for stmt in &term.stmts {
                if let Some(verdict_span) = terminated {
                    let span = match stmt {
                        Stmt::If(if_stmt) => if_stmt.span,
                        Stmt::Action(action) => action.span(),
                    };
                    self.diags.push(
                        Diagnostic::new(
                            span,
                            "unreachable statement",
                            "this statement can never execute",
                        )
                        .with_label(verdict_span, "the term already decided here"),
                    );
                    break;
                }
                match stmt {
                    Stmt::Action(action) => {
                        self.check_action(action, &params);
                        if matches!(action, ActionStmt::Accept(_) | ActionStmt::Reject(_)) {
                            terminated = Some(action.span());
                        }
                    }
                    Stmt::If(if_stmt) => {
                        self.check_expr(&if_stmt.cond, &params);
                        self.check_action_list(&if_stmt.then_actions, &params);
                        if let Some(else_actions) = &if_stmt.else_actions {
                            self.check_action_list(else_actions, &params);
                        }
                    }
                }
            }
        }
    }

    fn check_action_list(&mut self, actions: &[ActionStmt], params: &[&str]) {
        let mut terminated: Option<Span> = None;
        for action in actions {
            if let Some(verdict_span) = terminated {
                self.diags.push(
                    Diagnostic::new(
                        action.span(),
                        "unreachable action",
                        "this action can never execute",
                    )
                    .with_label(verdict_span, "the branch already decided here"),
                );
                break;
            }
            self.check_action(action, params);
            if matches!(action, ActionStmt::Accept(_) | ActionStmt::Reject(_)) {
                terminated = Some(action.span());
            }
        }
    }

    fn check_action(&mut self, action: &ActionStmt, params: &[&str]) {
        match action {
            ActionStmt::Accept(_) | ActionStmt::Reject(_) | ActionStmt::SetNextHop(..) => {}
            ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _) => {
                self.check_value_expr(expr, params);
            }
            ActionStmt::Community { kind, lit, .. } => {
                if lit.node.kind() != *kind {
                    let (kind_word, lit_word) =
                        (kind_keyword(*kind), kind_keyword(lit.node.kind()));
                    self.diags.push(
                        Diagnostic::new(
                            lit.span,
                            format!(
                                "community kind mismatch: `{kind_word}` action with a {} literal",
                                kind_describe(lit.node.kind())
                            ),
                            format!("this is a {} literal", kind_describe(lit.node.kind())),
                        )
                        .with_note(format!("use `add/remove {lit_word}` for this literal")),
                    );
                }
            }
            ActionStmt::Prepend { asn, count, .. } => {
                // A computed operand (`self`/`peer`, or an `origin`
                // identifier that is not a declared parameter —
                // LAN-296) needs no parameter check; the operand
                // decision itself is shared with lowering via
                // `PrependAsArg::operand`.
                if asn.operand(|name| params.contains(&name)).is_none()
                    && let PrependAsArg::Value(arg) = asn
                {
                    self.check_u32_arg(arg, params);
                }
                match count {
                    U32Arg::Lit(value, span) => {
                        if *value == 0 || *value > 255 {
                            self.diags.push(Diagnostic::new(
                                *span,
                                format!("prepend count {value} out of range"),
                                "must be 1-255",
                            ));
                        }
                    }
                    U32Arg::Param(name) => {
                        self.diags.push(Diagnostic::new(
                            name.span,
                            "prepend count must be a literal",
                            "parameters are not allowed here",
                        ).with_note(
                            "the count is encoded as a u8; a parameterized count cannot be range-checked at definition time",
                        ));
                    }
                }
            }
        }
    }

    /// Typecheck a value expression (LAN-299): operands must be u32 —
    /// literals, declared parameters, u32-typed fields — builtins must
    /// be `min`/`max`/`clamp` with the right arity, and every
    /// statically-evaluable subexpression must evaluate cleanly under
    /// checked arithmetic (`4294967295 + 1` is a compile error at its
    /// span, not a per-route runtime error).
    fn check_value_expr(&mut self, expr: &ValueExprAst, params: &[&str]) {
        match expr {
            ValueExprAst::Lit(..) => {}
            ValueExprAst::Ident(name) => {
                self.check_u32_arg(&U32Arg::Param(name.clone()), params);
            }
            ValueExprAst::Field(path) => match resolve_field(path) {
                Err(diag) => self.diags.push(diag),
                Ok(resolved) => {
                    if value_field_of(resolved).is_none() {
                        self.diags.push(
                            Diagnostic::new(
                                path.span,
                                format!("`{}` is not a u32 field", path.render()),
                                "arithmetic operands are u32",
                            )
                            .with_note(
                                "u32 fields: route.local-pref, route.med, route.as-path.len, \
                                 route.origin-as, peer.asn",
                            ),
                        );
                    }
                }
            },
            ValueExprAst::Binary { op, lhs, rhs, span } => {
                self.check_value_expr(lhs, params);
                self.check_value_expr(rhs, params);
                // Constant folding diagnostic, reported at the
                // smallest failing subexpression: both children fold
                // cleanly, this operator fails.
                if let (Some(l), Some(r)) = (fold_const(lhs), fold_const(rhs))
                    && let Err(kind) = checked_arith(*op, l, r)
                {
                    self.diags.push(Diagnostic::new(
                        *span,
                        format!("this expression always fails: {kind}"),
                        "statically invalid arithmetic",
                    ));
                }
            }
            ValueExprAst::Call { name, args, span } => {
                for arg in args {
                    self.check_value_expr(arg, params);
                }
                let Some(&(_, arity)) = VALUE_BUILTINS
                    .iter()
                    .find(|(builtin, _)| *builtin == name.node)
                else {
                    let mut diag = Diagnostic::new(
                        name.span,
                        format!("unknown builtin `{}`", name.node),
                        "not a value builtin",
                    );
                    if let Some(suggestion) =
                        closest(&name.node, VALUE_BUILTINS.iter().map(|(b, _)| *b))
                    {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    } else {
                        diag = diag
                            .with_note("value builtins: min(a, b), max(a, b), clamp(x, lo, hi)");
                    }
                    self.diags.push(diag);
                    return;
                };
                if args.len() != arity {
                    self.diags.push(Diagnostic::new(
                        *span,
                        format!(
                            "`{}` takes {arity} argument{} but {} {} supplied",
                            name.node,
                            if arity == 1 { "" } else { "s" },
                            args.len(),
                            if args.len() == 1 { "was" } else { "were" },
                        ),
                        "wrong number of arguments",
                    ));
                    return;
                }
                // Statically inverted clamp bounds are a compile
                // error (the data-dependent case fails per route on
                // the eval-error rail).
                if name.node == "clamp"
                    && let (Some(lo), Some(hi)) = (fold_const(&args[1]), fold_const(&args[2]))
                    && lo > hi
                {
                    self.diags.push(Diagnostic::new(
                        *span,
                        format!("clamp bounds are inverted: lo ({lo}) > hi ({hi})"),
                        "this clamp always fails",
                    ));
                }
            }
        }
    }

    fn check_u32_arg(&mut self, arg: &U32Arg, params: &[&str]) {
        if let U32Arg::Param(name) = arg
            && !params.contains(&name.node.as_str())
        {
            let mut diag = Diagnostic::new(
                name.span,
                format!("unknown parameter `{}`", name.node),
                "not a parameter of this policy",
            );
            if let Some(suggestion) = closest(&name.node, params.iter().copied()) {
                diag = diag.with_note(format!("did you mean `{suggestion}`?"));
            }
            self.diags.push(diag);
        }
    }

    // ── expressions ─────────────────────────────────────────────────

    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive per-field/type dispatch; splitting would scatter the match"
    )]
    fn check_expr(&mut self, expr: &Expr, params: &[&str]) {
        match expr {
            Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
                self.check_expr(lhs, params);
                self.check_expr(rhs, params);
            }
            Expr::Not(inner, _) => self.check_expr(inner, params),
            Expr::Cmp { field, op, rhs, .. } => self.check_cmp(field, *op, rhs, params),
            // LAN-299: both sides of a value comparison are u32 value
            // expressions; all four operators apply (the checked
            // evaluation model has no unordered u32 fields).
            Expr::ValueCmp { lhs, rhs, .. } => {
                self.check_value_expr(lhs, params);
                self.check_value_expr(rhs, params);
            }
            Expr::In { field, set } => self.check_in(field, set),
            Expr::Has { field, lit } => match resolve_field(field) {
                Err(diag) => self.diags.push(diag),
                Ok(resolved) => {
                    let expected = match resolved {
                        Field::Communities => Some(CommunityKind::Standard),
                        Field::LargeCommunities => Some(CommunityKind::Large),
                        Field::ExtCommunities => Some(CommunityKind::Ext),
                        _ => None,
                    };
                    match expected {
                            None => self.diags.push(
                                Diagnostic::new(
                                    field.span,
                                    format!("`has` is not defined on `{}`", field.render()),
                                    "`has` probes a community list",
                                )
                                .with_note(
                                    "`has` works on route.communities, route.large-communities, and route.ext-communities",
                                ),
                            ),
                            Some(kind) if lit.node.kind() != kind => self.diags.push(
                                Diagnostic::new(
                                    lit.span,
                                    format!(
                                        "community kind mismatch: `{}` holds {} communities but this is a {} literal",
                                        field.render(),
                                        kind_describe(kind),
                                        kind_describe(lit.node.kind()),
                                    ),
                                    "wrong community kind",
                                )
                                .with_note(format!(
                                    "match it via `route.{}`",
                                    kind_field(lit.node.kind())
                                )),
                            ),
                            Some(_) => {}
                        }
                }
            },
            Expr::Matches { field, pattern } => {
                self.require_as_path(field, "matches");
                if let Err(error) = AsPathRegex::new(&pattern.node) {
                    self.diags.push(Diagnostic::new(
                        pattern.span,
                        error,
                        "regex does not compile",
                    ));
                }
            }
            Expr::Contains { field, asn } => {
                self.require_as_path(field, "contains");
                self.check_u32_arg(asn, params);
            }
            Expr::Apply { policy, args, span } => {
                let Some(target) = self.policy(&policy.node) else {
                    let mut diag = Diagnostic::new(
                        policy.span,
                        format!("unknown policy `{}`", policy.node),
                        "no policy with this name",
                    );
                    let names: Vec<&str> = self
                        .file
                        .policies
                        .iter()
                        .map(|p| p.name.node.as_str())
                        .collect();
                    if let Some(suggestion) = closest(&policy.node, names) {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    }
                    self.diags.push(diag);
                    return;
                };
                if target.params.len() != args.len() {
                    self.diags.push(
                        Diagnostic::new(
                            *span,
                            format!(
                                "policy `{}` takes {} argument{} but {} {} supplied",
                                policy.node,
                                target.params.len(),
                                if target.params.len() == 1 { "" } else { "s" },
                                args.len(),
                                if args.len() == 1 { "was" } else { "were" },
                            ),
                            "wrong number of arguments",
                        )
                        .with_label(target.name.span, "policy defined here"),
                    );
                }
                for arg in args {
                    self.check_u32_arg(arg, params);
                }
            }
        }
    }

    fn require_as_path(&mut self, field: &FieldPath, op: &str) {
        match resolve_field(field) {
            Err(diag) => self.diags.push(diag),
            Ok(Field::AsPath) => {}
            Ok(_) => self.diags.push(Diagnostic::new(
                field.span,
                format!("`{op}` is not defined on `{}`", field.render()),
                format!("`{op}` works on route.as-path"),
            )),
        }
    }

    fn check_cmp(&mut self, field: &FieldPath, op: CmpOp, rhs: &Rhs, params: &[&str]) {
        let resolved = match resolve_field(field) {
            Ok(resolved) => resolved,
            Err(diag) => {
                self.diags.push(diag);
                return;
            }
        };
        let eq_only = |checker: &mut Self| {
            if matches!(op, CmpOp::Ge | CmpOp::Le) {
                checker.diags.push(Diagnostic::new(
                    field.span.to(rhs.span()),
                    format!("`{}` supports only `==` and `!=`", field.render()),
                    "ordering comparison on an unordered field",
                ));
            }
        };
        match resolved {
            Field::LocalPref | Field::Med | Field::AsPathLen => {
                self.expect_u32_rhs(field, rhs, params);
            }
            Field::PeerAsn | Field::OriginAs => {
                eq_only(self);
                self.expect_u32_rhs(field, rhs, params);
            }
            Field::EvpnRouteType => {
                eq_only(self);
                self.check_evpn_route_type_rhs(field, rhs);
            }
            Field::Rpki => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, RPKI_MEMBERS, params);
            }
            Field::Aspa => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, ASPA_MEMBERS, params);
            }
            Field::RouteType => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, ROUTE_TYPE_MEMBERS, params);
            }
            Field::Family => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, FAMILY_MEMBERS, params);
            }
            Field::NextHop => {
                eq_only(self);
                self.check_next_hop_rhs(field, rhs);
            }
            Field::PeerAddress => {
                eq_only(self);
                if !matches!(rhs, Rhs::Ip(..)) {
                    self.diags.push(type_mismatch(field, "an IP address", rhs));
                }
            }
            Field::PeerGroup => {
                eq_only(self);
                if !matches!(rhs, Rhs::Str(_)) {
                    self.diags
                        .push(type_mismatch(field, "a quoted group name", rhs));
                }
            }
            Field::Prefix => {
                eq_only(self);
                if !matches!(rhs, Rhs::Prefix(..)) {
                    self.diags.push(
                        type_mismatch(field, "a prefix literal", rhs)
                            .with_note("for set membership use `route.prefix in <prefix-set>`"),
                    );
                }
            }
            Field::Communities | Field::LargeCommunities | Field::ExtCommunities => {
                self.diags.push(
                    Diagnostic::new(
                        field.span.to(rhs.span()),
                        format!("`{}` cannot be compared directly", field.render()),
                        "community lists have no `==`",
                    )
                    .with_note(
                        "use `has <community>` for one value or `in <community-set>` for a set",
                    ),
                );
            }
            Field::AsPath => {
                self.diags.push(
                    Diagnostic::new(
                        field.span.to(rhs.span()),
                        "`route.as-path` cannot be compared directly",
                        "AS paths have no `==`",
                    )
                    .with_note(
                        "use `route.as-path.len` for length, `contains <asn>`, or `matches \"<regex>\"`",
                    ),
                );
            }
        }
    }

    /// `route.evpn-route-type` compares against a 1-5 integer literal
    /// (RFC 7432 §7 defines types 1-4; RFC 9136 adds the type 5 IP
    /// Prefix route); 0 and 6-255 are rejected as dead policies.
    fn check_evpn_route_type_rhs(&mut self, field: &FieldPath, rhs: &Rhs) {
        match rhs {
            // rustbgpd emits EVPN NLRIs of route types 1-5 only
            // (RFC 7432 §7 types 1-4 plus the RFC 9136 type 5 IP Prefix
            // route). A comparison against 0 or 6-255 can never match a
            // real route, so reject it as a dead policy rather than let
            // it silently never fire.
            Rhs::Int(value, span) if !(1..=5).contains(value) => {
                self.diags.push(Diagnostic::new(
                    *span,
                    format!("EVPN route type {value} out of range"),
                    "must be 1-5 (RFC 7432 §7 types 1-4, RFC 9136 type 5)",
                ));
            }
            Rhs::Int(..) => {}
            other => {
                self.diags
                    .push(type_mismatch(field, "an integer EVPN route type", other));
            }
        }
    }

    /// `route.next-hop` compares against an IP literal or — the one
    /// legal field-vs-field comparison (strict next-hop) —
    /// `peer.address`.
    fn check_next_hop_rhs(&mut self, field: &FieldPath, rhs: &Rhs) {
        match rhs {
            Rhs::Ip(..) => {}
            Rhs::Field(path) => match resolve_field(path) {
                Ok(Field::PeerAddress) => {}
                Ok(_) => self.diags.push(
                    Diagnostic::new(
                        path.span,
                        format!(
                            "`route.next-hop` cannot be compared against `{}`",
                            path.render()
                        ),
                        "only `peer.address` is allowed here",
                    )
                    .with_note(
                        "strict next-hop is `route.next-hop == peer.address`; other fields have no next-hop comparison",
                    ),
                ),
                Err(diag) => self.diags.push(diag),
            },
            other => self.diags.push(type_mismatch(
                field,
                "an IP address or `peer.address`",
                other,
            )),
        }
    }

    fn expect_u32_rhs(&mut self, field: &FieldPath, rhs: &Rhs, params: &[&str]) {
        match rhs {
            Rhs::Int(..) => {}
            Rhs::Ident(name) => {
                self.check_u32_arg(&U32Arg::Param(name.clone()), params);
            }
            other => self
                .diags
                .push(type_mismatch(field, "a u32 value or parameter", other)),
        }
    }

    fn expect_enum_rhs(&mut self, field: &FieldPath, rhs: &Rhs, members: &[&str], params: &[&str]) {
        let Rhs::Ident(name) = rhs else {
            self.diags.push(type_mismatch(
                field,
                &format!("one of {}", member_list(members)),
                rhs,
            ));
            return;
        };
        if members.contains(&name.node.as_str()) {
            return;
        }
        let mut diag = Diagnostic::new(
            name.span,
            format!("`{}` is not a valid `{}` value", name.node, field.render()),
            format!("expected one of {}", member_list(members)),
        );
        if params.contains(&name.node.as_str()) {
            diag = diag.with_note(format!(
                "`{}` is a u32 parameter; `{}` is an enum field",
                name.node,
                field.render()
            ));
        } else if let Some(suggestion) = closest(&name.node, members.iter().copied()) {
            diag = diag.with_note(format!("did you mean `{suggestion}`?"));
        }
        self.diags.push(diag);
    }

    /// The set kind an `in` membership test needs for a resolved field,
    /// and a description of what mistakenly-referenced kind a name
    /// actually is (for the wrong-kind note).
    fn set_kind_of(&self, name: &str) -> Option<&'static str> {
        if self.file.prefix_sets.iter().any(|s| s.name.node == name) {
            Some("prefix-set")
        } else if self.file.community_sets.iter().any(|s| s.name.node == name) {
            Some("community-set")
        } else if self.file.asn_sets.iter().any(|s| s.name.node == name) {
            Some("asn-set")
        } else {
            None
        }
    }

    /// Diagnose an `in <set>` reference that must resolve to a set of
    /// `kind`, with wrong-kind and did-you-mean notes.
    fn check_set_reference<'n>(
        &mut self,
        set: &Spanned<String>,
        kind: &str,
        need: &str,
        names: impl Iterator<Item = &'n Spanned<String>>,
    ) {
        let mut candidates = names.map(|n| n.node.as_str());
        if candidates.any(|name| name == set.node) {
            return;
        }
        let mut diag = Diagnostic::new(
            set.span,
            format!("unknown {kind} `{}`", set.node),
            format!("no {kind} with this name"),
        );
        if let Some(actual) = self.set_kind_of(&set.node) {
            diag = diag.with_note(format!("`{}` is a {actual}; {need}", set.node));
        } else if let Some(suggestion) = closest(
            &set.node,
            match kind {
                "prefix-set" => self
                    .file
                    .prefix_sets
                    .iter()
                    .map(|s| s.name.node.as_str())
                    .collect::<Vec<_>>(),
                "community-set" => self
                    .file
                    .community_sets
                    .iter()
                    .map(|s| s.name.node.as_str())
                    .collect(),
                _ => self
                    .file
                    .asn_sets
                    .iter()
                    .map(|s| s.name.node.as_str())
                    .collect(),
            },
        ) {
            diag = diag.with_note(format!("did you mean `{suggestion}`?"));
        }
        self.diags.push(diag);
    }

    fn check_in(&mut self, field: &FieldPath, set: &Spanned<String>) {
        let resolved = match resolve_field(field) {
            Ok(resolved) => resolved,
            Err(diag) => {
                self.diags.push(diag);
                return;
            }
        };
        match resolved {
            Field::Prefix => self.check_set_reference(
                set,
                "prefix-set",
                "`route.prefix in` needs a prefix-set",
                self.file.prefix_sets.iter().map(|s| &s.name),
            ),
            Field::Communities | Field::LargeCommunities | Field::ExtCommunities => self
                .check_set_reference(
                    set,
                    "community-set",
                    "community membership needs a community-set",
                    self.file.community_sets.iter().map(|s| &s.name),
                ),
            Field::OriginAs | Field::PeerAsn => self.check_set_reference(
                set,
                "asn-set",
                "ASN membership needs an asn-set",
                self.file.asn_sets.iter().map(|s| &s.name),
            ),
            _ => self.diags.push(
                Diagnostic::new(
                    field.span.to(set.span),
                    format!("`in` is not defined on `{}`", field.render()),
                    "`in` tests set membership",
                )
                .with_note(
                    "`in` works on route.prefix (prefix-sets), community lists \
                     (community-sets), and route.origin-as / peer.asn (asn-sets)",
                ),
            ),
        }
    }

    // ── apply DAG ───────────────────────────────────────────────────

    /// Policies referenced through `apply` must form a DAG. Reports one
    /// diagnostic per cycle, naming the full path.
    fn check_apply_dag(&mut self) {
        let edges = apply_edges(self.file);
        let mut done: HashSet<&str> = HashSet::new();
        for policy in &self.file.policies {
            let name = policy.name.node.as_str();
            if done.contains(name) {
                continue;
            }
            let mut path: Vec<&str> = Vec::new();
            if let Some((cycle, span)) = find_cycle(name, &edges, &mut path, &mut done) {
                self.diags.push(
                    Diagnostic::new(
                        span,
                        format!("`apply` cycle: {}", cycle.join(" -> ")),
                        "this `apply` closes the cycle",
                    )
                    .with_note("policy composition must form a DAG (no recursion)"),
                );
            }
        }
    }

    /// Bound `apply` composition depth and worst-case inlined size
    /// (LAN-290; [`MAX_APPLY_DEPTH`] / [`MAX_APPLY_EXPANSION`]).
    /// Lowering inlines applies recursively and trusts the
    /// typechecker, so both bounds are enforced here, before any
    /// lowering runs. Costs are parameter-independent (arguments are
    /// `u32` constants), so one analysis covers every monomorphization.
    /// The walk is iterative (Kahn topological order) — the checker
    /// itself cannot overflow on a deep chain — and policies on an
    /// `apply` cycle (diagnosed by [`Self::check_apply_dag`]) never
    /// become ready and are skipped. A policy over a limit gets one
    /// diagnostic and poisons its dependents (their costs clamp to
    /// trivial), so a single root cause does not cascade.
    fn check_apply_bounds(&mut self) {
        let file = self.file;
        let edges = apply_edges(file);
        // Kahn scaffolding: a policy is ready once every *known* apply
        // target (unknown names are diagnosed elsewhere) is processed.
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut pending: HashMap<&str, usize> = HashMap::new();
        let mut ready: VecDeque<&str> = VecDeque::new();
        for policy in &file.policies {
            let name = policy.name.node.as_str();
            let known: Vec<&str> = edges[name]
                .iter()
                .map(|&(target, _)| target)
                .filter(|target| edges.contains_key(target))
                .collect();
            if known.is_empty() {
                ready.push_back(name);
            } else {
                pending.insert(name, known.len());
                for target in known {
                    dependents.entry(target).or_default().push(name);
                }
            }
        }
        let defs: HashMap<&str, &PolicyDef> = file
            .policies
            .iter()
            .map(|p| (p.name.node.as_str(), p))
            .collect();
        let mut depth: HashMap<&str, u32> = HashMap::new();
        let mut pred_cost: HashMap<&str, u64> = HashMap::new();
        let mut poisoned: HashSet<&str> = HashSet::new();
        while let Some(name) = ready.pop_front() {
            if let Some(diag) = bound_policy(
                defs[name],
                &edges[name],
                &mut depth,
                &mut pred_cost,
                &mut poisoned,
            ) {
                self.diags.push(diag);
            }
            for &dependent in dependents.get(name).into_iter().flatten() {
                let left = pending.get_mut(dependent).expect("counted above");
                *left -= 1;
                if *left == 0 {
                    ready.push_back(dependent);
                }
            }
        }
    }

    // ── tests ───────────────────────────────────────────────────────

    fn check_tests(&mut self) {
        for test in &self.file.tests {
            let mut seen_fields: HashMap<&'static str, Span> = HashMap::new();
            for field in &test.route {
                let (name, span) = route_field_name(field);
                if let Some(&first) = seen_fields.get(name) {
                    self.diags.push(
                        Diagnostic::new(
                            span,
                            format!("duplicate route fixture field `{name}`"),
                            "already set",
                        )
                        .with_label(first, "first set here"),
                    );
                } else {
                    seen_fields.insert(name, span);
                }
                match field {
                    RouteField::Rpki(value) => {
                        self.check_fixture_enum(value, "rpki", RPKI_MEMBERS);
                    }
                    RouteField::Aspa(value) => {
                        self.check_fixture_enum(value, "aspa", ASPA_MEMBERS);
                    }
                    RouteField::RouteType(value) => {
                        self.check_fixture_enum(value, "route-type", ROUTE_TYPE_MEMBERS);
                    }
                    RouteField::Family(value) => {
                        self.check_fixture_enum(value, "family", FAMILY_MEMBERS);
                    }
                    RouteField::EvpnRouteType(value, span) => {
                        if *value > 255 {
                            self.diags.push(Diagnostic::new(
                                *span,
                                format!("EVPN route type {value} out of range"),
                                "must be 0-255",
                            ));
                        }
                    }
                    RouteField::Communities(lits, _) => {
                        self.check_fixture_community_kinds(lits, CommunityKind::Standard);
                    }
                    RouteField::LargeCommunities(lits, _) => {
                        self.check_fixture_community_kinds(lits, CommunityKind::Large);
                    }
                    RouteField::ExtCommunities(lits, _) => {
                        self.check_fixture_community_kinds(lits, CommunityKind::Ext);
                    }
                    _ => {}
                }
            }
            for expect in &test.expects {
                let Some(target) = self.policy(&expect.policy.node) else {
                    let mut diag = Diagnostic::new(
                        expect.policy.span,
                        format!("unknown policy `{}`", expect.policy.node),
                        "no policy with this name",
                    );
                    if let Some(suggestion) = closest(
                        &expect.policy.node,
                        self.file.policies.iter().map(|p| p.name.node.as_str()),
                    ) {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    }
                    self.diags.push(diag);
                    continue;
                };
                if target.params.len() != expect.args.len() {
                    self.diags.push(
                        Diagnostic::new(
                            expect.span,
                            format!(
                                "policy `{}` takes {} argument{} but {} {} supplied",
                                expect.policy.node,
                                target.params.len(),
                                if target.params.len() == 1 { "" } else { "s" },
                                expect.args.len(),
                                if expect.args.len() == 1 {
                                    "was"
                                } else {
                                    "were"
                                },
                            ),
                            "wrong number of arguments",
                        )
                        .with_label(target.name.span, "policy defined here"),
                    );
                }
            }
        }
    }

    fn check_fixture_enum(&mut self, value: &Spanned<String>, field: &str, members: &[&str]) {
        if !members.contains(&value.node.as_str()) {
            let mut diag = Diagnostic::new(
                value.span,
                format!("`{}` is not a valid `{field}` value", value.node),
                format!("expected one of {}", member_list(members)),
            );
            if let Some(suggestion) = closest(&value.node, members.iter().copied()) {
                diag = diag.with_note(format!("did you mean `{suggestion}`?"));
            }
            self.diags.push(diag);
        }
    }

    fn check_fixture_community_kinds(
        &mut self,
        lits: &[Spanned<super::ast::CommunityLit>],
        expected: CommunityKind,
    ) {
        for lit in lits {
            if lit.node.kind() != expected {
                self.diags.push(
                    Diagnostic::new(
                        lit.span,
                        format!(
                            "expected a {} literal in this list, found a {} literal",
                            kind_describe(expected),
                            kind_describe(lit.node.kind()),
                        ),
                        "wrong community kind",
                    )
                    .with_note(format!(
                        "put it in the `{}` fixture field",
                        kind_field(lit.node.kind())
                    )),
                );
            }
        }
    }
}

/// `apply` edges per policy: name → (target, span of the apply), in
/// source order, duplicates kept.
fn apply_edges(file: &SourceFile) -> HashMap<&str, Vec<(&str, Span)>> {
    let mut edges: HashMap<&str, Vec<(&str, Span)>> = HashMap::new();
    for policy in &file.policies {
        let mut targets = Vec::new();
        for term in &policy.terms {
            for stmt in &term.stmts {
                if let Stmt::If(if_stmt) = stmt {
                    collect_applies(&if_stmt.cond, &mut targets);
                }
            }
        }
        edges.insert(&policy.name.node, targets);
    }
    edges
}

/// Record trivial costs for an over-limit (or dependent-of-over-limit)
/// policy so one root cause yields one diagnostic, not a cascade.
fn poison_policy<'a>(
    name: &'a str,
    depth: &mut HashMap<&'a str, u32>,
    pred_cost: &mut HashMap<&'a str, u64>,
    poisoned: &mut HashSet<&'a str>,
) {
    poisoned.insert(name);
    depth.insert(name, 0);
    pred_cost.insert(name, 1);
}

/// One policy's LAN-290 bound check (see
/// [`Checker::check_apply_bounds`]): update the `depth` / `pred_cost`
/// memo tables (its apply targets are already present — Kahn order)
/// and return the diagnostic if the policy breaks a limit. An
/// over-limit or poisoned policy records trivial costs so dependents
/// don't repeat the diagnosis.
fn bound_policy<'a>(
    def: &'a PolicyDef,
    targets: &[(&'a str, Span)],
    depth: &mut HashMap<&'a str, u32>,
    pred_cost: &mut HashMap<&'a str, u64>,
    poisoned: &mut HashSet<&'a str>,
) -> Option<Diagnostic> {
    let name = def.name.node.as_str();
    if targets.iter().any(|(target, _)| poisoned.contains(target)) {
        poison_policy(name, depth, pred_cost, poisoned);
        return None;
    }
    // Composition depth: one past the deepest apply target (unknown
    // targets have no entry and are diagnosed elsewhere).
    let deepest = targets
        .iter()
        .filter_map(|&(target, span)| depth.get(target).map(|&d| (d + 1, span)))
        .max_by_key(|&(d, _)| d);
    if let Some((d, span)) = deepest {
        if d > MAX_APPLY_DEPTH {
            poison_policy(name, depth, pred_cost, poisoned);
            return Some(
                Diagnostic::new(
                    span,
                    format!("`apply` chain nests policies more than {MAX_APPLY_DEPTH} deep"),
                    "this `apply` exceeds the composition depth limit",
                )
                .with_note(
                    "every apply level inlines (and at least doubles) the applied policy's \
                     predicate; flatten the composition",
                ),
            );
        }
        depth.insert(name, d);
    } else {
        depth.insert(name, 0);
    }
    // Expansion: per-arm guard costs in decision order (upper bound:
    // every `if` decides; an `else` adds a negated arm; a bare action
    // run lowers to one `True`-guarded term). Action value expressions
    // (LAN-299) count toward the evaluation-cost budget alongside.
    let mut arms: Vec<u64> = Vec::new();
    let mut action_cost: u64 = 0;
    for term in &def.terms {
        for stmt in &term.stmts {
            match stmt {
                Stmt::If(if_stmt) => {
                    let cost = guard_cost(&if_stmt.cond, pred_cost);
                    arms.push(cost);
                    if if_stmt.else_actions.is_some() {
                        arms.push(cost.saturating_add(1));
                    }
                    for action in if_stmt
                        .then_actions
                        .iter()
                        .chain(if_stmt.else_actions.iter().flatten())
                    {
                        action_cost = action_cost.saturating_add(action_value_cost(action));
                    }
                }
                Stmt::Action(action) => {
                    arms.push(1);
                    action_cost = action_cost.saturating_add(action_value_cost(action));
                }
            }
        }
    }
    let lowered: u64 = arms.iter().fold(0u64, |acc, &g| acc.saturating_add(g));
    // ADR-0103 Decision 3: the worst-case per-route step bound. With
    // no loops, every lowered guard node and action value operator
    // evaluates at most once per route, so the bound is the same DP
    // sum the expansion budget uses plus the action value costs.
    if lowered.saturating_add(action_cost) > MAX_EVAL_COST {
        poison_policy(name, depth, pred_cost, poisoned);
        return Some(
            Diagnostic::new(
                def.name.span,
                format!(
                    "policy `{name}` exceeds the worst-case evaluation budget \
                     of {MAX_EVAL_COST} steps per route"
                ),
                "evaluation cost limit exceeded",
            )
            .with_note(
                "every guard node, arithmetic operator, and builtin counts one step; \
                 `apply` inlining multiplies — split or flatten the composition",
            ),
        );
    }
    if lowered > MAX_APPLY_EXPANSION {
        poison_policy(name, depth, pred_cost, poisoned);
        return Some(
            Diagnostic::new(
                def.name.span,
                format!(
                    "policy `{name}` expands past {MAX_APPLY_EXPANSION} IR nodes \
                     through `apply` inlining"
                ),
                "compiled size limit exceeded",
            )
            .with_note(
                "apply(p) inlines p's decision predicate at every use site; \
                 split or flatten the composition",
            ),
        );
    }
    // Cost of applying this policy elsewhere: `accept_predicate` is
    // first-match-faithful — arm i carries every prior decision arm's
    // guard negated — so it is a quadratic prefix sum over arm costs
    // (the trailing `prior` is the default-permit arm).
    let mut prior: u64 = 0;
    let mut total: u64 = 1; // the Or node
    for &g in &arms {
        total = total.saturating_add(prior).saturating_add(g);
        prior = prior.saturating_add(g).saturating_add(1);
    }
    pred_cost.insert(name, total.saturating_add(prior));
    None
}

/// Upper bound on the IR nodes `expr` lowers to, given the predicate
/// costs of already-processed `apply` targets (a missing entry —
/// unknown name or on a diagnosed cycle — counts as trivial; the file
/// has errors and will never lower). Doubles as the worst-case
/// per-route step count for the `MAX_EVAL_COST` budget: with no loops
/// (LAN-303), every lowered node evaluates at most once per route.
/// Recursion depth is capped by the parser's `MAX_EXPR_DEPTH`
/// (LAN-184).
fn guard_cost(expr: &Expr, pred_cost: &HashMap<&str, u64>) -> u64 {
    match expr {
        Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => 1u64
            .saturating_add(guard_cost(lhs, pred_cost))
            .saturating_add(guard_cost(rhs, pred_cost)),
        Expr::Not(inner, _) => 1u64.saturating_add(guard_cost(inner, pred_cost)),
        // `==`/`!=` on u32 fields lower widest: `Not(And(Ge, Le))`.
        Expr::Cmp { .. } => 4,
        // LAN-299: every operator/builtin in the value expressions
        // counts one step in the DP.
        Expr::ValueCmp { lhs, rhs, .. } => 1u64
            .saturating_add(value_cost(lhs))
            .saturating_add(value_cost(rhs)),
        Expr::Apply { policy, .. } => pred_cost.get(policy.node.as_str()).copied().unwrap_or(1),
        _ => 1,
    }
}

/// The value-expression steps an action contributes to the
/// evaluation-cost budget (LAN-299: only the computed `set` values
/// carry expressions; everything else is constant-time).
fn action_value_cost(action: &ActionStmt) -> u64 {
    match action {
        ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _) => value_cost(expr),
        _ => 0,
    }
}

/// Worst-case evaluation steps of a value expression (LAN-299): one
/// per operand read and one per operator/builtin step (`clamp`
/// charges two — it is a min/max pair).
fn value_cost(expr: &ValueExprAst) -> u64 {
    match expr {
        ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => 1,
        ValueExprAst::Binary { lhs, rhs, .. } => 1u64
            .saturating_add(value_cost(lhs))
            .saturating_add(value_cost(rhs)),
        ValueExprAst::Call { name, args, .. } => {
            let op_cost = if name.node == "clamp" { 2 } else { 1 };
            args.iter()
                .map(value_cost)
                .fold(op_cost, u64::saturating_add)
        }
    }
}

/// A constant subtree's checked-folded value, or `None` when it
/// contains a parameter/field or a folding step that itself fails
/// (reported where it happens — see `check_value_expr`). Folding uses
/// the same [`checked_arith`] as evaluation, so compile-time folding
/// and per-route evaluation can never disagree about what overflows.
fn fold_const(expr: &ValueExprAst) -> Option<u32> {
    match expr {
        ValueExprAst::Lit(value, _) => Some(*value),
        ValueExprAst::Ident(_) | ValueExprAst::Field(_) => None,
        ValueExprAst::Binary { op, lhs, rhs, .. } => {
            checked_arith(*op, fold_const(lhs)?, fold_const(rhs)?).ok()
        }
        ValueExprAst::Call { name, args, .. } => match (name.node.as_str(), args.as_slice()) {
            ("min", [a, b]) => Some(fold_const(a)?.min(fold_const(b)?)),
            ("max", [a, b]) => Some(fold_const(a)?.max(fold_const(b)?)),
            ("clamp", [x, lo, hi]) => {
                let (x, lo, hi) = (fold_const(x)?, fold_const(lo)?, fold_const(hi)?);
                (lo <= hi).then(|| x.clamp(lo, hi))
            }
            _ => None,
        },
    }
}

fn collect_applies<'a>(expr: &'a Expr, out: &mut Vec<(&'a str, Span)>) {
    match expr {
        Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
            collect_applies(lhs, out);
            collect_applies(rhs, out);
        }
        Expr::Not(inner, _) => collect_applies(inner, out),
        Expr::Apply { policy, span, .. } => out.push((&policy.node, *span)),
        _ => {}
    }
}

/// DFS cycle detection over the `apply` graph. `path` is the current
/// DFS stack; returns the cycle (closed: `a -> b -> a`) and the span of
/// the closing edge.
fn find_cycle<'a>(
    node: &'a str,
    edges: &HashMap<&'a str, Vec<(&'a str, Span)>>,
    path: &mut Vec<&'a str>,
    done: &mut HashSet<&'a str>,
) -> Option<(Vec<String>, Span)> {
    if let Some(position) = path.iter().position(|&seen| seen == node) {
        let mut cycle: Vec<String> = path[position..].iter().map(ToString::to_string).collect();
        cycle.push(node.to_string());
        // The span is filled in by the caller (the closing edge).
        return Some((cycle, Span::new(0..0)));
    }
    if done.contains(node) {
        return None;
    }
    path.push(node);
    if let Some(targets) = edges.get(node) {
        for &(target, span) in targets {
            if let Some((cycle, cycle_span)) = find_cycle(target, edges, path, done) {
                path.pop();
                done.insert(node);
                let span = if cycle_span == Span::new(0..0) {
                    span
                } else {
                    cycle_span
                };
                return Some((cycle, span));
            }
        }
    }
    path.pop();
    done.insert(node);
    None
}

fn type_mismatch(field: &FieldPath, expected: &str, found: &Rhs) -> Diagnostic {
    Diagnostic::new(
        found.span(),
        format!(
            "type mismatch: `{}` compares against {expected}, found {}",
            field.render(),
            found.describe()
        ),
        format!("expected {expected}"),
    )
}

fn member_list(members: &[&str]) -> String {
    members
        .iter()
        .map(|member| format!("`{member}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn kind_describe(kind: CommunityKind) -> &'static str {
    match kind {
        CommunityKind::Standard => "standard-community",
        CommunityKind::Large => "large-community",
        CommunityKind::Ext => "extended-community",
    }
}

fn kind_keyword(kind: CommunityKind) -> &'static str {
    match kind {
        CommunityKind::Standard => "community",
        CommunityKind::Large => "large-community",
        CommunityKind::Ext => "ext-community",
    }
}

fn kind_field(kind: CommunityKind) -> &'static str {
    match kind {
        CommunityKind::Standard => "communities",
        CommunityKind::Large => "large-communities",
        CommunityKind::Ext => "ext-communities",
    }
}

fn route_field_name(field: &RouteField) -> (&'static str, Span) {
    match field {
        RouteField::Prefix(_, span) => ("prefix", *span),
        RouteField::Communities(_, span) => ("communities", *span),
        RouteField::LargeCommunities(_, span) => ("large-communities", *span),
        RouteField::ExtCommunities(_, span) => ("ext-communities", *span),
        RouteField::AsPath(value) => ("as-path", value.span),
        RouteField::NextHop(_, span) => ("next-hop", *span),
        RouteField::LocalPref(_, span) => ("local-pref", *span),
        RouteField::Med(_, span) => ("med", *span),
        RouteField::Rpki(value) => ("rpki", value.span),
        RouteField::Aspa(value) => ("aspa", value.span),
        RouteField::RouteType(value) => ("route-type", value.span),
        RouteField::EvpnRouteType(_, span) => ("evpn-route-type", *span),
        RouteField::Family(value) => ("family", value.span),
    }
}
