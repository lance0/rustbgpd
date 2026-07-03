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

use std::collections::{HashMap, HashSet};

use crate::engine::AsPathRegex;

use super::ast::{
    ActionStmt, CmpOp, CommunityKind, Expr, FieldPath, FieldRoot, PolicyDef, Rhs, RouteField,
    SourceFile, Stmt, U32Arg,
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
    LocalPref,
    Med,
    NextHop,
    Rpki,
    Aspa,
    RouteType,
    EvpnRouteType,
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
    ("local-pref", Field::LocalPref),
    ("med", Field::Med),
    ("next-hop", Field::NextHop),
    ("rpki", Field::Rpki),
    ("aspa", Field::Aspa),
    ("route-type", Field::RouteType),
    ("evpn-route-type", Field::EvpnRouteType),
];

const PEER_FIELDS: &[(&str, Field)] = &[
    ("address", Field::PeerAddress),
    ("asn", Field::PeerAsn),
    ("group", Field::PeerGroup),
];

/// Enum members per enum-typed field, in language spelling.
pub(super) const RPKI_MEMBERS: &[&str] = &["valid", "invalid", "not-found"];
pub(super) const ASPA_MEMBERS: &[&str] = &["valid", "invalid", "unknown"];
pub(super) const ROUTE_TYPE_MEMBERS: &[&str] = &["local", "internal", "external"];

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
            ActionStmt::SetLocalPref(arg, _) | ActionStmt::SetMed(arg, _) => {
                self.check_u32_arg(arg, params);
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
                self.check_u32_arg(asn, params);
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
            Field::PeerAsn => {
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

    /// `route.evpn-route-type` compares against a 0-255 integer
    /// literal (RFC 7432 route types are 1-5).
    fn check_evpn_route_type_rhs(&mut self, field: &FieldPath, rhs: &Rhs) {
        match rhs {
            Rhs::Int(value, span) if *value > 255 => {
                self.diags.push(Diagnostic::new(
                    *span,
                    format!("EVPN route type {value} out of range"),
                    "must be 0-255 (RFC 7432 route types are 1-5)",
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

    fn check_in(&mut self, field: &FieldPath, set: &Spanned<String>) {
        let resolved = match resolve_field(field) {
            Ok(resolved) => resolved,
            Err(diag) => {
                self.diags.push(diag);
                return;
            }
        };
        match resolved {
            Field::Prefix => {
                if !self
                    .file
                    .prefix_sets
                    .iter()
                    .any(|s| s.name.node == set.node)
                {
                    let mut diag = Diagnostic::new(
                        set.span,
                        format!("unknown prefix-set `{}`", set.node),
                        "no prefix-set with this name",
                    );
                    if self
                        .file
                        .community_sets
                        .iter()
                        .any(|s| s.name.node == set.node)
                    {
                        diag = diag.with_note(format!(
                            "`{}` is a community-set; `route.prefix in` needs a prefix-set",
                            set.node
                        ));
                    } else if let Some(suggestion) = closest(
                        &set.node,
                        self.file.prefix_sets.iter().map(|s| s.name.node.as_str()),
                    ) {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    }
                    self.diags.push(diag);
                }
            }
            Field::Communities | Field::LargeCommunities | Field::ExtCommunities => {
                if !self
                    .file
                    .community_sets
                    .iter()
                    .any(|s| s.name.node == set.node)
                {
                    let mut diag = Diagnostic::new(
                        set.span,
                        format!("unknown community-set `{}`", set.node),
                        "no community-set with this name",
                    );
                    if self
                        .file
                        .prefix_sets
                        .iter()
                        .any(|s| s.name.node == set.node)
                    {
                        diag = diag.with_note(format!(
                            "`{}` is a prefix-set; community membership needs a community-set",
                            set.node
                        ));
                    } else if let Some(suggestion) = closest(
                        &set.node,
                        self.file
                            .community_sets
                            .iter()
                            .map(|s| s.name.node.as_str()),
                    ) {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    }
                    self.diags.push(diag);
                }
            }
            _ => self.diags.push(
                Diagnostic::new(
                    field.span.to(set.span),
                    format!("`in` is not defined on `{}`", field.render()),
                    "`in` tests set membership",
                )
                .with_note(
                    "`in` works on route.prefix (prefix-sets) and community lists (community-sets)",
                ),
            ),
        }
    }

    // ── apply DAG ───────────────────────────────────────────────────

    /// Policies referenced through `apply` must form a DAG. Reports one
    /// diagnostic per cycle, naming the full path.
    fn check_apply_dag(&mut self) {
        let mut edges: HashMap<&str, Vec<(&str, Span)>> = HashMap::new();
        for policy in &self.file.policies {
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
    }
}
