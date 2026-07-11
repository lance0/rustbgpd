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

use crate::datasets::{DatasetKind, MAX_UNIT_DATASETS};
use crate::engine::AsPathRegex;
use crate::eval::{MAX_EVAL_COST, MAX_LOOP_ITERATIONS, checked_arith};
use crate::ir::ValueField;

use super::ast::{
    ActionStmt, CmpOp, CommunityArg, CommunityKind, DatasetDecl, DatasetEntryAst, Expr, FieldPath,
    FieldRoot, FnDef, ForSource, ForStmt, PolicyDef, PrependAsArg, Rhs, RouteField, SourceFile,
    Stmt, U32Arg, ValueExprAst,
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

// `MAX_EVAL_COST` (ADR-0103 Decision 3) lives in `crate::eval` so the
// compile-time cost DP and the runtime fuel initializer can never
// disagree; it is enforced here in the same Kahn-ordered DP as the
// apply bounds. Every guard node, value operator/builtin (LAN-299),
// and loop iteration × body step (LAN-303, multiplicative — nested
// loops multiply) counts; a policy whose bound exceeds it is rejected
// with a diagnostic naming the policy.

/// Maximum `for`-loop nesting depth (LAN-303) — the apply-depth
/// precedent: composition bounds are small because each level
/// multiplies. Deeper nests are almost always a modeling error, and
/// the cost DP would reject most of them anyway.
const MAX_LOOP_DEPTH: u32 = 4;

/// The value-expression builtins (LAN-299) and their arities.
const VALUE_BUILTINS: &[(&str, usize)] = &[("min", 2), ("max", 2), ("clamp", 3)];

/// Maximum function call-graph depth (LAN-304, ADR-0103 Decision 3):
/// calls fully inline at lowering, so — exactly like `apply` — every
/// level of the call chain multiplies the inlined shape, and useful
/// compositions are intrinsically shallow. Enforced in the same
/// Kahn-ordered DP as the apply bounds, before lowering runs; the
/// lowering recursion trusts it.
const MAX_CALL_DEPTH: u32 = 8;

/// One function's inlining budget entry (LAN-304), computed by
/// [`Checker::check_fn_graph`] in Kahn (callee-first) order so every
/// entry is exact for the fully-inlined shape:
///
/// - `depth`: call-graph depth (a leaf is 1) — bounded by
///   [`MAX_CALL_DEPTH`].
/// - `cost`: worst-case evaluation steps / IR nodes one call site
///   expands to, excluding the argument expressions (those are charged
///   at the call site): one `Bind` term per parameter, each body
///   `let`'s bind + initializer, and the result bind + expression.
/// - `slots`: caller-frame slots one call site consumes — parameters +
///   body lets + the result slot + every nested call's slots. Mirrors
///   the lowerer's monotonic allocation exactly (nested-call binds
///   inside argument expressions are charged by the caller's
///   `call_slots` walk, not here).
struct FnCost {
    depth: u32,
    cost: u64,
    slots: u64,
}

/// Maximum `let` bindings per lexical scope (LAN-302, ADR-0103
/// Decision 3). A scope is one term body or one `if`/`else` body; the
/// grammar has exactly those two nesting levels, so the evaluation
/// frame is statically `2 × MAX_LOCALS` slots
/// (`crate::eval::LOCAL_FRAME_SLOTS`) — no runtime growth, ever.
const MAX_LOCALS: usize = 64;

/// Name-resolution scope for one policy body (LAN-302): the declared
/// parameters plus the `let` bindings currently visible, in
/// declaration order. Lookup is by reverse scan, so the innermost
/// declaration wins — deterministic shadowing of outer bindings and
/// of parameters. Bindings are visible only in **value positions**
/// (comparison operands, `set local-pref`/`set med` expressions);
/// position-typed identifiers — enum members, `origin` in
/// `prepend as`, builtin call names — resolve exactly as before, the
/// same per-position rule that lets a parameter named `origin` keep
/// its meaning (LAN-296).
struct Scope<'a> {
    params: Vec<&'a str>,
    lets: Vec<String>,
    /// False inside a function body (LAN-304): functions are closed
    /// over nothing — `route.`/`peer.` field reads are rejected there;
    /// every input arrives as a parameter, which keeps the
    /// `requires_*` analyses call-site-local and memoization trivial.
    fields_allowed: bool,
}

impl Scope<'_> {
    fn is_param(&self, name: &str) -> bool {
        self.params.contains(&name)
    }

    fn is_local(&self, name: &str) -> bool {
        self.lets.iter().any(|local| local == name)
    }
}

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
    // Functions first (LAN-304): their Kahn DP produces the per-fn
    // cost/slot/depth table the policy bounds below fold in.
    let fn_costs = checker.check_fns();
    for policy in &file.policies {
        checker.check_policy(policy);
        checker.check_policy_frames(policy, &fn_costs);
    }
    checker.check_apply_dag();
    checker.check_apply_bounds(&fn_costs);
    checker.check_tests();
    checker.diags
}

struct Checker<'a> {
    file: &'a SourceFile,
    diags: Vec<Diagnostic>,
}

impl<'a> Checker<'a> {
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
        // Functions get their own namespace (LAN-304): duplicates are
        // errors; sharing a name with a set or policy is allowed —
        // every reference position is disjoint (calls in value
        // positions, `apply` for policies, `in` for sets), the same
        // positional rule the contextual keywords ride on.
        self.duplicate_check("fn", self.file.fns.iter().map(|f| &f.name));
        self.duplicate_check("policy", self.file.policies.iter().map(|p| &p.name));
        self.duplicate_check("test", self.file.tests.iter().map(|t| &t.name));
        // LAN-305: datasets share the flat set namespace — reference
        // positions (`in`) cannot tell a dataset from a set, so a
        // shared name is ambiguity, not shadowing.
        self.duplicate_check("dataset", self.file.datasets.iter().map(|d| &d.name));
        for decl in &self.file.datasets {
            if let Some((kind, span)) = self.set_def_of(&decl.name.node) {
                self.diags.push(
                    Diagnostic::new(
                        decl.name.span,
                        format!(
                            "dataset `{}` collides with the {kind} of the same name",
                            decl.name.node
                        ),
                        "datasets share the set namespace",
                    )
                    .with_label(span, "set defined here")
                    .with_note("rename one of them — `in` could not tell which to probe"),
                );
            }
        }
        if self.file.datasets.len() > MAX_UNIT_DATASETS {
            let extra = &self.file.datasets[MAX_UNIT_DATASETS];
            self.diags.push(Diagnostic::new(
                extra.name.span,
                format!(
                    "more than {MAX_UNIT_DATASETS} dataset declarations in one compilation unit"
                ),
                "dataset budget exceeded",
            ));
        }
    }

    /// The declaration of a dataset by name (LAN-305).
    fn dataset_of(&self, name: &str) -> Option<&'a DatasetDecl> {
        self.file.datasets.iter().find(|d| d.name.node == name)
    }

    /// The names of every declared dataset of `kind`, for did-you-mean
    /// candidate lists (LAN-328).
    fn dataset_names(
        &self,
        kind: DatasetKind,
    ) -> impl Iterator<Item = &'a Spanned<String>> + use<'a> {
        self.file
            .datasets
            .iter()
            .filter(move |d| d.kind == kind)
            .map(|d| &d.name)
    }

    /// The kind and definition span of a source-defined set by name.
    fn set_def_of(&self, name: &str) -> Option<(&'static str, Span)> {
        if let Some(def) = self.file.prefix_sets.iter().find(|s| s.name.node == name) {
            Some(("prefix-set", def.name.span))
        } else if let Some(def) = self
            .file
            .community_sets
            .iter()
            .find(|s| s.name.node == name)
        {
            Some(("community-set", def.name.span))
        } else if let Some(def) = self.file.asn_sets.iter().find(|s| s.name.node == name) {
            Some(("asn-set", def.name.span))
        } else {
            None
        }
    }

    /// The kind and definition span of any user-defined symbol by name
    /// (LAN-328): sets, datasets, functions, policies. Used by the
    /// unknown-reference diagnostics to say what an exact name match in
    /// a different kind actually is, instead of suggesting a typo fix.
    fn symbol_def_of(&self, name: &str) -> Option<(&'static str, Span)> {
        self.set_def_of(name)
            .or_else(|| self.dataset_of(name).map(|d| ("dataset", d.name.span)))
            .or_else(|| {
                self.file
                    .fns
                    .iter()
                    .find(|f| f.name.node == name)
                    .map(|f| ("function", f.name.span))
            })
            .or_else(|| self.policy(name).map(|p| ("policy", p.name.span)))
    }

    // ── functions (LAN-304) ─────────────────────────────────────────

    /// Check every `fn` body — parameters, `let` scoping, purity (no
    /// context-field reads), builtin-name collisions — then validate
    /// the call graph and return the per-function cost table.
    fn check_fns(&mut self) -> HashMap<&'a str, FnCost> {
        for def in &self.file.fns {
            if VALUE_BUILTINS.iter().any(|(b, _)| *b == def.name.node) {
                self.diags.push(
                    Diagnostic::new(
                        def.name.span,
                        format!(
                            "function `{}` shadows the builtin of the same name",
                            def.name.node
                        ),
                        "`min`, `max`, and `clamp` are reserved value builtins",
                    )
                    .with_note("rename the function; builtin calls always win in value positions"),
                );
            }
            self.duplicate_check("parameter", def.params.iter());
            let mut scope = Scope {
                params: def.params.iter().map(|p| p.node.as_str()).collect(),
                lets: Vec::new(),
                fields_allowed: false,
            };
            // Parameters and lets share the body's single scope, so
            // both count against the per-scope binding cap.
            for (index, l) in def.lets.iter().enumerate() {
                // Initializer checked before declaring, so
                // `let x = x + 1` reads a parameter/earlier `x`
                // (shadowing, never self-reference) — the LAN-302 rule.
                self.check_value_expr(&l.init, &scope);
                if def.params.len() + index == MAX_LOCALS {
                    self.locals_exceeded(l.name.span);
                }
                scope.lets.push(l.name.node.clone());
            }
            self.check_value_expr(&def.result, &scope);
        }
        self.check_fn_graph()
    }

    /// Validate the function call graph — a DAG (cycles are compile
    /// errors naming the cycle), depth-capped at [`MAX_CALL_DEPTH`] —
    /// and compute each function's inlining cost/slot footprint in the
    /// same Kahn-ordered DP discipline as the apply bounds
    /// (ADR-0103 Decision 3: one place answers "how big can this
    /// program get").
    #[expect(
        clippy::too_many_lines,
        reason = "one Kahn pass — cycle check, depth, cost, slots; splitting would scatter the DP"
    )]
    fn check_fn_graph(&mut self) -> HashMap<&'a str, FnCost> {
        let file = self.file;
        let mut edges: HashMap<&str, Vec<(&str, Span)>> = HashMap::new();
        for def in &file.fns {
            let mut targets = Vec::new();
            for l in &def.lets {
                collect_fn_calls(&l.init, file, &mut targets);
            }
            collect_fn_calls(&def.result, file, &mut targets);
            edges.insert(&def.name.node, targets);
        }
        // Cycles: reuse the apply DFS — same diagnostic shape.
        let mut done: HashSet<&str> = HashSet::new();
        for def in &file.fns {
            let name = def.name.node.as_str();
            if done.contains(name) {
                continue;
            }
            let mut path: Vec<&str> = Vec::new();
            if let Some((cycle, span)) = find_cycle(name, &edges, &mut path, &mut done) {
                self.diags.push(
                    Diagnostic::new(
                        span,
                        format!("function call cycle: {}", cycle.join(" -> ")),
                        "this call closes the cycle",
                    )
                    .with_note(
                        "functions cannot recurse, directly or mutually — the call graph \
                         must form a DAG (ADR-0103)",
                    ),
                );
            }
        }
        // Kahn DP (callee-first). Functions on a diagnosed cycle never
        // become ready and are skipped; call sites naming them find no
        // entry and charge trivially (the file already has errors).
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut pending: HashMap<&str, usize> = HashMap::new();
        let mut ready: VecDeque<&str> = VecDeque::new();
        // Seed each name once. A duplicate `fn` is diagnosed elsewhere but
        // the cost pass still runs; `edges`/`defs` key by name (last def
        // wins), so seeding per `file.fns` entry would push a reverse-edge
        // for every duplicate while `pending.insert` kept only one count —
        // and the decrement below would then underflow.
        let mut seeded: HashSet<&str> = HashSet::new();
        for def in &file.fns {
            let name = def.name.node.as_str();
            if !seeded.insert(name) {
                continue;
            }
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
        let defs: HashMap<&str, &FnDef> =
            file.fns.iter().map(|f| (f.name.node.as_str(), f)).collect();
        let mut costs: HashMap<&str, FnCost> = HashMap::new();
        while let Some(name) = ready.pop_front() {
            let def = defs[name];
            let deepest = edges[name]
                .iter()
                .filter_map(|&(target, span)| costs.get(target).map(|c| (c.depth + 1, span)))
                .max_by_key(|&(d, _)| d);
            let depth = match deepest {
                Some((d, span)) if d > MAX_CALL_DEPTH => {
                    self.diags.push(
                        Diagnostic::new(
                            span,
                            format!("function call chain nests more than {MAX_CALL_DEPTH} deep"),
                            "this call exceeds the call-depth limit",
                        )
                        .with_note(
                            "calls fully inline at compile time, so every level multiplies \
                             the inlined shape (ADR-0103); flatten the composition",
                        ),
                    );
                    // Record trivially so dependents don't cascade —
                    // one root cause, one diagnostic.
                    costs.insert(
                        name,
                        FnCost {
                            depth: 0,
                            cost: 1,
                            slots: 0,
                        },
                    );
                    for &dependent in dependents.get(name).into_iter().flatten() {
                        let left = pending.get_mut(dependent).expect("counted above");
                        *left -= 1;
                        if *left == 0 {
                            ready.push_back(dependent);
                        }
                    }
                    continue;
                }
                Some((d, _)) => d,
                None => 1,
            };
            // One call site's fully-inlined shape: a Bind term per
            // parameter, each body let's bind + initializer, the
            // result bind + expression (argument costs land at the
            // call site via `value_cost`).
            let mut cost: u64 = def.params.len() as u64;
            let mut slots: u64 = (def.params.len() + def.lets.len() + 1) as u64;
            for l in &def.lets {
                cost = cost
                    .saturating_add(1)
                    .saturating_add(value_cost(&l.init, &costs));
                slots = slots.saturating_add(call_slots(&l.init, &costs));
            }
            cost = cost
                .saturating_add(1)
                .saturating_add(value_cost(&def.result, &costs));
            slots = slots.saturating_add(call_slots(&def.result, &costs));
            costs.insert(name, FnCost { depth, cost, slots });
            for &dependent in dependents.get(name).into_iter().flatten() {
                let left = pending.get_mut(dependent).expect("counted above");
                *left -= 1;
                if *left == 0 {
                    ready.push_back(dependent);
                }
            }
        }
        costs
    }

    /// The LAN-304 frame budget: inlined function bodies consume
    /// caller-frame slots, invisibly to the source-level `let`
    /// accounting, so each term's slot high-water mark — mirroring the
    /// lowerer's monotonic allocation with body-level scope reuse
    /// exactly — must fit the register file. Deep call chains × locals
    /// exceed it at compile time, never at the lowerer's assert.
    fn check_policy_frames(&mut self, policy: &PolicyDef, fns: &HashMap<&'a str, FnCost>) {
        for term in &policy.terms {
            let hw = stmts_slot_high_water(&term.stmts, 0, fns);
            let frame = crate::eval::LOCAL_FRAME_SLOTS as u64;
            if hw > frame {
                self.diags.push(
                    Diagnostic::new(
                        term.name.span,
                        format!(
                            "term `{}` needs {hw} binding slots after function inlining — \
                             more than the {frame}-slot frame",
                            term.name.node
                        ),
                        "binding frame exceeded",
                    )
                    .with_note(
                        "every call site materializes its arguments, body bindings, and \
                         result as caller-frame slots; shallow the call chain or split \
                         the term",
                    ),
                );
            }
        }
    }

    // ── policies ────────────────────────────────────────────────────

    fn check_policy(&mut self, policy: &PolicyDef) {
        self.duplicate_check("parameter", policy.params.iter());
        self.duplicate_check("term", policy.terms.iter().map(|t| &t.name));
        let mut scope = Scope {
            params: policy.params.iter().map(|p| p.node.as_str()).collect(),
            lets: Vec::new(),
            fields_allowed: true,
        };
        for term in &policy.terms {
            // Each term body is its own scope: bindings never cross
            // terms (LAN-302).
            scope.lets.clear();
            self.check_stmts(&term.stmts, &mut scope, 0);
        }
    }

    /// One statement sequence — a term body or, recursively, a `for`
    /// body (LAN-303) — as its own lexical scope. `loop_depth` counts
    /// enclosing loops (0 in a term body); `break`/`continue` need it,
    /// and nesting is capped against [`MAX_LOOP_DEPTH`].
    fn check_stmts(&mut self, stmts: &[Stmt], scope: &mut Scope, loop_depth: u32) {
        let mark = scope.lets.len();
        let mut scope_locals = 0usize;
        let mut terminated: Option<(Span, &'static str)> = None;
        for stmt in stmts {
            if let Some((terminal_span, label)) = terminated {
                let span = match stmt {
                    Stmt::If(if_stmt) => if_stmt.span,
                    Stmt::Action(action) => action.span(),
                    Stmt::For(for_stmt) => for_stmt.span,
                };
                self.diags.push(
                    Diagnostic::new(
                        span,
                        "unreachable statement",
                        "this statement can never execute",
                    )
                    .with_label(terminal_span, label),
                );
                break;
            }
            match stmt {
                // A body `let`: check the initializer against the
                // scope *before* declaring (so `let x = x + 1` reads
                // the outer/prior `x`), then bring the name into scope
                // for everything after it.
                Stmt::Action(ActionStmt::Let { name, init, .. }) => {
                    self.check_value_expr(init, scope);
                    self.declare_binding(scope, name, &mut scope_locals);
                }
                Stmt::Action(action) => {
                    self.check_action(action, scope, loop_depth);
                    match action {
                        ActionStmt::Accept(_) | ActionStmt::Reject(_) => {
                            terminated = Some((action.span(), "the term already decided here"));
                        }
                        ActionStmt::Break(_) | ActionStmt::Continue(_) => {
                            terminated =
                                Some((action.span(), "the walk already left this body here"));
                        }
                        _ => {}
                    }
                }
                Stmt::If(if_stmt) => {
                    self.check_expr(&if_stmt.cond, scope);
                    self.check_action_list(&if_stmt.then_actions, scope, loop_depth);
                    if let Some(else_actions) = &if_stmt.else_actions {
                        self.check_action_list(else_actions, scope, loop_depth);
                    }
                }
                Stmt::For(for_stmt) => self.check_for(for_stmt, scope, loop_depth),
            }
        }
        scope.lets.truncate(mark);
    }

    /// One `for` loop (LAN-303): validate the source is one of the
    /// finite u32-valued forms, cap nesting, then check the body in a
    /// fresh scope holding the loop variable.
    fn check_for(&mut self, for_stmt: &ForStmt, scope: &mut Scope, loop_depth: u32) {
        if loop_depth == MAX_LOOP_DEPTH {
            self.diags.push(
                Diagnostic::new(
                    for_stmt.span,
                    format!("loops nest more than {MAX_LOOP_DEPTH} deep"),
                    "loop nesting limit exceeded",
                )
                .with_note(
                    "nested loop cost multiplies per level (ADR-0103); restructure with \
                     set-membership probes instead",
                ),
            );
        }
        self.check_for_source(&for_stmt.source);
        let mark = scope.lets.len();
        let mut scope_locals = 0usize;
        // The loop variable is an immutable binding in the body scope,
        // fresh per iteration (LAN-302 slot model).
        self.declare_binding(scope, &for_stmt.var, &mut scope_locals);
        self.check_stmts(&for_stmt.body, scope, loop_depth + 1);
        scope.lets.truncate(mark);
    }

    /// The three iterable source forms (LAN-303): `route.communities`
    /// (standard, u32), `route.as-path` (ASNs), a named `asn-set`.
    /// Everything else gets a spanned diagnostic naming why — the
    /// finite-source grammar is what makes every loop bound provable
    /// or runtime-meterable.
    fn check_for_source(&mut self, source: &ForSource) {
        match source {
            ForSource::Field(path) => match resolve_field(path) {
                Err(diag) => self.diags.push(diag),
                Ok(Field::Communities | Field::AsPath) => {}
                Ok(Field::LargeCommunities | Field::ExtCommunities) => self.diags.push(
                    Diagnostic::new(
                        path.span,
                        format!("`{}` is not iterable", path.render()),
                        "large/extended communities are not u32 values",
                    )
                    .with_note(
                        "the loop variable is u32-typed (ADR-0103 Decision 2); only \
                         route.communities (standard, RFC 1997) and route.as-path iterate \
                         in this slice — probe large/ext communities with `has` or `in`",
                    ),
                ),
                Ok(_) => self.diags.push(
                    Diagnostic::new(
                        path.span,
                        format!("`{}` is not iterable", path.render()),
                        "not a collection",
                    )
                    .with_note(
                        "iterable sources: route.communities, route.as-path, or an asn-set name",
                    ),
                ),
            },
            ForSource::Set(name) => {
                // LAN-305: datasets are probe-only in this slice —
                // content is a runtime snapshot, so iteration bounds
                // are not compile-time knowledge the cost DP can use.
                if let Some(decl) = self.dataset_of(&name.node) {
                    self.diags.push(
                        Diagnostic::new(
                            name.span,
                            format!("dataset `{}` is not iterable", name.node),
                            "datasets are probe-only",
                        )
                        .with_label(decl.kind_span, "declared here")
                        .with_note(
                            "dataset content is an external runtime snapshot; probe it with `in` (one hash lookup) instead of iterating",
                        ),
                    );
                    return;
                }
                if let Some(def) = self.file.asn_sets.iter().find(|s| s.name.node == name.node) {
                    // Set sizes are compile-time knowledge: enforce
                    // the per-loop bound here instead of erroring per
                    // route at runtime.
                    if def.entries.len() > MAX_LOOP_ITERATIONS as usize {
                        self.diags.push(
                            Diagnostic::new(
                                name.span,
                                format!(
                                    "asn-set `{}` has {} members — more than the \
                                     {MAX_LOOP_ITERATIONS}-iteration loop bound",
                                    name.node,
                                    def.entries.len(),
                                ),
                                "set too large to iterate",
                            )
                            .with_note(
                                "probe large sets with `in` (one hash lookup) instead of \
                                 iterating them",
                            ),
                        );
                    }
                    return;
                }
                let mut diag = Diagnostic::new(
                    name.span,
                    format!("`{}` is not an iterable set", name.node),
                    "loops iterate asn-sets",
                );
                diag = match self.set_kind_of(&name.node) {
                    Some("community-set") => diag.with_note(
                        "community-set members are mixed-kind (not u32); iterate \
                         route.communities and probe with `in` instead",
                    ),
                    Some("prefix-set") => diag.with_note(
                        "prefix-set members are not u32 values; probe with \
                         `route.prefix in` instead",
                    ),
                    _ => {
                        if let Some((kind, span)) = self.symbol_def_of(&name.node) {
                            diag.with_note(format!(
                                "`{}` is {} {kind}, not an iterable asn-set",
                                name.node,
                                article(kind)
                            ))
                            .with_label(span, format!("`{}` is defined here", name.node))
                        } else {
                            with_suggestion(
                                diag,
                                &name.node,
                                self.file
                                    .asn_sets
                                    .iter()
                                    .map(|s| (s.name.node.as_str(), Some(s.name.span))),
                            )
                        }
                    }
                };
                self.diags.push(diag);
            }
        }
    }

    /// One `if`/`else` body — its own lexical scope (LAN-302): `let`
    /// bindings declared here are visible to the rest of the body and
    /// nowhere else. `loop_depth` scopes `break`/`continue` (LAN-303).
    fn check_action_list(&mut self, actions: &[ActionStmt], scope: &mut Scope, loop_depth: u32) {
        let mark = scope.lets.len();
        let mut body_locals = 0usize;
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
            if let ActionStmt::Let { name, init, .. } = action {
                self.check_value_expr(init, scope);
                self.declare_binding(scope, name, &mut body_locals);
                continue;
            }
            self.check_action(action, scope, loop_depth);
            if matches!(
                action,
                ActionStmt::Accept(_)
                    | ActionStmt::Reject(_)
                    | ActionStmt::Break(_)
                    | ActionStmt::Continue(_)
            ) {
                terminated = Some(action.span());
            }
        }
        scope.lets.truncate(mark);
    }

    /// Declare one binding: per-scope `MAX_LOCALS` cap (LAN-302) plus
    /// the whole-frame slot cap (LAN-303 — nested loop scopes share
    /// the 256-slot register file, `crate::eval::LOCAL_FRAME_SLOTS`).
    /// Diagnostics fire once at the first binding past each limit; the
    /// name still enters scope so resolution keeps reporting.
    fn declare_binding(
        &mut self,
        scope: &mut Scope,
        name: &Spanned<String>,
        scope_locals: &mut usize,
    ) {
        if *scope_locals == MAX_LOCALS {
            self.locals_exceeded(name.span);
        }
        *scope_locals += 1;
        if scope.lets.len() == crate::eval::LOCAL_FRAME_SLOTS {
            self.diags.push(
                Diagnostic::new(
                    name.span,
                    format!(
                        "more than {} bindings live at once across nested scopes",
                        crate::eval::LOCAL_FRAME_SLOTS
                    ),
                    "binding frame exceeded",
                )
                .with_note("split the term or fold intermediate values"),
            );
        }
        scope.lets.push(name.node.clone());
    }

    /// The 65th `let` of one scope (LAN-302, `MAX_LOCALS`): fires once,
    /// at the first binding past the limit.
    fn locals_exceeded(&mut self, span: Span) {
        self.diags.push(
            Diagnostic::new(
                span,
                format!("more than {MAX_LOCALS} `let` bindings in one scope"),
                "binding limit exceeded",
            )
            .with_note(
                "bindings compile to a fixed frame of 64 slots per scope (ADR-0103); \
                 split the term or fold intermediate values",
            ),
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per action kind; splitting would scatter the per-action rules"
    )]
    fn check_action(&mut self, action: &ActionStmt, scope: &Scope<'_>, loop_depth: u32) {
        match action {
            ActionStmt::Accept(_) | ActionStmt::Reject(_) | ActionStmt::SetNextHop(..) => {}
            ActionStmt::Let { .. } => unreachable!("`let` is scoped by the statement walkers"),
            // Loop control outside a loop body (LAN-303).
            ActionStmt::Break(span) | ActionStmt::Continue(span) => {
                if loop_depth == 0 {
                    let word = if matches!(action, ActionStmt::Break(_)) {
                        "break"
                    } else {
                        "continue"
                    };
                    self.diags.push(
                        Diagnostic::new(
                            *span,
                            format!("`{word}` outside a loop"),
                            "no enclosing `for` loop",
                        )
                        .with_note("`break`/`continue` control the innermost `for` body"),
                    );
                }
            }
            ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _) => {
                self.check_value_expr(expr, scope);
            }
            ActionStmt::Community {
                kind,
                arg: CommunityArg::Lit(lit),
                ..
            } => {
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
            // LAN-303: `add/remove community <binding>` — bindings are
            // u32-valued, so the variable form is standard-kind only,
            // and the name must resolve to a binding or parameter.
            ActionStmt::Community {
                kind,
                arg: CommunityArg::Var(name),
                ..
            } => {
                if *kind != CommunityKind::Standard {
                    self.diags.push(
                        Diagnostic::new(
                            name.span,
                            format!(
                                "`{}` actions take a literal, not a binding",
                                kind_keyword(*kind)
                            ),
                            "bindings are u32-valued",
                        )
                        .with_note(
                            "only standard (RFC 1997) communities are u32-shaped; \
                             large/extended community actions need a literal",
                        ),
                    );
                }
                if !scope.is_local(&name.node) && !scope.is_param(&name.node) {
                    let mut diag = Diagnostic::new(
                        name.span,
                        format!("unknown parameter or binding `{}`", name.node),
                        "not a parameter or `let`/loop binding in scope",
                    );
                    if let Some(suggestion) = closest(
                        &name.node,
                        scope
                            .params
                            .iter()
                            .copied()
                            .chain(scope.lets.iter().map(String::as_str)),
                    ) {
                        diag = diag.with_note(format!("did you mean `{suggestion}`?"));
                    }
                    self.diags.push(diag);
                }
            }
            ActionStmt::Prepend { asn, count, .. } => {
                // A computed operand (`self`/`peer`, or an `origin`
                // identifier that is not a declared parameter —
                // LAN-296) needs no parameter check; the operand
                // decision itself is shared with lowering via
                // `PrependAsArg::operand`. `let` bindings deliberately
                // do not resolve here: this is not a value position
                // (LAN-302 scoping rule), so `prepend as origin` keeps
                // its operand meaning even under a `let origin`.
                if asn.operand(|name| scope.is_param(name)).is_none()
                    && let PrependAsArg::Value(arg) = asn
                {
                    self.check_u32_arg(arg, scope);
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
    /// literals, declared parameters, `let` bindings (LAN-302),
    /// u32-typed fields — builtins must be `min`/`max`/`clamp` with
    /// the right arity, and every statically-evaluable subexpression
    /// must evaluate cleanly under checked arithmetic (`4294967295 +
    /// 1` is a compile error at its span, not a per-route runtime
    /// error).
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per value-expression kind; splitting would scatter the operand rules"
    )]
    fn check_value_expr(&mut self, expr: &ValueExprAst, scope: &Scope<'_>) {
        match expr {
            ValueExprAst::Lit(..) => {}
            // A bare identifier in a value position resolves innermost
            // `let` first, then parameters (LAN-302 shadowing). A name
            // followed by `(` is a builtin call (the `Call` arm), the
            // same per-position rule parameters already follow.
            ValueExprAst::Ident(name) => self.check_value_ident(name, scope),
            // Purity by construction (LAN-304): function bodies are
            // closed over nothing — every input arrives as a
            // parameter, so `requires_*` analyses stay call-site-local
            // and a call is a pure function of its arguments.
            ValueExprAst::Field(path) if !scope.fields_allowed => {
                self.diags.push(
                    Diagnostic::new(
                        path.span,
                        format!("`{}` read inside a function body", path.render()),
                        "functions are closed over nothing",
                    )
                    .with_note(
                        "functions are pure over their parameters (ADR-0103); pass the \
                         field as an argument at the call site",
                    ),
                );
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
                self.check_value_expr(lhs, scope);
                self.check_value_expr(rhs, scope);
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
                    self.check_value_expr(arg, scope);
                }
                let Some(&(_, arity)) = VALUE_BUILTINS
                    .iter()
                    .find(|(builtin, _)| *builtin == name.node)
                else {
                    // A user-defined function (LAN-304): arity-checked
                    // here; the call graph and budgets are validated
                    // in `check_fn_graph`.
                    if let Some(def) = self.file.fns.iter().find(|f| f.name.node == name.node) {
                        if def.params.len() != args.len() {
                            self.diags.push(
                                Diagnostic::new(
                                    *span,
                                    format!(
                                        "function `{}` takes {} argument{} but {} {} supplied",
                                        name.node,
                                        def.params.len(),
                                        if def.params.len() == 1 { "" } else { "s" },
                                        args.len(),
                                        if args.len() == 1 { "was" } else { "were" },
                                    ),
                                    "wrong number of arguments",
                                )
                                .with_label(def.name.span, "function defined here"),
                            );
                        }
                        return;
                    }
                    let mut diag = Diagnostic::new(
                        name.span,
                        format!("unknown function or builtin `{}`", name.node),
                        "not a function or value builtin",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&name.node) {
                        let note = if kind == "policy" {
                            format!(
                                "`{}` is a policy — policies are predicates, composed with \
                                 `apply({}(...))`, not called for a value",
                                name.node, name.node
                            )
                        } else {
                            format!(
                                "`{}` is {} {kind}, not a function",
                                name.node,
                                article(kind)
                            )
                        };
                        diag = diag
                            .with_note(note)
                            .with_label(span, format!("`{}` is defined here", name.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &name.node,
                            VALUE_BUILTINS.iter().map(|(b, _)| (*b, None)).chain(
                                self.file
                                    .fns
                                    .iter()
                                    .map(|f| (f.name.node.as_str(), Some(f.name.span))),
                            ),
                        );
                        if diag.notes.is_empty() {
                            diag = diag.with_note(
                                "value builtins: min(a, b), max(a, b), clamp(x, lo, hi)",
                            );
                        }
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

    /// A bare identifier in a value position (LAN-302): innermost
    /// `let` binding, else parameter, else a spanned unknown-name
    /// diagnostic suggesting across both.
    fn check_value_ident(&mut self, name: &Spanned<String>, scope: &Scope<'_>) {
        if scope.is_local(&name.node) || scope.is_param(&name.node) {
            return;
        }
        let mut diag = Diagnostic::new(
            name.span,
            format!("unknown parameter or binding `{}`", name.node),
            "not a parameter or `let` binding in scope",
        );
        if let Some(suggestion) = closest(
            &name.node,
            scope
                .params
                .iter()
                .copied()
                .chain(scope.lets.iter().map(String::as_str)),
        ) {
            diag = diag.with_note(format!("did you mean `{suggestion}`?"));
        }
        self.diags.push(diag);
    }

    /// A compile-time-constant u32 position (prepend operands/counts,
    /// `apply` arguments, `contains` ASNs): literals and parameters
    /// only. `let` bindings are runtime values and get a dedicated
    /// diagnostic instead of "unknown parameter" (LAN-302).
    fn check_u32_arg(&mut self, arg: &U32Arg, scope: &Scope<'_>) {
        let U32Arg::Param(name) = arg else { return };
        if scope.is_param(&name.node) {
            return;
        }
        if scope.is_local(&name.node) {
            self.diags.push(
                Diagnostic::new(
                    name.span,
                    format!("`{}` is a `let` binding", name.node),
                    "this position needs a literal or parameter",
                )
                .with_note("bindings are runtime values; this argument is fixed at compile time"),
            );
            return;
        }
        let mut diag = Diagnostic::new(
            name.span,
            format!("unknown parameter `{}`", name.node),
            "not a parameter of this policy",
        );
        if let Some(suggestion) = closest(&name.node, scope.params.iter().copied()) {
            diag = diag.with_note(format!("did you mean `{suggestion}`?"));
        }
        self.diags.push(diag);
    }

    // ── expressions ─────────────────────────────────────────────────

    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive per-field/type dispatch; splitting would scatter the match"
    )]
    fn check_expr(&mut self, expr: &Expr, scope: &Scope<'_>) {
        match expr {
            Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
                self.check_expr(lhs, scope);
                self.check_expr(rhs, scope);
            }
            Expr::Not(inner, _) => self.check_expr(inner, scope),
            Expr::Cmp { field, op, rhs, .. } => self.check_cmp(field, *op, rhs, scope),
            // LAN-299: both sides of a value comparison are u32 value
            // expressions; all four operators apply (the checked
            // evaluation model has no unordered u32 fields).
            Expr::ValueCmp { lhs, rhs, .. } => {
                self.check_value_expr(lhs, scope);
                self.check_value_expr(rhs, scope);
            }
            Expr::In { field, set } => self.check_in(field, set),
            // LAN-303: `<binding> in <set>` — u32 value against an
            // asn-set, or a community-set's standard members.
            Expr::IdentIn { ident, set } => {
                self.check_value_ident(ident, scope);
                if self.file.asn_sets.iter().any(|s| s.name.node == set.node)
                    || self
                        .file
                        .community_sets
                        .iter()
                        .any(|s| s.name.node == set.node)
                {
                    // Community-set probes match standard members only
                    // (the binding is a raw u32) — documented in the
                    // language reference.
                } else if let Some(decl) = self.dataset_of(&set.node) {
                    // LAN-305: asn-set / community-set datasets probe
                    // exactly like their in-language kinds; prefix
                    // datasets are not u32-probeable.
                    if decl.kind == DatasetKind::Prefix {
                        self.diags.push(
                            Diagnostic::new(
                                set.span,
                                format!(
                                    "`{}` is a prefix-set dataset; bindings are u32 values and cannot probe prefixes",
                                    set.node
                                ),
                                "wrong dataset kind",
                            )
                            .with_label(decl.kind_span, "declared here"),
                        );
                    }
                } else {
                    let mut diag = Diagnostic::new(
                        set.span,
                        format!("unknown asn-set or community-set `{}`", set.node),
                        "binding membership probes asn-sets and community-sets",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&set.node) {
                        let note = if kind == "prefix-set" {
                            format!(
                                "`{}` is a prefix-set; bindings are u32 values and cannot \
                                 probe prefixes",
                                set.node
                            )
                        } else {
                            format!(
                                "`{}` is {} {kind}, not an asn-set or community-set",
                                set.node,
                                article(kind)
                            )
                        };
                        diag = diag
                            .with_note(note)
                            .with_label(span, format!("`{}` is defined here", set.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &set.node,
                            self.file
                                .asn_sets
                                .iter()
                                .map(|s| &s.name)
                                .chain(self.file.community_sets.iter().map(|s| &s.name))
                                .chain(self.dataset_names(DatasetKind::Asn))
                                .chain(self.dataset_names(DatasetKind::Community))
                                .map(|n| (n.node.as_str(), Some(n.span))),
                        );
                    }
                    self.diags.push(diag);
                }
            }
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
                self.check_u32_arg(asn, scope);
            }
            Expr::Apply { policy, args, span } => {
                // Borrow the target through the file field directly so
                // its lifetime is independent of `self` (diagnostics
                // below need `&mut self`).
                let file = self.file;
                let Some(target) = file.policies.iter().find(|p| p.name.node == policy.node) else {
                    let mut diag = Diagnostic::new(
                        policy.span,
                        format!("unknown policy `{}`", policy.node),
                        "no policy with this name",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&policy.node) {
                        diag = diag
                            .with_note(format!(
                                "`{}` is {} {kind}, not a policy — `apply` composes policies",
                                policy.node,
                                article(kind)
                            ))
                            .with_label(span, format!("`{}` is defined here", policy.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &policy.node,
                            self.file
                                .policies
                                .iter()
                                .map(|p| (p.name.node.as_str(), Some(p.name.span))),
                        );
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
                // LAN-302: `apply` inlines its target as a pure
                // predicate expression — there is no term walk to
                // execute the target's `Bind` terms in, so a target
                // that declares bindings is rejected here rather than
                // given silently divergent semantics. LAN-304 `fn` is
                // the designed vehicle for composing computed values.
                if let Some(let_span) = first_let(target) {
                    self.diags.push(
                        Diagnostic::new(
                            *span,
                            format!(
                                "cannot `apply` policy `{}`: it declares `let` bindings",
                                policy.node
                            ),
                            "`apply` targets cannot use `let`",
                        )
                        .with_label(let_span, "first `let` is here")
                        .with_note(
                            "`apply` inlines the target as a pure predicate; factor the \
                             shared value into the applying policy instead",
                        ),
                    );
                }
                // LAN-303: loops execute per iteration; a pure inlined
                // predicate has no walk to run them in — same rule as
                // `let` above.
                if let Some(loop_span) = first_loop(target) {
                    self.diags.push(
                        Diagnostic::new(
                            *span,
                            format!(
                                "cannot `apply` policy `{}`: it contains a `for` loop",
                                policy.node
                            ),
                            "`apply` targets cannot use `for`",
                        )
                        .with_label(loop_span, "first `for` is here")
                        .with_note(
                            "`apply` inlines the target as a pure predicate; keep loops \
                             in the applying policy instead",
                        ),
                    );
                }
                // LAN-304: a function call is sugar for a scope of
                // `let` bindings, so it rides the same rule — a pure
                // inlined predicate has no walk to execute binds in.
                if let Some(call_span) = first_fn_call(target, self.file) {
                    self.diags.push(
                        Diagnostic::new(
                            *span,
                            format!(
                                "cannot `apply` policy `{}`: it calls functions",
                                policy.node
                            ),
                            "`apply` targets cannot call functions",
                        )
                        .with_label(call_span, "first call is here")
                        .with_note(
                            "`apply` inlines the target as a pure predicate, and a call \
                             lowers to binding terms a predicate cannot execute; call the \
                             function in the applying policy instead",
                        ),
                    );
                }
                for arg in args {
                    self.check_u32_arg(arg, scope);
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

    fn check_cmp(&mut self, field: &FieldPath, op: CmpOp, rhs: &Rhs, scope: &Scope<'_>) {
        let resolved = match resolve_field(field) {
            Ok(resolved) => resolved,
            Err(diag) => {
                self.diags.push(diag);
                return;
            }
        };
        if binding_value_cmp(rhs, resolved, scope) {
            return;
        }
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
                self.expect_u32_rhs(field, rhs, scope);
            }
            Field::PeerAsn | Field::OriginAs => {
                eq_only(self);
                self.expect_u32_rhs(field, rhs, scope);
            }
            Field::EvpnRouteType => {
                eq_only(self);
                self.check_evpn_route_type_rhs(field, rhs);
            }
            Field::Rpki => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, RPKI_MEMBERS, scope);
            }
            Field::Aspa => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, ASPA_MEMBERS, scope);
            }
            Field::RouteType => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, ROUTE_TYPE_MEMBERS, scope);
            }
            Field::Family => {
                eq_only(self);
                self.expect_enum_rhs(field, rhs, FAMILY_MEMBERS, scope);
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

    fn expect_u32_rhs(&mut self, field: &FieldPath, rhs: &Rhs, scope: &Scope<'_>) {
        match rhs {
            Rhs::Int(..) => {}
            Rhs::Ident(name) => {
                self.check_u32_arg(&U32Arg::Param(name.clone()), scope);
            }
            other => self
                .diags
                .push(type_mismatch(field, "a u32 value or parameter", other)),
        }
    }

    fn expect_enum_rhs(
        &mut self,
        field: &FieldPath,
        rhs: &Rhs,
        members: &[&str],
        scope: &Scope<'_>,
    ) {
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
        if scope.is_local(&name.node) {
            diag = diag.with_note(format!(
                "`{}` is a u32 `let` binding; `{}` is an enum field",
                name.node,
                field.render()
            ));
        } else if scope.is_param(&name.node) {
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
        let candidates: Vec<(&str, Option<Span>)> =
            names.map(|n| (n.node.as_str(), Some(n.span))).collect();
        if candidates.iter().any(|&(name, _)| name == set.node) {
            return;
        }
        let mut diag = Diagnostic::new(
            set.span,
            format!("unknown {kind} `{}`", set.node),
            format!("no {kind} with this name"),
        );
        // An exact name match of a different kind beats a typo
        // suggestion (LAN-328): the reference is wrong, not misspelled.
        if let Some((actual, span)) = self.symbol_def_of(&set.node) {
            diag = diag
                .with_note(format!(
                    "`{}` is {} {actual}; {need}",
                    set.node,
                    article(actual)
                ))
                .with_label(span, format!("`{}` is defined here", set.node));
        } else {
            diag = with_suggestion(diag, &set.node, candidates);
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
        // LAN-305: a dataset reference resolves like a set of its
        // declared kind; a wrong-kind dataset is the same class of
        // error as a wrong-kind set.
        let expected_kind = match resolved {
            Field::Prefix => Some(DatasetKind::Prefix),
            Field::Communities | Field::LargeCommunities | Field::ExtCommunities => {
                Some(DatasetKind::Community)
            }
            Field::OriginAs | Field::PeerAsn => Some(DatasetKind::Asn),
            _ => None,
        };
        if let (Some(expected), Some(decl)) = (expected_kind, self.dataset_of(&set.node)) {
            if decl.kind != expected {
                self.diags.push(
                    Diagnostic::new(
                        set.span,
                        format!(
                            "`{}` is a {} dataset but this probe needs a {expected}",
                            set.node, decl.kind
                        ),
                        "wrong dataset kind",
                    )
                    .with_label(decl.kind_span, "declared here"),
                );
            }
            return;
        }
        match resolved {
            // Right-kind datasets are valid `in` targets (LAN-305), so
            // they are suggestion candidates alongside the sets.
            Field::Prefix => self.check_set_reference(
                set,
                "prefix-set",
                "`route.prefix in` needs a prefix-set",
                self.file
                    .prefix_sets
                    .iter()
                    .map(|s| &s.name)
                    .chain(self.dataset_names(DatasetKind::Prefix)),
            ),
            Field::Communities | Field::LargeCommunities | Field::ExtCommunities => self
                .check_set_reference(
                    set,
                    "community-set",
                    "community membership needs a community-set",
                    self.file
                        .community_sets
                        .iter()
                        .map(|s| &s.name)
                        .chain(self.dataset_names(DatasetKind::Community)),
                ),
            Field::OriginAs | Field::PeerAsn => self.check_set_reference(
                set,
                "asn-set",
                "ASN membership needs an asn-set",
                self.file
                    .asn_sets
                    .iter()
                    .map(|s| &s.name)
                    .chain(self.dataset_names(DatasetKind::Asn)),
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
    /// trivial), so a single root cause does not cascade. `fns` folds
    /// LAN-304 function inlining into the same DP: every call site
    /// charges the callee's fully-inlined cost.
    fn check_apply_bounds(&mut self, fns: &HashMap<&'a str, FnCost>) {
        let file = self.file;
        let edges = apply_edges(file);
        // Kahn scaffolding: a policy is ready once every *known* apply
        // target (unknown names are diagnosed elsewhere) is processed.
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut pending: HashMap<&str, usize> = HashMap::new();
        let mut ready: VecDeque<&str> = VecDeque::new();
        // Seed each name once — a duplicate `policy` is diagnosed
        // elsewhere but this pass still runs, and `edges`/`defs` key by
        // name; seeding per `file.policies` entry would push a duplicate
        // reverse-edge while `pending.insert` kept one count, underflowing
        // the decrement below (mirrors the `check_fns` guard).
        let mut seeded: HashSet<&str> = HashSet::new();
        for policy in &file.policies {
            let name = policy.name.node.as_str();
            if !seeded.insert(name) {
                continue;
            }
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
                file,
                fns,
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

    #[expect(
        clippy::too_many_lines,
        reason = "fixture fields, dataset overrides, and expect arity in one linear pass"
    )]
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
            // LAN-305: dataset overrides must name declared datasets,
            // once each, with members of the declared kind.
            let mut seen_datasets: HashMap<&str, Span> = HashMap::new();
            for def in &test.datasets {
                if let Some(&first) = seen_datasets.get(def.name.node.as_str()) {
                    self.diags.push(
                        Diagnostic::new(
                            def.name.span,
                            format!("duplicate dataset override `{}`", def.name.node),
                            "already provided",
                        )
                        .with_label(first, "first override is here"),
                    );
                } else {
                    seen_datasets.insert(&def.name.node, def.name.span);
                }
                let Some(decl) = self.dataset_of(&def.name.node) else {
                    let mut diag = Diagnostic::new(
                        def.name.span,
                        format!("unknown dataset `{}`", def.name.node),
                        "no dataset declared with this name",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&def.name.node) {
                        diag = diag
                            .with_note(format!(
                                "`{}` is {} {kind}, not a dataset — overrides fill declared \
                                 datasets",
                                def.name.node,
                                article(kind)
                            ))
                            .with_label(span, format!("`{}` is defined here", def.name.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &def.name.node,
                            self.file
                                .datasets
                                .iter()
                                .map(|d| (d.name.node.as_str(), Some(d.name.span))),
                        );
                    }
                    self.diags.push(diag);
                    continue;
                };
                for entry in &def.entries {
                    let ok = matches!(
                        (&entry.node, decl.kind),
                        (DatasetEntryAst::Prefix(_), DatasetKind::Prefix)
                            | (DatasetEntryAst::Asn(_), DatasetKind::Asn)
                            | (DatasetEntryAst::Community(_), DatasetKind::Community)
                    );
                    if !ok {
                        self.diags.push(
                            Diagnostic::new(
                                entry.span,
                                format!(
                                    "member kind mismatch: dataset `{}` is a {}",
                                    def.name.node, decl.kind
                                ),
                                "wrong member kind",
                            )
                            .with_label(decl.kind_span, "declared here"),
                        );
                    }
                }
            }
            for expect in &test.expects {
                let Some(target) = self.policy(&expect.policy.node) else {
                    let mut diag = Diagnostic::new(
                        expect.policy.span,
                        format!("unknown policy `{}`", expect.policy.node),
                        "no policy with this name",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&expect.policy.node) {
                        diag = diag
                            .with_note(format!(
                                "`{}` is {} {kind}, not a policy — `expect` runs policies",
                                expect.policy.node,
                                article(kind)
                            ))
                            .with_label(span, format!("`{}` is defined here", expect.policy.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &expect.policy.node,
                            self.file
                                .policies
                                .iter()
                                .map(|p| (p.name.node.as_str(), Some(p.name.span))),
                        );
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
    fn walk_stmts<'a>(stmts: &'a [Stmt], targets: &mut Vec<(&'a str, Span)>) {
        for stmt in stmts {
            match stmt {
                Stmt::If(if_stmt) => collect_applies(&if_stmt.cond, targets),
                Stmt::Action(_) => {}
                // LAN-303: `if apply(p)` inside a loop body still
                // participates in the DAG/bounds analyses.
                Stmt::For(for_stmt) => walk_stmts(&for_stmt.body, targets),
            }
        }
    }
    let mut edges: HashMap<&str, Vec<(&str, Span)>> = HashMap::new();
    for policy in &file.policies {
        let mut targets = Vec::new();
        for term in &policy.terms {
            walk_stmts(&term.stmts, &mut targets);
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
#[expect(
    clippy::too_many_lines,
    reason = "one DP pass over every statement kind; splitting would scatter the budget model"
)]
fn bound_policy<'a>(
    def: &'a PolicyDef,
    targets: &[(&'a str, Span)],
    file: &SourceFile,
    fns: &HashMap<&'a str, FnCost>,
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
    // LAN-303: loop body IR nodes (counted once, toward compiled size)
    // — the iteration-multiplied step cost lands in `action_cost`.
    let mut loop_nodes: u64 = 0;
    for term in &def.terms {
        for stmt in &term.stmts {
            match stmt {
                Stmt::If(if_stmt) => {
                    let cost = guard_cost(&if_stmt.cond, pred_cost, fns);
                    arms.push(cost);
                    if if_stmt.else_actions.is_some() {
                        arms.push(cost.saturating_add(1));
                    }
                    for action in if_stmt
                        .then_actions
                        .iter()
                        .chain(if_stmt.else_actions.iter().flatten())
                    {
                        // A body `let` (LAN-302) lowers to its own Bind
                        // term that re-evaluates the branch guard (the
                        // else side adds a negation) — charge one arm
                        // per binding on top of its initializer cost.
                        if matches!(action, ActionStmt::Let { .. }) {
                            arms.push(cost.saturating_add(1));
                        }
                        action_cost = action_cost.saturating_add(action_value_cost(action, fns));
                    }
                }
                Stmt::Action(action) => {
                    arms.push(1);
                    action_cost = action_cost.saturating_add(action_value_cost(action, fns));
                }
                // LAN-303: one IR term for the loop itself; the body
                // charges the eval-cost budget at bound × per-iteration
                // steps — multiplicative for nested loops, which is
                // what rejects e.g. a communities loop nested inside an
                // as-path loop (4096 × 4096 body steps) at compile time
                // rather than metering it per route.
                Stmt::For(for_stmt) => {
                    arms.push(1);
                    let (nodes, steps) = for_costs(for_stmt, pred_cost, file, fns);
                    loop_nodes = loop_nodes.saturating_add(nodes);
                    action_cost = action_cost.saturating_add(steps);
                }
            }
        }
    }
    let lowered: u64 = arms
        .iter()
        .fold(0u64, |acc, &g| acc.saturating_add(g))
        .saturating_add(loop_nodes);
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
                "apply(p) inlines p's decision predicate — and every function call its \
                 fully-inlined body — at every use site; split or flatten the composition",
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
fn guard_cost(expr: &Expr, pred_cost: &HashMap<&str, u64>, fns: &HashMap<&str, FnCost>) -> u64 {
    match expr {
        Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => 1u64
            .saturating_add(guard_cost(lhs, pred_cost, fns))
            .saturating_add(guard_cost(rhs, pred_cost, fns)),
        Expr::Not(inner, _) => 1u64.saturating_add(guard_cost(inner, pred_cost, fns)),
        // `==`/`!=` on u32 fields lower widest: `Not(And(Ge, Le))`.
        Expr::Cmp { .. } => 4,
        // LAN-299: every operator/builtin in the value expressions
        // counts one step in the DP. LAN-304: a function call charges
        // its fully-inlined body per call site.
        Expr::ValueCmp { lhs, rhs, .. } => 1u64
            .saturating_add(value_cost(lhs, fns))
            .saturating_add(value_cost(rhs, fns)),
        Expr::Apply { policy, .. } => pred_cost.get(policy.node.as_str()).copied().unwrap_or(1),
        _ => 1,
    }
}

/// Static iteration bound of one loop source (LAN-303): the actual
/// member count for asn-set sources (compile-time knowledge; larger
/// than the cap is rejected with its own diagnostic), the hard
/// per-loop cap for route-attribute sources (their only static bound —
/// the runtime cap guarantees it).
fn loop_iteration_bound(source: &ForSource, file: &SourceFile) -> u64 {
    match source {
        ForSource::Set(name) => file
            .asn_sets
            .iter()
            .find(|s| s.name.node == name.node)
            .map_or(u64::from(MAX_LOOP_ITERATIONS), |s| s.entries.len() as u64),
        ForSource::Field(_) => u64::from(MAX_LOOP_ITERATIONS),
    }
}

/// One loop's `(body IR nodes, worst-case evaluation steps)` for the
/// cost DP (LAN-303): nodes count once toward compiled size; steps are
/// the static iteration bound × per-iteration body cost — nested loops
/// multiply through the recursion, which is the ADR-0103 Decision 3
/// compounding-composition defense.
fn for_costs(
    for_stmt: &ForStmt,
    pred_cost: &HashMap<&str, u64>,
    file: &SourceFile,
    fns: &HashMap<&str, FnCost>,
) -> (u64, u64) {
    let mut nodes: u64 = 1; // the ForEach term
    let mut body_steps: u64 = 1; // the loop-var bind per iteration
    for stmt in &for_stmt.body {
        match stmt {
            Stmt::If(if_stmt) => {
                let guard = guard_cost(&if_stmt.cond, pred_cost, fns);
                // Upper bound per iteration: the guard (twice with an
                // else — the negated arm) plus every body action.
                let arms: u64 = if if_stmt.else_actions.is_some() { 2 } else { 1 };
                nodes = nodes.saturating_add(guard.saturating_mul(arms));
                body_steps = body_steps.saturating_add(guard.saturating_mul(arms));
                for action in if_stmt
                    .then_actions
                    .iter()
                    .chain(if_stmt.else_actions.iter().flatten())
                {
                    nodes = nodes.saturating_add(1);
                    body_steps = body_steps
                        .saturating_add(1)
                        .saturating_add(action_value_cost(action, fns));
                }
            }
            Stmt::Action(action) => {
                nodes = nodes.saturating_add(1);
                body_steps = body_steps
                    .saturating_add(1)
                    .saturating_add(action_value_cost(action, fns));
            }
            Stmt::For(inner) => {
                let (inner_nodes, inner_steps) = for_costs(inner, pred_cost, file, fns);
                nodes = nodes.saturating_add(inner_nodes);
                body_steps = body_steps.saturating_add(inner_steps);
            }
        }
    }
    let bound = loop_iteration_bound(&for_stmt.source, file);
    (nodes, bound.saturating_mul(body_steps).saturating_add(1))
}

/// LAN-302: a `let` binding on the right of a u32-field comparison
/// makes it a value comparison (that is what it lowers to), so all
/// four operators apply and both sides are u32 — nothing further to
/// check. Non-u32 fields keep their per-field diagnostics (enum
/// members win in enum positions; bindings resolve only in value
/// positions).
fn binding_value_cmp(rhs: &Rhs, resolved: Field, scope: &Scope<'_>) -> bool {
    matches!(rhs, Rhs::Ident(name)
        if scope.is_local(&name.node) && value_field_of(resolved).is_some())
}

/// The value-expression steps an action contributes to the
/// evaluation-cost budget (LAN-299: only the computed `set` values
/// carry expressions; everything else is constant-time. LAN-302: a
/// `let` charges its initializer plus one slot-write step; each read
/// already costs one step as a `value_cost` operand).
fn action_value_cost(action: &ActionStmt, fns: &HashMap<&str, FnCost>) -> u64 {
    match action {
        ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _) => value_cost(expr, fns),
        ActionStmt::Let { init, .. } => value_cost(init, fns).saturating_add(1),
        _ => 0,
    }
}

/// Span of the first `let` statement anywhere in a policy — term
/// bodies, `if`/`else` bodies, and loop bodies — or `None`. Backs the
/// LAN-302 `apply`-target rejection.
fn first_let(def: &PolicyDef) -> Option<Span> {
    fn in_actions(actions: &[ActionStmt]) -> Option<Span> {
        actions.iter().find_map(|action| match action {
            ActionStmt::Let { span, .. } => Some(*span),
            _ => None,
        })
    }
    fn in_stmts(stmts: &[Stmt]) -> Option<Span> {
        stmts.iter().find_map(|stmt| match stmt {
            Stmt::Action(ActionStmt::Let { span, .. }) => Some(*span),
            Stmt::Action(_) => None,
            Stmt::If(if_stmt) => in_actions(&if_stmt.then_actions)
                .or_else(|| if_stmt.else_actions.as_deref().and_then(in_actions)),
            Stmt::For(for_stmt) => in_stmts(&for_stmt.body),
        })
    }
    def.terms.iter().find_map(|term| in_stmts(&term.stmts))
}

/// Span of the first `for` loop anywhere in a policy, or `None`.
/// Backs the LAN-303 `apply`-target rejection (loops cannot inline as
/// pure predicates).
fn first_loop(def: &PolicyDef) -> Option<Span> {
    fn in_stmts(stmts: &[Stmt]) -> Option<Span> {
        stmts.iter().find_map(|stmt| match stmt {
            Stmt::For(for_stmt) => Some(for_stmt.span),
            _ => None,
        })
    }
    def.terms.iter().find_map(|term| in_stmts(&term.stmts))
}

/// Span of the first user-function call anywhere in a policy — guard
/// value expressions, `set` values, and `let` initializers, in every
/// statement position — or `None`. Backs the LAN-304 `apply`-target
/// rejection (calls lower to binding terms a pure predicate cannot
/// execute).
fn first_fn_call(def: &PolicyDef, file: &SourceFile) -> Option<Span> {
    fn in_value(expr: &ValueExprAst, file: &SourceFile) -> Option<Span> {
        match expr {
            ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => None,
            ValueExprAst::Binary { lhs, rhs, .. } => {
                in_value(lhs, file).or_else(|| in_value(rhs, file))
            }
            ValueExprAst::Call { name, args, span } => {
                if file.fns.iter().any(|f| f.name.node == name.node) {
                    return Some(*span);
                }
                args.iter().find_map(|arg| in_value(arg, file))
            }
        }
    }
    fn in_expr(expr: &Expr, file: &SourceFile) -> Option<Span> {
        match expr {
            Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
                in_expr(lhs, file).or_else(|| in_expr(rhs, file))
            }
            Expr::Not(inner, _) => in_expr(inner, file),
            Expr::ValueCmp { lhs, rhs, .. } => in_value(lhs, file).or_else(|| in_value(rhs, file)),
            _ => None,
        }
    }
    fn in_action(action: &ActionStmt, file: &SourceFile) -> Option<Span> {
        match action {
            ActionStmt::SetLocalPref(expr, _)
            | ActionStmt::SetMed(expr, _)
            | ActionStmt::Let { init: expr, .. } => in_value(expr, file),
            _ => None,
        }
    }
    fn in_stmts(stmts: &[Stmt], file: &SourceFile) -> Option<Span> {
        stmts.iter().find_map(|stmt| match stmt {
            Stmt::Action(action) => in_action(action, file),
            Stmt::If(if_stmt) => in_expr(&if_stmt.cond, file)
                .or_else(|| if_stmt.then_actions.iter().find_map(|a| in_action(a, file)))
                .or_else(|| {
                    if_stmt
                        .else_actions
                        .iter()
                        .flatten()
                        .find_map(|a| in_action(a, file))
                }),
            Stmt::For(for_stmt) => in_stmts(&for_stmt.body, file),
        })
    }
    def.terms
        .iter()
        .find_map(|term| in_stmts(&term.stmts, file))
}

/// Every user-function call in a value expression, as `(name, span)`
/// call-graph edges (LAN-304) — builtins and unknown names excluded,
/// arguments walked for nested calls.
fn collect_fn_calls<'a>(expr: &'a ValueExprAst, file: &SourceFile, out: &mut Vec<(&'a str, Span)>) {
    match expr {
        ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => {}
        ValueExprAst::Binary { lhs, rhs, .. } => {
            collect_fn_calls(lhs, file, out);
            collect_fn_calls(rhs, file, out);
        }
        ValueExprAst::Call { name, args, span } => {
            if file.fns.iter().any(|f| f.name.node == name.node) {
                out.push((&name.node, *span));
            }
            for arg in args {
                collect_fn_calls(arg, file, out);
            }
        }
    }
}

/// Caller-frame slots a value expression's function calls consume when
/// inlined (LAN-304): each call site allocates its callee's full slot
/// footprint plus whatever its argument expressions' own calls need —
/// exactly the lowerer's monotonic allocation order.
fn call_slots(expr: &ValueExprAst, fns: &HashMap<&str, FnCost>) -> u64 {
    match expr {
        ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => 0,
        ValueExprAst::Binary { lhs, rhs, .. } => {
            call_slots(lhs, fns).saturating_add(call_slots(rhs, fns))
        }
        ValueExprAst::Call { name, args, .. } => {
            let own = fns.get(name.node.as_str()).map_or(0, |fc| fc.slots);
            args.iter()
                .map(|arg| call_slots(arg, fns))
                .fold(own, u64::saturating_add)
        }
    }
}

/// Function-call slots consumed by a guard expression's value
/// comparisons (LAN-304 frame accounting; other guard forms carry no
/// value expressions).
fn guard_call_slots(expr: &Expr, fns: &HashMap<&str, FnCost>) -> u64 {
    match expr {
        Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
            guard_call_slots(lhs, fns).saturating_add(guard_call_slots(rhs, fns))
        }
        Expr::Not(inner, _) => guard_call_slots(inner, fns),
        Expr::ValueCmp { lhs, rhs, .. } => {
            call_slots(lhs, fns).saturating_add(call_slots(rhs, fns))
        }
        // `apply` targets cannot call functions (rejected above).
        _ => 0,
    }
}

/// One statement sequence's frame-slot high-water mark (LAN-304),
/// mirroring the lowerer's `LetEnv` discipline exactly: statement-level
/// allocations (guard call binds, `set` value call binds, `let`s and
/// their initializer call binds) persist for the rest of the term;
/// `if`/`else` and loop bodies mark/reset, so sibling scopes reuse
/// slots (their readers execute before the sibling's binds — LAN-302).
fn stmts_slot_high_water(stmts: &[Stmt], base: u64, fns: &HashMap<&str, FnCost>) -> u64 {
    fn actions_high_water(actions: &[ActionStmt], base: u64, fns: &HashMap<&str, FnCost>) -> u64 {
        let mut cur = base;
        for action in actions {
            match action {
                ActionStmt::Let { init, .. } => {
                    cur = cur.saturating_add(call_slots(init, fns)).saturating_add(1);
                }
                ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _) => {
                    cur = cur.saturating_add(call_slots(expr, fns));
                }
                _ => {}
            }
        }
        cur
    }
    let mut cur = base;
    let mut high = base;
    for stmt in stmts {
        match stmt {
            Stmt::Action(ActionStmt::Let { init, .. }) => {
                cur = cur.saturating_add(call_slots(init, fns)).saturating_add(1);
            }
            Stmt::Action(ActionStmt::SetLocalPref(expr, _) | ActionStmt::SetMed(expr, _)) => {
                cur = cur.saturating_add(call_slots(expr, fns));
            }
            Stmt::Action(_) => {}
            Stmt::If(if_stmt) => {
                cur = cur.saturating_add(guard_call_slots(&if_stmt.cond, fns));
                high = high.max(actions_high_water(&if_stmt.then_actions, cur, fns));
                if let Some(else_actions) = &if_stmt.else_actions {
                    high = high.max(actions_high_water(else_actions, cur, fns));
                }
            }
            // Loop variable + body in a nested scope, reset on exit.
            Stmt::For(for_stmt) => {
                high = high.max(stmts_slot_high_water(
                    &for_stmt.body,
                    cur.saturating_add(1),
                    fns,
                ));
            }
        }
        high = high.max(cur);
    }
    high
}

/// Worst-case evaluation steps of a value expression (LAN-299): one
/// per operand read and one per operator/builtin step (`clamp`
/// charges two — it is a min/max pair).
fn value_cost(expr: &ValueExprAst, fns: &HashMap<&str, FnCost>) -> u64 {
    match expr {
        ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => 1,
        ValueExprAst::Binary { lhs, rhs, .. } => 1u64
            .saturating_add(value_cost(lhs, fns))
            .saturating_add(value_cost(rhs, fns)),
        ValueExprAst::Call { name, args, .. } => {
            // LAN-304: a user-function call charges its fully-inlined
            // body (the Kahn table entry) plus the result read; its
            // arguments are charged below like any operand. A name in
            // neither table is an unknown-call diagnostic elsewhere.
            let op_cost = if let Some(fc) = fns.get(name.node.as_str()) {
                fc.cost.saturating_add(1)
            } else if name.node == "clamp" {
                2
            } else {
                1
            };
            args.iter()
                .map(|arg| value_cost(arg, fns))
                .fold(op_cost, u64::saturating_add)
        }
    }
}

/// A constant subtree's checked-folded value, or `None` when it
/// contains a parameter/field or a folding step that itself fails
/// (reported where it happens — see `check_value_expr`). Folding uses
/// the same [`checked_arith`] as evaluation, so compile-time folding
/// and per-route evaluation can never disagree about what overflows.
pub(super) fn fold_const(expr: &ValueExprAst) -> Option<u32> {
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

/// "a" / "an" for a symbol-kind noun in a diagnostic note
/// ("an asn-set", "a prefix-set").
fn article(kind: &str) -> &'static str {
    if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    }
}

/// Attach the shared "did you mean" note for the closest candidate
/// (LAN-328), plus a definition-site label when the candidate is a
/// user-defined symbol — ariadne renders the label with the defining
/// file and line. Candidates without a span (builtins) get the note
/// only; no candidate within the [`closest`] budget leaves `diag`
/// untouched.
fn with_suggestion<'n>(
    diag: Diagnostic,
    name: &str,
    candidates: impl IntoIterator<Item = (&'n str, Option<Span>)>,
) -> Diagnostic {
    let candidates: Vec<(&str, Option<Span>)> = candidates.into_iter().collect();
    let Some(suggestion) = closest(name, candidates.iter().map(|&(candidate, _)| candidate)) else {
        return diag;
    };
    let diag = diag.with_note(format!("did you mean `{suggestion}`?"));
    let defined = candidates
        .iter()
        .find(|&&(candidate, _)| candidate == suggestion)
        .and_then(|&(_, span)| span);
    match defined {
        Some(span) => diag.with_label(span, format!("`{suggestion}` is defined here")),
        None => diag,
    }
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
