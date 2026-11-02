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
    ActionStmt, CallArg, CmpOp, CommunityArg, CommunityKind, DatasetDecl, DatasetEntryAst, Expr,
    FieldPath, FieldRoot, FnDef, ForSource, ForStmt, IfStmt, NextHopArg, ParamType, PolicyDef,
    PrependAsArg, Rhs, RouteField, SourceFile, Stmt, U32Arg, ValueExprAst,
};
use super::diag::{Diagnostic, DiagnosticCode, Span, Spanned, closest};

/// A resolved route/peer context field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Field {
    Prefix,
    Communities,
    LargeCommunities,
    ExtCommunities,
    AsPath,
    AsPathLen,
    CommunitiesLen,
    LargeCommunitiesLen,
    ExtCommunitiesLen,
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

/// Maximum `if` nesting depth: an `if` inside an `if` body, up to this
/// many levels, the loop precedent. An `else if` chain is one level, at
/// any length. Each level conjoins one more guard into every IR term it
/// lowers to, and the cost DP charges every re-evaluated guard.
const MAX_IF_DEPTH: u32 = 4;

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
/// Decision 3). A scope is one term, loop, or `if`/`else` body. Sibling
/// scopes reuse slots, and every binding live along one path shares the
/// fixed `crate::eval::LOCAL_FRAME_SLOTS` frame, which
/// `declare_binding` and the per-term high-water check enforce, so
/// deeper nesting never grows the frame at runtime.
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
    /// The policy's parameters of a type other than `u32`, which resolve
    /// only in positions of their own type.
    typed: Vec<(&'a str, ParamType)>,
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

    fn typed_param(&self, name: &str) -> Option<ParamType> {
        self.typed
            .iter()
            .find(|(param, _)| *param == name)
            .map(|(_, ty)| *ty)
    }

    /// The type of a parameter `name`, `u32` included.
    fn param_type(&self, name: &str) -> Option<ParamType> {
        if self.is_param(name) {
            Some(ParamType::U32)
        } else {
            self.typed_param(name)
        }
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

/// Whether a comparison against `field` resolves an identifier to an `ip`
/// parameter: the address fields. Shared with lowering, so both passes
/// read a name the same way.
pub(super) fn takes_ip_param(field: Field) -> bool {
    matches!(field, Field::NextHop | Field::PeerAddress)
}

/// What a reserved parameter name already means, or `None` for a free
/// name: an enum value, a well-known community, or a `prepend as`
/// operand. Reserving them at the declaration gives every pass the same
/// reading of the name.
fn reserved_param_meaning(name: &str) -> Option<String> {
    if super::parser::is_well_known_alias(name) {
        return Some("a well-known community".to_string());
    }
    if matches!(name, "origin" | "path-first") {
        return Some(format!("the `prepend as {name}` operand"));
    }
    [
        ("route.rpki", RPKI_MEMBERS),
        ("route.aspa", ASPA_MEMBERS),
        ("route.route-type", ROUTE_TYPE_MEMBERS),
        ("route.family", FAMILY_MEMBERS),
    ]
    .iter()
    .find(|(_, members)| members.contains(&name))
    .map(|(field, _)| format!("a `{field}` value"))
}

/// The optional value `exists <field>` tests, or `None` for a field
/// that is always present (LAN-2790).
pub(super) fn optional_field(field: Field) -> Option<crate::ir::OptionalField> {
    use crate::ir::OptionalField;
    match field {
        Field::OriginAs => Some(OptionalField::OriginAs),
        Field::PeerAsn => Some(OptionalField::PeerAsn),
        Field::Med => Some(OptionalField::Med),
        Field::LocalPref => Some(OptionalField::LocalPref),
        Field::NextHop => Some(OptionalField::NextHop),
        _ => None,
    }
}

/// Resolve a dotted field path to a [`Field`], or a diagnostic with a
/// suggestion.
pub(super) fn resolve_field(path: &FieldPath) -> Result<Field, Diagnostic> {
    let (table, root_name) = match path.root {
        FieldRoot::Route => (ROUTE_FIELDS, "route"),
        FieldRoot::Peer => (PEER_FIELDS, "peer"),
    };
    let first = &path.segs[0];
    let Some(&(_, field)) = table.iter().find(|(name, _)| *name == first.node) else {
        let mut diag = Diagnostic::coded(
            DiagnosticCode::Typecheck,
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
        2 if path.segs[1].node == "len" => match field {
            Field::AsPath => Ok(Field::AsPathLen),
            Field::Communities => Ok(Field::CommunitiesLen),
            Field::LargeCommunities => Ok(Field::LargeCommunitiesLen),
            Field::ExtCommunities => Ok(Field::ExtCommunitiesLen),
            _ => Err(no_sub_field(first, &path.segs[1])),
        },
        _ => Err(no_sub_field(first, &path.segs[1])),
    }
}

fn no_sub_field(first: &Spanned<String>, extra: &Spanned<String>) -> Diagnostic {
    Diagnostic::coded(
        DiagnosticCode::Typecheck,
        extra.span,
        format!("field `{}` has no sub-field `{}`", first.node, extra.node),
        "unexpected sub-field",
    )
    .with_note(
        "the sub-fields are `route.as-path.len`, `route.communities.len`, \
         `route.large-communities.len`, and `route.ext-communities.len`",
    )
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
        Field::CommunitiesLen => Some(ValueField::CommunitiesLen),
        Field::LargeCommunitiesLen => Some(ValueField::LargeCommunitiesLen),
        Field::ExtCommunitiesLen => Some(ValueField::ExtCommunitiesLen),
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
        let set_names = self
            .file
            .prefix_sets
            .iter()
            .map(|s| ("prefix-set", &s.name))
            .chain(
                self.file
                    .community_sets
                    .iter()
                    .map(|s| ("community-set", &s.name)),
            )
            .chain(self.file.asn_sets.iter().map(|s| ("asn-set", &s.name)))
            .chain(self.file.datasets.iter().map(|d| ("dataset", &d.name)));
        for (kind, name) in set_names {
            if super::parser::is_well_known_alias(&name.node) {
                self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        name.span,
                        format!(
                            "{kind} `{}` has the name of a well-known community",
                            name.node
                        ),
                        "reserved name",
                    )
                    .with_note(
                        "an argument spelled like a well-known community is that community, \
                         so a set with this name could never be passed; rename the set",
                    ),
                );
            }
        }
        if self.file.datasets.len() > MAX_UNIT_DATASETS {
            let extra = &self.file.datasets[MAX_UNIT_DATASETS];
            self.diags.push(Diagnostic::coded(
                DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                typed: Vec::new(),
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
        for param in &policy.params {
            if let Some(meaning) = reserved_param_meaning(&param.node) {
                self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        param.span,
                        format!("parameter `{}` has the name of {meaning}", param.node),
                        "reserved name",
                    )
                    .with_note(
                        "a parameter cannot be named like an enum value, a well-known \
                         community or the `prepend as` operands `origin` and `path-first`: \
                         those positions read the name with its fixed meaning; rename the \
                         parameter",
                    ),
                );
            }
        }
        let mut params = Vec::new();
        let mut typed = Vec::new();
        for (param, ty) in policy.params.iter().zip(&policy.param_types) {
            if *ty == ParamType::U32 {
                params.push(param.node.as_str());
                continue;
            }
            typed.push((param.node.as_str(), *ty));
            // A set parameter stands where a set name does; sharing a
            // name with a set would make that position ambiguous.
            if ty.set_kind().is_some()
                && let Some((kind, span)) = self.symbol_def_of(&param.node)
                && matches!(kind, "prefix-set" | "community-set" | "asn-set" | "dataset")
            {
                self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        param.span,
                        format!(
                            "parameter `{}` has the name of {} {kind}",
                            param.node,
                            article(kind)
                        ),
                        "set parameters and sets share one namespace",
                    )
                    .with_label(span, format!("`{}` is defined here", param.node)),
                );
            }
        }
        let mut scope = Scope {
            params,
            typed,
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
                    Stmt::If(if_stmt) => if_stmt.span(),
                    Stmt::Action(action) => action.span(),
                    Stmt::For(for_stmt) => for_stmt.span,
                };
                self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                Stmt::If(if_stmt) => self.check_if(if_stmt, scope, loop_depth, 0),
                Stmt::For(for_stmt) => self.check_for(for_stmt, scope, loop_depth),
            }
        }
        scope.lets.truncate(mark);
    }

    /// One `for` loop (LAN-303): validate the source is one of the
    /// finite u32-valued forms, cap nesting, then check the body in a
    /// fresh scope holding the loop variable.
    fn check_for(&mut self, for_stmt: &ForStmt, scope: &mut Scope, loop_depth: u32) {
        if let ForSource::Set(name) = &for_stmt.source
            && let Some(ty) = scope.typed_param(&name.node)
        {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    name.span,
                    format!(
                        "parameter `{}` is {} {}; loops iterate a named asn-set only",
                        name.node,
                        ty.article(),
                        ty.keyword()
                    ),
                    "a set parameter is not a loop source",
                )
                .with_note("a loop's bound is the set's size at compile time, which a parameter does not have"),
            );
        }
        if loop_depth == MAX_LOOP_DEPTH {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
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
    #[expect(
        clippy::too_many_lines,
        reason = "one match over the three iterable forms keeps type diagnostics and finite-source bounds together"
    )]
    fn check_for_source(&mut self, source: &ForSource) {
        match source {
            ForSource::Field(path) => match resolve_field(path) {
                Err(diag) => self.diags.push(diag),
                Ok(Field::Communities | Field::AsPath) => {}
                Ok(Field::LargeCommunities | Field::ExtCommunities) => self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                            Diagnostic::coded(
                                DiagnosticCode::Typecheck,
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
                let mut diag = Diagnostic::coded(
                    DiagnosticCode::Typecheck,
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

    /// One `if` chain at `if_depth` enclosing `if` bodies: every guard,
    /// then every body. `MAX_IF_DEPTH` caps the nesting.
    fn check_if(&mut self, if_stmt: &IfStmt, scope: &mut Scope, loop_depth: u32, if_depth: u32) {
        if if_depth == MAX_IF_DEPTH {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    if_stmt.span(),
                    format!("`if` statements nest more than {MAX_IF_DEPTH} deep"),
                    "`if` nesting limit exceeded",
                )
                .with_note(
                    "every level conjoins another guard into each branch; use `else if` \
                     or split the term (`&&` also joins conditions, but its operands may \
                     evaluate in either order, so it cannot stand in for nesting when an \
                     operand can fail closed)",
                ),
            );
        }
        for branch in &if_stmt.branches {
            self.check_expr(&branch.cond, scope);
            self.check_if_body(&branch.body, scope, loop_depth, if_depth + 1);
        }
        if let Some(else_body) = &if_stmt.else_body {
            self.check_if_body(&else_body.body, scope, loop_depth, if_depth + 1);
        }
    }

    /// One `if`/`else` body — its own lexical scope (LAN-302): `let`
    /// bindings declared here are visible to the rest of the body and
    /// nowhere else. `loop_depth` scopes `break`/`continue` (LAN-303);
    /// `if_depth` counts the enclosing `if` bodies, this one included.
    fn check_if_body(&mut self, body: &[Stmt], scope: &mut Scope, loop_depth: u32, if_depth: u32) {
        let mark = scope.lets.len();
        let mut body_locals = 0usize;
        let mut terminated: Option<Span> = None;
        for stmt in body {
            if let Some(verdict_span) = terminated {
                let (span, message, label) = match stmt {
                    Stmt::Action(action) => (
                        action.span(),
                        "unreachable action",
                        "this action can never execute",
                    ),
                    Stmt::If(if_stmt) => (
                        if_stmt.span(),
                        "unreachable statement",
                        "this statement can never execute",
                    ),
                    Stmt::For(for_stmt) => (
                        for_stmt.span,
                        "unreachable statement",
                        "this statement can never execute",
                    ),
                };
                self.diags.push(
                    Diagnostic::coded(DiagnosticCode::Typecheck, span, message, label)
                        .with_label(verdict_span, "the branch already decided here"),
                );
                break;
            }
            let action = match stmt {
                Stmt::Action(action) => action,
                Stmt::If(if_stmt) => {
                    self.check_if(if_stmt, scope, loop_depth, if_depth);
                    continue;
                }
                // The parser admits no loop in an `if` body.
                Stmt::For(for_stmt) => {
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        for_stmt.span,
                        "`for` is not allowed in an `if` body",
                        "loops go in term or loop bodies",
                    ));
                    continue;
                }
            };
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
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
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
            Diagnostic::coded(
                DiagnosticCode::Typecheck,
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
            ActionStmt::SetNextHop(NextHopArg::Param(name), _) => {
                if scope.typed_param(&name.node) != Some(ParamType::Ip)
                    && !self.typed_param_misused(name, scope, "an `ip` parameter")
                {
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        name.span,
                        format!("unknown `ip` parameter `{}`", name.node),
                        "`set next-hop` takes an address, `self`, or an `ip` parameter",
                    ));
                }
            }
            ActionStmt::Accept(_)
            | ActionStmt::Reject(_)
            | ActionStmt::SetNextHop(..)
            | ActionStmt::Community {
                add: false,
                arg: CommunityArg::All(_),
                ..
            } => {}
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
            ActionStmt::Community {
                add: true,
                kind,
                arg: CommunityArg::All(span),
                ..
            } => {
                self.diags.push(Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    *span,
                    format!("`add {}` takes a literal value", kind_keyword(*kind)),
                    "wildcards are removal-only",
                ));
            }
            ActionStmt::Community {
                add,
                kind,
                arg: CommunityArg::LargeAdminWildcard(global),
                ..
            } => {
                if *add || *kind != CommunityKind::Large {
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        global.span,
                        "large-community wildcard requires `remove large-community`",
                        "wildcards are removal-only and large-community-only",
                    ));
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                // A `let` shadows an outer parameter here, as in value
                // positions; lowering resolves the same way.
                let local = scope.is_local(&name.node);
                let community_param =
                    !local && scope.typed_param(&name.node) == Some(ParamType::Community);
                if local || community_param {
                    // Resolved.
                } else if self.typed_param_misused(name, scope, "a community") {
                    // Reported.
                } else if !scope.is_param(&name.node) {
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
            ActionStmt::Community {
                add,
                kind,
                arg: CommunityArg::InSet { set, negate },
                ..
            } => self.check_remove_in_set(*add, *kind, set, *negate, scope),
            ActionStmt::Prepend { asn, count, .. } => {
                // A computed operand (`self`, `peer`, `origin`,
                // `path-first`) needs no parameter check. Parameters
                // cannot take the operand names, so the operand decision
                // (`PrependAsArg::operand`, shared with lowering) depends
                // on the name alone. `let` bindings deliberately
                // do not resolve here: this is not a value position
                // (LAN-302 scoping rule), so `prepend as origin` keeps
                // its operand meaning even under a `let origin`.
                if asn.operand().is_none()
                    && let PrependAsArg::Value(arg) = asn
                {
                    self.check_u32_arg(arg, scope);
                    if let U32Arg::Lit(asn, span) = arg
                        && *asn == 0
                    {
                        self.diags.push(Diagnostic::coded(
                            DiagnosticCode::Typecheck,
                            *span,
                            "AS 0 cannot be prepended (RFC 7607)",
                            "ASN cannot be 0",
                        ));
                    }
                }
                match count {
                    U32Arg::Lit(value, span) => {
                        if *value == 0 || *value > 255 {
                            self.diags.push(Diagnostic::coded(
                                DiagnosticCode::Typecheck,
                                *span,
                                format!("prepend count {value} out of range"),
                                "must be 1-255",
                            ));
                        }
                    }
                    // A u32 parameter: its argument is range-checked where the
                    // policy is instantiated (an attach, a test, `apply`).
                    U32Arg::Param(_) => self.check_u32_arg(count, scope),
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                            Diagnostic::coded(
                                DiagnosticCode::Typecheck,
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
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                                Diagnostic::coded(
                                    DiagnosticCode::Typecheck,
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
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
        if self.typed_param_misused(name, scope, "a u32 value") {
            return;
        }
        let mut diag = Diagnostic::coded(
            DiagnosticCode::Typecheck,
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
        if self.typed_param_misused(name, scope, "a u32 value") {
            return;
        }
        if scope.is_local(&name.node) {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    name.span,
                    format!("`{}` is a `let` binding", name.node),
                    "this position needs a literal or parameter",
                )
                .with_note("bindings are runtime values; this argument is fixed at compile time"),
            );
            return;
        }
        let mut diag = Diagnostic::coded(
            DiagnosticCode::Typecheck,
            name.span,
            format!("unknown parameter `{}`", name.node),
            "not a parameter of this policy",
        );
        if let Some(suggestion) = closest(&name.node, scope.params.iter().copied()) {
            diag = diag.with_note(format!("did you mean `{suggestion}`?"));
        }
        self.diags.push(diag);
    }

    /// A non-`u32` parameter in a position of another type: reports it and
    /// returns true.
    fn typed_param_misused(
        &mut self,
        name: &Spanned<String>,
        scope: &Scope<'_>,
        wanted: &str,
    ) -> bool {
        let Some(ty) = scope.typed_param(&name.node) else {
            return false;
        };
        self.diags.push(Diagnostic::coded(
            DiagnosticCode::Typecheck,
            name.span,
            format!(
                "parameter `{}` is {} {}, but this position needs {wanted}",
                name.node,
                ty.article(),
                ty.keyword()
            ),
            "parameter type mismatch",
        ));
        true
    }

    /// A typed parameter where a set name goes: `route.prefix in p`,
    /// `x in p`. `wanted` lists the set types the position accepts.
    fn check_set_param(&mut self, set: &Spanned<String>, ty: ParamType, wanted: &[ParamType]) {
        if !wanted.contains(&ty) {
            let names: Vec<_> = wanted
                .iter()
                .map(|ty| format!("`{}`", ty.keyword()))
                .collect();
            self.diags.push(Diagnostic::coded(
                DiagnosticCode::Typecheck,
                set.span,
                format!(
                    "parameter `{}` is {} {}, but this probe needs {}",
                    set.node,
                    ty.article(),
                    ty.keyword(),
                    names.join(" or ")
                ),
                "parameter type mismatch",
            ));
        }
    }

    /// The arguments of a policy reference against the callee's parameter
    /// types. `scope` is the caller's inside `apply`, where a name may be
    /// one of its parameters; `None` in a test `expect`.
    fn check_call_args(
        &mut self,
        target: &PolicyDef,
        args: &[Spanned<CallArg>],
        scope: Option<&Scope<'_>>,
    ) {
        for (index, arg) in args.iter().enumerate().take(target.param_types.len()) {
            let ty = target.param_types[index];
            if let (Some(scope), CallArg::Name(name)) = (scope, &arg.node) {
                // A u32 position keeps its established checks: parameter,
                // `let` binding, or unknown name.
                if ty == ParamType::U32 && scope.typed_param(name).is_none() {
                    self.check_u32_arg(&U32Arg::Param(Spanned::new(name.clone(), arg.span)), scope);
                    continue;
                }
                if let Some(caller) = scope.param_type(name) {
                    if caller != ty {
                        self.diags.push(Diagnostic::coded(
                            DiagnosticCode::Typecheck,
                            arg.span,
                            format!(
                                "parameter `{name}` is {} {}, but `{}` takes {} {}",
                                caller.article(),
                                caller.keyword(),
                                target.params[index].node,
                                ty.article(),
                                ty.keyword()
                            ),
                            "parameter type mismatch",
                        ));
                    }
                    continue;
                }
            }
            if let Err(reason) = check_call_arg(self.file, target, index, &arg.node) {
                self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        arg.span,
                        reason,
                        "invalid argument",
                    )
                    .with_label(target.params[index].span, "parameter declared here"),
                );
            }
        }
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
            Expr::In { field, set } => {
                if let Some(ty) = scope.typed_param(&set.node) {
                    let wanted: &[ParamType] = match resolve_field(field) {
                        Ok(Field::Prefix) => &[ParamType::PrefixSet],
                        Ok(
                            Field::Communities | Field::LargeCommunities | Field::ExtCommunities,
                        ) => &[ParamType::CommunitySet],
                        Ok(Field::OriginAs | Field::PeerAsn) => &[ParamType::AsnSet],
                        _ => &[],
                    };
                    if wanted.is_empty() {
                        self.check_in(field, set);
                    } else {
                        self.check_set_param(set, ty, wanted);
                    }
                } else {
                    self.check_in(field, set);
                }
            }
            // LAN-303: `<binding> in <set>` — u32 value against an
            // asn-set, or a community-set's standard members.
            Expr::IdentIn { ident, set } => {
                self.check_value_ident(ident, scope);
                if let Some(ty) = scope.typed_param(&set.node) {
                    self.check_set_param(set, ty, &[ParamType::AsnSet, ParamType::CommunitySet]);
                } else if self.file.asn_sets.iter().any(|s| s.name.node == set.node)
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
                            Diagnostic::coded(
                                DiagnosticCode::Typecheck,
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
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
            Expr::HasParam { field, param } => match resolve_field(field) {
                Err(diag) => self.diags.push(diag),
                Ok(Field::Communities) => {
                    if scope.typed_param(&param.node) != Some(ParamType::Community)
                        && !self.typed_param_misused(param, scope, "a `community` parameter")
                    {
                        self.diags.push(Diagnostic::coded(
                            DiagnosticCode::Typecheck,
                            param.span,
                            format!("unknown `community` parameter `{}`", param.node),
                            "`has` takes a community literal or a `community` parameter",
                        ));
                    }
                }
                Ok(_) => self.diags.push(
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        field.span.to(param.span),
                        format!(
                            "`{}` cannot be probed with a `community` parameter",
                            field.render()
                        ),
                        "`community` parameters are standard communities",
                    )
                    .with_note("`has <parameter>` works on route.communities"),
                ),
            },
            // LAN-2790: a presence test for the optional values a
            // condition can see as missing (or as their default).
            Expr::Exists { field, span } => match resolve_field(field) {
                Err(diag) => self.diags.push(diag),
                Ok(resolved) => {
                    if optional_field(resolved).is_none() {
                        self.diags.push(
                            Diagnostic::coded(
                                DiagnosticCode::Typecheck,
                                *span,
                                format!("`exists` does not support `{}`", field.render()),
                                "no presence test for this field",
                            )
                            .with_note(
                                "presence tests support only: route.origin-as, peer.asn, \
                                 route.med, route.local-pref, route.next-hop",
                            ),
                        );
                    }
                }
            },
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
                                Diagnostic::coded(
                                    DiagnosticCode::Typecheck,
                                    field.span,
                                    format!("`has` is not defined on `{}`", field.render()),
                                    "`has` probes a community list",
                                )
                                .with_note(
                                    "`has` works on route.communities, route.large-communities, and route.ext-communities",
                                ),
                            ),
                            Some(kind) if lit.node.kind() != kind => self.diags.push(
                                Diagnostic::coded(
                                    DiagnosticCode::Typecheck,
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
                    self.diags.push(Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                self.check_call_args(target, args, Some(scope));
                if target.params.len() != args.len() {
                    self.diags.push(
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
            }
        }
    }

    fn require_as_path(&mut self, field: &FieldPath, op: &str) {
        match resolve_field(field) {
            Err(diag) => self.diags.push(diag),
            Ok(Field::AsPath) => {}
            Ok(_) => self.diags.push(Diagnostic::coded(
                DiagnosticCode::Typecheck,
                field.span,
                format!("`{op}` is not defined on `{}`", field.render()),
                format!("`{op}` works on route.as-path"),
            )),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per field type; splitting would scatter the comparison rules"
    )]
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
                checker.diags.push(Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    field.span.to(rhs.span()),
                    format!("`{}` supports only `==` and `!=`", field.render()),
                    "ordering comparison on an unordered field",
                ));
            }
        };
        match resolved {
            Field::LocalPref
            | Field::Med
            | Field::AsPathLen
            | Field::CommunitiesLen
            | Field::LargeCommunitiesLen
            | Field::ExtCommunitiesLen => {
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
            field
                if takes_ip_param(field)
                    && matches!(rhs, Rhs::Ident(name) if scope.typed_param(&name.node) == Some(ParamType::Ip)) =>
            {
                eq_only(self);
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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

    /// `route.evpn-route-type` compares against supported Types 1–6.
    /// Unsupported types never enter the RIB, so reject dead comparisons.
    fn check_evpn_route_type_rhs(&mut self, field: &FieldPath, rhs: &Rhs) {
        match rhs {
            Rhs::Int(value, span) if !(1..=6).contains(value) => {
                self.diags.push(Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    *span,
                    format!("EVPN route type {value} out of range"),
                    "must be 1-6 (RFC 7432, RFC 9136, RFC 9251)",
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
        let mut diag = Diagnostic::coded(
            DiagnosticCode::Typecheck,
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

    /// `remove <kind> in SET` / `not in SET`: removal-only, against a
    /// community-set (not a dataset) that has members of the action's kind
    /// — otherwise `in` removes nothing and `not in` removes everything.
    fn check_remove_in_set(
        &mut self,
        add: bool,
        kind: CommunityKind,
        set: &Spanned<String>,
        negate: bool,
        scope: &Scope<'_>,
    ) {
        let keyword = kind_keyword(kind);
        let form = if negate { "not in" } else { "in" };
        if add {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    set.span,
                    format!("`add {keyword} {form}` is not an action"),
                    "set membership selects arrived values to remove",
                )
                .with_note(format!("use `remove {keyword} {form} {}`", set.node)),
            );
            return;
        }
        // A set parameter stands for its argument here, as in every other
        // set position. Its members are known only at instantiation, so
        // the member-kind notes below apply to named sets.
        if let Some(ty) = scope.typed_param(&set.node) {
            self.check_set_param(set, ty, &[ParamType::CommunitySet]);
            return;
        }
        if let Some(def) = self
            .file
            .community_sets
            .iter()
            .find(|s| s.name.node == set.node)
        {
            match removal_set_problem(def, kind, negate) {
                None => {}
                Some(RemovalSetProblem::NoRouteTargetOrOrigin) => {
                    self.diags
                        .push(ext_not_in_without_rt_ro(set, def.name.span));
                }
                Some(RemovalSetProblem::NoMembers { effect }) => {
                    let mut diag = Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    set.span,
                    format!(
                        "community-set `{}` has no {} members, so `remove {keyword} {form} {}` {effect}",
                        set.node,
                        kind_describe(kind),
                        set.node,
                    ),
                    format!("no {} member", kind_describe(kind)),
                )
                .with_label(def.name.span, format!("`{}` is defined here", set.node));
                    if negate {
                        diag = diag.with_note(format!(
                            "to strip every {}, write `{}`",
                            kind_describe(kind),
                            community_attribute(kind).remove_all_str()
                        ));
                    }
                    self.diags.push(diag);
                }
            }
        } else if self.dataset_of(&set.node).is_some() {
            self.diags.push(
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
                    set.span,
                    format!(
                        "`remove {keyword} {form}` takes a community-set; `{}` is a dataset",
                        set.node
                    ),
                    "datasets are not supported here",
                )
                .with_note(format!(
                    "probe the dataset in a guard (`route.communities in {}`), or define \
                     the members as a community-set",
                    set.node
                )),
            );
        } else {
            self.check_set_reference(
                set,
                "community-set",
                "removal by membership needs a community-set",
                self.file.community_sets.iter().map(|s| &s.name),
            );
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
        let mut diag = Diagnostic::coded(
            DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                            self.diags.push(Diagnostic::coded(
                                DiagnosticCode::Typecheck,
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
                    RouteField::AsPath(value) => {
                        if let Err(error) = super::testing::parse_fixture_as_path(&value.node) {
                            // Point at the offending character when the
                            // literal has no escapes (string offsets then
                            // map 1:1 past the opening quote).
                            let span = if value.node.contains(['\\', '"']) {
                                value.span
                            } else {
                                let start = value.span.start + 1 + error.offset;
                                Span {
                                    start,
                                    end: start + error.len,
                                    file: value.span.file,
                                }
                            };
                            self.diags.push(
                                Diagnostic::coded(
                                    DiagnosticCode::Typecheck,
                                    span,
                                    format!("invalid fixture `as-path`: {}", error.message),
                                    "not an AS path",
                                )
                                .with_note(
                                    "write space-separated ASNs, with `{...}` for an AS_SET \
                                     (e.g. \"64500 {64501 64502}\")",
                                ),
                            );
                        }
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
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
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
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                            Diagnostic::coded(
                                DiagnosticCode::Typecheck,
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
            for call in test.expects.iter().flat_map(|expect| &expect.calls) {
                let file = self.file;
                let Some(target) = file
                    .policies
                    .iter()
                    .find(|p| p.name.node == call.policy.node)
                else {
                    let mut diag = Diagnostic::coded(
                        DiagnosticCode::Typecheck,
                        call.policy.span,
                        format!("unknown policy `{}`", call.policy.node),
                        "no policy with this name",
                    );
                    if let Some((kind, span)) = self.symbol_def_of(&call.policy.node) {
                        diag = diag
                            .with_note(format!(
                                "`{}` is {} {kind}, not a policy — `expect` runs policies",
                                call.policy.node,
                                article(kind)
                            ))
                            .with_label(span, format!("`{}` is defined here", call.policy.node));
                    } else {
                        diag = with_suggestion(
                            diag,
                            &call.policy.node,
                            self.file
                                .policies
                                .iter()
                                .map(|p| (p.name.node.as_str(), Some(p.name.span))),
                        );
                    }
                    self.diags.push(diag);
                    continue;
                };
                self.check_call_args(target, &call.args, None);
                if target.params.len() != call.args.len() {
                    self.diags.push(
                        Diagnostic::coded(
                            DiagnosticCode::Typecheck,
                            call.args
                                .last()
                                .map_or(call.policy.span, |arg| call.policy.span.to(arg.span)),
                            format!(
                                "policy `{}` takes {} argument{} but {} {} supplied",
                                call.policy.node,
                                target.params.len(),
                                if target.params.len() == 1 { "" } else { "s" },
                                call.args.len(),
                                if call.args.len() == 1 { "was" } else { "were" },
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
            let mut diag = Diagnostic::coded(
                DiagnosticCode::Typecheck,
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
                    Diagnostic::coded(
                        DiagnosticCode::Typecheck,
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
                Stmt::If(if_stmt) => {
                    for branch in &if_stmt.branches {
                        collect_applies(&branch.cond, targets);
                    }
                    for body in if_stmt.bodies() {
                        walk_stmts(body, targets);
                    }
                }
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
                Diagnostic::coded(
                    DiagnosticCode::Typecheck,
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
    // charges a `True`-guarded term for itself and each hoisted call
    // bind, though a run of them may merge into one). Action value expressions
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
                    if_terms(
                        if_stmt,
                        PathCost::default(),
                        pred_cost,
                        fns,
                        &mut |guard, terms, action| {
                            push_arms(&mut arms, guard, terms);
                            if let Some(action) = action {
                                action_cost =
                                    action_cost.saturating_add(action_value_cost(action, fns));
                            }
                        },
                    );
                }
                Stmt::Action(action) => {
                    let terms = guarded_action_terms(std::slice::from_ref(action), fns);
                    push_arms(&mut arms, 1, terms);
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
            Diagnostic::coded(
                DiagnosticCode::Typecheck,
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
            Diagnostic::coded(
                DiagnosticCode::Typecheck,
                def.name.span,
                format!(
                    "policy `{name}` expands past {MAX_APPLY_EXPANSION} IR nodes \
                     through `apply` inlining or `if` branches"
                ),
                "compiled size limit exceeded",
            )
            .with_note(
                "apply(p) inlines p's decision predicate — and every function call its \
                 fully-inlined body — at every use site, and every `else if` branch \
                 repeats the negation of each earlier guard in its chain; split or \
                 flatten the composition, or shorten the chain",
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

/// How a policy uses its parameters where an argument has a range: as a
/// `prepend` count (1–255), a `prepend` ASN (not 0, RFC 7607), a `set
/// next-hop` operand (a usable unicast address), or the set of `remove
/// <kind> in` / `not in` (a community-set, not a dataset). A parameter
/// passed on through `apply(q(...))` inherits the uses of `q`'s parameter,
/// so an argument is checked against every place its value reaches.
#[derive(Clone, Default)]
pub(super) struct ValueUses<'a> {
    counts: Vec<&'a str>,
    prepend_asns: Vec<&'a str>,
    next_hops: Vec<&'a str>,
    /// Each removal by membership a parameter names: the parameter, the
    /// community kind and whether it is `not in`.
    removal_sets: Vec<(&'a str, CommunityKind, bool)>,
}

impl<'a> ValueUses<'a> {
    /// The parameter uses of one action.
    fn record(&mut self, action: &'a ActionStmt) {
        match action {
            ActionStmt::Prepend { asn, count, .. } => {
                if let U32Arg::Param(name) = count {
                    self.counts.push(&name.node);
                }
                if asn.operand().is_none()
                    && let PrependAsArg::Value(U32Arg::Param(name)) = asn
                {
                    self.prepend_asns.push(&name.node);
                }
            }
            ActionStmt::SetNextHop(NextHopArg::Param(name), _) => self.next_hops.push(&name.node),
            ActionStmt::Community {
                kind,
                arg: CommunityArg::InSet { set, negate },
                ..
            } => self.removal_sets.push((&set.node, *kind, *negate)),
            _ => {}
        }
    }
}

/// The [`ValueUses`] of `def`'s parameters, following `apply` arguments.
/// Each policy is analysed once; a policy met again on its own path (a
/// cycle) contributes nothing, and the walk stops past
/// [`MAX_APPLY_DEPTH`]. Both are rejected on their own, and in a file
/// that passes those checks neither cut is ever taken. The cut keeps
/// the recursion within the depth limit, since this runs before the
/// composition checks.
pub(super) fn param_value_uses<'a>(file: &'a SourceFile, def: &'a PolicyDef) -> ValueUses<'a> {
    fn exprs<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
        match expr {
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                exprs(lhs, out);
                exprs(rhs, out);
            }
            Expr::Not(inner, _) => exprs(inner, out),
            Expr::Apply { .. } => out.push(expr),
            _ => {}
        }
    }
    fn walk<'a>(stmts: &'a [Stmt], actions: &mut Vec<&'a ActionStmt>, applies: &mut Vec<&'a Expr>) {
        for stmt in stmts {
            match stmt {
                Stmt::Action(action) => actions.push(action),
                Stmt::If(if_stmt) => {
                    for branch in &if_stmt.branches {
                        exprs(&branch.cond, applies);
                    }
                    for body in if_stmt.bodies() {
                        walk(body, actions, applies);
                    }
                }
                Stmt::For(for_stmt) => walk(&for_stmt.body, actions, applies),
            }
        }
    }
    fn uses<'a>(
        file: &'a SourceFile,
        def: &'a PolicyDef,
        depth: u32,
        memo: &mut HashMap<&'a str, Option<ValueUses<'a>>>,
    ) -> ValueUses<'a> {
        if depth > MAX_APPLY_DEPTH {
            return ValueUses::default();
        }
        match memo.get(def.name.node.as_str()) {
            Some(Some(done)) => return done.clone(),
            Some(None) => return ValueUses::default(),
            None => {}
        }
        memo.insert(&def.name.node, None);
        let mut actions = Vec::new();
        let mut applies = Vec::new();
        for term in &def.terms {
            walk(&term.stmts, &mut actions, &mut applies);
        }
        let mut out = ValueUses::default();
        for action in actions {
            out.record(action);
        }
        for apply in applies {
            let Expr::Apply { policy, args, .. } = apply else {
                continue;
            };
            let Some(callee) = file.policies.iter().find(|p| p.name.node == policy.node) else {
                continue;
            };
            let inner = uses(file, callee, depth + 1, memo);
            for (arg, param) in args.iter().zip(&callee.params) {
                let CallArg::Name(name) = &arg.node else {
                    continue;
                };
                let Some(own) = def.params.iter().find(|p| p.node == *name) else {
                    continue;
                };
                let own = own.node.as_str();
                let param = param.node.as_str();
                for (theirs, ours) in [
                    (&inner.counts, &mut out.counts),
                    (&inner.prepend_asns, &mut out.prepend_asns),
                    (&inner.next_hops, &mut out.next_hops),
                ] {
                    if theirs.contains(&param) && !ours.contains(&own) {
                        ours.push(own);
                    }
                }
                for &(theirs, kind, negate) in &inner.removal_sets {
                    if theirs == param && !out.removal_sets.contains(&(own, kind, negate)) {
                        out.removal_sets.push((own, kind, negate));
                    }
                }
            }
        }
        memo.insert(&def.name.node, Some(out.clone()));
        out
    }
    uses(file, def, 0, &mut HashMap::new())
}

/// One literal argument against the callee's parameter at `index`: its
/// type, an existing set or dataset of the parameter's kind, and the
/// value range of a parameter used as a `prepend` count or `set next-hop`
/// operand. The same check runs for a test `expect`, an `apply`, and a
/// configured chain reference.
pub(super) fn check_call_arg(
    file: &SourceFile,
    def: &PolicyDef,
    index: usize,
    arg: &CallArg,
) -> Result<(), String> {
    let ty = def.param_types[index];
    let param = def.params[index].node.as_str();
    let uses = param_value_uses(file, def);
    match (ty, arg) {
        (ParamType::U32, CallArg::Int(value)) => {
            if uses.counts.contains(&param) && !(1..=255).contains(value) {
                return Err(format!(
                    "prepend count {value} out of range for parameter `{param}` (must be 1-255)"
                ));
            }
            if uses.prepend_asns.contains(&param) && *value == 0 {
                return Err(format!(
                    "AS 0 cannot be prepended (RFC 7607) for parameter `{param}`"
                ));
            }
            Ok(())
        }
        (ParamType::Community, CallArg::Community(_)) => Ok(()),
        (ParamType::Ip, CallArg::Ip(addr)) => {
            if uses.next_hops.contains(&param)
                && let Err(why) = crate::engine::NextHopAction::check_specific(*addr)
            {
                return Err(format!(
                    "invalid next hop {addr} for parameter `{param}`: {why}"
                ));
            }
            Ok(())
        }
        (
            ParamType::PrefixSet | ParamType::CommunitySet | ParamType::AsnSet,
            CallArg::Name(name),
        ) => {
            let kind = ty.set_kind().expect("a set type");
            let declared = match ty {
                ParamType::PrefixSet => file.prefix_sets.iter().any(|s| s.name.node == *name),
                ParamType::CommunitySet => file.community_sets.iter().any(|s| s.name.node == *name),
                _ => file.asn_sets.iter().any(|s| s.name.node == *name),
            } || file
                .datasets
                .iter()
                .any(|d| d.name.node == *name && d.kind == kind);
            let removals = uses
                .removal_sets
                .iter()
                .filter(|(used, _, _)| *used == param);
            let community_set = file.community_sets.iter().find(|s| s.name.node == *name);
            if declared {
                for &(_, kind, negate) in removals {
                    let Some(def) = community_set else {
                        return Err(format!(
                            "`{name}` is a dataset, but parameter `{param}` is the set of a \
                             `remove ... in` action, which takes a community-set"
                        ));
                    };
                    let form = if negate { "not in" } else { "in" };
                    let action = format!("`remove {} {form} {param}`", kind_keyword(kind));
                    match removal_set_problem(def, kind, negate) {
                        None => {}
                        Some(RemovalSetProblem::NoRouteTargetOrOrigin) => {
                            return Err(format!(
                                "community-set `{name}` has no route-target or route-origin \
                                 members, so {action} removes every route target and route origin"
                            ));
                        }
                        Some(RemovalSetProblem::NoMembers { effect }) => {
                            return Err(format!(
                                "community-set `{name}` has no {} members, so {action} {effect}",
                                kind_describe(kind)
                            ));
                        }
                    }
                }
                Ok(())
            } else {
                Err(format!(
                    "unknown {} `{name}` for parameter `{param}` (name {} {} or {} {kind} dataset)",
                    ty.keyword(),
                    ty.article(),
                    ty.keyword(),
                    ty.article()
                ))
            }
        }
        _ => Err(format!(
            "argument `{arg}` is not {} {} (parameter `{param}`)",
            ty.article(),
            ty.keyword()
        )),
    }
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

/// Record `terms` lowered terms of `guard` IR nodes each, at most one past
/// the size budget: an inlined function graph can multiply a term count
/// into the billions, and every arm costs at least one node, so a capped
/// list still exceeds the budget and its diagnostic fires.
fn push_arms(arms: &mut Vec<u64>, guard: u64, terms: u64) {
    let room = (MAX_APPLY_EXPANSION + 1).saturating_sub(arms.len() as u64);
    arms.extend((0..terms.min(room)).map(|_| guard));
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
            // Upper bound per iteration: every lowered term's guard (each
            // branch's path conjunction, re-evaluated per term) plus
            // every body action.
            Stmt::If(if_stmt) => {
                if_terms(
                    if_stmt,
                    PathCost::default(),
                    pred_cost,
                    fns,
                    &mut |guard, terms, action| {
                        let guards = guard.saturating_mul(terms);
                        nodes = nodes.saturating_add(guards);
                        body_steps = body_steps.saturating_add(guards);
                        if let Some(action) = action {
                            nodes = nodes.saturating_add(1);
                            body_steps = body_steps
                                .saturating_add(1)
                                .saturating_add(action_value_cost(action, fns));
                        }
                    },
                );
            }
            Stmt::Action(action) => {
                let terms = guarded_action_terms(std::slice::from_ref(action), fns);
                nodes = nodes.saturating_add(terms);
                body_steps = body_steps
                    .saturating_add(terms)
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

/// An `if` path condition as the lowerer builds it: one flat `And` over
/// `count` conditions whose IR nodes sum to `nodes` (no `And` node for a
/// single condition; the unconditional `True` node for none).
#[derive(Clone, Copy, Default)]
struct PathCost {
    nodes: u64,
    count: u64,
}

impl PathCost {
    /// The path with one more condition of `nodes` IR nodes.
    fn with(self, nodes: u64) -> Self {
        Self {
            nodes: self.nodes.saturating_add(nodes),
            count: self.count.saturating_add(1),
        }
    }

    /// The path's IR nodes, its `And` included; an empty path lowers to
    /// one `True` node.
    fn cost(self) -> u64 {
        self.nodes.saturating_add(u64::from(self.count > 1)).max(1)
    }
}

/// Every IR term an `if` chain lowers to, reported as
/// `(guard nodes, terms, action)` — mirroring the lowerer: branch `k`
/// is guarded by the path condition, the negation of every earlier
/// branch guard that can fall through, and its own guard, in one flat
/// `And`; the final `else` by the path and those negations; a nested
/// `if` conjoins its chain onto its body's path. A branch whose body
/// always decides adds no negation (`coverage::body_decides`). Every
/// term re-evaluates its whole guard, and each report charges it.
/// `action` is `None` for an empty body's placeholder term and for a
/// nested guard's function-call binds. A single flat `if` keeps its
/// established lowering, the `else` guarded by the negated condition.
fn if_terms<'a>(
    if_stmt: &'a IfStmt,
    path: PathCost,
    pred_cost: &HashMap<&str, u64>,
    fns: &HashMap<&str, FnCost>,
    out: &mut dyn FnMut(u64, u64, Option<&'a ActionStmt>),
) {
    fn body_terms<'a>(
        body: &'a [Stmt],
        path: PathCost,
        pred_cost: &HashMap<&str, u64>,
        fns: &HashMap<&str, FnCost>,
        out: &mut dyn FnMut(u64, u64, Option<&'a ActionStmt>),
    ) {
        if body.is_empty() {
            out(path.cost(), 1, None);
        }
        for stmt in body {
            match stmt {
                Stmt::Action(action) => out(
                    path.cost(),
                    guarded_action_terms(std::slice::from_ref(action), fns),
                    Some(action),
                ),
                Stmt::If(inner) => if_terms(inner, path, pred_cost, fns, out),
                // Rejected by the typechecker; nothing lowers.
                Stmt::For(_) => {}
            }
        }
    }
    let flat = if_stmt.is_flat();
    let mut prefix = path;
    for branch in &if_stmt.branches {
        let guard = guard_cost(&branch.cond, pred_cost, fns);
        // A guard's function-call binds run once the walk reaches the
        // branch, under its path condition.
        let binds = guard_call_slots(&branch.cond, fns);
        if binds != 0 {
            out(prefix.cost(), binds, None);
        }
        body_terms(&branch.body, prefix.with(guard), pred_cost, fns, out);
        // A flat `if` whose body only binds still gates its `else` with a
        // placeholder term after the binds.
        if flat
            && if_stmt.else_body.is_some()
            && !branch.body.is_empty()
            && branch
                .body
                .iter()
                .all(|stmt| matches!(stmt, Stmt::Action(ActionStmt::Let { .. })))
        {
            out(prefix.with(guard).cost(), 1, None);
        }
        if flat || !super::coverage::body_decides(&branch.body) {
            prefix = prefix.with(guard.saturating_add(1));
        }
    }
    if let Some(else_body) = &if_stmt.else_body {
        body_terms(&else_body.body, prefix, pred_cost, fns, out);
    }
}

/// Conservative guarded-tail count: every source action plus every Bind term
/// hoisted by an inline user call, with one arm retained for an empty branch.
fn guarded_action_terms(actions: &[ActionStmt], fns: &HashMap<&str, FnCost>) -> u64 {
    actions
        .iter()
        .map(|action| {
            1 + match action {
                ActionStmt::SetLocalPref(expr, _)
                | ActionStmt::SetMed(expr, _)
                | ActionStmt::Let { init: expr, .. } => call_slots(expr, fns),
                _ => 0,
            }
        })
        .fold(0, u64::saturating_add)
        .max(1)
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
        ActionStmt::Community {
            arg: CommunityArg::LargeAdminWildcard(_),
            ..
        } => crate::eval::MAX_LARGE_COMMUNITIES_PER_ROUTE,
        // One step per arrived value of the kind, as for the strip-all form.
        // A step probes the set: one exact hash probe plus at most
        // `MAX_COMMUNITY_PATTERN_SCAN` pattern comparisons.
        ActionStmt::Community {
            kind,
            arg: CommunityArg::All(_) | CommunityArg::InSet { .. },
            ..
        } => crate::eval::max_communities_per_route(community_attribute(*kind)),
        _ => 0,
    }
}

/// Span of the first `let` statement anywhere in a policy — term
/// bodies, `if`/`else` bodies, and loop bodies — or `None`. Backs the
/// LAN-302 `apply`-target rejection.
fn first_let(def: &PolicyDef) -> Option<Span> {
    fn in_stmts(stmts: &[Stmt]) -> Option<Span> {
        stmts.iter().find_map(|stmt| match stmt {
            Stmt::Action(ActionStmt::Let { span, .. }) => Some(*span),
            Stmt::Action(_) => None,
            Stmt::If(if_stmt) => if_stmt.bodies().find_map(in_stmts),
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
            Stmt::If(if_stmt) => if_stmt
                .branches
                .iter()
                .find_map(|branch| in_expr(&branch.cond, file))
                .or_else(|| if_stmt.bodies().find_map(|body| in_stmts(body, file))),
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
            // Every branch guard's call binds persist at this level; each
            // body is a nested scope, reset on exit.
            Stmt::If(if_stmt) => {
                for branch in &if_stmt.branches {
                    cur = cur.saturating_add(guard_call_slots(&branch.cond, fns));
                    high = high.max(stmts_slot_high_water(&branch.body, cur, fns));
                }
                if let Some(else_body) = &if_stmt.else_body {
                    high = high.max(stmts_slot_high_water(&else_body.body, cur, fns));
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

/// DFS cycle detection over the `apply` (or function call) graph, with
/// an explicit stack: an acyclic chain of any length cannot exhaust the
/// thread stack before the depth checks reject it. `path` is the current
/// DFS path; returns the cycle (closed: `a -> b -> a`) and the span of
/// the closing edge. Every node the walk leaves, including on a cycle, is
/// recorded in `done`.
fn find_cycle<'a>(
    start: &'a str,
    edges: &HashMap<&'a str, Vec<(&'a str, Span)>>,
    path: &mut Vec<&'a str>,
    done: &mut HashSet<&'a str>,
) -> Option<(Vec<String>, Span)> {
    if done.contains(start) {
        return None;
    }
    // Each frame is a node on the path and the index of its next edge.
    let mut stack: Vec<(&'a str, usize)> = vec![(start, 0)];
    path.push(start);
    while let Some(&(node, next)) = stack.last() {
        let targets = edges.get(node).map_or(&[][..], Vec::as_slice);
        let Some(&(target, span)) = targets.get(next) else {
            stack.pop();
            path.pop();
            done.insert(node);
            continue;
        };
        if let Some(frame) = stack.last_mut() {
            frame.1 += 1;
        }
        if let Some(position) = path.iter().position(|&seen| seen == target) {
            let mut cycle: Vec<String> = path[position..].iter().map(ToString::to_string).collect();
            cycle.push(target.to_string());
            for (left, _) in stack.drain(..).rev() {
                path.pop();
                done.insert(left);
            }
            return Some((cycle, span));
        }
        if !done.contains(target) {
            stack.push((target, 0));
            path.push(target);
        }
    }
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
    Diagnostic::coded(
        DiagnosticCode::Typecheck,
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

/// The `remove ext-community not in SET` diagnostic for a set without a
/// route-target or route-origin member.
fn ext_not_in_without_rt_ro(set: &Spanned<String>, def_span: Span) -> Diagnostic {
    Diagnostic::coded(
        DiagnosticCode::Typecheck,
        set.span,
        format!(
            "community-set `{}` has no route-target or route-origin members, so \
             `remove ext-community not in {}` removes every route target and route origin",
            set.node, set.node,
        ),
        "no RT or RO member",
    )
    .with_label(def_span, format!("`{}` is defined here", set.node))
    .with_note(
        "`ext-community not in` considers only route targets and route origins; \
         other extended communities are never removed by it",
    )
}

/// Why a community-set cannot be the set of `remove <kind> in` / `not in`.
enum RemovalSetProblem {
    /// `ext-community not in` with extended members but no route target or
    /// route origin: it would remove every arrived RT and RO.
    NoRouteTargetOrOrigin,
    /// No member of the action's kind; `effect` says what the action
    /// would do instead.
    NoMembers { effect: String },
}

/// The member check for a removal set, shared by a named set and a set
/// reached through a parameter, so both are held to the same rules.
fn removal_set_problem(
    def: &super::ast::CommunitySetDef,
    kind: CommunityKind,
    negate: bool,
) -> Option<RemovalSetProblem> {
    let has_kind = def
        .entries
        .iter()
        .any(|entry| member_kind(&entry.node) == kind);
    // `ext-community not in` acts on route targets and route origins only,
    // so its set needs one of those.
    if negate
        && kind == CommunityKind::Ext
        && has_kind
        && !def.entries.iter().any(|entry| names_rt_or_ro(&entry.node))
    {
        return Some(RemovalSetProblem::NoRouteTargetOrOrigin);
    }
    if has_kind {
        return None;
    }
    let effect = if negate && kind == CommunityKind::Ext {
        "removes every arrived route target and route origin".to_string()
    } else if negate {
        format!("removes every arrived {}", kind_describe(kind))
    } else {
        "never removes anything".to_string()
    };
    Some(RemovalSetProblem::NoMembers { effect })
}

/// Whether a set member names a route target or route origin.
fn names_rt_or_ro(member: &crate::sets::CommunityMember) -> bool {
    use crate::engine::CommunityMatch;
    use crate::sets::{CommunityMember, CommunityPattern};
    match member {
        CommunityMember::Exact(cm) => matches!(
            cm,
            CommunityMatch::RouteTarget { .. } | CommunityMatch::RouteOrigin { .. }
        ),
        CommunityMember::Pattern(pattern) => matches!(
            **pattern,
            CommunityPattern::RouteTarget { .. } | CommunityPattern::RouteOrigin { .. }
        ),
    }
}

/// The community kind of a set member.
fn member_kind(member: &crate::sets::CommunityMember) -> CommunityKind {
    use crate::engine::CommunityMatch;
    use crate::sets::{CommunityMember, CommunityPattern};
    match member {
        CommunityMember::Exact(CommunityMatch::Standard { .. }) => CommunityKind::Standard,
        CommunityMember::Exact(CommunityMatch::LargeCommunity { .. }) => CommunityKind::Large,
        CommunityMember::Exact(_) => CommunityKind::Ext,
        CommunityMember::Pattern(pattern) => match **pattern {
            CommunityPattern::Standard { .. } => CommunityKind::Standard,
            CommunityPattern::Large { .. } => CommunityKind::Large,
            CommunityPattern::RouteTarget { .. } | CommunityPattern::RouteOrigin { .. } => {
                CommunityKind::Ext
            }
        },
    }
}

/// The IR attribute a community action kind addresses.
pub(super) fn community_attribute(kind: CommunityKind) -> crate::ir::CommunityAttribute {
    match kind {
        CommunityKind::Standard => crate::ir::CommunityAttribute::Standard,
        CommunityKind::Large => crate::ir::CommunityAttribute::Large,
        CommunityKind::Ext => crate::ir::CommunityAttribute::Extended,
    }
}

pub(super) fn kind_keyword(kind: CommunityKind) -> &'static str {
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
