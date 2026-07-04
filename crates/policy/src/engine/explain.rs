//! Statement-level chain attribution — explain-only.
//!
//! [`explain_chain_statements`](crate::engine::explain::explain_chain_statements)
//! re-walks a policy chain the same way
//! [`PolicyChain::evaluate_with_attribution`] does, but records *which
//! statement* inside each policy decided (or that the policy fell
//! through to its default action), the conditions that statement
//! matched, and the attribute modifications it contributes — the
//! per-statement enrichment ADR-0073 deferred from v1.
//!
//! This module follows the same discipline as the RIB-side tiebreaker
//! explain (`best_path_cmp_with_reason` in `crates/rib`): the hot
//! evaluation path is **never** routed through here. The chain walk is
//! deliberately duplicated rather than factored into the live
//! evaluator, and the two are pinned together by the agreement matrix
//! in `engine/tests/statement_trace.rs` — the trace's terminal action
//! and terminal policy must equal what `evaluate_chain_with_attribution`
//! returns for the same context. Per-statement *matching* is not
//! duplicated: both walks call the same (private) `PolicyStatement::matches`,
//! so they cannot disagree about whether an individual statement fires.
//!
//! Rendering contract: `matched_conditions` and `modifications` are
//! lists of `"<label> <detail>"` strings whose leading label is stable
//! (`prefix`, `community`, `as_path`, `neighbor_set`, `route_type`,
//! `evpn_route_type`, `rpki`, `aspa`, `as_path_len`, `local_pref`,
//! `med`, `next_hop`, `any`, plus `guard` for an `.rpol` member's
//! deciding guard; modification labels add `extended_community` /
//! `large_community`). The detail portion is human-oriented and not a
//! machine-parsable grammar — consume the structured indices and the
//! leading label for automation, mirroring the `vs_best_reason` /
//! `vs_best_detail` split on the best-path explain surface.
//!
//! `.rpol` chain members (ADR-0096) trace at term granularity: the
//! step's `term_name`/`term_traces` carry the walk over the member's
//! compiled IR terms, with guards rendered back to `.rpol` surface
//! syntax by this module's pretty-printer (sets by source name). Guard
//! *evaluation* is shared with the live evaluator
//! (`CompiledChain::guard_matches`), so the two walks cannot disagree
//! about whether a guard fires; the rpol agreement matrix in
//! `statement_trace.rs` additionally pins the trace against
//! `evaluate_recording_hits` term by term.

use std::fmt::Write as _;

use super::{
    CommunityMatch, IMPLICIT_LOCAL_PREF, IMPLICIT_MED, NextHopAction, PolicyAction, PolicyChain,
    PolicyStatement, RouteContext, RouteModifications, RouteType,
};
use crate::ir::{Cmp, CompiledChain, CompiledPolicy, MatchExpr, Term, TermAction};

/// One step of a statement-level chain trace: how a single policy in
/// the chain disposed of the route.
///
/// Exactly one step exists per policy the chain *evaluated* — a Deny
/// terminates the walk, so policies after a denying one carry no step
/// (they were never consulted; inventing "skipped" steps would imply an
/// evaluation that did not happen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementAttribution {
    /// 0-based position of the policy within the chain.
    pub policy_index: usize,
    /// Configured policy name (`None` = inline / anonymous).
    pub policy_name: Option<String>,
    /// 0-based index of the first matching statement within the
    /// policy. `None` = no statement matched and the policy's
    /// `default_action` decided (the fallthrough case).
    pub statement_index: Option<usize>,
    /// The action this policy contributed (the matched statement's
    /// action, or the default action on fallthrough).
    pub action: PolicyAction,
    /// Stable `"<label> <detail>"` summaries of every condition the
    /// matched statement carries — all of them matched (statement
    /// conditions AND together). `["any"]` for an unconditional
    /// statement; empty on a default-action fallthrough (there is no
    /// statement to summarize).
    pub matched_conditions: Vec<String>,
    /// Rendered modifications this statement contributes, with
    /// `before -> after` for scalar attributes. The "before" side is
    /// always the route's *pre-policy* value: chain semantics
    /// accumulate modifications and apply them once after the walk, so
    /// a later statement does not see an earlier statement's edits.
    /// For an `.rpol` member this is the policy's merged contribution
    /// (matched `Continue` terms folded under the deciding permit,
    /// mirroring the live evaluator's merge).
    pub modifications: Vec<String>,
    /// `.rpol` term name of the deciding term (ADR-0096). `None` for
    /// TOML statements and for default-action fallthroughs.
    pub term_name: Option<String>,
    /// Per-term rendered trace lines for an `.rpol` member, in walk
    /// order: `term <name>: <guard> => <action> [matched|not matched]`.
    /// Terms after the deciding one were never evaluated and carry no
    /// line (the same philosophy as chain policies after a deny); on a
    /// default-action fallthrough every term appears. Empty for TOML
    /// members. Guards render in `.rpol` surface syntax (sets by their
    /// source name); human-oriented, not a machine-parsable grammar.
    pub term_traces: Vec<String>,
}

/// A full statement-level trace of one chain evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStatementTrace {
    /// The terminal action — must agree with
    /// [`PolicyChain::evaluate_with_attribution`] for the same inputs
    /// (pinned by the agreement tests).
    pub action: PolicyAction,
    /// One entry per policy evaluated, in chain order. Empty for an
    /// absent or empty chain (implicit permit, nothing to attribute).
    pub steps: Vec<StatementAttribution>,
}

/// Re-walk `chain` against `ctx`, attributing the decision to the
/// statement (or default action) inside each evaluated policy.
///
/// Explain-only: never called from the live import/export evaluation
/// path. `None` / empty chains return `Permit` with no steps, matching
/// `evaluate_chain_with_attribution`'s implicit-permit contract.
#[must_use]
pub fn explain_chain_statements(
    chain: Option<&PolicyChain>,
    ctx: &RouteContext<'_>,
) -> ChainStatementTrace {
    let Some(chain) = chain else {
        return ChainStatementTrace {
            action: PolicyAction::Permit,
            steps: Vec::new(),
        };
    };

    let mut steps = Vec::new();
    for (policy_index, named) in chain.policies.iter().enumerate() {
        if let Some(rpol) = named.rpol.as_deref() {
            // `.rpol` member: walk the pre-compiled IR terms against
            // the donor chain's own set tables (guard evaluation goes
            // through the live evaluator's `guard_matches`, so the two
            // walks cannot disagree about a guard).
            let mut denied = false;
            for policy in &rpol.policies {
                let step = trace_rpol_policy(policy_index, named.name.clone(), policy, rpol, ctx);
                denied = step.action == PolicyAction::Deny;
                steps.push(step);
                if denied {
                    break;
                }
            }
            if denied {
                return ChainStatementTrace {
                    action: PolicyAction::Deny,
                    steps,
                };
            }
            continue;
        }
        let matched = named.policy.entries.iter().position(|e| e.matches(ctx));
        let (statement_index, action, matched_conditions, modifications) = match matched {
            Some(index) => {
                let entry = &named.policy.entries[index];
                // Live-path parity: a Deny terminator returns
                // `PolicyResult::deny()` and never applies its set
                // clauses, so a denying statement must not claim
                // modifications in the trace either.
                let modifications = if entry.action == PolicyAction::Permit {
                    render_modifications(&entry.modifications, ctx)
                } else {
                    Vec::new()
                };
                (
                    Some(index),
                    entry.action,
                    render_matched_conditions(entry, ctx),
                    modifications,
                )
            }
            None => (None, named.policy.default_action, Vec::new(), Vec::new()),
        };
        steps.push(StatementAttribution {
            policy_index,
            policy_name: named.name.clone(),
            statement_index,
            action,
            matched_conditions,
            modifications,
            term_name: None,
            term_traces: Vec::new(),
        });
        if action == PolicyAction::Deny {
            // Chain semantics: a Deny terminates evaluation. Later
            // policies were never consulted, so they get no step.
            return ChainStatementTrace {
                action: PolicyAction::Deny,
                steps,
            };
        }
    }
    ChainStatementTrace {
        action: PolicyAction::Permit,
        steps,
    }
}

/// Render a standard (RFC 1997) community as `ASN:VALUE`.
fn fmt_standard_community(value: u32) -> String {
    format!("{}:{}", value >> 16, value & 0xFFFF)
}

fn fmt_community_match(cm: &CommunityMatch) -> String {
    match cm {
        CommunityMatch::Standard { value } => fmt_standard_community(*value),
        CommunityMatch::RouteTarget { global, local } => format!("RT:{global}:{local}"),
        CommunityMatch::RouteOrigin { global, local } => format!("RO:{global}:{local}"),
        CommunityMatch::LargeCommunity {
            global_admin,
            local_data1,
            local_data2,
        } => format!("LC:{global_admin}:{local_data1}:{local_data2}"),
        // Well-known values (e.g. the RFC 8097 OV_* states) render by
        // name via the wire Display impl; unknown raws render as hex.
        CommunityMatch::ExactExt(raw) => rustbgpd_wire::ExtendedCommunity::new(*raw).to_string(),
    }
}

fn route_type_label(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::Local => "local",
        RouteType::Internal => "internal",
        RouteType::External => "external",
    }
}

/// Summarize every condition the matched statement carries. All of
/// them held (statement predicates AND together), so listing the
/// configured set *is* the matched-condition set. Within the
/// `match_community` OR-list, only the criterion that actually matched
/// the route is reported.
fn render_matched_conditions(entry: &PolicyStatement, ctx: &RouteContext<'_>) -> Vec<String> {
    let mut out = Vec::new();

    if let Some(prefix) = entry.prefix {
        let mut s = format!("prefix {prefix}");
        if let Some(ge) = entry.ge {
            let _ = write!(s, " ge {ge}");
        }
        if let Some(le) = entry.le {
            let _ = write!(s, " le {le}");
        }
        out.push(s);
    }

    if !entry.match_community.is_empty() {
        // OR semantics: report the first criterion the route satisfies
        // (the statement matched, so one must exist).
        let matched = entry.match_community.iter().find(|cm| {
            ctx.extended_communities.iter().any(|ec| cm.matches_ec(ec))
                || ctx.communities.iter().any(|c| cm.matches_standard(*c))
                || ctx.large_communities.iter().any(|lc| cm.matches_large(lc))
        });
        if let Some(cm) = matched {
            out.push(format!("community {}", fmt_community_match(cm)));
        }
    }

    if let Some(regex) = entry.match_as_path.as_ref() {
        out.push(format!("as_path ~ {:?}", regex.pattern()));
    }

    if let Some(set) = entry.match_neighbor_set.as_ref() {
        // Report the member kind that admitted this peer, mirroring
        // `NeighborSetMatch::matches`'s address → ASN → group order.
        if let Some(addr) = ctx.peer_address.filter(|a| set.addresses.contains(a)) {
            out.push(format!("neighbor_set address {addr}"));
        } else if let Some(asn) = ctx.peer_asn.filter(|a| set.remote_asns.contains(a)) {
            out.push(format!("neighbor_set asn {asn}"));
        } else if let Some(group) = ctx
            .peer_group
            .filter(|g| set.peer_groups.iter().any(|name| name == g))
        {
            out.push(format!("neighbor_set group {group}"));
        }
    }

    if let Some(route_type) = entry.match_route_type {
        out.push(format!("route_type {}", route_type_label(route_type)));
    }
    if let Some(rt) = entry.match_evpn_route_type {
        out.push(format!("evpn_route_type {rt}"));
    }
    if let Some(state) = entry.match_rpki_validation {
        out.push(format!("rpki {state}"));
    }
    if let Some(state) = entry.match_aspa_validation {
        out.push(format!("aspa {state}"));
    }
    if let Some(v) = entry.match_as_path_length_ge {
        out.push(format!("as_path_len >= {v}"));
    }
    if let Some(v) = entry.match_as_path_length_le {
        out.push(format!("as_path_len <= {v}"));
    }
    if let Some(v) = entry.match_local_pref_ge {
        out.push(format!("local_pref >= {v}"));
    }
    if let Some(v) = entry.match_local_pref_le {
        out.push(format!("local_pref <= {v}"));
    }
    if let Some(v) = entry.match_med_ge {
        out.push(format!("med >= {v}"));
    }
    if let Some(v) = entry.match_med_le {
        out.push(format!("med <= {v}"));
    }
    if let Some(nh) = entry.match_next_hop {
        out.push(format!("next_hop {nh}"));
    }

    if out.is_empty() {
        // Unconditional statement: it matches everything. Render that
        // honestly instead of an empty list (which would read like a
        // default-action fallthrough).
        out.push("any".to_string());
    }
    out
}

/// Render the statement's modifications, with `before -> after` where
/// the pre-policy value is knowable from the context. Scalar "before"
/// values use the same implicit defaults the match engine uses
/// (`LOCAL_PREF` 100 / `MED` 0, RFC 4271) so the rendered transition is
/// consistent with what `local_pref >= N` matching saw.
fn render_modifications(mods: &RouteModifications, ctx: &RouteContext<'_>) -> Vec<String> {
    let mut out = Vec::new();

    if let Some(lp) = mods.set_local_pref {
        out.push(format!(
            "local_pref {} -> {lp}",
            ctx.local_pref.unwrap_or(IMPLICIT_LOCAL_PREF)
        ));
    }
    if let Some(med) = mods.set_med {
        out.push(format!("med {} -> {med}", ctx.med.unwrap_or(IMPLICIT_MED)));
    }
    if let Some(action) = mods.set_next_hop.as_ref() {
        let before = ctx
            .next_hop
            .map_or_else(|| "none".to_string(), |a| a.to_string());
        let after = match action {
            NextHopAction::Self_ => "self".to_string(),
            NextHopAction::Specific(addr) => addr.to_string(),
        };
        out.push(format!("next_hop {before} -> {after}"));
    }
    for c in &mods.communities_add {
        out.push(format!("community + {}", fmt_standard_community(*c)));
    }
    for c in &mods.communities_remove {
        out.push(format!("community - {}", fmt_standard_community(*c)));
    }
    for ec in &mods.extended_communities_add {
        out.push(format!("extended_community + {ec}"));
    }
    for ec in &mods.extended_communities_remove {
        out.push(format!("extended_community - {ec}"));
    }
    for lc in &mods.large_communities_add {
        out.push(format!("large_community + {lc}"));
    }
    for lc in &mods.large_communities_remove {
        out.push(format!("large_community - {lc}"));
    }
    if let Some((asn, count)) = mods.as_path_prepend {
        out.push(format!("as_path prepend {asn} x{count}"));
    }
    out
}

// ---------------------------------------------------------------------
// `.rpol` member tracing (ADR-0096 explain slice).
// ---------------------------------------------------------------------

/// Trace one pre-compiled `.rpol` policy: walk its terms exactly like
/// `CompiledChain::evaluate_policy` (first decider wins, matched
/// `Continue` modifications accumulate under an eventual permit and are
/// discarded by a deny), rendering a `term_traces` line per evaluated
/// term. `tables` is the member's donor chain — its set/regex tables
/// and names are self-contained.
fn trace_rpol_policy(
    policy_index: usize,
    policy_name: Option<String>,
    policy: &CompiledPolicy,
    tables: &CompiledChain,
    ctx: &RouteContext<'_>,
) -> StatementAttribution {
    let mut term_traces = Vec::new();
    let mut continued: Option<RouteModifications> = None;
    let mut decided: Option<(usize, &Term)> = None;
    for (index, term) in policy.terms.iter().enumerate() {
        let matched = tables.guard_matches(&term.guard, ctx);
        term_traces.push(format!(
            "term {}: {} => {} [{}]",
            term.name.as_deref().unwrap_or("<unnamed>"),
            render_expr(&term.guard, tables),
            render_term_action(&term.action),
            if matched { "matched" } else { "not matched" },
        ));
        if !matched {
            continue;
        }
        match &term.action {
            TermAction::Continue(mods) => {
                continued
                    .get_or_insert_with(RouteModifications::default)
                    .merge_from(mods.clone());
            }
            TermAction::Permit(_) | TermAction::Deny => {
                decided = Some((index, term));
                break;
            }
        }
    }
    if let Some((index, term)) = decided {
        // Live-path parity: a deny discards accumulated Continue
        // modifications and contributes none of its own.
        let (action, modifications) = match &term.action {
            TermAction::Permit(mods) => {
                let mut merged = continued.unwrap_or_default();
                merged.merge_from(mods.clone());
                (PolicyAction::Permit, render_modifications(&merged, ctx))
            }
            _ => (PolicyAction::Deny, Vec::new()),
        };
        StatementAttribution {
            policy_index,
            policy_name,
            statement_index: Some(index),
            action,
            matched_conditions: vec![format!("guard {}", render_expr(&term.guard, tables))],
            modifications,
            term_name: term.name.clone(),
            term_traces,
        }
    } else {
        // Fallthrough to the policy default; a permitting default
        // keeps accumulated Continue modifications (live parity).
        let modifications = match (policy.default_action, continued) {
            (PolicyAction::Permit, Some(mods)) => render_modifications(&mods, ctx),
            _ => Vec::new(),
        };
        StatementAttribution {
            policy_index,
            policy_name,
            statement_index: None,
            action: policy.default_action,
            matched_conditions: Vec::new(),
            modifications,
            term_name: None,
            term_traces,
        }
    }
}

/// Render a compiled term's action in `.rpol` surface syntax, e.g.
/// `set local-pref 200; accept` / `reject` / `add community 65001:999;
/// continue` (`continue` names the IR fallthrough — a term body that
/// modified without a verdict).
fn render_term_action(action: &TermAction) -> String {
    let (mods, verdict) = match action {
        TermAction::Permit(mods) => (Some(mods), "accept"),
        TermAction::Deny => (None, "reject"),
        TermAction::Continue(mods) => (Some(mods), "continue"),
    };
    let mut parts = mods.map_or_else(Vec::new, render_action_stmts);
    parts.push(verdict.to_string());
    parts.join("; ")
}

/// Modifications as `.rpol` action statements (static description of
/// what the term *does* — contrast `render_modifications`, which
/// renders the `before -> after` transition for a specific route).
fn render_action_stmts(mods: &RouteModifications) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(lp) = mods.set_local_pref {
        out.push(format!("set local-pref {lp}"));
    }
    if let Some(med) = mods.set_med {
        out.push(format!("set med {med}"));
    }
    if let Some(action) = mods.set_next_hop.as_ref() {
        let target = match action {
            NextHopAction::Self_ => "self".to_string(),
            NextHopAction::Specific(addr) => addr.to_string(),
        };
        out.push(format!("set next-hop {target}"));
    }
    for c in &mods.communities_add {
        out.push(format!("add community {}", fmt_standard_community(*c)));
    }
    for c in &mods.communities_remove {
        out.push(format!("remove community {}", fmt_standard_community(*c)));
    }
    for lc in &mods.large_communities_add {
        out.push(format!(
            "add community {}:{}:{}",
            lc.global_admin, lc.local_data1, lc.local_data2
        ));
    }
    for lc in &mods.large_communities_remove {
        out.push(format!(
            "remove community {}:{}:{}",
            lc.global_admin, lc.local_data1, lc.local_data2
        ));
    }
    for ec in &mods.extended_communities_add {
        out.push(format!("add community {ec}"));
    }
    for ec in &mods.extended_communities_remove {
        out.push(format!("remove community {ec}"));
    }
    if let Some((asn, count)) = mods.as_path_prepend {
        out.push(format!("prepend {asn} {count}"));
    }
    out
}

// ---------------------------------------------------------------------
// Guard pretty-printer: compiled MatchExpr back to `.rpol` surface
// syntax. Sets render by their source name where the chain tables carry
// one. Compact and human-oriented; a lowering round-trip is NOT
// guaranteed (e.g. `==` on integers renders as its `>= && <=` pair,
// `contains N` as its `matches "_N_"` regex).
// ---------------------------------------------------------------------

/// Binding strength for parenthesization: `Or` < `And` < atoms.
/// A multi-member neighbor set renders as an internal `||`, so it
/// binds like `Or`.
fn binding(expr: &MatchExpr) -> u8 {
    match expr {
        MatchExpr::Or(_) => 0,
        MatchExpr::NeighborIn(set)
            if set.addresses.len() + set.remote_asns.len() + set.peer_groups.len() > 1 =>
        {
            0
        }
        MatchExpr::And(_) => 1,
        _ => 2,
    }
}

/// Render `expr` against `tables` (the chain whose set/regex ids the
/// expression references).
pub(crate) fn render_expr(expr: &MatchExpr, tables: &CompiledChain) -> String {
    render_prec(expr, tables, 0)
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per MatchExpr node type; splitting would scatter the rendering table"
)]
fn render_prec(expr: &MatchExpr, tables: &CompiledChain, min_binding: u8) -> String {
    let rendered = match expr {
        MatchExpr::True => "true".to_string(),
        MatchExpr::PrefixInSet(id) => format!(
            "route.prefix in {}",
            set_label(&tables.prefix_set_names, id.0, "prefix-set")
        ),
        MatchExpr::PrefixEq { prefix, ge, le } => {
            let mut out = format!("route.prefix == {prefix}");
            if let Some(ge) = ge {
                let _ = write!(out, " ge {ge}");
            }
            if let Some(le) = le {
                let _ = write!(out, " le {le}");
            }
            out
        }
        MatchExpr::PrefixNe { prefix, ge, le } => {
            let mut out = format!("route.prefix != {prefix}");
            if let Some(ge) = ge {
                let _ = write!(out, " ge {ge}");
            }
            if let Some(le) = le {
                let _ = write!(out, " le {le}");
            }
            out
        }
        MatchExpr::CommunityContains(cm) => {
            format!(
                "{} has {}",
                community_field(&[*cm]),
                fmt_community_match(cm)
            )
        }
        MatchExpr::CommunityInSet(id) => {
            let field = tables
                .community_sets
                .get(id.0 as usize)
                .map_or("route.communities", |set| community_field(set.criteria()));
            format!(
                "{field} in {}",
                set_label(&tables.community_set_names, id.0, "community-set")
            )
        }
        MatchExpr::AsPathMatches(id) => format!(
            "route.as-path matches {:?}",
            tables
                .as_path_regexes
                .get(id.0 as usize)
                .map_or("", |regex| regex.pattern())
        ),
        MatchExpr::AsPathLen(cmp) => render_cmp("route.as-path.len", *cmp),
        MatchExpr::LocalPref(cmp) => render_cmp("route.local-pref", *cmp),
        MatchExpr::Med(cmp) => render_cmp("route.med", *cmp),
        MatchExpr::NextHopEq(addr) => format!("route.next-hop == {addr}"),
        MatchExpr::NextHopNe(addr) => format!("route.next-hop != {addr}"),
        MatchExpr::NextHopEqPeer => "route.next-hop == peer.address".to_string(),
        MatchExpr::NextHopNePeer => "route.next-hop != peer.address".to_string(),
        MatchExpr::NeighborIn(set) => {
            let mut parts: Vec<String> = Vec::new();
            for addr in &set.addresses {
                parts.push(format!("peer.address == {addr}"));
            }
            for asn in &set.remote_asns {
                parts.push(format!("peer.asn == {asn}"));
            }
            for group in &set.peer_groups {
                parts.push(format!("peer.group == {group:?}"));
            }
            if parts.is_empty() {
                // An empty neighbor set never matches.
                "false".to_string()
            } else {
                parts.join(" || ")
            }
        }
        MatchExpr::RouteTypeIs(route_type) => {
            format!("route.route-type == {}", route_type_label(*route_type))
        }
        MatchExpr::RouteTypeNe(route_type) => {
            format!("route.route-type != {}", route_type_label(*route_type))
        }
        MatchExpr::EvpnRouteTypeIs(evpn_type) => {
            format!("route.evpn-route-type == {evpn_type}")
        }
        MatchExpr::EvpnRouteTypeNe(evpn_type) => {
            format!("route.evpn-route-type != {evpn_type}")
        }
        MatchExpr::RpkiIs(state) => format!(
            "route.rpki == {}",
            match state {
                rustbgpd_wire::RpkiValidation::Valid => "valid",
                rustbgpd_wire::RpkiValidation::Invalid => "invalid",
                rustbgpd_wire::RpkiValidation::NotFound => "not-found",
            }
        ),
        MatchExpr::AspaIs(state) => format!(
            "route.aspa == {}",
            match state {
                rustbgpd_wire::AspaValidation::Valid => "valid",
                rustbgpd_wire::AspaValidation::Invalid => "invalid",
                rustbgpd_wire::AspaValidation::Unknown => "unknown",
            }
        ),
        MatchExpr::And(children) => {
            if children.is_empty() {
                "true".to_string()
            } else {
                children
                    .iter()
                    .map(|child| render_prec(child, tables, 2))
                    .collect::<Vec<_>>()
                    .join(" && ")
            }
        }
        MatchExpr::Or(children) => {
            if children.is_empty() {
                // An empty Or never matches.
                "false".to_string()
            } else {
                children
                    .iter()
                    .map(|child| render_prec(child, tables, 1))
                    .collect::<Vec<_>>()
                    .join(" || ")
            }
        }
        MatchExpr::Not(inner) => {
            // Always parenthesized: `!(...)` is unambiguous regardless
            // of the inner expression's shape.
            return format!("!({})", render_prec(inner, tables, 0));
        }
    };
    if binding(expr) < min_binding {
        format!("({rendered})")
    } else {
        rendered
    }
}

fn render_cmp(field: &str, cmp: Cmp) -> String {
    match cmp {
        Cmp::Ge(bound) => format!("{field} >= {bound}"),
        Cmp::Le(bound) => format!("{field} <= {bound}"),
    }
}

/// The `.rpol` field a community criterion set reads: all-standard →
/// `route.communities`, all-large → `route.large-communities`,
/// all-RT/RO → `route.ext-communities`, mixed → the generic
/// `route.communities`.
fn community_field(criteria: &[CommunityMatch]) -> &'static str {
    let mut fields = criteria.iter().map(|cm| match cm {
        CommunityMatch::Standard { .. } => "route.communities",
        CommunityMatch::LargeCommunity { .. } => "route.large-communities",
        CommunityMatch::RouteTarget { .. }
        | CommunityMatch::RouteOrigin { .. }
        | CommunityMatch::ExactExt(_) => "route.ext-communities",
    });
    let Some(first) = fields.next() else {
        return "route.communities";
    };
    if fields.all(|field| field == first) {
        first
    } else {
        "route.communities"
    }
}

fn set_label(names: &[Option<String>], id: u32, kind: &str) -> String {
    names
        .get(id as usize)
        .cloned()
        .flatten()
        .unwrap_or_else(|| format!("{kind}#{id}"))
}
