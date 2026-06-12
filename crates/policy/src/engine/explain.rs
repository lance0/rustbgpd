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
//! `med`, `next_hop`, `any`; modification labels add
//! `extended_community` / `large_community`). The detail portion is
//! human-oriented and not a machine-parsable grammar — consume the
//! structured indices and the leading label for automation, mirroring
//! the `vs_best_reason` / `vs_best_detail` split on the best-path
//! explain surface.

use std::fmt::Write as _;

use super::{
    CommunityMatch, IMPLICIT_LOCAL_PREF, IMPLICIT_MED, NextHopAction, PolicyAction, PolicyChain,
    PolicyStatement, RouteContext, RouteModifications, RouteType,
};

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
    pub modifications: Vec<String>,
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
