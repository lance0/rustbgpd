use rustbgpd_api::peer_types::{
    ValidationPolicyDimensionSnapshot, ValidationPolicyDisposition,
    ValidationPolicyPostureSnapshot, ValidationPolicyScopeSnapshot,
};
use rustbgpd_policy::PolicyChain;
use rustbgpd_policy::ir::{ValidationDimension, ValidationDisposition};

use super::PeerManager;

const MAX_SCOPES: usize = 4096;
const MAX_IR_VISITS: usize = 100_000;

impl PeerManager {
    pub(super) fn validation_policy_posture(&self) -> ValidationPolicyPostureSnapshot {
        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_unstable_by_key(|(key, _)| *key);
        let mut ranges: Vec<_> = self
            .current_config
            .dynamic_neighbors
            .iter()
            .map(|range| {
                (
                    (
                        crate::config::effective_prefix_str(&range.prefix),
                        range.peer_group.as_str(),
                        range.remote_asn,
                    ),
                    range,
                )
            })
            .collect();
        ranges.sort_unstable_by_key(|(key, _)| *key);

        let total = peers.len().saturating_add(ranges.len());
        let omitted = total.saturating_sub(MAX_SCOPES);
        let mut remaining = MAX_SCOPES;
        let mut visits = 0;
        let mut scopes = Vec::with_capacity(total.min(MAX_SCOPES));

        for (key, managed) in peers.into_iter().take(remaining) {
            scopes.push(scope_snapshot(
                format!("{key}"),
                if managed.is_dynamic {
                    "dynamic_peer"
                } else {
                    "static_peer"
                },
                managed.import_policy.as_ref(),
                &mut visits,
            ));
            remaining -= 1;
        }

        for ((canonical, _, _), range) in ranges.into_iter().take(remaining) {
            let Some((addr, prefix_len)) = canonical else {
                scopes.push(unknown_scope(
                    range.prefix.clone(),
                    "dynamic_range",
                    "resolution_ambiguous",
                ));
                continue;
            };
            let scope = format!("{addr}/{prefix_len}");
            let Some(group) = self.current_config.peer_groups.get(&range.peer_group) else {
                scopes.push(unknown_scope(scope, "dynamic_range", "resolution_failed"));
                continue;
            };
            match self.current_config.resolve_dynamic_neighbor(
                addr,
                range.remote_asn,
                range.description.as_deref().unwrap_or(&range.peer_group),
                group,
                &range.peer_group,
                self.current_config.rfc8212_external_asn(range.remote_asn),
            ) {
                Ok(resolved) => scopes.push(scope_snapshot(
                    scope,
                    "dynamic_range",
                    resolved.import_policy.as_ref(),
                    &mut visits,
                )),
                Err(_) => scopes.push(unknown_scope(scope, "dynamic_range", "resolution_failed")),
            }
        }

        let complete = omitted == 0;
        ValidationPolicyPostureSnapshot {
            rpki_invalid: aggregate(&scopes, complete, ValidationDimension::Rpki),
            aspa_invalid: aggregate(&scopes, complete, ValidationDimension::Aspa),
            scopes,
            complete,
            omitted: u32::try_from(omitted).unwrap_or(u32::MAX),
        }
    }
}

fn scope_snapshot(
    scope: String,
    kind: &'static str,
    chain: Option<&PolicyChain>,
    visits: &mut usize,
) -> ValidationPolicyScopeSnapshot {
    ValidationPolicyScopeSnapshot {
        scope,
        kind,
        rpki_invalid: analyze(chain, ValidationDimension::Rpki, visits),
        aspa_invalid: analyze(chain, ValidationDimension::Aspa, visits),
    }
}

fn analyze(
    chain: Option<&PolicyChain>,
    dimension: ValidationDimension,
    visits: &mut usize,
) -> ValidationPolicyDimensionSnapshot {
    let disposition = chain.map_or(ValidationDisposition::Unenforced, |chain| {
        chain
            .compiled()
            .invalid_validation_disposition(dimension, visits, MAX_IR_VISITS)
    });
    match disposition {
        ValidationDisposition::Enforced => dimension_snapshot(
            ValidationPolicyDisposition::Enforced,
            "invalid_route_denied",
        ),
        ValidationDisposition::Unenforced => dimension_snapshot(
            ValidationPolicyDisposition::Unenforced,
            if chain.is_some() {
                "invalid_route_permitted"
            } else {
                "no_import_policy"
            },
        ),
        ValidationDisposition::Unknown => {
            dimension_snapshot(ValidationPolicyDisposition::Unknown, "indeterminate_policy")
        }
    }
}

fn unknown_scope(
    scope: String,
    kind: &'static str,
    reason: &'static str,
) -> ValidationPolicyScopeSnapshot {
    let unknown = dimension_snapshot(ValidationPolicyDisposition::Unknown, reason);
    ValidationPolicyScopeSnapshot {
        scope,
        kind,
        rpki_invalid: unknown.clone(),
        aspa_invalid: unknown,
    }
}

fn dimension_snapshot(
    disposition: ValidationPolicyDisposition,
    reason: &'static str,
) -> ValidationPolicyDimensionSnapshot {
    ValidationPolicyDimensionSnapshot {
        disposition,
        reason,
    }
}

fn aggregate(
    scopes: &[ValidationPolicyScopeSnapshot],
    complete: bool,
    dimension: ValidationDimension,
) -> ValidationPolicyDimensionSnapshot {
    let rows = scopes.iter().map(|scope| match dimension {
        ValidationDimension::Rpki => &scope.rpki_invalid,
        ValidationDimension::Aspa => &scope.aspa_invalid,
    });
    let mut any = false;
    let mut all_enforced = true;
    for row in rows {
        any = true;
        if row.disposition == ValidationPolicyDisposition::Unenforced {
            return dimension_snapshot(ValidationPolicyDisposition::Unenforced, "scope_unenforced");
        }
        all_enforced &= row.disposition == ValidationPolicyDisposition::Enforced;
    }
    if complete && any && all_enforced {
        dimension_snapshot(ValidationPolicyDisposition::Enforced, "all_scopes_enforced")
    } else {
        dimension_snapshot(
            ValidationPolicyDisposition::Unknown,
            if complete {
                "scope_indeterminate"
            } else {
                "incomplete"
            },
        )
    }
}
