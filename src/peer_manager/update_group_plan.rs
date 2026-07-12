use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{
    PlannedGroupability, RibUpdate, UpdateGroupClassification, UpdateGroupClassifierInput,
    UpdateGroupFamilyImpact, UpdateGroupImpactPlan, UpdateGroupImpactRollup,
    UpdateGroupPeerSnapshot, classify_update_group,
};
use tokio::sync::oneshot;

use super::{PeerManager, RIB_REPLY_TIMEOUT};
use crate::config::{Config, ResolvedNeighbor};

fn by_peer(config: &Config) -> Result<BTreeMap<IpAddr, ResolvedNeighbor>, String> {
    config
        .resolved_neighbors()
        .map_err(|error| error.to_string())
        .map(|rows| {
            rows.into_iter()
                .map(|row| (row.transport_config.remote_addr.ip(), row))
                .collect()
        })
}

fn preserves_negotiation(current: &ResolvedNeighbor, candidate: &ResolvedNeighbor) -> bool {
    let left = &current.transport_config;
    let right = &candidate.transport_config;
    left.peer.remote_asn == right.peer.remote_asn
        && left.peer.families == right.peer.families
        && left.peer.add_path_send == right.peer.add_path_send
        && left.peer.add_path_receive == right.peer.add_path_receive
        && left.peer.graceful_restart == right.peer.graceful_restart
        && left.peer.gr_restart_time == right.peer.gr_restart_time
        && left.peer.prefix_orf_receive == right.peer.prefix_orf_receive
        && left.peer.disable_ipv4_unicast == right.peer.disable_ipv4_unicast
        && left.llgr_stale_time == right.llgr_stale_time
        && left.route_reflector_client == right.route_reflector_client
        && left.orr_vantage == right.orr_vantage
        && left.per_client_best == right.per_client_best
}

fn candidate_input(
    live: &UpdateGroupPeerSnapshot,
    candidate: &ResolvedNeighbor,
    local_asn: u32,
) -> UpdateGroupClassifierInput {
    let policy = candidate.export_policy.as_ref();
    UpdateGroupClassifierInput {
        policy_fingerprint: policy.map(|chain| format!("{chain:?}")),
        policy_requires_peer_context: policy.is_some_and(PolicyChain::requires_peer_context),
        target_is_ebgp: candidate.transport_config.peer.remote_asn != local_asn,
        target_is_rr_client: candidate.transport_config.route_reflector_client,
        sendable_families: live.input.sendable_families.clone(),
        llgr_families: live.input.llgr_families.clone(),
        add_path_send: live.input.add_path_send,
        per_client_best: candidate.transport_config.per_client_best,
        orr_vantage: candidate.transport_config.orr_vantage.is_some(),
        orf_installed: live.input.orf_installed,
    }
}

fn raw_state(classification: &UpdateGroupClassification) -> PlannedGroupability {
    match classification {
        UpdateGroupClassification::Groupable(input) => PlannedGroupability::Group {
            id: format!("raw:{input:?}"),
        },
        other => PlannedGroupability::Private {
            reason: other.reason().expect("fallback has a reason").to_string(),
        },
    }
}

fn canonicalize_group(
    state: PlannedGroupability,
    ids: &BTreeMap<String, String>,
) -> PlannedGroupability {
    match state {
        PlannedGroupability::Group { id } => PlannedGroupability::Group {
            id: ids.get(&id).expect("collected group fingerprint").clone(),
        },
        other => other,
    }
}

fn transition(current: &PlannedGroupability, candidate: &PlannedGroupability) -> &'static str {
    use PlannedGroupability::{Absent, Group, Indeterminate, Private};
    match (current, candidate) {
        (Group { id: a }, Group { id: b }) if a == b => "no_op",
        (Private { reason: a }, Private { reason: b }) if a == b => "no_op",
        (Absent, Absent) => "no_op",
        (Group { .. }, Group { .. }) | (_, Absent) | (Absent, Group { .. }) => "regroup",
        (Private { .. }, Group { .. }) => "shared_migration",
        (_, Private { .. }) => "private_resync",
        (_, Indeterminate { .. }) | (Indeterminate { .. }, _) => "indeterminate",
    }
}

impl PeerManager {
    #[expect(
        clippy::too_many_lines,
        reason = "keeps snapshot classification, canonical IDs, and rollup in one auditable pure planning pass"
    )]
    pub(super) async fn plan_update_group_impact(
        &self,
        candidate: &Config,
    ) -> Result<UpdateGroupImpactPlan, String> {
        let (reply, recv) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryUpdateGroupSnapshot { reply })
            .await
            .map_err(|_| "RIB unavailable while planning update-group impact".to_string())?;
        let snapshot = tokio::time::timeout(RIB_REPLY_TIMEOUT, recv)
            .await
            .map_err(|_| "RIB update-group snapshot timed out".to_string())?
            .map_err(|_| "RIB dropped update-group snapshot reply".to_string())?;

        let current = by_peer(&self.current_config)?;
        let candidate = by_peer(candidate)?;
        let live = snapshot
            .peers
            .into_iter()
            .map(|row| (row.peer, row))
            .collect::<BTreeMap<_, _>>();
        let peers = current
            .keys()
            .chain(candidate.keys())
            .copied()
            .collect::<BTreeSet<_>>();

        let mut rows = Vec::new();
        let mut raw_groups = BTreeSet::new();
        for peer in peers {
            let current_cfg = current.get(&peer);
            let candidate_cfg = candidate.get(&peer);
            let live = live.get(&peer);
            let current_state = live.map_or_else(
                || PlannedGroupability::Indeterminate {
                    reason: "indeterminate_session_negotiation".to_string(),
                },
                |row| raw_state(&row.classification),
            );
            let candidate_state = match (live, current_cfg, candidate_cfg) {
                (Some(live), Some(current), Some(candidate))
                    if preserves_negotiation(current, candidate) =>
                {
                    raw_state(&classify_update_group(candidate_input(
                        live,
                        candidate,
                        self.local_asn,
                    )))
                }
                _ => PlannedGroupability::Indeterminate {
                    reason: "indeterminate_session_negotiation".to_string(),
                },
            };
            for state in [&current_state, &candidate_state] {
                if let PlannedGroupability::Group { id } = state {
                    raw_groups.insert(id.clone());
                }
            }
            let families = live.map_or_else(BTreeSet::new, |row| {
                row.input.sendable_families.iter().copied().collect()
            });
            for (afi, safi) in families {
                rows.push((
                    peer,
                    afi,
                    safi,
                    current_state.clone(),
                    candidate_state.clone(),
                ));
            }
            if live.is_none() || rows.last().is_none_or(|row| row.0 != peer) {
                rows.push((peer, 0, 0, current_state, candidate_state));
            }
        }

        let ids = raw_groups
            .into_iter()
            .enumerate()
            .map(|(index, raw)| (raw, format!("plan-group-{:03}", index + 1)))
            .collect::<BTreeMap<_, _>>();
        let mut entries = Vec::with_capacity(rows.len());
        let mut rollup = UpdateGroupImpactRollup::default();
        let mut affected = BTreeSet::new();
        for (peer, afi, safi, current, candidate) in rows {
            let current = canonicalize_group(current, &ids);
            let candidate = canonicalize_group(candidate, &ids);
            let class = transition(&current, &candidate).to_string();
            let changed = class != "no_op";
            if changed {
                affected.insert(peer);
                rollup.affected_families += 1;
            }
            match class.as_str() {
                "no_op" => rollup.no_op += 1,
                "regroup" => rollup.regroup += 1,
                "shared_migration" => rollup.shared_migration += 1,
                "private_resync" => rollup.private_resync += 1,
                _ => rollup.indeterminate += 1,
            }
            let local_resync =
                changed && !matches!(candidate, PlannedGroupability::Indeterminate { .. });
            if local_resync {
                rollup.local_resyncs += 1;
            }
            let reason = match &candidate {
                PlannedGroupability::Group { .. } => "groupable".to_string(),
                other => other.label(),
            };
            entries.push(UpdateGroupFamilyImpact {
                peer,
                afi,
                safi,
                current,
                candidate,
                transition: class,
                reason,
                provenance: "runtime_groupability_classifier".to_string(),
                local_resync,
                remote_route_refresh: false,
            });
        }
        rollup.affected_peers = u32::try_from(affected.len()).unwrap_or(u32::MAX);
        let candidate_groups = entries
            .iter()
            .filter_map(|row| match &row.candidate {
                PlannedGroupability::Group { id } => Some(id),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let candidate_private = entries
            .iter()
            .filter_map(|row| {
                matches!(row.candidate, PlannedGroupability::Private { .. }).then_some(row.peer)
            })
            .collect::<BTreeSet<_>>();
        rollup.projected_shared_groups = u32::try_from(candidate_groups.len()).unwrap_or(u32::MAX);
        rollup.projected_private_views = u32::try_from(candidate_private.len()).unwrap_or(u32::MAX);
        let projected_peers = entries
            .iter()
            .map(|row| row.peer)
            .collect::<BTreeSet<_>>()
            .len();
        let (capacity_class, capacity_basis) = if rollup.indeterminate > 0 {
            ("unknown", "future session negotiation is not projected")
        } else if candidate_private.is_empty() && candidate_groups.len() == 1 {
            ("fully_shared", "one shared group and no private views")
        } else if candidate_private.is_empty() && projected_peers <= 1_000 {
            (
                "within_uniform",
                "inside the measured 1000-peer uniform envelope",
            )
        } else if candidate_private.len() <= 100 && projected_peers <= 1_000 {
            (
                "within_mixed",
                "inside the measured 900-shared/100-private envelope",
            )
        } else {
            (
                "outside_measured",
                "outside published update-group receipt envelopes",
            )
        };
        Ok(UpdateGroupImpactPlan {
            schema_version: 1,
            entries,
            rollup,
            capacity_class: capacity_class.to_string(),
            capacity_basis: capacity_basis.to_string(),
        })
    }
}
