use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{
    PlannedGroupability, RibUpdate, UpdateGroupClassification, UpdateGroupClassifierInput,
    UpdateGroupFamilyImpact, UpdateGroupImpactPlan, UpdateGroupImpactRollup,
    UpdateGroupPeerSnapshot, UpdateGroupSnapshot, classify_update_group,
};
use tokio::sync::oneshot;

use super::{PeerManager, RIB_REPLY_TIMEOUT};
use crate::config::{Config, ResolvedNeighbor};

#[derive(Debug)]
pub(super) enum UpdateGroupImpactPlanError {
    InvalidCandidate(String),
    Internal(String),
}

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
        && same_families(&left.peer.families, &right.peer.families)
        && left.peer.add_path_send == right.peer.add_path_send
        && left.peer.add_path_receive == right.peer.add_path_receive
        && left.peer.graceful_restart == right.peer.graceful_restart
        && left.peer.gr_restart_time == right.peer.gr_restart_time
        && left.peer.prefix_orf_receive == right.peer.prefix_orf_receive
        && left.peer.disable_ipv4_unicast == right.peer.disable_ipv4_unicast
        && left.llgr_stale_time == right.llgr_stale_time
}

fn same_families<T: Eq>(left: &[T], right: &[T]) -> bool {
    left.iter().all(|family| right.contains(family))
        && right.iter().all(|family| left.contains(family))
}

fn candidate_input(
    live: &UpdateGroupPeerSnapshot,
    candidate: &ResolvedNeighbor,
    local_asn: u32,
) -> UpdateGroupClassifierInput {
    let policy = candidate.export_policy.as_ref();
    UpdateGroupClassifierInput {
        policy_fingerprint: policy.map(|chain| format!("{chain:?}")),
        policy_provenance: policy.map(|chain| chain.groupability_provenance().to_string()),
        policy_requires_peer_context: policy.is_some_and(PolicyChain::requires_peer_context),
        target_is_ebgp: candidate.transport_config.peer.remote_asn != local_asn,
        target_is_rr_client: candidate.transport_config.route_reflector_client,
        target_local_role: candidate
            .transport_config
            .peer
            .local_role
            .map(rustbgpd_wire::BgpRole::to_u8),
        sendable_families: live.input.sendable_families.clone(),
        llgr_families: live.input.llgr_families.clone(),
        add_path_send: live.input.add_path_send,
        per_client_best: candidate.transport_config.per_client_best,
        orr_vantage: candidate.transport_config.orr_vantage,
        orf_installed: live.input.orf_installed,
    }
}

fn raw_state(
    classification: &UpdateGroupClassification,
    private_fingerprint: &str,
) -> PlannedGroupability {
    match classification {
        UpdateGroupClassification::Groupable(input) => PlannedGroupability::Group {
            id: format!("raw:{input:?}"),
        },
        other => PlannedGroupability::Private {
            reason: other.reason().expect("fallback has a reason").to_string(),
            fingerprint: private_fingerprint.to_string(),
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

fn plan_local_ids(raw_groups: impl IntoIterator<Item = String>) -> BTreeMap<String, String> {
    raw_groups
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, raw)| (raw, format!("plan-group-{:03}", index + 1)))
        .collect()
}

fn transition(current: &PlannedGroupability, candidate: &PlannedGroupability) -> &'static str {
    use PlannedGroupability::{Absent, Group, Indeterminate, Private};
    match (current, candidate) {
        (Group { id: a }, Group { id: b }) if a == b => "no_op",
        (
            Private {
                reason: ar,
                fingerprint: af,
            },
            Private {
                reason: br,
                fingerprint: bf,
            },
        ) if ar == br && af == bf => "no_op",
        (Absent, Absent) => "no_op",
        // Deleting a never-established peer (Indeterminate -> Absent) is not a
        // regroup; the indeterminate arm below must win for that case.
        (Group { .. } | Private { .. }, Absent) | (Group { .. } | Absent, Group { .. }) => {
            "regroup"
        }
        (Private { .. }, Group { .. }) => "shared_migration",
        (_, Private { .. }) => "private_resync",
        (_, Indeterminate { .. }) | (Indeterminate { .. }, _) => "indeterminate",
    }
}

fn requires_local_resync(candidate: &PlannedGroupability, changed: bool) -> bool {
    changed
        && !matches!(
            candidate,
            PlannedGroupability::Indeterminate { .. } | PlannedGroupability::Absent
        )
}

fn projected_peer_count(entries: &[UpdateGroupFamilyImpact]) -> usize {
    entries
        .iter()
        .filter(|row| !matches!(row.candidate, PlannedGroupability::Absent))
        .map(|row| row.peer)
        .collect::<BTreeSet<_>>()
        .len()
}

fn capacity_class(
    projected_peers: usize,
    shared_groups: usize,
    private_views: usize,
    indeterminate: u32,
) -> (&'static str, &'static str) {
    if indeterminate > 0 {
        ("unknown", "future session negotiation is not projected")
    } else if projected_peers == 1_000 && private_views == 0 && shared_groups == 1 {
        (
            "within_uniform",
            "exact measured 1000-peer uniform topology",
        )
    } else if private_views == 0 && shared_groups == 1 {
        (
            "fully_shared",
            "structurally one shared group; no measured capacity claim",
        )
    } else if projected_peers == 1_000 && private_views == 100 && shared_groups == 1 {
        (
            "within_mixed",
            "inside the measured 900-shared/100-private envelope",
        )
    } else {
        (
            "outside_measured",
            "outside published update-group receipt envelopes",
        )
    }
}

impl PeerManager {
    pub(super) async fn query_update_group_snapshot(&self) -> Result<UpdateGroupSnapshot, String> {
        let (reply, recv) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryUpdateGroupSnapshot { reply })
            .await
            .map_err(|_| "RIB unavailable while planning update-group impact".to_string())?;
        tokio::time::timeout(RIB_REPLY_TIMEOUT, recv)
            .await
            .map_err(|_| "RIB update-group snapshot timed out".to_string())?
            .map_err(|_| "RIB dropped update-group snapshot reply".to_string())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keeps snapshot classification, canonical IDs, and rollup in one auditable pure planning pass"
    )]
    pub(super) fn plan_update_group_impact(
        &self,
        candidate: &Config,
        snapshot: UpdateGroupSnapshot,
    ) -> Result<UpdateGroupImpactPlan, UpdateGroupImpactPlanError> {
        let current =
            by_peer(&self.current_config).map_err(UpdateGroupImpactPlanError::Internal)?;
        let candidate = by_peer(candidate).map_err(UpdateGroupImpactPlanError::InvalidCandidate)?;
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
            let current_state = if current_cfg.is_none() {
                PlannedGroupability::Absent
            } else {
                live.map_or_else(
                    || PlannedGroupability::Indeterminate {
                        reason: "indeterminate_session_negotiation".to_string(),
                    },
                    |row| raw_state(&row.classification, &format!("{:?}", row.input)),
                )
            };
            let candidate_state = match (live, current_cfg, candidate_cfg) {
                (_, _, None) => PlannedGroupability::Absent,
                (Some(live), Some(current), Some(candidate))
                    if preserves_negotiation(current, candidate) =>
                {
                    let input = candidate_input(live, candidate, self.local_asn);
                    let fingerprint = format!("{input:?}");
                    raw_state(&classify_update_group(input), &fingerprint)
                }
                _ => PlannedGroupability::Indeterminate {
                    reason: "indeterminate_session_negotiation".to_string(),
                },
            };
            let provenance = match (&candidate_state, candidate_cfg) {
                (PlannedGroupability::Indeterminate { .. }, _) => "session_negotiation".to_string(),
                (_, Some(candidate)) => candidate
                    .export_policy
                    .as_ref()
                    .map_or("no_export_policy", PolicyChain::groupability_provenance)
                    .to_string(),
                _ => "session_negotiation".to_string(),
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
                    provenance.clone(),
                ));
            }
            if live.is_none() || rows.last().is_none_or(|row| row.0 != peer) {
                rows.push((peer, 0, 0, current_state, candidate_state, provenance));
            }
        }

        let ids = plan_local_ids(raw_groups);
        let mut entries = Vec::with_capacity(rows.len());
        let mut rollup = UpdateGroupImpactRollup::default();
        let mut affected = BTreeSet::new();
        for (peer, afi, safi, current, candidate, provenance) in rows {
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
            let local_resync = requires_local_resync(&candidate, changed);
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
                provenance,
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
        let projected_peers = projected_peer_count(&entries);
        let (capacity_class, capacity_basis) = capacity_class(
            projected_peers,
            candidate_groups.len(),
            candidate_private.len(),
            rollup.indeterminate,
        );
        Ok(UpdateGroupImpactPlan {
            schema_version: 1,
            entries,
            rollup,
            capacity_class: capacity_class.to_string(),
            capacity_basis: capacity_basis.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_fixture() -> UpdateGroupSnapshot {
        let input = UpdateGroupClassifierInput {
            policy_fingerprint: Some("policy-a".to_string()),
            policy_provenance: Some("toml_compiled_ir".to_string()),
            policy_requires_peer_context: false,
            target_is_ebgp: true,
            target_is_rr_client: false,
            target_local_role: None,
            sendable_families: vec![(1, 1)],
            llgr_families: vec![],
            add_path_send: false,
            per_client_best: false,
            orr_vantage: None,
            orf_installed: false,
        };
        UpdateGroupSnapshot {
            peers: vec![UpdateGroupPeerSnapshot {
                peer: "192.0.2.1".parse().unwrap(),
                classification: classify_update_group(input.clone()),
                input,
                runtime_membership: "group:1".to_string(),
            }],
        }
    }

    #[test]
    fn snapshot_identity_is_fixed_width_deterministic_and_state_sensitive() {
        let key = crate::config::RuntimeSnapshotKey::random();
        let snapshot = snapshot_fixture();
        assert_eq!(key.digest_context(&snapshot).len(), 8);
        assert_eq!(key.digest_context(&snapshot), key.digest_context(&snapshot));

        let mut changed = snapshot;
        changed.peers[0].runtime_membership = "private:orf_installed".to_string();
        assert_ne!(
            key.digest_context(&changed),
            key.digest_context(&snapshot_fixture())
        );
    }

    #[test]
    fn transitions_keep_resync_and_indeterminate_distinct() {
        let shared_a = PlannedGroupability::Group {
            id: "plan-group-001".to_string(),
        };
        let shared_b = PlannedGroupability::Group {
            id: "plan-group-002".to_string(),
        };
        let private = PlannedGroupability::Private {
            reason: "policy_peer_context".to_string(),
            fingerprint: "policy-a".to_string(),
        };
        let unknown = PlannedGroupability::Indeterminate {
            reason: "indeterminate_session_negotiation".to_string(),
        };
        assert_eq!(transition(&shared_a, &shared_a), "no_op");
        assert_eq!(transition(&shared_a, &shared_b), "regroup");
        assert_eq!(transition(&private, &shared_a), "shared_migration");
        assert_eq!(transition(&shared_a, &private), "private_resync");
        assert_eq!(transition(&shared_a, &unknown), "indeterminate");
        let changed_private = PlannedGroupability::Private {
            reason: "policy_peer_context".to_string(),
            fingerprint: "policy-b".to_string(),
        };
        assert_eq!(transition(&private, &changed_private), "private_resync");
        assert_eq!(
            transition(&shared_a, &PlannedGroupability::Absent),
            "regroup"
        );
        assert_eq!(
            transition(&PlannedGroupability::Absent, &unknown),
            "indeterminate"
        );
        // Deleting a never-established peer must not count as a regroup.
        assert_eq!(
            transition(&unknown, &PlannedGroupability::Absent),
            "indeterminate"
        );
    }

    #[test]
    fn negotiation_family_comparison_is_order_and_duplicate_independent() {
        assert!(same_families(&[(1, 1), (2, 1), (1, 1)], &[(2, 1), (1, 1)]));
        assert!(!same_families(&[(1, 1)], &[(1, 1), (2, 1)]));
    }

    #[test]
    fn deletion_is_not_a_projected_peer_or_local_resync() {
        let deleted = PlannedGroupability::Absent;
        assert_eq!(
            transition(
                &PlannedGroupability::Group {
                    id: "plan-group-001".to_string()
                },
                &deleted
            ),
            "regroup"
        );
        assert!(!requires_local_resync(&deleted, true));

        let entries = [UpdateGroupFamilyImpact {
            peer: "192.0.2.1".parse().unwrap(),
            afi: 1,
            safi: 1,
            current: PlannedGroupability::Group {
                id: "plan-group-001".to_string(),
            },
            candidate: deleted,
            transition: "regroup".to_string(),
            reason: "absent".to_string(),
            provenance: "session_negotiation".to_string(),
            local_resync: false,
            remote_route_refresh: false,
        }];
        assert_eq!(projected_peer_count(&entries), 0);
    }

    #[test]
    fn plan_local_group_ids_are_not_runtime_ids() {
        let raw = PlannedGroupability::Group {
            id: "raw:fingerprint".to_string(),
        };
        let ids = BTreeMap::from([("raw:fingerprint".to_string(), "plan-group-001".to_string())]);
        assert_eq!(
            canonicalize_group(raw, &ids),
            PlannedGroupability::Group {
                id: "plan-group-001".to_string()
            }
        );
    }

    #[test]
    fn plan_local_ids_are_insertion_order_independent() {
        let forward = plan_local_ids([
            "raw:c".to_string(),
            "raw:a".to_string(),
            "raw:b".to_string(),
        ]);
        let reverse = plan_local_ids([
            "raw:b".to_string(),
            "raw:a".to_string(),
            "raw:c".to_string(),
        ]);
        assert_eq!(forward, reverse);
        assert_eq!(forward["raw:a"], "plan-group-001");
    }

    #[test]
    fn uniform_and_mixed_fleet_capacity_goldens() {
        assert_eq!(capacity_class(1_000, 1, 0, 0).0, "within_uniform");
        assert_eq!(capacity_class(1_000, 2, 0, 0).0, "outside_measured");
        assert_eq!(capacity_class(1_000, 1, 100, 0).0, "within_mixed");
        assert_eq!(capacity_class(1_000, 1, 101, 0).0, "outside_measured");
        assert_eq!(capacity_class(10, 1, 0, 0).0, "fully_shared");
        assert_eq!(capacity_class(10, 1, 0, 1).0, "unknown");
    }

    #[test]
    fn classifier_transition_matrix_covers_planner_states() {
        fn fixture(policy: &str) -> UpdateGroupClassifierInput {
            UpdateGroupClassifierInput {
                policy_fingerprint: Some(policy.to_string()),
                policy_provenance: Some("toml_compiled_ir".to_string()),
                policy_requires_peer_context: false,
                target_is_ebgp: false,
                target_is_rr_client: true,
                target_local_role: None,
                sendable_families: vec![(1, 1)],
                llgr_families: vec![],
                add_path_send: false,
                per_client_best: false,
                orr_vantage: None,
                orf_installed: false,
            }
        }
        let shared_a = fixture("a");
        let shared_b = fixture("b");
        let mut private_peer = fixture("peer");
        private_peer.policy_requires_peer_context = true;
        let mut private_orf = fixture("orf");
        private_orf.orf_installed = true;
        let mut orr_a = fixture("orr");
        orr_a.orr_vantage = Some("192.0.2.10".parse().unwrap());
        let mut orr_b = orr_a.clone();
        orr_b.orr_vantage = Some("192.0.2.11".parse().unwrap());
        let mut rtc = fixture("rtc");
        rtc.sendable_families = vec![(1, 128), (1, 132)];
        let cases = [
            (
                "shared_to_shared",
                shared_a.clone(),
                shared_b.clone(),
                "regroup",
            ),
            (
                "shared_to_private",
                shared_a.clone(),
                private_peer.clone(),
                "private_resync",
            ),
            (
                "private_to_shared",
                private_peer.clone(),
                shared_a.clone(),
                "shared_migration",
            ),
            (
                "private_to_private",
                private_peer.clone(),
                private_orf,
                "private_resync",
            ),
            (
                "same_reason_orr_vantage_change",
                orr_a,
                orr_b,
                "private_resync",
            ),
            (
                "content_identical_reinstall",
                shared_a.clone(),
                shared_a.clone(),
                "no_op",
            ),
            ("rtc_membership_stable", rtc.clone(), rtc, "no_op"),
        ];
        for (name, current_input, candidate_input, expected) in cases {
            let current_fingerprint = format!("{current_input:?}");
            let candidate_fingerprint = format!("{candidate_input:?}");
            let current = raw_state(&classify_update_group(current_input), &current_fingerprint);
            let planned = raw_state(
                &classify_update_group(candidate_input),
                &candidate_fingerprint,
            );
            assert_eq!(transition(&current, &planned), expected, "plan {name}");
        }
    }
}
