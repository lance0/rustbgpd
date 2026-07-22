use super::{
    Afi, ControlFlow, Event, Message, NotificationCode, PeerCommand, PeerSession, PeerSessionState,
    RibUpdate, RouteRefreshMessage, Safi, SessionNotificationDirection, SessionState,
    cease_subcode, debug, info, warn,
};
use crate::handle::{MaxPrefixState, PeerCommandError, WarmCheckpointSessionState};

struct TcpAoSessionAddOnlyPlan {
    connected_peer: std::net::IpAddr,
    owners: Vec<crate::TcpAoRotationOwner>,
    desired_metadata: Vec<super::TcpAoKeyMetadata>,
}

struct TcpAoSessionSelectionPlan {
    connected_peer: std::net::IpAddr,
    owners: Vec<crate::TcpAoRotationOwner>,
    selected_owner: crate::listener::TcpAoSelectedOwner,
    staged_active_keyring: Option<crate::TcpAoKeyring>,
    staged_metadata: Vec<super::TcpAoKeyMetadata>,
    final_metadata: Vec<super::TcpAoKeyMetadata>,
    selection_changed: bool,
}

struct TcpAoSessionDeletePlan {
    connected_peer: std::net::IpAddr,
    current_owners: Vec<crate::TcpAoRotationOwner>,
    desired_owners: Vec<crate::TcpAoRotationOwner>,
    desired_active_keyring: Option<crate::TcpAoKeyring>,
    desired_metadata: Vec<super::TcpAoKeyMetadata>,
    already_applied: bool,
    deletion_changed: bool,
}

fn tcp_ao_owner_views(
    owners: &[crate::TcpAoRotationOwner],
) -> Vec<crate::socket_opts::TcpAoMktOwner<'_>> {
    owners
        .iter()
        .map(|owner| crate::socket_opts::TcpAoMktOwner {
            owner: owner.owner,
            peer: owner.peer,
            prefix_len: owner.prefix_len,
            keyring: &owner.keyring,
        })
        .collect()
}

fn current_tcp_ao_owner_keyrings(
    owners: &[crate::TcpAoRotationOwner],
    current: &[super::TcpAoKeyMetadata],
) -> Result<Vec<crate::TcpAoRotationOwner>, PeerCommandError> {
    let mut matched = vec![false; current.len()];
    let mut current_owners = Vec::new();
    for owner in owners {
        let configs = owner
            .keyring
            .iter()
            .filter(|config| {
                let desired_matches = current
                    .iter()
                    .enumerate()
                    .filter(|(index, metadata)| {
                        !matched[*index]
                            && metadata.peer == owner.peer
                            && metadata.prefix_len == owner.prefix_len
                            && metadata.send_id == config.send_id
                            && metadata.recv_id == config.recv_id
                            && metadata.algorithm == config.algorithm
                    })
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                if desired_matches.len() == 1 {
                    matched[desired_matches[0]] = true;
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        if !configs.is_empty() {
            current_owners.push(crate::TcpAoRotationOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: crate::TcpAoKeyring(configs),
            });
        }
    }
    if matched.iter().any(|matched| !matched) {
        return Err(PeerCommandError::CommandFailed(
            "TCP-AO current session inventory is not uniquely represented by the desired owner union"
                .to_string(),
        ));
    }
    Ok(current_owners)
}

fn tcp_ao_key_core_eq(left: &crate::TcpAoConfig, right: &crate::TcpAoConfig) -> bool {
    left.key == right.key
        && left.send_id == right.send_id
        && left.recv_id == right.recv_id
        && left.algorithm == right.algorithm
}

fn metadata_for_owners(owners: &[crate::TcpAoRotationOwner]) -> Vec<super::TcpAoKeyMetadata> {
    owners
        .iter()
        .flat_map(|owner| {
            owner.keyring.iter().map(|key| super::TcpAoKeyMetadata {
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                send_id: key.send_id,
                recv_id: key.recv_id,
                algorithm: key.algorithm,
                preferred: key.preferred,
                deprecated: key.deprecated,
            })
        })
        .collect()
}

fn tcp_ao_deletion_survivors(
    current: &crate::TcpAoKeyring,
    desired: &crate::TcpAoKeyring,
) -> Result<Vec<usize>, PeerCommandError> {
    if desired.0.is_empty() || desired.0.len() > current.0.len() {
        return Err(PeerCommandError::CommandFailed(
            "TCP-AO deletion requires a nonempty survivor keyring".to_string(),
        ));
    }
    let mut survivors = Vec::with_capacity(desired.0.len());
    let mut search_from = 0;
    for desired_key in &desired.0 {
        let matches = current
            .0
            .iter()
            .enumerate()
            .skip(search_from)
            .filter(|(_, current_key)| *current_key == desired_key)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion reorders, redefines, duplicates, or adds an MKT".to_string(),
            ));
        }
        survivors.push(matches[0]);
        search_from = matches[0] + 1;
    }
    if current.selected() != desired.selected() {
        return Err(PeerCommandError::CommandFailed(
            "TCP-AO deletion may not remove or change the selected MKT".to_string(),
        ));
    }
    if current
        .0
        .iter()
        .enumerate()
        .any(|(index, key)| !survivors.contains(&index) && !key.deprecated)
    {
        return Err(PeerCommandError::CommandFailed(
            "TCP-AO deletion may remove only deprecated MKTs".to_string(),
        ));
    }
    Ok(survivors)
}

fn sorted_family_limits<T>(
    limits: impl Iterator<Item = ((Afi, Safi), T)>,
) -> Vec<((Afi, Safi), T)> {
    let mut limits: Vec<_> = limits.collect();
    limits.sort_by_key(|((afi, safi), _)| (*afi as u16, *safi as u8));
    limits
}

fn remaining_prefix_headroom(limit: Option<u32>, count: usize) -> Option<u32> {
    limit.map(|limit| limit.saturating_sub(u32::try_from(count).unwrap_or(u32::MAX)))
}

impl PeerSession {
    #[expect(
        clippy::too_many_lines,
        reason = "selection validation keeps exact owner, inventory, and staged-metadata checks together"
    )]
    fn prepare_tcp_ao_selection(
        &self,
        desired: &crate::config::TcpAoSessionSelection,
    ) -> Result<TcpAoSessionSelectionPlan, PeerCommandError> {
        if !self.tcp_ao_protected {
            return Err(PeerCommandError::CommandFailed(
                "refusing TCP-AO selection on an unprotected session".to_string(),
            ));
        }
        if self.connect_task.is_some() {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO selection cannot advance while an older selection connect attempt is in flight; retry the identical generation"
                    .to_string(),
            ));
        }
        if self.tcp_ao_generation.next() != Some(desired.generation)
            && self.tcp_ao_generation != desired.generation
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO selection generation is not the immediate applied successor".to_string(),
            ));
        }
        if self
            .tcp_ao_pending_selection
            .as_ref()
            .is_some_and(|retained| retained != desired)
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO selection retry changed its immutable session candidate".to_string(),
            ));
        }

        let connected_peer = self.config.remote_addr.ip();
        let connected_prefix = if connected_peer.is_ipv4() { 32 } else { 128 };
        let (owners, selected_owner) = if self.tcp_ao_accept_only_session {
            let selected_owner = desired.accepted_selected_owner.ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "accepted TCP-AO selection lacks an explicit selected owner".to_string(),
                )
            })?;
            if self.tcp_ao_stream_was_accepted && self.tcp_ao_selected_owner != Some(selected_owner)
            {
                return Err(PeerCommandError::CommandFailed(
                    "accepted TCP-AO selection changed the explicit selected owner".to_string(),
                ));
            }
            (desired.accepted_owners.to_vec(), selected_owner)
        } else {
            let keyring = desired.active_keyring.clone().ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "active TCP-AO selection lacks its exact static keyring".to_string(),
                )
            })?;
            (
                vec![crate::TcpAoRotationOwner {
                    owner: crate::TcpAoListenerOwnerKind::Static,
                    peer: connected_peer,
                    prefix_len: connected_prefix,
                    keyring,
                }],
                crate::listener::TcpAoSelectedOwner {
                    owner: crate::TcpAoListenerOwnerKind::Static,
                    peer: connected_peer,
                    prefix_len: connected_prefix,
                },
            )
        };
        let selected_matches = owners
            .iter()
            .filter(|owner| {
                owner.owner == selected_owner.owner
                    && owner.peer == selected_owner.peer
                    && owner.prefix_len == selected_owner.prefix_len
            })
            .count();
        if selected_matches != 1 {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO explicit selected owner is not unique in the complete owner union"
                    .to_string(),
            ));
        }
        let desired_selected_key = owners
            .iter()
            .find(|owner| {
                owner.owner == selected_owner.owner
                    && owner.peer == selected_owner.peer
                    && owner.prefix_len == selected_owner.prefix_len
            })
            .and_then(|owner| owner.keyring.selected())
            .expect("unique selected owner was validated");
        let current_selected_key = self
            .config
            .tcp_ao
            .as_ref()
            .and_then(crate::TcpAoKeyring::selected)
            .ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "TCP-AO session lacks its current selected-owner keyring".to_string(),
                )
            })?;
        let selection_changed = !tcp_ao_key_core_eq(current_selected_key, desired_selected_key);

        let final_metadata = metadata_for_owners(&owners);
        if self.read_half.is_some() && final_metadata.len() != self.tcp_ao_key_metadata.len() {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO selection may not add or remove an installed MKT".to_string(),
            ));
        }
        let mut staged_metadata = final_metadata.clone();
        for staged in &mut staged_metadata {
            let matches = self
                .tcp_ao_key_metadata
                .iter()
                .filter(|current| {
                    current.peer == staged.peer
                        && current.prefix_len == staged.prefix_len
                        && current.send_id == staged.send_id
                        && current.recv_id == staged.recv_id
                        && current.algorithm == staged.algorithm
                })
                .collect::<Vec<_>>();
            if self.read_half.is_some() && matches.len() != 1 {
                return Err(PeerCommandError::CommandFailed(
                    "TCP-AO selection inventory is not an exact unchanged owner union".to_string(),
                ));
            }
            if let Some(current) = matches.first() {
                if current.deprecated && !staged.deprecated {
                    return Err(PeerCommandError::CommandFailed(
                        "TCP-AO selection may not undeprecate an MKT".to_string(),
                    ));
                }
                // Deprecation is the final metadata-only substep. Selection
                // stages only preferred metadata until peer use is observed.
                staged.deprecated = current.deprecated;
            }
        }

        let staged_active_keyring = match desired.active_keyring.as_ref() {
            Some(desired_ring) => {
                let current_ring = self.config.tcp_ao.as_ref().ok_or_else(|| {
                    PeerCommandError::CommandFailed(
                        "active TCP-AO selection lacks its current exact keyring".to_string(),
                    )
                })?;
                if current_ring.0.len() != desired_ring.0.len()
                    || !current_ring
                        .0
                        .iter()
                        .zip(&desired_ring.0)
                        .all(|(current, desired)| tcp_ao_key_core_eq(current, desired))
                {
                    return Err(PeerCommandError::CommandFailed(
                        "active TCP-AO selection may not add, remove, reorder, or redefine an MKT"
                            .to_string(),
                    ));
                }
                let mut staged = desired_ring.clone();
                for (key, current) in staged.0.iter_mut().zip(&current_ring.0) {
                    if current.deprecated && !key.deprecated {
                        return Err(PeerCommandError::CommandFailed(
                            "TCP-AO selection may not undeprecate an MKT".to_string(),
                        ));
                    }
                    key.deprecated = current.deprecated;
                }
                Some(staged)
            }
            None => None,
        };

        Ok(TcpAoSessionSelectionPlan {
            connected_peer,
            owners,
            selected_owner,
            staged_active_keyring,
            staged_metadata,
            final_metadata,
            selection_changed,
        })
    }

    fn preflight_tcp_ao_selection(
        &self,
        desired: &crate::config::TcpAoSessionSelection,
    ) -> Result<(), PeerCommandError> {
        let plan = self.prepare_tcp_ao_selection(desired)?;
        let Some(stream) = self.read_half.as_ref() else {
            return Ok(());
        };
        let owners = tcp_ao_owner_views(&plan.owners);
        crate::socket_opts::preflight_tcp_ao_rnext(
            stream.as_ref(),
            &owners,
            plan.selected_owner,
            plan.connected_peer,
        )
        .map(drop)
        .map_err(|error| {
            PeerCommandError::CommandFailed(format!(
                "failed to preflight exact TCP-AO selection inventory: {error}"
            ))
        })
    }

    fn apply_tcp_ao_selection(
        &mut self,
        desired: crate::config::TcpAoSessionSelection,
    ) -> Result<(), PeerCommandError> {
        let plan = self.prepare_tcp_ao_selection(&desired)?;
        if self.tcp_ao_pending_selection.as_ref() == Some(&desired)
            && (self.read_half.is_none() || self.tcp_ao_successor_pkt_good_baseline.is_some())
        {
            return Ok(());
        }
        if let Some(stream) = self.read_half.as_ref() {
            let owners = tcp_ao_owner_views(&plan.owners);
            let preflight = crate::socket_opts::preflight_tcp_ao_rnext(
                stream.as_ref(),
                &owners,
                plan.selected_owner,
                plan.connected_peer,
            )
            .map_err(|error| {
                PeerCommandError::CommandFailed(format!(
                    "failed to preflight exact TCP-AO selection inventory: {error}"
                ))
            })?;
            let applied = crate::socket_opts::apply_tcp_ao_rnext(
                stream.as_ref(),
                &preflight,
                plan.selected_owner,
                plan.connected_peer,
            )
            .map_err(|error| {
                let mutation_started = error.mutation_started();
                let message = format!(
                    "failed to select TCP-AO successor RNext: {}",
                    error.into_inner()
                );
                if mutation_started {
                    PeerCommandError::TcpAoMutationFailed(message)
                } else {
                    PeerCommandError::CommandFailed(message)
                }
            });
            match applied {
                Ok(applied) => {
                    self.tcp_ao_info = Some(applied.snapshot);
                    self.tcp_ao_successor_pkt_good_baseline =
                        Some(applied.successor_pkt_good_baseline);
                }
                Err(error @ PeerCommandError::TcpAoMutationFailed(_)) => {
                    self.close_tcp();
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        } else {
            self.tcp_ao_successor_pkt_good_baseline = None;
        }
        self.tcp_ao_key_metadata = plan.staged_metadata;
        if plan.staged_active_keyring.is_some() {
            self.config.tcp_ao = plan.staged_active_keyring;
        }
        self.tcp_ao_pending_selection = Some(desired);
        self.tcp_ao_selection_observed = false;
        Ok(())
    }

    fn observe_tcp_ao_selection(
        &mut self,
        desired: &crate::config::TcpAoSessionSelection,
    ) -> Result<(), PeerCommandError> {
        if self.tcp_ao_pending_selection.as_ref() != Some(desired) {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO successor observation lacks its identical retained selection".to_string(),
            ));
        }
        let plan = self.prepare_tcp_ao_selection(desired)?;
        let Some(stream) = self.read_half.as_ref() else {
            return Err(PeerCommandError::TcpAoAwaitingPeer(
                "TCP-AO successor observation is awaiting a protected connected socket".to_string(),
            ));
        };
        let owners = tcp_ao_owner_views(&plan.owners);
        match crate::socket_opts::observe_tcp_ao_successor(
            stream.as_ref(),
            &owners,
            plan.selected_owner,
            plan.connected_peer,
            self.tcp_ao_successor_pkt_good_baseline.ok_or_else(|| {
                PeerCommandError::TcpAoAwaitingPeer(
                    "TCP-AO successor observation is awaiting a generation-relative baseline"
                        .to_string(),
                )
            })?,
        ) {
            Ok(snapshot) => {
                self.tcp_ao_info = Some(snapshot);
                self.tcp_ao_selection_observed = true;
                Ok(())
            }
            Err(crate::socket_opts::TcpAoSuccessorObservationError::AwaitingPeer(error)) => {
                Err(PeerCommandError::TcpAoAwaitingPeer(error))
            }
            Err(crate::socket_opts::TcpAoSuccessorObservationError::Failed(error)) => {
                Err(PeerCommandError::CommandFailed(format!(
                    "failed TCP-AO successor observation: {error}"
                )))
            }
        }
    }

    fn commit_tcp_ao_selection(
        &mut self,
        desired: &crate::config::TcpAoSessionSelection,
    ) -> Result<(), PeerCommandError> {
        let observed_selection = self.tcp_ao_pending_selection.as_ref() == Some(desired)
            && self.tcp_ao_selection_observed;
        let plan = self.prepare_tcp_ao_selection(desired)?;
        if (!observed_selection && self.tcp_ao_pending_selection.is_some())
            || (self.tcp_ao_pending_selection.is_none() && plan.selection_changed)
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO selection metadata commit lacks cohort observation proof".to_string(),
            ));
        }
        self.tcp_ao_key_metadata = plan.final_metadata;
        if desired.active_keyring.is_some() {
            self.config.tcp_ao.clone_from(&desired.active_keyring);
        }
        self.tcp_ao_generation = desired.generation;
        self.tcp_ao_pending_selection = None;
        self.tcp_ao_successor_pkt_good_baseline = None;
        self.tcp_ao_selection_observed = false;
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "deletion validation keeps the exact generation, owner union, survivor, and selected-owner proof together"
    )]
    fn prepare_tcp_ao_delete(
        &self,
        deletion: &crate::TcpAoSessionDeletion,
    ) -> Result<TcpAoSessionDeletePlan, PeerCommandError> {
        if !self.tcp_ao_protected {
            return Err(PeerCommandError::CommandFailed(
                "refusing TCP-AO deletion on an unprotected session".to_string(),
            ));
        }
        if self.connect_task.is_some() {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion cannot advance while an older-inventory connect attempt is in flight; retry the identical generation"
                    .to_string(),
            ));
        }
        if self.tcp_ao_pending_selection.is_some() {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion cannot overlap an uncommitted successor selection".to_string(),
            ));
        }
        if deletion.current.generation.next() != Some(deletion.generation)
            || deletion.desired.generation != deletion.generation
            || (self.tcp_ao_generation != deletion.current.generation
                && self.tcp_ao_generation != deletion.generation)
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion generation is not the immediate applied successor".to_string(),
            ));
        }

        let connected_peer = self.config.remote_addr.ip();
        let connected_prefix = if connected_peer.is_ipv4() { 32 } else { 128 };
        let owner_for_active = |keyring: Option<&crate::TcpAoKeyring>| {
            keyring
                .cloned()
                .map(|keyring| {
                    vec![crate::TcpAoRotationOwner {
                        owner: crate::TcpAoListenerOwnerKind::Static,
                        peer: connected_peer,
                        prefix_len: connected_prefix,
                        keyring,
                    }]
                })
                .unwrap_or_default()
        };
        let (current_owners, desired_owners) = if self.tcp_ao_stream_was_accepted {
            (
                deletion.current.accepted_owners.to_vec(),
                deletion.desired.accepted_owners.to_vec(),
            )
        } else {
            (
                owner_for_active(deletion.current.active_keyring.as_ref()),
                owner_for_active(deletion.desired.active_keyring.as_ref()),
            )
        };
        if current_owners.len() != desired_owners.len() || current_owners.is_empty() {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion may not add or remove a protected owner".to_string(),
            ));
        }
        let mut removed = false;
        for current_owner in &current_owners {
            let matching = desired_owners
                .iter()
                .filter(|desired_owner| {
                    desired_owner.owner == current_owner.owner
                        && desired_owner.peer == current_owner.peer
                        && desired_owner.prefix_len == current_owner.prefix_len
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(PeerCommandError::CommandFailed(
                    "TCP-AO deletion changed or duplicated an owner identity".to_string(),
                ));
            }
            let survivors =
                tcp_ao_deletion_survivors(&current_owner.keyring, &matching[0].keyring)?;
            removed |= survivors.len() != current_owner.keyring.0.len();
        }
        let current_metadata = metadata_for_owners(&current_owners);
        let desired_metadata = metadata_for_owners(&desired_owners);
        if desired_metadata.len() > crate::TCP_AO_MAX_INSPECT_KEYS {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO deletion survivor inventory exceeds inspection capacity".to_string(),
            ));
        }
        let already_applied = self.tcp_ao_generation == deletion.generation;
        if self.read_half.is_some()
            && self.tcp_ao_key_metadata
                != if already_applied {
                    desired_metadata.clone()
                } else {
                    current_metadata
                }
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO session metadata does not equal the deletion generation inventory"
                    .to_string(),
            ));
        }
        if self.tcp_ao_stream_was_accepted {
            let selected = self.tcp_ao_selected_owner.ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "accepted TCP-AO deletion lacks its selected-owner identity".to_string(),
                )
            })?;
            if desired_owners
                .iter()
                .filter(|owner| {
                    owner.owner == selected.owner
                        && owner.peer == selected.peer
                        && owner.prefix_len == selected.prefix_len
                })
                .count()
                != 1
            {
                return Err(PeerCommandError::CommandFailed(
                    "TCP-AO deletion changed the accepted socket's selected owner".to_string(),
                ));
            }
        }

        Ok(TcpAoSessionDeletePlan {
            connected_peer,
            current_owners,
            desired_owners,
            desired_active_keyring: deletion.desired.active_keyring.clone(),
            desired_metadata,
            already_applied,
            deletion_changed: removed,
        })
    }

    fn preflight_tcp_ao_delete(
        &self,
        deletion: &crate::TcpAoSessionDeletion,
    ) -> Result<(), PeerCommandError> {
        let plan = self.prepare_tcp_ao_delete(deletion)?;
        let Some(stream) = self.read_half.as_ref() else {
            return Ok(());
        };
        let desired = tcp_ao_owner_views(&plan.desired_owners);
        if plan.already_applied || !plan.deletion_changed {
            return crate::socket_opts::preflight_tcp_ao_add_only(
                stream.as_ref(),
                &desired,
                &desired,
                Some(plan.connected_peer),
            )
            .map(drop)
            .map_err(|error| {
                PeerCommandError::CommandFailed(format!(
                    "failed to revalidate applied TCP-AO deletion inventory: {error}"
                ))
            });
        }
        let current = tcp_ao_owner_views(&plan.current_owners);
        crate::socket_opts::preflight_tcp_ao_delete(
            stream.as_ref(),
            &current,
            &desired,
            Some(plan.connected_peer),
        )
        .map(drop)
        .map_err(|error| {
            PeerCommandError::CommandFailed(format!(
                "failed to preflight exact TCP-AO deletion inventory: {error}"
            ))
        })
    }

    pub(super) fn apply_tcp_ao_delete(
        &mut self,
        deletion: &crate::TcpAoSessionDeletion,
    ) -> Result<(), PeerCommandError> {
        self.apply_tcp_ao_delete_with(deletion, |stream, current, desired, connected_peer| {
            crate::socket_opts::preflight_tcp_ao_delete(
                stream,
                current,
                desired,
                Some(connected_peer),
            )
            .map_err(|error| {
                PeerCommandError::CommandFailed(format!(
                    "failed to preflight exact TCP-AO deletion inventory: {error}"
                ))
            })
            .and_then(|preflight| {
                crate::socket_opts::apply_tcp_ao_delete(stream, preflight, desired).map_err(
                    |error| {
                        let mutation_started = error.mutation_started();
                        let message = format!(
                            "failed to apply exact TCP-AO deletion inventory: {}",
                            error.into_inner()
                        );
                        if mutation_started {
                            PeerCommandError::TcpAoMutationFailed(message)
                        } else {
                            PeerCommandError::CommandFailed(message)
                        }
                    },
                )
            })
        })
    }

    pub(super) fn apply_tcp_ao_delete_with<F>(
        &mut self,
        deletion: &crate::TcpAoSessionDeletion,
        mutate_connected: F,
    ) -> Result<(), PeerCommandError>
    where
        F: FnOnce(
            &tokio::net::TcpStream,
            &[crate::socket_opts::TcpAoMktOwner<'_>],
            &[crate::socket_opts::TcpAoMktOwner<'_>],
            std::net::IpAddr,
        ) -> Result<Option<crate::TcpAoInfoSnapshot>, PeerCommandError>,
    {
        let plan = self.prepare_tcp_ao_delete(deletion)?;
        if plan.already_applied {
            return self.preflight_tcp_ao_delete(deletion);
        }
        if !plan.deletion_changed {
            self.preflight_tcp_ao_delete(deletion)?;
            self.config.tcp_ao = plan.desired_active_keyring;
            self.tcp_ao_generation = deletion.generation;
            return Ok(());
        }
        if let Some(stream) = self.read_half.as_ref() {
            let current = tcp_ao_owner_views(&plan.current_owners);
            let desired = tcp_ao_owner_views(&plan.desired_owners);
            let result = mutate_connected(stream.as_ref(), &current, &desired, plan.connected_peer);
            match result {
                Ok(Some(snapshot)) => self.tcp_ao_info = Some(snapshot),
                Ok(None) => {
                    self.close_tcp();
                    return Err(PeerCommandError::TcpAoMutationFailed(
                        "connected TCP-AO deletion returned no socket snapshot".to_string(),
                    ));
                }
                Err(error @ PeerCommandError::TcpAoMutationFailed(_)) => {
                    self.close_tcp();
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        self.tcp_ao_key_metadata = plan.desired_metadata;
        self.config.tcp_ao = plan.desired_active_keyring;
        self.tcp_ao_generation = deletion.generation;
        Ok(())
    }

    fn prepare_tcp_ao_add_only(
        &self,
        desired: &crate::TcpAoSessionGeneration,
    ) -> Result<Option<TcpAoSessionAddOnlyPlan>, PeerCommandError> {
        if desired.generation == self.tcp_ao_generation {
            return Ok(None);
        }
        if self.tcp_ao_generation.next() != Some(desired.generation) {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO session generation is not the immediate applied successor".to_string(),
            ));
        }
        if !self.tcp_ao_protected {
            return Err(PeerCommandError::CommandFailed(
                "refusing TCP-AO generation on an unprotected session".to_string(),
            ));
        }
        if self.connect_task.is_some() {
            // The task owns a clone of the pre-generation TransportConfig and
            // may already have installed that exact keyring on its socket. Do
            // not advance metadata/config underneath it: let the attempt
            // finish, then retry the same immutable generation against the
            // resulting socket (or the next disconnected attempt).
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO generation cannot advance while an older-inventory connect attempt is in flight; retry the generation"
                    .to_string(),
            ));
        }
        if !self.tcp_ao_stream_was_accepted {
            let target = desired.active_keyring.as_ref().ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "protected active-open session is missing its desired TCP-AO keyring"
                        .to_string(),
                )
            })?;
            let current = self.config.tcp_ao.as_ref().ok_or_else(|| {
                PeerCommandError::CommandFailed(
                    "protected active-open session lacks its current TCP-AO keyring".to_string(),
                )
            })?;
            if !target.0.starts_with(&current.0) || target.selected() != current.selected() {
                return Err(PeerCommandError::CommandFailed(
                    "TCP-AO active-open generation is not an add-only keyring successor"
                        .to_string(),
                ));
            }
        }

        let connected_peer = self.config.remote_addr.ip();
        let connected_prefix = if connected_peer.is_ipv4() { 32 } else { 128 };
        let owners = if self.tcp_ao_stream_was_accepted {
            desired.accepted_owners.to_vec()
        } else {
            desired
                .active_keyring
                .as_ref()
                .map(|keyring| {
                    vec![crate::TcpAoRotationOwner {
                        owner: crate::TcpAoListenerOwnerKind::Static,
                        peer: connected_peer,
                        prefix_len: connected_prefix,
                        keyring: keyring.clone(),
                    }]
                })
                .unwrap_or_default()
        };
        let desired_metadata = owners
            .iter()
            .flat_map(|owner| {
                owner.keyring.iter().map(|key| super::TcpAoKeyMetadata {
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    send_id: key.send_id,
                    recv_id: key.recv_id,
                    algorithm: key.algorithm,
                    preferred: key.preferred,
                    deprecated: key.deprecated,
                })
            })
            .collect::<Vec<_>>();
        if desired_metadata.len() > crate::TCP_AO_MAX_INSPECT_KEYS {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO session generation exceeds inspection capacity".to_string(),
            ));
        }
        let metadata_contains = |candidate: &super::TcpAoKeyMetadata| {
            desired_metadata.iter().any(|desired| {
                desired.peer == candidate.peer
                    && desired.prefix_len == candidate.prefix_len
                    && desired.send_id == candidate.send_id
                    && desired.recv_id == candidate.recv_id
                    && desired.algorithm == candidate.algorithm
            })
        };
        if self.read_half.is_some()
            && self
                .tcp_ao_key_metadata
                .iter()
                .any(|current| !metadata_contains(current))
        {
            return Err(PeerCommandError::CommandFailed(
                "TCP-AO add-only generation would remove or redefine an installed MKT".to_string(),
            ));
        }

        Ok(Some(TcpAoSessionAddOnlyPlan {
            connected_peer,
            owners,
            desired_metadata,
        }))
    }

    fn preflight_tcp_ao_add_only(
        &self,
        desired: &crate::TcpAoSessionGeneration,
    ) -> Result<(), PeerCommandError> {
        if desired.generation == self.tcp_ao_generation {
            let Some(stream) = self.read_half.as_ref() else {
                return Ok(());
            };
            let connected_peer = self.config.remote_addr.ip();
            let owners = if self.tcp_ao_stream_was_accepted {
                desired.accepted_owners.to_vec()
            } else {
                desired
                    .active_keyring
                    .as_ref()
                    .map(|keyring| {
                        vec![crate::TcpAoRotationOwner {
                            owner: crate::TcpAoListenerOwnerKind::Static,
                            peer: connected_peer,
                            prefix_len: if connected_peer.is_ipv4() { 32 } else { 128 },
                            keyring: keyring.clone(),
                        }]
                    })
                    .unwrap_or_default()
            };
            let current_owners = current_tcp_ao_owner_keyrings(&owners, &self.tcp_ao_key_metadata)?;
            let current = tcp_ao_owner_views(&current_owners);
            let desired = tcp_ao_owner_views(&owners);
            return crate::socket_opts::preflight_tcp_ao_add_only(
                stream.as_ref(),
                &current,
                &desired,
                Some(connected_peer),
            )
            .map(drop)
            .map_err(|error| {
                PeerCommandError::CommandFailed(format!(
                    "failed to revalidate committed TCP-AO session inventory: {error}"
                ))
            });
        }
        let Some(plan) = self.prepare_tcp_ao_add_only(desired)? else {
            return Ok(());
        };
        let Some(stream) = self.read_half.as_ref() else {
            return Ok(());
        };
        let current_owners =
            current_tcp_ao_owner_keyrings(&plan.owners, &self.tcp_ao_key_metadata)?;
        let current = tcp_ao_owner_views(&current_owners);
        let desired = tcp_ao_owner_views(&plan.owners);
        crate::socket_opts::preflight_tcp_ao_add_only(
            stream.as_ref(),
            &current,
            &desired,
            Some(plan.connected_peer),
        )
        .map(drop)
        .map_err(|error| {
            PeerCommandError::CommandFailed(format!(
                "failed to preflight complete TCP-AO session inventory: {error}"
            ))
        })
    }

    pub(super) fn apply_tcp_ao_add_only(
        &mut self,
        desired: crate::TcpAoSessionGeneration,
    ) -> Result<(), PeerCommandError> {
        let Some(plan) = self.prepare_tcp_ao_add_only(&desired)? else {
            return Ok(());
        };
        let TcpAoSessionAddOnlyPlan {
            connected_peer,
            owners,
            desired_metadata,
        } = plan;

        if self.read_half.is_some() {
            let current_owners = current_tcp_ao_owner_keyrings(&owners, &self.tcp_ao_key_metadata)?;
            let apply = {
                let stream = self.read_half.as_ref().expect("checked connected stream");
                let current = tcp_ao_owner_views(&current_owners);
                let desired_views = tcp_ao_owner_views(&owners);
                crate::socket_opts::preflight_tcp_ao_add_only(
                    stream.as_ref(),
                    &current,
                    &desired_views,
                    Some(connected_peer),
                )
                .map_err(|error| {
                    PeerCommandError::CommandFailed(format!(
                        "failed to preflight complete TCP-AO session inventory: {error}"
                    ))
                })
                .and_then(|preflight| {
                    crate::socket_opts::apply_tcp_ao_add_only(
                        stream.as_ref(),
                        preflight,
                        &desired_views,
                        Some(connected_peer),
                    )
                    .map_err(|error| {
                        let mutation_started = error.mutation_started();
                        let message = format!(
                            "failed to apply complete TCP-AO session inventory: {}",
                            error.into_inner()
                        );
                        if mutation_started {
                            PeerCommandError::TcpAoMutationFailed(message)
                        } else {
                            PeerCommandError::CommandFailed(message)
                        }
                    })
                })
            };
            match apply {
                Ok(Some(snapshot)) => self.tcp_ao_info = Some(snapshot),
                Ok(None) => {
                    self.close_tcp();
                    return Err(PeerCommandError::TcpAoMutationFailed(
                        "connected TCP-AO apply returned no socket snapshot".to_string(),
                    ));
                }
                Err(error @ PeerCommandError::TcpAoMutationFailed(_)) => {
                    self.close_tcp();
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
            self.tcp_ao_key_metadata = desired_metadata;
        }

        self.config.tcp_ao = desired.active_keyring;
        self.tcp_ao_generation = desired.generation;
        Ok(())
    }

    fn refresh_tcp_ao_info(&mut self) {
        self.refresh_tcp_ao_info_with(crate::socket_opts::get_tcp_ao_info);
    }

    pub(super) fn refresh_tcp_ao_info_with<F>(&mut self, inspect: F)
    where
        F: FnOnce(&tokio::net::TcpStream) -> std::io::Result<crate::TcpAoInfoSnapshot>,
    {
        if !self.tcp_ao_protected {
            self.tcp_ao_info = None;
            return;
        }
        let Some(read_half) = self.read_half.as_ref() else {
            self.tcp_ao_info = None;
            return;
        };
        match inspect(read_half.as_ref()) {
            Ok(mut snapshot) => {
                if self.tcp_ao_key_metadata.is_empty() {
                    self.tcp_ao_key_metadata =
                        super::tcp_ao_key_metadata(&self.config, None, self.tcp_ao_selected_owner);
                }
                let connected_peer = self.config.remote_addr.ip();
                let connected_prefix_len = if connected_peer.is_ipv4() { 32 } else { 128 };
                for key in &mut snapshot.keys {
                    if let Some(metadata) = self.tcp_ao_key_metadata.iter().find(|metadata| {
                        let selector_matches = (metadata.peer == key.peer
                            && metadata.prefix_len == key.prefix_len)
                            || (key.peer == connected_peer
                                && key.prefix_len == connected_prefix_len);
                        selector_matches
                            && metadata.send_id == key.send_id
                            && metadata.recv_id == key.recv_id
                            && metadata.algorithm == key.algorithm
                    }) {
                        // Linux may normalize every listener selector inherited
                        // by an accepted child to the connected host prefix.
                        // IDs are disjoint across covering owners, so restore
                        // the validated owner selector as well as the redacted
                        // declaration flags on every live refresh.
                        key.peer = metadata.peer;
                        key.prefix_len = metadata.prefix_len;
                        key.preferred = metadata.preferred;
                        key.deprecated = metadata.deprecated;
                    }
                }
                self.tcp_ao_info = Some(snapshot);
            }
            Err(error) => {
                if self.tcp_ao_info.is_some() {
                    warn!(
                        peer = %self.peer_label,
                        %error,
                        "live TCP-AO inspection became unavailable"
                    );
                } else {
                    debug!(
                        peer = %self.peer_label,
                        %error,
                        "live TCP-AO inspection unavailable"
                    );
                }
                // Never fall back to a connection-time snapshot: a stale
                // healthy value would be more dangerous than UNAVAILABLE.
                self.tcp_ao_info = None;
            }
        }
    }

    /// Map external commands to FSM events.
    #[expect(
        clippy::too_many_lines,
        reason = "command dispatch centralizes all external peer-session control paths"
    )]
    pub(super) async fn handle_command(&mut self, cmd: PeerCommand) -> ControlFlow<()> {
        match cmd {
            PeerCommand::Start => {
                self.stop_requested = false;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStart).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Stop { reason } => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStop { reason }).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Shutdown => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                info!(peer = %self.peer_label, "shutdown requested");
                if self.fsm.state() == SessionState::Established {
                    self.drive_fsm(Event::ManualStop { reason: None }).await;
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
            PeerCommand::QueryState { reply } => {
                // TCP_AO_INFO is cumulative for this socket. Its in-actor
                // getsockopt is a bounded, nonblocking kernel-memory read, so
                // refresh at the query boundary for current operator health.
                self.refresh_tcp_ao_info();
                let uptime_secs = self.established_at.map_or(0, |t| t.elapsed().as_secs());
                // Prefer FSM's negotiated (available at OpenConfirm) over
                // self.negotiated (set later at SessionEstablished). This is
                // critical for collision detection: handle_inbound() reads
                // remote_router_id via QueryState when the session is in
                // OpenConfirm.
                let neg = self.fsm.negotiated().or(self.negotiated.as_ref());
                let (messages_received, messages_sent) =
                    self.metrics.peer_message_totals(&self.peer_label);
                let prefix_count = self.known_prefix_count();
                let prefix_count_ipv4 = self.known_unicast_v4;
                let prefix_count_ipv6 = self.known_unicast_v6;
                let negotiated_session = (self.fsm.state() == SessionState::Established)
                    .then(|| {
                        let negotiated = neg?;
                        let mut families = negotiated.negotiated_families.clone();
                        families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                        let graceful_restart = negotiated.peer_gr_capable.then(|| {
                            let mut peer_families = negotiated
                                .peer_gr_families
                                .iter()
                                .map(|family| (family.afi, family.safi))
                                .collect::<Vec<_>>();
                            peer_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                            crate::NegotiatedGracefulRestartState {
                                peer_families,
                                peer_restart_time: negotiated.peer_restart_time,
                                effective_retention_time: self.config.peer.graceful_restart.then(
                                    || {
                                        negotiated
                                            .peer_restart_time
                                            .min(self.config.gr_peer_restart_time_max)
                                    },
                                ),
                            }
                        });
                        Some(crate::NegotiatedSessionState {
                            hold_time: negotiated.hold_time,
                            remote_router_id: negotiated.peer_router_id,
                            four_octet_as: negotiated.four_octet_as,
                            families,
                            graceful_restart,
                        })
                    })
                    .flatten();
                let state = PeerSessionState {
                    fsm_state: self.fsm.state(),
                    peer_ip: self.peer_ip,
                    peer_asn: neg.map(|n| n.peer_asn),
                    prefix_count,
                    max_prefix: MaxPrefixState {
                        prefix_count_ipv4,
                        prefix_count_ipv6,
                        max_prefixes: self.config.max_prefixes,
                        max_prefixes_ipv4: self.config.max_prefixes_ipv4,
                        max_prefixes_ipv6: self.config.max_prefixes_ipv6,
                        headroom: remaining_prefix_headroom(self.config.max_prefixes, prefix_count),
                        headroom_ipv4: remaining_prefix_headroom(
                            self.config.max_prefixes_ipv4,
                            prefix_count_ipv4,
                        ),
                        headroom_ipv6: remaining_prefix_headroom(
                            self.config.max_prefixes_ipv6,
                            prefix_count_ipv6,
                        ),
                    },
                    negotiated_hold_time: neg.map(|n| n.hold_time),
                    four_octet_as: neg.map(|n| n.four_octet_as),
                    remote_router_id: neg.map(|n| n.peer_router_id),
                    negotiated_session,
                    local_role: neg.and_then(|n| n.local_role),
                    remote_role: neg.and_then(|n| n.remote_role),
                    role_negotiated: neg.is_some_and(|n| n.role_negotiated),
                    peer_paths_limits: neg
                        .map(|n| {
                            sorted_family_limits(
                                n.peer_paths_limits
                                    .iter()
                                    .map(|(family, limit)| (*family, *limit)),
                            )
                        })
                        .unwrap_or_default(),
                    effective_add_path_send_limits: neg
                        .map(|n| {
                            sorted_family_limits(
                                n.effective_add_path_send_limits
                                    .iter()
                                    .map(|(family, limit)| (*family, *limit)),
                            )
                        })
                        .unwrap_or_default(),
                    updates_received: self.updates_received,
                    updates_sent: self.updates_sent,
                    notifications_received: self.notifications_received,
                    notifications_sent: self.notifications_sent,
                    messages_received,
                    messages_sent,
                    otc_routes_blocked: self.otc_routes_blocked,
                    import_policy_routes_permitted: self.import_policy_routes_permitted,
                    import_policy_routes_denied: self.import_policy_routes_denied,
                    flap_count: self.flap_count,
                    uptime_secs,
                    last_error: self.last_error.clone(),
                    tcp_ao_info: self.tcp_ao_info.clone().map(Box::new),
                    tcp_ao_protected: self.tcp_ao_protected,
                    slow_peer: self.slow_peer,
                };
                let _ = reply.send(state);
                ControlFlow::Continue(())
            }
            PeerCommand::QueryWarmCheckpointState { reply } => {
                let neg = self.fsm.negotiated().or(self.negotiated.as_ref());
                let mut negotiated_families = neg
                    .map(|negotiated| negotiated.negotiated_families.clone())
                    .unwrap_or_default();
                negotiated_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                let mut peer_gr_families = neg
                    .map(|negotiated| {
                        negotiated
                            .peer_gr_families
                            .iter()
                            .map(|family| (family.afi, family.safi))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                peer_gr_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                let mut add_path_receive_families = neg
                    .map(|negotiated| {
                        negotiated
                            .add_path_families
                            .iter()
                            .filter_map(|(family, mode)| {
                                matches!(
                                    mode,
                                    rustbgpd_wire::AddPathMode::Receive
                                        | rustbgpd_wire::AddPathMode::Both
                                )
                                .then_some(*family)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                add_path_receive_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                let state = WarmCheckpointSessionState {
                    fsm_state: self.fsm.state(),
                    peer_asn: neg.map(|negotiated| negotiated.peer_asn),
                    peer_router_id: neg.map(|negotiated| negotiated.peer_router_id),
                    negotiated_families,
                    peer_gr_families,
                    peer_gr_capable: neg.is_some_and(|negotiated| negotiated.peer_gr_capable),
                    peer_gr_restart_time: neg.map_or(0, |negotiated| negotiated.peer_restart_time),
                    add_path_receive_families,
                };
                let _ = reply.send(state);
                ControlFlow::Continue(())
            }
            PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                if self.fsm.state() != SessionState::Established {
                    let _ = reply.send(Err(PeerCommandError::NotEstablished));
                    return ControlFlow::Continue(());
                }
                if !self
                    .negotiated
                    .as_ref()
                    .is_some_and(|n| n.peer_route_refresh)
                {
                    let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
                    return ControlFlow::Continue(());
                }
                if !self.negotiated_families.contains(&(afi, safi)) {
                    let _ = reply.send(Err(PeerCommandError::FamilyNotNegotiated { afi, safi }));
                    return ControlFlow::Continue(());
                }
                let msg = Message::RouteRefresh(RouteRefreshMessage::new(afi, safi));
                if let Err(e) = self.enqueue_priority(&msg) {
                    let _ = reply.send(Err(PeerCommandError::SendFailed(e.to_string())));
                } else {
                    info!(peer = %self.peer_label, ?afi, ?safi, "sent ROUTE-REFRESH");
                    self.metrics
                        .record_message_sent(&self.peer_label, "route_refresh");
                    let _ = reply.send(Ok(()));
                }
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateImportPolicy { policy, reply } => {
                self.install_import_policy(policy);
                // ADR-0073: advancing the session-local generation makes
                // every decision recorded under the prior chain read as
                // STALE on a subsequent explain lookup. saturating_add so
                // a pathologically long-lived session that somehow wraps
                // u64 degrades to "always current" rather than panicking.
                self.import_policy_generation = self.import_policy_generation.saturating_add(1);
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::ExplainImportPolicy {
                afi,
                safi,
                prefix,
                path_id,
                reply,
            } => {
                use super::import_decision_cache::{ImportDecisionKey, ResolvedMatch};
                let generation = self.import_policy_generation;
                let mut matches = match path_id {
                    Some(path_id) => {
                        let key = ImportDecisionKey {
                            afi,
                            safi,
                            prefix,
                            path_id,
                        };
                        vec![ResolvedMatch {
                            path_id,
                            result: self.import_decision_cache.lookup(&key, generation),
                            statements: Vec::new(),
                        }]
                    }
                    None => self
                        .import_decision_cache
                        .lookup_all_paths(afi, safi, &prefix, generation),
                };
                // Statement-level attribution, re-derived on demand from the
                // cached pre-policy context against the session's import
                // chain. Explain-only work on the command path — the inbound
                // UPDATE hot path is untouched.
                // Typed family from the explain key's AFI/SAFI — the
                // same pair the cached decision was recorded under
                // (LAN-295).
                let family = rustbgpd_policy::RouteFamily::from_afi_safi(afi, safi);
                for m in &mut matches {
                    m.statements = self.statement_trace_for(prefix, family, &m.result);
                }
                let _ = reply.send(super::import_decision_cache::ImportExplainReply {
                    current_generation: generation,
                    cache_enabled: self.import_explain_enabled,
                    matches,
                });
                ControlFlow::Continue(())
            }
            PeerCommand::ListRejectedRoutes { reply } => {
                // LAN-472: read-only retention snapshot. Bounded by the
                // configured cap, so the clone stays diagnostic-sized;
                // the inbound UPDATE hot path is untouched.
                let _ = reply.send(super::rejected_routes::RejectedRoutesReply {
                    enabled: self.reject_retention_enabled,
                    capacity: self.rejected_routes.capacity(),
                    entries: self.rejected_routes.snapshot(),
                });
                ControlFlow::Continue(())
            }
            PeerCommand::QueryImportPolicyTermHits { reply } => {
                // Read-only snapshot of the live counters (ADR-0096
                // Decision 3.3). No counter moves; a session without an
                // installed import chain has nothing to report.
                let snapshot =
                    self.import_policy
                        .as_ref()
                        .map(|chain| crate::handle::ImportPolicyTermHits {
                            generation: self.import_policy_generation,
                            evals: chain.hit_counters().evals(),
                            eval_errors: chain.hit_counters().eval_errors(),
                            last_error: chain
                                .hit_counters()
                                .last_error()
                                .map(|error| error.to_string()),
                            terms: chain.term_hit_rows(),
                        });
                let _ = reply.send(snapshot);
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateExportPolicy { policy, reply } => {
                self.export_policy = policy;
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateRuntimeConfig {
                max_prefixes,
                max_prefixes_ipv4,
                max_prefixes_ipv6,
                gr_stale_routes_time,
                gr_peer_restart_time_max,
                local_ipv6_nexthop,
                remove_private_as,
                reply,
            } => {
                // LAN-341 hot-apply: these knobs are read from
                // `self.config` on every evaluation (see the command's
                // doc) — no FSM event, no TCP impact. A lowered
                // `max_prefixes` trips on the next received UPDATE,
                // matching the reload matrix's documented semantics.
                // For the export-affecting knobs (`local_ipv6_nexthop`,
                // `remove_private_as`) the swap alone is NOT the whole
                // apply: the peer manager follows it with a
                // `RibUpdate::RefreshPeerOutbound` so preflight-suppressed
                // routes are re-probed and advertised AS_PATHs re-encoded
                // under the new values.
                self.config.max_prefixes = max_prefixes;
                self.config.max_prefixes_ipv4 = max_prefixes_ipv4;
                self.config.max_prefixes_ipv6 = max_prefixes_ipv6;
                self.config.gr_stale_routes_time = gr_stale_routes_time;
                self.config.gr_peer_restart_time_max = gr_peer_restart_time_max;
                self.config.local_ipv6_nexthop = local_ipv6_nexthop;
                self.config.remove_private_as = remove_private_as;
                self.publish_export_profile();
                info!(peer = %self.peer_label, "hot-applied runtime config knobs");
                let _ = reply.send(Ok(()));
                // ADR-0108: a per-family limit lowered below the family's
                // current unique-prefix count enforces immediately, not on
                // the next UPDATE — a quiet peer must not keep a table that
                // the operator just bounded below it. The aggregate keeps
                // its historical next-UPDATE semantics (excluded here via
                // `include_aggregate = false`).
                self.enforce_max_prefix_limits(false).await;
                ControlFlow::Continue(())
            }
            PeerCommand::ApplyTcpAoAddOnly { desired, reply } => {
                let generation = desired.generation.as_u64();
                let result = self.apply_tcp_ao_add_only(desired);
                if result.is_ok() {
                    info!(peer = %self.peer_label, generation, "applied TCP-AO add-only generation");
                }
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::PreflightTcpAoAddOnly { desired, reply } => {
                let result = self.preflight_tcp_ao_add_only(&desired);
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::PreflightTcpAoSelection { desired, reply } => {
                let result = self.preflight_tcp_ao_selection(&desired);
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::ApplyTcpAoSelection { desired, reply } => {
                let generation = desired.generation.as_u64();
                let result = self.apply_tcp_ao_selection(desired);
                if result.is_ok() {
                    info!(peer = %self.peer_label, generation, "selected TCP-AO successor RNext");
                }
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::ObserveTcpAoSelection { desired, reply } => {
                let result = self.observe_tcp_ao_selection(&desired);
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::CommitTcpAoSelection { desired, reply } => {
                let generation = desired.generation.as_u64();
                let result = self.commit_tcp_ao_selection(&desired);
                if result.is_ok() {
                    info!(peer = %self.peer_label, generation, "committed TCP-AO selection metadata");
                }
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::PreflightTcpAoDelete { desired, reply } => {
                let result = self.preflight_tcp_ao_delete(&desired);
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::ApplyTcpAoDelete { desired, reply } => {
                let generation = desired.generation.as_u64();
                let result = self.apply_tcp_ao_delete(&desired);
                if result.is_ok() {
                    info!(peer = %self.peer_label, generation, "applied TCP-AO deletion generation");
                }
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            PeerCommand::ResetTcpAoAfterFailedMutation {
                desired_generation,
                reply,
            } => {
                warn!(
                    peer = %self.peer_label,
                    generation = desired_generation.as_u64(),
                    "discarding TCP stream after partial TCP-AO generation mutation"
                );
                self.close_tcp();
                let _ = reply.send(());
                ControlFlow::Continue(())
            }
            PeerCommand::UpdateGracefulShutdown { enabled, reply } => {
                // Idempotent: re-setting to the same value is a no-op.
                // The toggle takes effect for the next outbound update;
                // RFC 8326 §5 expects the operator to follow this with
                // a re-advertise so peers see the tagged routes.
                self.advertise_graceful_shutdown = enabled;
                self.publish_export_profile();
                info!(
                    peer = %self.peer_label,
                    enabled,
                    "RFC 8326 graceful-shutdown advertise toggled"
                );
                let _ = reply.send(Ok(()));
                ControlFlow::Continue(())
            }
            PeerCommand::ActivateMaxPrefixMetrics { reply } => {
                self.max_prefix_metric_lease.active = true;
                self.sync_max_prefix_capacity_metrics();
                let _ = reply.send(());
                ControlFlow::Continue(())
            }
            PeerCommand::CollisionDump => {
                info!(peer = %self.peer_label, "collision dump: sending Cease/7");
                self.stop_requested = true;
                self.reconnect_timer = None;
                // Send Cease/7 NOTIFICATION
                let notif = rustbgpd_wire::NotificationMessage::new(
                    NotificationCode::Cease,
                    cease_subcode::CONNECTION_COLLISION_RESOLUTION,
                    bytes::Bytes::new(),
                );
                self.emit_notification_event(SessionNotificationDirection::Sent, &notif, None);
                let _ = self.enqueue_priority(&Message::Notification(notif));
                self.notifications_sent += 1;
                // Clean up RIB if Established
                if self.fsm.state() == SessionState::Established {
                    let _ = self
                        .rib_tx
                        .send(RibUpdate::PeerDown {
                            peer: self.peer_ip,
                            session_id: self.session_identity.id,
                        })
                        .await;
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
        }
    }

    /// Re-derive the statement-level trace for one resolved explain
    /// match (ADR-0073 statement-level enrichment).
    ///
    /// Only a current-generation `Hit` with a `Permit` / `Deny` outcome
    /// qualifies: a same-generation hit guarantees the session's import
    /// chain is byte-for-byte the chain that produced the cached
    /// decision, so walking it again against the cached pre-policy
    /// context reproduces the original evaluation. `Stale` entries
    /// are skipped (their chain is gone — tracing the *current* chain
    /// could contradict the recorded outcome) and `Withdrawn`
    /// tombstones shed the context the reconstruction needs.
    ///
    /// The cached context is an owned copy of the fields produced by the same
    /// extractor the inbound hot path uses (`PolicyAttrSummary::from_route_attrs`)
    /// plus the stored evaluation-time next-hop, so the trace cannot drift from
    /// the live evaluation's view of the route. As a final belt-and-braces gate,
    /// a trace whose terminal action disagrees with the recorded outcome is
    /// dropped rather than rendered — an explain surface must never contradict
    /// its own headline answer.
    fn statement_trace_for(
        &self,
        prefix: rustbgpd_wire::Prefix,
        family: Option<rustbgpd_policy::RouteFamily>,
        result: &super::import_decision_cache::LookupResult,
    ) -> Vec<rustbgpd_policy::StatementAttribution> {
        use super::import_decision_cache::{CachedOutcome, LookupResult};
        use rustbgpd_policy::{PolicyAction, RouteContext, RouteType, explain_chain_statements};

        let LookupResult::Hit(decision) = result else {
            return Vec::new();
        };
        let expected_action = match decision.outcome {
            CachedOutcome::Permit => PolicyAction::Permit,
            CachedOutcome::Deny => PolicyAction::Deny,
            CachedOutcome::Withdrawn => return Vec::new(),
        };

        let cached = &decision.policy_context;
        // Session-identity fields mirror the inbound eval sites: the
        // peer's negotiated ASN and eBGP/iBGP classification are
        // properties of the established session and cannot have
        // changed since the decision was recorded on it.
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);
        let ctx = RouteContext {
            prefix: Some(prefix),
            next_hop: decision.next_hop,
            extended_communities: &cached.extended_communities,
            communities: &cached.communities,
            large_communities: &cached.large_communities,
            as_path_str: &cached.as_path_str,
            as_path: cached.as_path.as_ref(),
            as_path_len: cached.as_path_len,
            origin_asn: cached.origin_asn,
            validation_state: decision.rpki,
            aspa_state: decision.aspa,
            peer_address: Some(self.peer_ip),
            peer_asn: self.negotiated.as_ref().map(|n| n.peer_asn),
            peer_group: self.config.peer_group.as_deref(),
            route_type: Some(if is_ebgp {
                RouteType::External
            } else {
                RouteType::Internal
            }),
            family,
            evpn_route_type: None,
            local_pref: cached.local_pref,
            med: cached.med,
        };
        let trace = explain_chain_statements(self.import_policy.as_ref(), &ctx);
        if trace.action == expected_action {
            trace.steps
        } else {
            // Should be unreachable for a same-generation hit; pinned
            // by the policy-crate agreement tests. Prefer "no trace"
            // over a trace that contradicts the recorded outcome.
            debug_assert_eq!(trace.action, expected_action, "explain trace diverged");
            Vec::new()
        }
    }
}
