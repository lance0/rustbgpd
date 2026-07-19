use std::net::IpAddr;

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_transport::{
    PeerCommand, TcpAoKeyring, TcpAoListenerKey, TcpAoRotationGeneration, TcpAoRotationOwner,
    TcpAoRotationPhase, TcpAoRotationStatus, TcpAoSessionGeneration,
};
use tokio::sync::{mpsc, oneshot};

use super::{PEER_LIFECYCLE_COMMAND_TIMEOUT, PeerManager, TcpAoDesiredInventory};

type SessionApplyPlan = Vec<(
    PeerKey,
    TcpAoSessionGeneration,
    Vec<mpsc::Sender<PeerCommand>>,
)>;

fn canonical_desired_inventory(
    generation: TcpAoRotationGeneration,
    listener_keys: &[TcpAoListenerKey],
    static_keyrings: &[(PeerKey, TcpAoKeyring)],
) -> TcpAoDesiredInventory {
    let mut listener_keys = listener_keys.to_vec();
    listener_keys.sort_by_key(|key| {
        let owner = match key.owner {
            rustbgpd_transport::TcpAoListenerOwnerKind::Static => 0_u8,
            rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic => 1_u8,
        };
        (key.peer, key.prefix_len, owner)
    });
    let mut static_keyrings = static_keyrings.to_vec();
    static_keyrings.sort_by(|(left, _), (right, _)| left.cmp(right));
    TcpAoDesiredInventory {
        generation,
        listener_keys,
        static_keyrings,
    }
}

fn retain_desired_inventory(
    retained: &mut Option<TcpAoDesiredInventory>,
    desired: TcpAoDesiredInventory,
) -> Result<(), String> {
    match retained {
        Some(current) if current == &desired => Ok(()),
        Some(_) => {
            Err("TCP-AO failed generation retry changed its immutable global inventory".to_string())
        }
        None => {
            *retained = Some(desired);
            Ok(())
        }
    }
}

fn mask_v4(address: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        address & (u32::MAX << (32 - prefix_len))
    }
}

fn mask_v6(address: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        address & (u128::MAX << (128 - prefix_len))
    }
}

fn owner_covers(owner: &TcpAoListenerKey, address: IpAddr) -> bool {
    match (owner.peer, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if owner.prefix_len <= 32 => {
            mask_v4(network.into(), owner.prefix_len) == mask_v4(address.into(), owner.prefix_len)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if owner.prefix_len <= 128 => {
            mask_v6(network.into(), owner.prefix_len) == mask_v6(address.into(), owner.prefix_len)
        }
        _ => false,
    }
}

fn keyring_is_append_only(current: &TcpAoKeyring, desired: &TcpAoKeyring) -> bool {
    desired.0.starts_with(&current.0) && desired.selected() == current.selected()
}

fn record_tcp_ao_generation_applied(
    status: &mut TcpAoRotationStatus,
    generation: TcpAoRotationGeneration,
) {
    *status = TcpAoRotationStatus {
        desired: generation,
        applied: generation,
        phase: TcpAoRotationPhase::Idle,
        last_error: None,
    };
}

fn complete_tcp_ao_generation<'a>(
    global: &mut TcpAoRotationStatus,
    protected_peers: impl Iterator<Item = &'a mut TcpAoRotationStatus>,
    generation: TcpAoRotationGeneration,
) {
    for status in protected_peers {
        record_tcp_ao_generation_applied(status, generation);
    }
    record_tcp_ao_generation_applied(global, generation);
}

fn target_for_peer(
    peer: &PeerKey,
    is_dynamic: bool,
    listener_keys: &[TcpAoListenerKey],
    static_keyrings: &[(PeerKey, TcpAoKeyring)],
    generation: TcpAoRotationGeneration,
) -> TcpAoSessionGeneration {
    let active_keyring = (!is_dynamic)
        .then(|| {
            static_keyrings
                .iter()
                .find(|(candidate, _)| candidate == peer)
                .map(|(_, keyring)| keyring.clone())
        })
        .flatten();
    let accepted_owners = listener_keys
        .iter()
        .filter(|owner| owner_covers(owner, peer.address))
        .map(|owner| TcpAoRotationOwner {
            peer: owner.peer,
            prefix_len: owner.prefix_len,
            keyring: owner.config.clone(),
        })
        .collect::<Vec<_>>();
    TcpAoSessionGeneration {
        generation,
        active_keyring,
        accepted_owners: accepted_owners.into(),
    }
}

async fn apply_to_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionGeneration,
) -> Result<(), SessionApplyFailure> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::ApplyTcpAoAddOnly { desired, reply }),
    )
    .await
    .map_err(|_| SessionApplyFailure::before_mutation("TCP-AO session command delivery timed out"))?
    .map_err(|_| {
        SessionApplyFailure::before_mutation("TCP-AO session task exited before generation apply")
    })?;
    let response = tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| {
            SessionApplyFailure::after_delivery(
                "TCP-AO session generation acknowledgement timed out",
            )
        })?
        .map_err(|_| {
            SessionApplyFailure::after_delivery("TCP-AO session generation acknowledgement dropped")
        })?;
    response.map_err(|error| SessionApplyFailure {
        mutation_may_have_started: matches!(
            &error,
            rustbgpd_transport::PeerCommandError::TcpAoMutationFailed(_)
        ),
        message: error.to_string(),
    })
}

struct SessionApplyFailure {
    message: String,
    mutation_may_have_started: bool,
}

impl SessionApplyFailure {
    fn before_mutation(message: &str) -> Self {
        Self {
            message: message.to_string(),
            mutation_may_have_started: false,
        }
    }

    fn after_delivery(message: &str) -> Self {
        Self {
            message: message.to_string(),
            // A dropped/timed-out acknowledgement cannot prove where the
            // synchronous session command stopped. Reset all siblings.
            mutation_may_have_started: true,
        }
    }
}

async fn reset_sessions_after_failed_mutation(
    sessions: &[mpsc::Sender<PeerCommand>],
    generation: TcpAoRotationGeneration,
) -> Vec<String> {
    let mut failures = Vec::new();
    for commands in sessions {
        let (reply, response) = oneshot::channel();
        let command = PeerCommand::ResetTcpAoAfterFailedMutation {
            desired_generation: generation,
            reply,
        };
        match tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, commands.send(command)).await {
            Ok(Ok(())) => {
                match tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        failures.push("session reset acknowledgement dropped".to_string());
                    }
                    Err(_) => failures.push("session reset acknowledgement timed out".to_string()),
                }
            }
            Ok(Err(_)) => {
                // An exited session cannot reuse its old connected stream.
            }
            Err(_) => failures.push("session reset command delivery timed out".to_string()),
        }
    }
    failures
}

async fn preflight_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionGeneration,
) -> Result<(), String> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::PreflightTcpAoAddOnly { desired, reply }),
    )
    .await
    .map_err(|_| "TCP-AO session preflight delivery timed out".to_string())?
    .map_err(|_| "TCP-AO session task exited before generation preflight".to_string())?;
    tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| "TCP-AO session preflight acknowledgement timed out".to_string())?
        .map_err(|_| "TCP-AO session preflight acknowledgement dropped".to_string())?
        .map_err(|error| error.to_string())
}

impl PeerManager {
    pub(super) fn mark_tcp_ao_add_only_failed(
        &mut self,
        generation: TcpAoRotationGeneration,
        error: &str,
    ) {
        self.tcp_ao_rotation = TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_generation,
            phase: TcpAoRotationPhase::AddOnlyFailed,
            last_error: Some(error.to_string()),
        };
        for managed in self
            .peers
            .values_mut()
            .filter(|managed| managed.tcp_ao_protected)
        {
            managed.tcp_ao_rotation.desired = generation;
            managed.tcp_ao_rotation.phase = TcpAoRotationPhase::AddOnlyFailed;
            managed.tcp_ao_rotation.last_error = Some(error.to_string());
        }
    }

    fn build_tcp_ao_add_only_plan(
        &self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<SessionApplyPlan, String> {
        if generation != self.tcp_ao_generation && self.tcp_ao_generation.next() != Some(generation)
        {
            return Err(
                "TCP-AO peer generation is not current or the immediate applied successor"
                    .to_string(),
            );
        }
        let mut plan = Vec::new();
        let mut peers = self.peers.keys().cloned().collect::<Vec<_>>();
        peers.sort();
        for peer in peers {
            let managed = &self.peers[&peer];
            if !managed.tcp_ao_protected {
                continue;
            }
            let desired = target_for_peer(
                &peer,
                managed.is_dynamic,
                listener_keys,
                static_keyrings,
                generation,
            );
            if !managed.is_dynamic {
                let current = managed.transport_config.tcp_ao.as_ref().ok_or_else(|| {
                    format!("protected static peer {peer:?} lacks its active-open keyring")
                })?;
                let target = desired.active_keyring.as_ref().ok_or_else(|| {
                    format!("TCP-AO generation omits protected static peer {peer:?}")
                })?;
                if managed.tcp_ao_rotation.applied != generation
                    && !keyring_is_append_only(current, target)
                {
                    return Err(format!(
                        "TCP-AO generation for {peer:?} is not an append-only keyring successor"
                    ));
                }
            } else if desired.accepted_owners.is_empty() {
                return Err(format!(
                    "TCP-AO generation has no covering listener owner for dynamic peer {peer:?}"
                ));
            }
            let mut sessions = vec![managed.handle.commands_sender()];
            if let Some(pending) = &managed.pending_inbound {
                sessions.push(pending.handle.commands_sender());
            }
            plan.push((peer, desired, sessions));
        }
        Ok(plan)
    }

    pub(super) async fn preflight_tcp_ao_add_only(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        let desired_inventory =
            canonical_desired_inventory(generation, listener_keys, static_keyrings);
        if let Err(error) =
            retain_desired_inventory(&mut self.tcp_ao_desired_inventory, desired_inventory)
        {
            self.mark_tcp_ao_add_only_failed(generation, &error);
            return Err(error);
        }
        self.tcp_ao_rotation = TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_generation,
            phase: TcpAoRotationPhase::AddOnly,
            last_error: None,
        };
        let plan = match self.build_tcp_ao_add_only_plan(generation, listener_keys, static_keyrings)
        {
            Ok(plan) => plan,
            Err(error) => {
                self.mark_tcp_ao_add_only_failed(generation, &error);
                return Err(error);
            }
        };
        for (peer, _, _) in &plan {
            let applied = self.peers[peer].tcp_ao_rotation.applied;
            self.peers
                .get_mut(peer)
                .expect("peer came from current map")
                .tcp_ao_rotation = TcpAoRotationStatus {
                desired: generation,
                applied,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            };
        }
        for (_, desired, sessions) in plan {
            for commands in sessions {
                if let Err(error) = preflight_session(commands, desired.clone()).await {
                    self.mark_tcp_ao_add_only_failed(generation, &error);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "global apply keeps immutable-inventory fencing, ordered peer commits, and failure bookkeeping in one transaction boundary"
    )]
    pub(super) async fn apply_tcp_ao_add_only(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        if generation == self.tcp_ao_generation {
            if let Some(retained) = self.tcp_ao_desired_inventory.as_ref() {
                let desired =
                    canonical_desired_inventory(generation, listener_keys, static_keyrings);
                if retained != &desired {
                    let error =
                        "TCP-AO committed generation retry changed its immutable global inventory"
                            .to_string();
                    self.mark_tcp_ao_add_only_failed(generation, &error);
                    return Err(error);
                }
                self.tcp_ao_desired_inventory = None;
            }
            complete_tcp_ao_generation(
                &mut self.tcp_ao_rotation,
                self.peers
                    .values_mut()
                    .filter(|managed| managed.tcp_ao_protected)
                    .map(|managed| &mut managed.tcp_ao_rotation),
                generation,
            );
            return Ok(());
        }
        let desired_inventory =
            canonical_desired_inventory(generation, listener_keys, static_keyrings);
        if let Err(error) =
            retain_desired_inventory(&mut self.tcp_ao_desired_inventory, desired_inventory)
        {
            self.mark_tcp_ao_add_only_failed(generation, &error);
            return Err(error);
        }
        let plan = match self.build_tcp_ao_add_only_plan(generation, listener_keys, static_keyrings)
        {
            Ok(plan) => plan,
            Err(error) => {
                self.mark_tcp_ao_add_only_failed(generation, &error);
                return Err(error);
            }
        };

        for (peer, _, _) in &plan {
            let applied = self.peers[peer].tcp_ao_rotation.applied;
            self.peers
                .get_mut(peer)
                .expect("peer came from current map")
                .tcp_ao_rotation = TcpAoRotationStatus {
                desired: generation,
                applied,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            };
        }

        for (peer, desired, sessions) in plan {
            let mut error = None;
            for commands in &sessions {
                if let Err(failure) = apply_to_session(commands.clone(), desired.clone()).await {
                    error = Some(failure);
                    break;
                }
            }
            if let Some(failure) = error {
                let mut error = failure.message;
                if failure.mutation_may_have_started {
                    let reset_failures =
                        reset_sessions_after_failed_mutation(&sessions, generation).await;
                    if !reset_failures.is_empty() {
                        error = format!(
                            "{error}; fail-closed sibling reset was incomplete: {}",
                            reset_failures.join(", ")
                        );
                        // A saturated/wedged command channel cannot prove the
                        // potentially mutated socket was discarded. Abort both
                        // tasks so dropping their futures closes every primary
                        // and pending child stream before any later collision
                        // path can reuse them.
                        if let Some(managed) = self.peers.get(&peer) {
                            managed.handle.abort_for_transport_safety();
                            if let Some(pending) = &managed.pending_inbound {
                                pending.handle.abort_for_transport_safety();
                            }
                        }
                    }
                }
                self.tcp_ao_rotation.phase = TcpAoRotationPhase::AddOnlyFailed;
                self.tcp_ao_rotation.last_error = Some(format!(
                    "global generation stopped after peer {peer:?} failed: {error}"
                ));
                for (candidate_peer, candidate) in &mut self.peers {
                    if candidate.tcp_ao_rotation.desired != generation {
                        continue;
                    }
                    candidate.tcp_ao_rotation.phase = TcpAoRotationPhase::AddOnlyFailed;
                    candidate.tcp_ao_rotation.last_error = Some(if candidate_peer == &peer {
                        error.clone()
                    } else {
                        format!("global generation stopped after peer {peer:?} failed: {error}")
                    });
                }
                return Err(format!(
                    "TCP-AO add-only generation failed for {peer:?}: {error}"
                ));
            }
            // This peer's primary and pending child have both acknowledged the
            // immutable generation. Record that durable per-peer truth before
            // moving to the next peer. A later peer failure changes the phase
            // to failed, but must not erase which earlier peers actually
            // applied the generation.
            let managed = self
                .peers
                .get_mut(&peer)
                .expect("preflighted peer remains owned");
            managed.transport_config.tcp_ao = if managed.is_dynamic {
                // Dynamic sessions never active-open, but their managed
                // transport template is reused for later collision
                // candidates. Keep the most-specific owning keyring there so
                // declaration-only preferred/deprecated metadata remains
                // truthful for a child accepted after this generation commits.
                desired
                    .accepted_owners
                    .iter()
                    .max_by_key(|owner| owner.prefix_len)
                    .map(|owner| owner.keyring.clone())
            } else {
                desired.active_keyring
            };
            record_tcp_ao_generation_applied(&mut managed.tcp_ao_rotation, generation);
        }
        self.tcp_ao_generation = generation;
        self.tcp_ao_desired_inventory = None;
        complete_tcp_ao_generation(
            &mut self.tcp_ao_rotation,
            self.peers
                .values_mut()
                .filter(|managed| managed.tcp_ao_protected)
                .map(|managed| &mut managed.tcp_ao_rotation),
            generation,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::ManagedPeer;
    use rustbgpd_fsm::PeerConfig;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_transport::TcpAoListenerOwnerKind;
    use rustbgpd_transport::{
        PeerCommandError, PeerHandle, TcpAoAlgorithm, TcpAoConfig, TransportConfig,
    };
    use std::net::{Ipv4Addr, SocketAddr};

    fn key(send_id: u8, recv_id: u8) -> TcpAoConfig {
        TcpAoConfig {
            key: format!("secret-{send_id}").into(),
            send_id,
            recv_id,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
    }

    #[test]
    fn accepted_target_keeps_complete_overlapping_owner_union() {
        let peer = PeerKey::new("192.0.2.9".parse().unwrap(), None);
        let listener_keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.0".parse().unwrap(),
                prefix_len: 24,
                config: TcpAoKeyring(vec![key(1, 2)]),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.8".parse().unwrap(),
                prefix_len: 29,
                config: TcpAoKeyring(vec![key(3, 4), key(5, 6)]),
            },
        ];
        let target = target_for_peer(
            &peer,
            true,
            &listener_keys,
            &[],
            TcpAoRotationGeneration::new(2).unwrap(),
        );
        assert_eq!(target.accepted_owners.len(), 2);
        assert_eq!(
            target
                .accepted_owners
                .iter()
                .flat_map(|owner| owner.keyring.iter().map(|key| key.send_id))
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
    }

    #[test]
    fn failed_generation_retry_requires_exact_canonical_global_inventory() {
        let peer = PeerKey::new("192.0.2.9".parse().unwrap(), None);
        let listener = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Static,
            peer: peer.address,
            prefix_len: 32,
            config: TcpAoKeyring(vec![key(1, 2), key(3, 4)]),
        };
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = canonical_desired_inventory(
            generation,
            std::slice::from_ref(&listener),
            &[(peer.clone(), listener.config.clone())],
        );
        let mut retained = None;
        retain_desired_inventory(&mut retained, desired.clone()).unwrap();

        let mut changed_listener = listener.clone();
        changed_listener.config.0[1].key = "changed-after-partial-apply".into();
        let changed = canonical_desired_inventory(
            generation,
            &[changed_listener],
            &[(peer, listener.config)],
        );
        assert!(retain_desired_inventory(&mut retained, changed).is_err());
        assert_eq!(retained.as_ref(), Some(&desired));
    }

    #[tokio::test]
    async fn mutation_failure_resets_primary_and_pending_session_streams() {
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoSessionGeneration {
            generation,
            active_keyring: None,
            accepted_owners: Vec::new().into(),
        };
        let (primary_tx, mut primary_rx) = mpsc::channel(4);
        let (pending_tx, mut pending_rx) = mpsc::channel(4);
        let (primary_reset_tx, primary_reset_rx) = oneshot::channel();
        let (pending_reset_tx, pending_reset_rx) = oneshot::channel();
        tokio::spawn(async move {
            let Some(PeerCommand::ApplyTcpAoAddOnly { reply, .. }) = primary_rx.recv().await else {
                panic!("primary should receive generation apply");
            };
            let _ = reply.send(Err(
                rustbgpd_transport::PeerCommandError::TcpAoMutationFailed(
                    "injected post-add inventory failure".to_string(),
                ),
            ));
            let Some(PeerCommand::ResetTcpAoAfterFailedMutation { reply, .. }) =
                primary_rx.recv().await
            else {
                panic!("primary should receive fail-closed reset");
            };
            let _ = reply.send(());
            let _ = primary_reset_tx.send(());
        });
        tokio::spawn(async move {
            let Some(PeerCommand::ResetTcpAoAfterFailedMutation { reply, .. }) =
                pending_rx.recv().await
            else {
                panic!("pending child should receive fail-closed reset");
            };
            let _ = reply.send(());
            let _ = pending_reset_tx.send(());
        });

        let failure = apply_to_session(primary_tx.clone(), desired)
            .await
            .unwrap_err();
        assert!(failure.mutation_may_have_started);
        let resets =
            reset_sessions_after_failed_mutation(&[primary_tx, pending_tx], generation).await;
        assert!(resets.is_empty());
        primary_reset_rx.await.unwrap();
        pending_reset_rx.await.unwrap();
    }

    fn rotation_peer_handle(apply_result: Result<(), PeerCommandError>) -> PeerHandle {
        let (commands, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    PeerCommand::ApplyTcpAoAddOnly { reply, .. } => {
                        let _ = reply.send(apply_result.clone());
                    }
                    PeerCommand::Shutdown
                    | PeerCommand::Stop { .. }
                    | PeerCommand::CollisionDump => break,
                    _ => {}
                }
            }
            Ok(())
        });
        PeerHandle::from_parts(commands, task)
    }

    fn install_rotation_peer(
        manager: &mut PeerManager,
        address: IpAddr,
        session_id: u64,
        handle: PeerHandle,
        keyring: TcpAoKeyring,
    ) -> PeerKey {
        let peer = PeerKey::new(address, None);
        let mut transport = TransportConfig::new(
            PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1)),
            SocketAddr::new(address, 179),
        );
        transport.tcp_ao = Some(keyring);
        manager.peers.insert(
            peer.clone(),
            ManagedPeer {
                handle,
                session_id,
                remote_asn: 65_002,
                description: address.to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(90),
                max_prefixes: None,
                max_prefix_restart_seconds: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                tcp_ao_protected: true,
                tcp_ao_rotation: TcpAoRotationStatus::default(),
                accepted_dynamic_range: None,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );
        manager.register_session(session_id, &peer);
        peer
    }

    #[tokio::test]
    async fn later_peer_failure_preserves_earlier_peer_applied_generation() {
        let old = TcpAoRotationGeneration::STARTUP;
        let new = old.next().unwrap();
        let (_manager_tx, manager_rx) = mpsc::channel(4);
        let (rib_tx, _rib_rx) = mpsc::channel(4);
        let mut manager = PeerManager::new(
            manager_rx,
            65_001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let old_keyring = TcpAoKeyring(vec![key(1, 11)]);
        let desired_keyring = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let peer_a = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            rotation_peer_handle(Ok(())),
            old_keyring.clone(),
        );
        let peer_b = install_rotation_peer(
            &mut manager,
            "192.0.2.2".parse().unwrap(),
            2,
            rotation_peer_handle(Err(PeerCommandError::CommandFailed(
                "injected peer B apply failure".to_string(),
            ))),
            old_keyring,
        );
        let static_keyrings = vec![
            (peer_a.clone(), desired_keyring.clone()),
            (peer_b.clone(), desired_keyring),
        ];

        let error = manager
            .apply_tcp_ao_add_only(new, &[], &static_keyrings)
            .await
            .unwrap_err();
        assert!(error.contains("injected peer B apply failure"));

        let peer_a = &manager.peers[&peer_a];
        let peer_b = &manager.peers[&peer_b];
        assert_eq!(peer_a.tcp_ao_rotation.applied, new);
        assert_eq!(peer_b.tcp_ao_rotation.applied, old);
        assert_eq!(
            peer_a.tcp_ao_rotation.phase,
            TcpAoRotationPhase::AddOnlyFailed
        );
        assert_eq!(
            peer_b.tcp_ao_rotation.phase,
            TcpAoRotationPhase::AddOnlyFailed
        );
        assert_eq!(peer_a.transport_config.tcp_ao.as_ref().unwrap().0.len(), 2);
        assert_eq!(peer_b.transport_config.tcp_ao.as_ref().unwrap().0.len(), 1);
        assert_eq!(manager.tcp_ao_generation, old);
        assert_eq!(manager.tcp_ao_rotation.applied, old);
    }

    #[tokio::test]
    async fn same_generation_recovery_clears_global_and_peer_accept_fences() {
        let old = TcpAoRotationGeneration::STARTUP;
        let recovered = old.next().unwrap();
        let staged = || TcpAoRotationStatus {
            desired: recovered,
            applied: recovered,
            phase: TcpAoRotationPhase::AddOnly,
            last_error: Some("lost listener commit acknowledgement".to_string()),
        };
        let (_manager_tx, manager_rx) = mpsc::channel(4);
        let (rib_tx, _rib_rx) = mpsc::channel(4);
        let mut manager = PeerManager::new(
            manager_rx,
            65_001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        manager.tcp_ao_generation = recovered;
        manager.tcp_ao_rotation = staged();
        let keyring = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let peer = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            // A same-generation recovery must only repair bookkeeping; it
            // must not re-send the already acknowledged socket mutation.
            rotation_peer_handle(Err(PeerCommandError::CommandFailed(
                "same-generation mutation was unexpectedly replayed".to_string(),
            ))),
            keyring.clone(),
        );
        manager.peers.get_mut(&peer).unwrap().tcp_ao_rotation = staged();

        manager
            .apply_tcp_ao_add_only(recovered, &[], &[(peer.clone(), keyring)])
            .await
            .unwrap();

        for status in [
            &manager.tcp_ao_rotation,
            &manager.peers[&peer].tcp_ao_rotation,
        ] {
            assert_eq!(status.desired, recovered);
            assert_eq!(status.applied, recovered);
            assert_eq!(status.phase, TcpAoRotationPhase::Idle);
            assert!(status.last_error.is_none());
        }
    }
}
