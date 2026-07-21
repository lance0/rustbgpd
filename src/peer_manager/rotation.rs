use std::net::IpAddr;

use futures::future::join_all;
use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_transport::{
    PeerCommand, TcpAoKeyring, TcpAoListenerKey, TcpAoRotationGeneration, TcpAoRotationOperation,
    TcpAoRotationOwner, TcpAoRotationPhase, TcpAoRotationStatus, TcpAoSessionGeneration,
    TcpAoSessionSelection,
};
use tokio::sync::{mpsc, oneshot};

use super::{ManagedPeer, PEER_LIFECYCLE_COMMAND_TIMEOUT, PeerManager, TcpAoDesiredInventory};

type SessionApplyPlan = Vec<(
    PeerKey,
    TcpAoSessionGeneration,
    Vec<mpsc::Sender<PeerCommand>>,
)>;

struct SessionSelectionPlanEntry {
    peer: PeerKey,
    desired: TcpAoSessionSelection,
    sessions: Vec<mpsc::Sender<PeerCommand>>,
    selection_changed: bool,
}

type SessionSelectionPlan = Vec<SessionSelectionPlanEntry>;

pub(crate) const TCP_AO_AWAITING_PEER_PREFIX: &str = "awaiting_peer:";

fn canonical_desired_inventory(
    generation: TcpAoRotationGeneration,
    operation: TcpAoRotationOperation,
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
        operation,
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

fn selected_owner_for_peer(
    listener_keys: &[TcpAoListenerKey],
    address: IpAddr,
) -> Option<rustbgpd_transport::listener::TcpAoSelectedOwner> {
    let host_prefix = if address.is_ipv4() { 32 } else { 128 };
    if let Some(owner) = listener_keys.iter().find(|owner| {
        owner.owner == rustbgpd_transport::TcpAoListenerOwnerKind::Static
            && owner.peer == address
            && owner.prefix_len == host_prefix
    }) {
        return Some(owner.into());
    }
    (0..=host_prefix).rev().find_map(|prefix_len| {
        listener_keys
            .iter()
            .find(|owner| {
                owner.owner == rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic
                    && owner.prefix_len == prefix_len
                    && owner_covers(owner, address)
            })
            .map(Into::into)
    })
}

fn keyring_is_append_only(current: &TcpAoKeyring, desired: &TcpAoKeyring) -> bool {
    desired.0.starts_with(&current.0) && desired.selected() == current.selected()
}

fn key_core_eq(
    current: &rustbgpd_transport::TcpAoConfig,
    desired: &rustbgpd_transport::TcpAoConfig,
) -> bool {
    current.key == desired.key
        && current.send_id == desired.send_id
        && current.recv_id == desired.recv_id
        && current.algorithm == desired.algorithm
}

fn managed_selected_owner(
    peer: &PeerKey,
    managed: &ManagedPeer,
) -> rustbgpd_transport::listener::TcpAoSelectedOwner {
    if let Some(range) = managed.accepted_dynamic_range.as_ref() {
        rustbgpd_transport::listener::TcpAoSelectedOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
            peer: range.addr,
            prefix_len: range.prefix_len,
        }
    } else {
        rustbgpd_transport::listener::TcpAoSelectedOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Static,
            peer: peer.address,
            prefix_len: if peer.address.is_ipv4() { 32 } else { 128 },
        }
    }
}

fn peer_selection_changed(
    peer: &PeerKey,
    managed: &ManagedPeer,
    desired: &TcpAoSessionSelection,
) -> Result<bool, String> {
    let desired_owner = desired.accepted_selected_owner.ok_or_else(|| {
        format!("TCP-AO selection lacks an explicit desired owner for peer {peer:?}")
    })?;
    let desired_ring = desired
        .accepted_owners
        .iter()
        .find(|owner| {
            owner.owner == desired_owner.owner
                && owner.peer == desired_owner.peer
                && owner.prefix_len == desired_owner.prefix_len
        })
        .map(|owner| &owner.keyring)
        .or(desired.active_keyring.as_ref())
        .ok_or_else(|| format!("TCP-AO selection lacks a desired keyring for peer {peer:?}"))?;
    let current_ring = managed.transport_config.tcp_ao.as_ref().ok_or_else(|| {
        format!("protected peer {peer:?} lacks its current selected-owner keyring")
    })?;
    let current_key = current_ring
        .selected()
        .ok_or_else(|| format!("protected peer {peer:?} lacks a current selectable TCP-AO key"))?;
    let desired_key = desired_ring
        .selected()
        .ok_or_else(|| format!("protected peer {peer:?} lacks a desired selectable TCP-AO key"))?;
    Ok(managed_selected_owner(peer, managed) != desired_owner
        || !key_core_eq(current_key, desired_key))
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
    let active_keyring = if is_dynamic {
        selected_owner_for_peer(listener_keys, peer.address).and_then(|selected| {
            listener_keys
                .iter()
                .find(|owner| {
                    owner.owner == selected.owner
                        && owner.peer == selected.peer
                        && owner.prefix_len == selected.prefix_len
                })
                .map(|owner| owner.config.clone())
        })
    } else {
        static_keyrings
            .iter()
            .find(|(candidate, _)| candidate == peer)
            .map(|(_, keyring)| keyring.clone())
    };
    let accepted_owners = listener_keys
        .iter()
        .filter(|owner| owner_covers(owner, peer.address))
        .map(|owner| TcpAoRotationOwner {
            owner: owner.owner,
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

fn selection_target_for_peer(
    peer: &PeerKey,
    is_dynamic: bool,
    listener_keys: &[TcpAoListenerKey],
    static_keyrings: &[(PeerKey, TcpAoKeyring)],
    generation: TcpAoRotationGeneration,
) -> Result<TcpAoSessionSelection, String> {
    let target = target_for_peer(peer, is_dynamic, listener_keys, static_keyrings, generation);
    let accepted_selected_owner = selected_owner_for_peer(listener_keys, peer.address)
        .or_else(|| {
            (!is_dynamic).then_some(rustbgpd_transport::listener::TcpAoSelectedOwner {
                owner: rustbgpd_transport::TcpAoListenerOwnerKind::Static,
                peer: peer.address,
                prefix_len: if peer.address.is_ipv4() { 32 } else { 128 },
            })
        })
        .ok_or_else(|| format!("TCP-AO selection has no explicit owner for peer {peer:?}"))?;
    Ok(TcpAoSessionSelection {
        generation,
        active_keyring: target.active_keyring,
        accepted_owners: target.accepted_owners,
        accepted_selected_owner: Some(accepted_selected_owner),
    })
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

async fn reset_affected_selection_cohort(
    plan: &SessionSelectionPlan,
    generation: TcpAoRotationGeneration,
) -> Vec<String> {
    let resets = plan
        .iter()
        .filter(|entry| entry.selection_changed)
        .map(|entry| reset_sessions_after_failed_mutation(&entry.sessions, generation));
    join_all(resets).await.into_iter().flatten().collect()
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

async fn preflight_selection_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionSelection,
) -> Result<(), String> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::PreflightTcpAoSelection { desired, reply }),
    )
    .await
    .map_err(|_| "TCP-AO selection preflight delivery timed out".to_string())?
    .map_err(|_| "TCP-AO session task exited before selection preflight".to_string())?;
    tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| "TCP-AO selection preflight acknowledgement timed out".to_string())?
        .map_err(|_| "TCP-AO selection preflight acknowledgement dropped".to_string())?
        .map_err(|error| error.to_string())
}

async fn apply_selection_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionSelection,
) -> Result<(), SessionApplyFailure> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::ApplyTcpAoSelection { desired, reply }),
    )
    .await
    .map_err(|_| SessionApplyFailure::before_mutation("TCP-AO selection delivery timed out"))?
    .map_err(|_| {
        SessionApplyFailure::before_mutation("TCP-AO session task exited before selection apply")
    })?;
    let response = tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| {
            SessionApplyFailure::after_delivery("TCP-AO selection acknowledgement timed out")
        })?
        .map_err(|_| {
            SessionApplyFailure::after_delivery("TCP-AO selection acknowledgement dropped")
        })?;
    response.map_err(|error| SessionApplyFailure {
        mutation_may_have_started: matches!(
            &error,
            rustbgpd_transport::PeerCommandError::TcpAoMutationFailed(_)
        ),
        message: error.to_string(),
    })
}

enum SessionObservation {
    Observed,
    Awaiting(String),
}

async fn observe_selection_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionSelection,
) -> Result<SessionObservation, String> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::ObserveTcpAoSelection { desired, reply }),
    )
    .await
    .map_err(|_| "TCP-AO selection observation delivery timed out".to_string())?
    .map_err(|_| "TCP-AO session task exited before selection observation".to_string())?;
    let result = tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| "TCP-AO selection observation acknowledgement timed out".to_string())?
        .map_err(|_| "TCP-AO selection observation acknowledgement dropped".to_string())?;
    match result {
        Ok(()) => Ok(SessionObservation::Observed),
        Err(rustbgpd_transport::PeerCommandError::TcpAoAwaitingPeer(error)) => {
            Ok(SessionObservation::Awaiting(error))
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn commit_selection_session(
    commands: mpsc::Sender<PeerCommand>,
    desired: TcpAoSessionSelection,
) -> Result<(), String> {
    let (reply, response) = oneshot::channel();
    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT,
        commands.send(PeerCommand::CommitTcpAoSelection { desired, reply }),
    )
    .await
    .map_err(|_| "TCP-AO selection metadata commit delivery timed out".to_string())?
    .map_err(|_| "TCP-AO session task exited before selection metadata commit".to_string())?;
    tokio::time::timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| "TCP-AO selection metadata commit acknowledgement timed out".to_string())?
        .map_err(|_| "TCP-AO selection metadata commit acknowledgement dropped".to_string())?
        .map_err(|error| error.to_string())
}

impl PeerManager {
    fn abort_affected_selection_cohort(&self, plan: &SessionSelectionPlan) {
        for entry in plan.iter().filter(|entry| entry.selection_changed) {
            let managed = self
                .peers
                .get(&entry.peer)
                .expect("selection plan peer remains owned");
            managed.handle.abort_for_transport_safety();
            if let Some(pending) = &managed.pending_inbound {
                pending.handle.abort_for_transport_safety();
            }
        }
    }

    pub(super) fn mark_tcp_ao_rotation_failed(
        &mut self,
        generation: TcpAoRotationGeneration,
        operation: TcpAoRotationOperation,
        error: &str,
    ) {
        let phase = match operation {
            TcpAoRotationOperation::AddOnly => TcpAoRotationPhase::AddOnlyFailed,
            TcpAoRotationOperation::Selection => TcpAoRotationPhase::SelectionFailed,
        };
        self.tcp_ao_rotation = TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_generation,
            phase,
            last_error: Some(error.to_string()),
        };
        for managed in self
            .peers
            .values_mut()
            .filter(|managed| managed.tcp_ao_protected)
        {
            managed.tcp_ao_rotation.desired = generation;
            managed.tcp_ao_rotation.phase = phase;
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

    fn build_tcp_ao_selection_plan(
        &self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<SessionSelectionPlan, String> {
        if generation != self.tcp_ao_generation && self.tcp_ao_generation.next() != Some(generation)
        {
            return Err(
                "TCP-AO selection generation is not current or the immediate applied successor"
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
            let desired = selection_target_for_peer(
                &peer,
                managed.is_dynamic,
                listener_keys,
                static_keyrings,
                generation,
            )?;
            let selection_changed = peer_selection_changed(&peer, managed, &desired)?;
            if !managed.is_dynamic && desired.active_keyring.is_none() {
                return Err(format!(
                    "TCP-AO selection omits protected static peer {peer:?}"
                ));
            }
            if managed.is_dynamic && desired.accepted_owners.is_empty() {
                return Err(format!(
                    "TCP-AO selection has no covering listener owner for peer {peer:?}"
                ));
            }
            let mut sessions = vec![managed.handle.commands_sender()];
            if let Some(pending) = &managed.pending_inbound {
                sessions.push(pending.handle.commands_sender());
            }
            plan.push(SessionSelectionPlanEntry {
                peer,
                desired,
                sessions,
                selection_changed,
            });
        }
        Ok(plan)
    }

    pub(super) async fn preflight_tcp_ao_rotation(
        &mut self,
        generation: TcpAoRotationGeneration,
        operation: TcpAoRotationOperation,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        match operation {
            TcpAoRotationOperation::AddOnly => {
                self.preflight_tcp_ao_add_only(generation, listener_keys, static_keyrings)
                    .await
            }
            TcpAoRotationOperation::Selection => {
                self.preflight_tcp_ao_selection(generation, listener_keys, static_keyrings)
                    .await
            }
        }
    }

    pub(super) async fn apply_tcp_ao_rotation(
        &mut self,
        generation: TcpAoRotationGeneration,
        operation: TcpAoRotationOperation,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        match operation {
            TcpAoRotationOperation::AddOnly => {
                self.apply_tcp_ao_add_only(generation, listener_keys, static_keyrings)
                    .await
            }
            TcpAoRotationOperation::Selection => {
                self.apply_tcp_ao_selection(generation, listener_keys, static_keyrings)
                    .await
            }
        }
    }

    async fn preflight_tcp_ao_add_only(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        let desired_inventory = canonical_desired_inventory(
            generation,
            TcpAoRotationOperation::AddOnly,
            listener_keys,
            static_keyrings,
        );
        if let Err(error) =
            retain_desired_inventory(&mut self.tcp_ao_desired_inventory, desired_inventory)
        {
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::AddOnly, &error);
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
                self.mark_tcp_ao_rotation_failed(
                    generation,
                    TcpAoRotationOperation::AddOnly,
                    &error,
                );
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
                    self.mark_tcp_ao_rotation_failed(
                        generation,
                        TcpAoRotationOperation::AddOnly,
                        &error,
                    );
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
    async fn apply_tcp_ao_add_only(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        if generation == self.tcp_ao_generation {
            if let Some(retained) = self.tcp_ao_desired_inventory.as_ref() {
                let desired = canonical_desired_inventory(
                    generation,
                    TcpAoRotationOperation::AddOnly,
                    listener_keys,
                    static_keyrings,
                );
                if retained != &desired {
                    let error =
                        "TCP-AO committed generation retry changed its immutable global inventory"
                            .to_string();
                    self.mark_tcp_ao_rotation_failed(
                        generation,
                        TcpAoRotationOperation::AddOnly,
                        &error,
                    );
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
        let desired_inventory = canonical_desired_inventory(
            generation,
            TcpAoRotationOperation::AddOnly,
            listener_keys,
            static_keyrings,
        );
        if let Err(error) =
            retain_desired_inventory(&mut self.tcp_ao_desired_inventory, desired_inventory)
        {
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::AddOnly, &error);
            return Err(error);
        }
        let plan = match self.build_tcp_ao_add_only_plan(generation, listener_keys, static_keyrings)
        {
            Ok(plan) => plan,
            Err(error) => {
                self.mark_tcp_ao_rotation_failed(
                    generation,
                    TcpAoRotationOperation::AddOnly,
                    &error,
                );
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
                let selected = selected_owner_for_peer(listener_keys, peer.address)
                    .expect("preflighted protected peer has an explicit selected owner");
                desired
                    .accepted_owners
                    .iter()
                    .find(|owner| {
                        owner.owner == selected.owner
                            && owner.peer == selected.peer
                            && owner.prefix_len == selected.prefix_len
                    })
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

    async fn preflight_tcp_ao_selection(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        let inventory = canonical_desired_inventory(
            generation,
            TcpAoRotationOperation::Selection,
            listener_keys,
            static_keyrings,
        );
        if let Err(error) = retain_desired_inventory(&mut self.tcp_ao_desired_inventory, inventory)
        {
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::Selection, &error);
            return Err(error);
        }
        let plan =
            match self.build_tcp_ao_selection_plan(generation, listener_keys, static_keyrings) {
                Ok(plan) => plan,
                Err(error) => {
                    self.mark_tcp_ao_rotation_failed(
                        generation,
                        TcpAoRotationOperation::Selection,
                        &error,
                    );
                    return Err(error);
                }
            };
        self.tcp_ao_rotation = TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_generation,
            phase: TcpAoRotationPhase::Selecting,
            last_error: None,
        };
        for entry in &plan {
            let applied = self.peers[&entry.peer].tcp_ao_rotation.applied;
            self.peers
                .get_mut(&entry.peer)
                .expect("peer came from current map")
                .tcp_ao_rotation = TcpAoRotationStatus {
                desired: generation,
                applied,
                phase: TcpAoRotationPhase::Selecting,
                last_error: None,
            };
        }
        let mut preflights = Vec::new();
        for entry in plan.iter().filter(|entry| entry.selection_changed) {
            for commands in &entry.sessions {
                let peer = entry.peer.clone();
                let desired = entry.desired.clone();
                let commands = commands.clone();
                preflights.push(async move {
                    (peer, preflight_selection_session(commands, desired).await)
                });
            }
        }
        for (peer, result) in join_all(preflights).await {
            if let Err(error) = result {
                let error = format!("TCP-AO selection preflight failed for {peer:?}: {error}");
                self.mark_tcp_ao_rotation_failed(
                    generation,
                    TcpAoRotationOperation::Selection,
                    &error,
                );
                return Err(error);
            }
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "selection deliberately separates cohort apply, observation, and metadata commit passes"
    )]
    async fn apply_tcp_ao_selection(
        &mut self,
        generation: TcpAoRotationGeneration,
        listener_keys: &[TcpAoListenerKey],
        static_keyrings: &[(PeerKey, TcpAoKeyring)],
    ) -> Result<(), String> {
        let inventory = canonical_desired_inventory(
            generation,
            TcpAoRotationOperation::Selection,
            listener_keys,
            static_keyrings,
        );
        if generation == self.tcp_ao_generation {
            if self
                .tcp_ao_desired_inventory
                .as_ref()
                .is_some_and(|retained| retained != &inventory)
            {
                let error =
                    "TCP-AO committed selection retry changed its immutable global inventory"
                        .to_string();
                self.mark_tcp_ao_rotation_failed(
                    generation,
                    TcpAoRotationOperation::Selection,
                    &error,
                );
                return Err(error);
            }
            self.tcp_ao_desired_inventory = None;
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
        if let Err(error) = retain_desired_inventory(&mut self.tcp_ao_desired_inventory, inventory)
        {
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::Selection, &error);
            return Err(error);
        }
        let plan =
            match self.build_tcp_ao_selection_plan(generation, listener_keys, static_keyrings) {
                Ok(plan) => plan,
                Err(error) => {
                    self.mark_tcp_ao_rotation_failed(
                        generation,
                        TcpAoRotationOperation::Selection,
                        &error,
                    );
                    return Err(error);
                }
            };

        for entry in &plan {
            let applied = self.peers[&entry.peer].tcp_ao_rotation.applied;
            self.peers
                .get_mut(&entry.peer)
                .expect("peer came from current map")
                .tcp_ao_rotation = TcpAoRotationStatus {
                desired: generation,
                applied,
                phase: TcpAoRotationPhase::Selecting,
                last_error: None,
            };
        }

        // Pass 1: every affected socket selects the successor and records its
        // own immediately-preceding pkt_good baseline. Independent session
        // commands run concurrently, but this whole pass completes before
        // observation begins. No declaration deprecation is committed here.
        let mut applies = Vec::new();
        for entry in plan.iter().filter(|entry| entry.selection_changed) {
            for commands in &entry.sessions {
                let peer = entry.peer.clone();
                let desired = entry.desired.clone();
                let commands = commands.clone();
                applies
                    .push(async move { (peer, apply_selection_session(commands, desired).await) });
            }
        }
        let apply_results = join_all(applies).await;
        if let Some((peer, failure)) = apply_results
            .iter()
            .find_map(|(peer, result)| result.as_ref().err().map(|error| (peer, error)))
        {
            // All affected commands were in flight together. If any command
            // succeeded, or a failing acknowledgement cannot prove mutation
            // never started, fail closed across the complete affected cohort.
            let mutation_may_have_started = apply_results.iter().any(|(_, result)| {
                result
                    .as_ref()
                    .map_or_else(|error| error.mutation_may_have_started, |()| true)
            });
            let mut reset_failures = Vec::new();
            if mutation_may_have_started {
                reset_failures = reset_affected_selection_cohort(&plan, generation).await;
                if !reset_failures.is_empty() {
                    self.abort_affected_selection_cohort(&plan);
                }
            }
            let mut detail = failure.message.clone();
            if !reset_failures.is_empty() {
                detail = format!(
                    "{detail}; fail-closed cohort reset was incomplete: {}",
                    reset_failures.join(", ")
                );
            }
            let error = format!("TCP-AO selection generation failed for {peer:?}: {detail}");
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::Selection, &error);
            return Err(error);
        }

        // Pass 2: observe the affected cohort before any session receives the
        // final metadata-only deprecation commit. Unchanged peers need no new
        // generation-relative packet proof and receive no observation command.
        let mut awaiting = std::collections::BTreeMap::<PeerKey, Vec<String>>::new();
        let mut observations = Vec::new();
        for entry in plan.iter().filter(|entry| entry.selection_changed) {
            for commands in &entry.sessions {
                let peer = entry.peer.clone();
                let desired = entry.desired.clone();
                let commands = commands.clone();
                observations.push(async move {
                    (peer, observe_selection_session(commands, desired).await)
                });
            }
        }
        let observation_results = join_all(observations).await;
        if let Some((peer, error)) = observation_results.iter().find_map(|(peer, result)| {
            result
                .as_ref()
                .err()
                .map(|error| (peer.clone(), error.clone()))
        }) {
            // Pass 1 already changed RNext across the affected cohort. A
            // terminal inventory/counter/read/delivery failure is not the
            // retryable AwaitingPeer outcome, so every affected stream must be
            // discarded before publishing SelectionFailed. If any session
            // cannot acknowledge the reset, abort all cohort tasks so no
            // potentially mutated stream remains reusable.
            let reset_failures = reset_affected_selection_cohort(&plan, generation).await;
            if !reset_failures.is_empty() {
                self.abort_affected_selection_cohort(&plan);
            }
            let mut error = format!("TCP-AO selection observation failed for {peer:?}: {error}");
            if !reset_failures.is_empty() {
                error = format!(
                    "{error}; fail-closed cohort reset was incomplete and all affected session tasks were aborted: {}",
                    reset_failures.join(", ")
                );
            }
            self.mark_tcp_ao_rotation_failed(generation, TcpAoRotationOperation::Selection, &error);
            return Err(error);
        }
        for (peer, result) in observation_results {
            if let Ok(SessionObservation::Awaiting(error)) = result {
                awaiting.entry(peer).or_default().push(error);
            }
        }
        if !awaiting.is_empty() {
            let detail = awaiting
                .iter()
                .map(|(peer, errors)| format!("{peer:?}: {}", errors.join(", ")))
                .collect::<Vec<_>>()
                .join("; ");
            self.tcp_ao_rotation = TcpAoRotationStatus {
                desired: generation,
                applied: self.tcp_ao_generation,
                phase: TcpAoRotationPhase::AwaitingPeer,
                last_error: Some(detail.clone()),
            };
            for entry in &plan {
                let status = &mut self
                    .peers
                    .get_mut(&entry.peer)
                    .expect("observed peer remains owned")
                    .tcp_ao_rotation;
                if let Some(errors) = awaiting.get(&entry.peer) {
                    status.phase = TcpAoRotationPhase::AwaitingPeer;
                    status.last_error = Some(errors.join(", "));
                } else {
                    status.phase = TcpAoRotationPhase::Selecting;
                    status.last_error = None;
                }
            }
            return Err(format!("{TCP_AO_AWAITING_PEER_PREFIX} {detail}"));
        }

        // Pass 3: observation succeeded everywhere. Commit only declaration
        // metadata on all sessions, still without deleting an MKT or setting
        // Linux Current. Unchanged sessions advance generation bookkeeping and
        // any union metadata without receiving selection/observation commands.
        let mut commits = Vec::new();
        for entry in &plan {
            for commands in &entry.sessions {
                let peer = entry.peer.clone();
                let desired = entry.desired.clone();
                let commands = commands.clone();
                commits
                    .push(async move { (peer, commit_selection_session(commands, desired).await) });
            }
        }
        for (peer, result) in join_all(commits).await {
            if let Err(error) = result {
                let error =
                    format!("TCP-AO selection metadata commit failed for {peer:?}: {error}");
                self.mark_tcp_ao_rotation_failed(
                    generation,
                    TcpAoRotationOperation::Selection,
                    &error,
                );
                return Err(error);
            }
        }

        for entry in &plan {
            let managed = self
                .peers
                .get_mut(&entry.peer)
                .expect("committed selection peer remains owned");
            managed.transport_config.tcp_ao = if managed.is_dynamic {
                let selected = entry
                    .desired
                    .accepted_selected_owner
                    .expect("preflighted selection has an explicit owner");
                entry
                    .desired
                    .accepted_owners
                    .iter()
                    .find(|owner| {
                        owner.owner == selected.owner
                            && owner.peer == selected.peer
                            && owner.prefix_len == selected.prefix_len
                    })
                    .map(|owner| owner.keyring.clone())
            } else {
                entry.desired.active_keyring.clone()
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
    fn selected_owner_prefers_static_exact_then_dynamic_lpm_without_losing_union() {
        let address: IpAddr = "192.0.2.9".parse().unwrap();
        let mut dynamic_24 = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: TcpAoKeyring(vec![key(1, 2)]),
        };
        let dynamic_32 = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: address,
            prefix_len: 32,
            config: TcpAoKeyring(vec![key(3, 4)]),
        };
        let static_exact = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Static,
            peer: address,
            prefix_len: 32,
            config: TcpAoKeyring(vec![key(5, 6)]),
        };
        assert_eq!(
            selected_owner_for_peer(
                &[dynamic_24.clone(), dynamic_32.clone(), static_exact],
                address,
            )
            .unwrap()
            .owner,
            TcpAoListenerOwnerKind::Static
        );
        assert_eq!(
            selected_owner_for_peer(&[dynamic_24.clone(), dynamic_32], address)
                .unwrap()
                .prefix_len,
            32
        );
        dynamic_24.prefix_len = 23;
        assert_eq!(
            selected_owner_for_peer(&[dynamic_24], address)
                .unwrap()
                .prefix_len,
            23
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
            TcpAoRotationOperation::AddOnly,
            std::slice::from_ref(&listener),
            &[(peer.clone(), listener.config.clone())],
        );
        let mut retained = None;
        retain_desired_inventory(&mut retained, desired.clone()).unwrap();

        let mut changed_listener = listener.clone();
        changed_listener.config.0[1].key = "changed-after-partial-apply".into();
        let changed = canonical_desired_inventory(
            generation,
            TcpAoRotationOperation::AddOnly,
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

    fn selection_peer_handle(
        label: &'static str,
        order: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        await_first_observation: bool,
        reject_selection_commands: bool,
    ) -> PeerHandle {
        let (commands, mut rx) = mpsc::channel(8);
        let observations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_observations = observations.clone();
        let task = tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    PeerCommand::PreflightTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("preflight-{label}"));
                        let result = if reject_selection_commands {
                            Err(PeerCommandError::CommandFailed(format!(
                                "unchanged peer {label} received selection preflight"
                            )))
                        } else {
                            Ok(())
                        };
                        let _ = reply.send(result);
                    }
                    PeerCommand::ApplyTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("apply-{label}"));
                        let result = if reject_selection_commands {
                            Err(PeerCommandError::CommandFailed(format!(
                                "unchanged peer {label} received selection apply"
                            )))
                        } else {
                            Ok(())
                        };
                        let _ = reply.send(result);
                    }
                    PeerCommand::ObserveTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("observe-{label}"));
                        let attempt =
                            task_observations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let result = if reject_selection_commands {
                            Err(PeerCommandError::CommandFailed(format!(
                                "unchanged peer {label} received selection observation"
                            )))
                        } else if await_first_observation && attempt == 0 {
                            Err(PeerCommandError::TcpAoAwaitingPeer(
                                "injected generation-relative observation miss".to_string(),
                            ))
                        } else {
                            Ok(())
                        };
                        let _ = reply.send(result);
                    }
                    PeerCommand::CommitTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("commit-{label}"));
                        let _ = reply.send(Ok(()));
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

    fn selection_preflight_barrier_peer_handle(
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    ) -> PeerHandle {
        let (commands, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    PeerCommand::PreflightTcpAoSelection { reply, .. } => {
                        barrier.wait().await;
                        let _ = reply.send(Ok(()));
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

    fn selection_apply_reset_peer_handle(
        label: &'static str,
        order: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        apply_result: Result<(), PeerCommandError>,
        observation_result: Result<(), PeerCommandError>,
        drop_reset_ack: bool,
    ) -> PeerHandle {
        let (commands, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    PeerCommand::ApplyTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("apply-{label}"));
                        let _ = reply.send(apply_result.clone());
                    }
                    PeerCommand::ObserveTcpAoSelection { reply, .. } => {
                        order.lock().unwrap().push(format!("observe-{label}"));
                        let _ = reply.send(observation_result.clone());
                    }
                    PeerCommand::ResetTcpAoAfterFailedMutation { reply, .. } => {
                        order.lock().unwrap().push(format!("reset-{label}"));
                        if drop_reset_ack {
                            drop(reply);
                            break;
                        }
                        let _ = reply.send(());
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
    #[expect(
        clippy::too_many_lines,
        reason = "load-bearing cohort proof keeps changed and unchanged peer setup, retry, and commit ordering together"
    )]
    async fn selection_observes_affected_cohort_before_metadata_commit_and_retries_same_generation()
    {
        let old = TcpAoRotationGeneration::STARTUP;
        let generation = old.next().unwrap();
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
        let current = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let mut desired = current.clone();
        desired.0[0].deprecated = true;
        desired.0[1].preferred = true;
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer_a = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            selection_peer_handle("a", order.clone(), false, false),
            current.clone(),
        );
        let peer_b = install_rotation_peer(
            &mut manager,
            "192.0.2.2".parse().unwrap(),
            2,
            selection_peer_handle("b", order.clone(), true, false),
            current,
        );
        // This peer's implicit first-nondeprecated selection is unchanged.
        // It must advance generation metadata without any low-level selection
        // preflight, RNext apply, or generation-relative observation.
        let unchanged = TcpAoKeyring(vec![key(7, 17)]);
        let peer_c = install_rotation_peer(
            &mut manager,
            "192.0.2.3".parse().unwrap(),
            3,
            selection_peer_handle("c", order.clone(), false, true),
            unchanged.clone(),
        );
        let listener_keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_a.address,
                prefix_len: 32,
                config: desired.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_b.address,
                prefix_len: 32,
                config: desired.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_c.address,
                prefix_len: 32,
                config: unchanged.clone(),
            },
        ];
        let static_keyrings = vec![
            (peer_a.clone(), desired.clone()),
            (peer_b.clone(), desired.clone()),
            (peer_c.clone(), unchanged.clone()),
        ];

        manager
            .preflight_tcp_ao_selection(generation, &listener_keys, &static_keyrings)
            .await
            .unwrap();
        let preflight_order = order.lock().unwrap().clone();
        assert!(preflight_order.iter().any(|step| step == "preflight-a"));
        assert!(preflight_order.iter().any(|step| step == "preflight-b"));
        assert!(!preflight_order.iter().any(|step| step == "preflight-c"));

        let first = manager
            .apply_tcp_ao_selection(generation, &listener_keys, &static_keyrings)
            .await
            .unwrap_err();
        assert!(first.starts_with(TCP_AO_AWAITING_PEER_PREFIX));
        assert_eq!(manager.tcp_ao_generation, old);
        assert_eq!(
            manager.tcp_ao_rotation.phase,
            TcpAoRotationPhase::AwaitingPeer
        );
        assert!(
            order
                .lock()
                .unwrap()
                .iter()
                .all(|step| !step.starts_with("commit"))
        );
        assert!(
            order
                .lock()
                .unwrap()
                .iter()
                .all(|step| !["preflight-c", "apply-c", "observe-c"].contains(&step.as_str()))
        );

        manager
            .apply_tcp_ao_selection(generation, &listener_keys, &static_keyrings)
            .await
            .unwrap();
        let order = order.lock().unwrap().clone();
        let first_commit = order
            .iter()
            .position(|step| step.starts_with("commit"))
            .unwrap();
        let last_observe = order
            .iter()
            .rposition(|step| step.starts_with("observe"))
            .unwrap();
        assert!(first_commit > last_observe);
        assert!(order.iter().any(|step| step == "commit-c"));
        assert!(
            order
                .iter()
                .all(|step| !["preflight-c", "apply-c", "observe-c"].contains(&step.as_str()))
        );
        assert_eq!(manager.tcp_ao_generation, generation);
        assert_eq!(manager.tcp_ao_rotation.phase, TcpAoRotationPhase::Idle);
        assert_eq!(
            manager.peers[&peer_a]
                .transport_config
                .tcp_ao
                .as_ref()
                .unwrap(),
            &desired
        );
        assert_eq!(
            manager.peers[&peer_c]
                .transport_config
                .tcp_ao
                .as_ref()
                .unwrap(),
            &unchanged
        );
    }

    #[tokio::test]
    async fn selection_preflight_dispatches_affected_cohort_concurrently() {
        let old = TcpAoRotationGeneration::STARTUP;
        let generation = old.next().unwrap();
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
        let current = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let mut desired = current.clone();
        desired.0[0].deprecated = true;
        desired.0[1].preferred = true;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let peer_a = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            selection_preflight_barrier_peer_handle(barrier.clone()),
            current.clone(),
        );
        let peer_b = install_rotation_peer(
            &mut manager,
            "192.0.2.2".parse().unwrap(),
            2,
            selection_preflight_barrier_peer_handle(barrier),
            current,
        );
        let listener_keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_a.address,
                prefix_len: 32,
                config: desired.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_b.address,
                prefix_len: 32,
                config: desired.clone(),
            },
        ];
        let static_keyrings = vec![(peer_a, desired.clone()), (peer_b, desired.clone())];

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            manager.preflight_tcp_ao_selection(generation, &listener_keys, &static_keyrings),
        )
        .await
        .expect("both preflight commands must be in flight before either reply")
        .unwrap();
    }

    #[tokio::test]
    async fn concurrent_selection_apply_failure_resets_every_affected_session() {
        let old = TcpAoRotationGeneration::STARTUP;
        let generation = old.next().unwrap();
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
        let current = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let mut desired = current.clone();
        desired.0[0].deprecated = true;
        desired.0[1].preferred = true;
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer_a = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            selection_apply_reset_peer_handle("a", order.clone(), Ok(()), Ok(()), false),
            current.clone(),
        );
        let peer_b = install_rotation_peer(
            &mut manager,
            "192.0.2.2".parse().unwrap(),
            2,
            selection_apply_reset_peer_handle(
                "b",
                order.clone(),
                Err(PeerCommandError::TcpAoMutationFailed(
                    "injected concurrent mutation failure".to_string(),
                )),
                Ok(()),
                false,
            ),
            current,
        );
        let listener_keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_a.address,
                prefix_len: 32,
                config: desired.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_b.address,
                prefix_len: 32,
                config: desired.clone(),
            },
        ];
        let static_keyrings = vec![(peer_a, desired.clone()), (peer_b, desired.clone())];

        let error = manager
            .apply_tcp_ao_selection(generation, &listener_keys, &static_keyrings)
            .await
            .unwrap_err();
        assert!(error.contains("injected concurrent mutation failure"));
        assert_eq!(
            manager.tcp_ao_rotation.phase,
            TcpAoRotationPhase::SelectionFailed
        );
        let order = order.lock().unwrap();
        assert!(order.iter().any(|step| step == "apply-a"));
        assert!(order.iter().any(|step| step == "apply-b"));
        // With concurrent dispatch, A may already have mutated before B's
        // failure arrives. Resetting only B would leave an uncommitted RNext
        // live on A, so both affected sessions must fail closed.
        assert!(order.iter().any(|step| step == "reset-a"));
        assert!(order.iter().any(|step| step == "reset-b"));
    }

    #[tokio::test]
    async fn terminal_selection_observation_failure_resets_or_aborts_entire_affected_cohort() {
        let old = TcpAoRotationGeneration::STARTUP;
        let generation = old.next().unwrap();
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
        let current = TcpAoKeyring(vec![key(1, 11), key(2, 12)]);
        let mut desired = current.clone();
        desired.0[0].deprecated = true;
        desired.0[1].preferred = true;
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer_a = install_rotation_peer(
            &mut manager,
            "192.0.2.1".parse().unwrap(),
            1,
            selection_apply_reset_peer_handle("a", order.clone(), Ok(()), Ok(()), false),
            current.clone(),
        );
        let peer_b = install_rotation_peer(
            &mut manager,
            "192.0.2.2".parse().unwrap(),
            2,
            selection_apply_reset_peer_handle(
                "b",
                order.clone(),
                Ok(()),
                Err(PeerCommandError::CommandFailed(
                    "injected terminal authentication-counter failure".to_string(),
                )),
                true,
            ),
            current,
        );
        let listener_keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_a.address,
                prefix_len: 32,
                config: desired.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: peer_b.address,
                prefix_len: 32,
                config: desired.clone(),
            },
        ];
        let static_keyrings = vec![
            (peer_a.clone(), desired.clone()),
            (peer_b.clone(), desired.clone()),
        ];

        let error = manager
            .apply_tcp_ao_selection(generation, &listener_keys, &static_keyrings)
            .await
            .unwrap_err();
        assert!(error.contains("injected terminal authentication-counter failure"));
        assert!(error.contains("all affected session tasks were aborted"));
        assert_eq!(
            manager.tcp_ao_rotation.phase,
            TcpAoRotationPhase::SelectionFailed
        );
        let order = order.lock().unwrap().clone();
        for step in [
            "apply-a",
            "apply-b",
            "observe-a",
            "observe-b",
            "reset-a",
            "reset-b",
        ] {
            assert!(order.iter().any(|actual| actual == step), "missing {step}");
        }
        tokio::task::yield_now().await;
        // B dropped its reset acknowledgement. Without the coarse abort
        // backstop, A's successfully mutated stream could remain live and be
        // reused after a terminal observation failure.
        assert!(manager.peers[&peer_a].handle.is_finished());
        assert!(manager.peers[&peer_b].handle.is_finished());
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
