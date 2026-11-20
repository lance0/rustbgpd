//! Keep config intents and session ends in admission order without buffering
//! any primary route updates. The pending writer's old policy remains
//! authoritative.
use super::{PeerId, RibManager, RibUpdate};
use rustbgpd_telemetry::metrics::RibActorTurnKind;

// Each intent can carry a whole policy batch. Keep this window small even
// when the route-ingest mailbox has thousands of slots.
const MAX_DEFERRED_INTENTS: usize = 8;

pub(super) enum Intake {
    Apply,
    Retain,
    Hold,
}

fn operation(mut message: &RibUpdate) -> &RibUpdate {
    loop {
        match message {
            RibUpdate::SessionRoutes { routes, .. } => message = routes,
            #[cfg(feature = "bench-internals")]
            RibUpdate::BenchVpnAdmissionWithCredit { update, .. } => message = update,
            _ => return message,
        }
    }
}

fn session_end(message: &RibUpdate) -> bool {
    matches!(
        message,
        RibUpdate::PeerDown { .. }
            | RibUpdate::PeerGracefulRestart { .. }
            | RibUpdate::LateSessionEnd(_)
    )
}

fn plain_route_input(message: &RibUpdate) -> bool {
    match message {
        RibUpdate::WireRoutesReceived(batch) => {
            batch.flowspec_announced.is_empty() && batch.flowspec_withdrawn.is_empty()
        }
        RibUpdate::RoutesReceived {
            flowspec_announced,
            flowspec_withdrawn,
            ..
        } => flowspec_announced.is_empty() && flowspec_withdrawn.is_empty(),
        RibUpdate::VpnRoutesReceived { .. } | RibUpdate::LabeledRoutesReceived { .. } => true,
        _ => false,
    }
}

impl RibManager {
    pub(super) fn session_end_retained(&self) -> bool {
        self.first_group_deferred_intents.iter().any(session_end)
    }

    /// Give the pending owner every turn so that a retained session end
    /// replays next. Without an owner the replay is already due at the next
    /// turn and nothing would clear the seal.
    pub(super) fn seal_behind_retained_session_end(&mut self) -> bool {
        let seal = self.session_end_retained()
            && (self.first_group_pending_writer().is_some()
                || self.optional_destination_retirement_active());
        if seal {
            self.seal_first_group_commit_frontier();
        }
        seal
    }

    /// Intake for the primary FIFO. Only unicast, labeled, VPN and EVPN route
    /// input from other peers' sessions passes a retained session end.
    /// Everything else holds the head, as it did behind a held end: reads and
    /// commands can be teardown barriers, an End-of-RIB can release a
    /// selection deferral the teardown would re-arm, and a `FlowSpec` rule
    /// can be validated against the ended session's unicast route.
    pub(super) fn first_group_primary_intake(&self, message: &RibUpdate) -> Intake {
        let intake = self.first_group_intake(message);
        if !self.session_end_retained() || self.first_group_replay_due() {
            return intake;
        }
        let next = operation(message);
        let passes = match intake {
            Intake::Apply => plain_route_input(next),
            // Policy commands and session ends replay in admission order. A
            // family unlock or slow-state clear changes what later route
            // input exports, so it keeps the FIFO behind it.
            Intake::Retain => next.actor_turn_kind() != RibActorTurnKind::PeerState,
            Intake::Hold => true,
        };
        if passes { intake } else { Intake::Hold }
    }

    pub(super) fn first_group_replay_due(&self) -> bool {
        (!self.first_group_deferred_intents.is_empty() || self.first_group_general_head.is_some())
            && self.first_group_pending_writer().is_none()
            && !self.optional_destination_retirement_active()
    }

    /// The actor serves these before accepting new primary work, honoring its
    /// ordinary transition and delivery fences. Their admission was charged
    /// when received, including for an intent coexisting with a commit cutoff.
    pub(super) fn take_first_group_deferred_intent(&mut self) -> Option<RibUpdate> {
        if !self.first_group_replay_due() || !self.pending_route_batches.is_empty() {
            return None;
        }
        self.first_group_deferred_intents
            .pop_front()
            .or_else(|| self.first_group_general_head.take().map(|head| *head))
    }

    /// Shared by both lanes. The general lane has no order against the
    /// primary FIFO, so its reads are not held behind a retained session end.
    /// A hold leaves the complete original envelope at head.
    pub(super) fn first_group_intake(&self, message: &RibUpdate) -> Intake {
        let writer = self.first_group_pending_writer().map(operation);
        let retiring_optional = self.optional_destination_retirement_active();
        if writer.is_none() && !retiring_optional {
            return Intake::Apply;
        }
        // A held general head was admitted after the retained intents. A
        // replayed intent can own another preparation before that head runs.
        // Keep newer admissions behind it across both preparations.
        if self.first_group_general_head.is_some() {
            return Intake::Hold;
        }
        let next = operation(message);
        let kind = next.actor_turn_kind();
        let room = self.first_group_deferred_intents.len()
            < self.rx.max_capacity().min(MAX_DEFERRED_INTENTS);
        // A late writer may rebuild the evicted table. Keep its original
        // request and reply until the last allocation releases the slot.
        if kind == RibActorTurnKind::OutboundPolicy
            || (retiring_optional
                && matches!(
                    next,
                    RibUpdate::PeerSlowState { slow: false, .. }
                        | RibUpdate::PeerFamilySendable { .. }
                ))
        {
            return if room { Intake::Retain } else { Intake::Hold };
        }
        // A session end is one small message that only has to follow the
        // writer and its own peer's earlier input. Holding it at the FIFO head
        // would make every other peer's routes wait for the rest of the build.
        // Retained, it replays in admission order after the writer commits,
        // and the peer check below keeps that peer's later messages behind it.
        let behind_writer = if room && session_end(next) {
            Intake::Retain
        } else {
            Intake::Hold
        };
        let peer = match next {
            RibUpdate::PeerDeleted { peer, .. }
            | RibUpdate::ReleasePeer { peer }
            | RibUpdate::RebindPeer { peer, .. }
            | RibUpdate::RefreshPeerOutbound { peer, .. }
            | RibUpdate::ReplayPeerOutbound { peer, .. }
            | RibUpdate::ConfirmPeerOutbound { peer, .. } => Some(*peer),
            _ => next.session_peer(),
        };
        // Even a route receipt/EoR from this session follows its older
        // family activation or slow-state change. Other routes can enter the
        // normal old-policy distribution pass before commit.
        if let Some(peer) = peer
            && (writer.and_then(RibUpdate::session_peer) == Some(peer)
                || self
                    .first_group_deferred_intents
                    .iter()
                    .any(|intent| intent.session_peer() == Some(peer)))
        {
            return behind_writer;
        }
        if matches!(
            kind,
            RibActorTurnKind::Routes | RibActorTurnKind::EndOfRib | RibActorTurnKind::Query
        ) {
            return Intake::Apply;
        }
        if matches!(
            next,
            RibUpdate::BeginClose | RibUpdate::RetireEorGraceInterface { .. }
        ) {
            return Intake::Hold;
        }
        if let Some(peer) = peer
            && (writer
                .is_some_and(|writer| self.first_group_writer_affects_peer(writer, peer, next))
                || self.first_group_deferred_intents.iter().any(|intent| {
                    self.first_group_writer_affects_peer(operation(intent), peer, next)
                })
                || self
                    .first_group_build
                    .as_ref()
                    .is_some_and(|job| self.mutation_targets_first_group(next, job.gid)))
        {
            return behind_writer;
        }
        Intake::Apply
    }

    fn first_group_writer_affects_peer(
        &self,
        writer: &RibUpdate,
        peer: PeerId,
        next: &RibUpdate,
    ) -> bool {
        let attached = |attachments: &std::collections::BTreeMap<
            crate::PeerEndpoint,
            Vec<std::sync::Arc<str>>,
        >| {
            self.peer_has_conditional_advertisements(peer)
                || peer
                    .endpoint()
                    .is_some_and(|endpoint| attachments.contains_key(&endpoint))
                || matches!(next, RibUpdate::RebindPeer { .. })
        };
        match writer {
            RibUpdate::ReplacePeerExportPolicy { peer: target, .. }
            | RibUpdate::PrepareExportPolicyDestination { peer: target, .. }
            | RibUpdate::DiscardPreparedExportPolicyDestination { peer: target, .. } => {
                *target == peer
            }
            RibUpdate::ReplacePeerExportPolicies { replacements, .. }
            | RibUpdate::ReplacePeerExportPoliciesAuthoritatively { replacements, .. }
            | RibUpdate::ApplyPacedExportPolicies { replacements, .. }
            | RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. }
            | RibUpdate::RestorePacedExportPolicies { replacements, .. } => {
                replacements.iter().any(|r| r.peer == peer)
            }
            RibUpdate::ReevaluatePeerExportPolicies { peers, .. } => peers.contains(&peer),
            RibUpdate::InstallConditionalAdvertisements { set, .. } => attached(&set.attachments),
            RibUpdate::RestoreConditionalAdvertisements { capture, .. } => {
                attached(&capture.attachments)
            }
            RibUpdate::ReobserveConditionalAdvertisements { .. }
            | RibUpdate::PrepareOutboundPrefixLimits { .. }
            | RibUpdate::ApplyOutboundPrefixLimits { .. } => true,
            _ => writer.session_peer() == Some(peer),
        }
    }

    pub(super) fn first_group_allows_lookahead(&mut self) -> bool {
        if self.first_group_replay_due() {
            return false;
        }
        if self
            .primary_lookahead
            .as_ref()
            .is_some_and(|head| matches!(self.first_group_primary_intake(head), Intake::Hold))
        {
            self.seal_first_group_commit_frontier();
            return false;
        }
        true
    }
}
