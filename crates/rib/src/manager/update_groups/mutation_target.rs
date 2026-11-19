//! Detect a writer that needs the destination of a private registration build.
//! Project its proposed change before the handler changes any installed state.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustbgpd_wire::{Afi, Safi};

use super::RibManager;
use crate::update::RibUpdate;
use crate::{PeerEndpoint, PeerId};

#[derive(Clone, Copy)]
enum MembershipChange {
    ClearPolicy,
    RecoverSlowPeer,
    ActivateFamily((Afi, Safi), Option<u32>),
    RemoveConditionalAttachment,
}

enum SlotTarget {
    Held,
    Occupied,
    Cold,
}

impl RibManager {
    /// A clean transition and the shared authoritative cohort kernel can leave
    /// a new table memberless across polls or a deferred residual walk. Check
    /// their chain-only destinations before the command acquires its fence or
    /// installs any candidate policy. Paced per-peer writes join immediately.
    pub(in crate::manager) fn policy_needs_other_build_slot(
        &mut self,
        update: &RibUpdate,
        held: usize,
    ) -> bool {
        let (replacements, clean) = match update.unmetered() {
            RibUpdate::ReplacePeerExportPolicies { replacements, .. }
                if replacements.len() >= 2 =>
            {
                (replacements, true)
            }
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            } if !reply.is_closed() => (replacements, false),
            RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. } => {
                (replacements, false)
            }
            _ => return false,
        };
        self.with_replacement_readiness(|manager| {
            // A uniform cohort repeats one source and chain. An occupied
            // destination stays occupied throughout this read-only projection.
            let mut last_occupied = None;
            let mut targets_held = false;
            let mut targets_other = false;
            for replacement in replacements {
                manager.replacement_checkpoint(false);
                let peer = replacement.peer;
                if !manager.outbound_peers.contains_key(&peer) {
                    continue;
                }
                let source_policy = (manager.grouped_member_of(peer), &replacement.export_policy);
                if last_occupied == Some(source_policy) {
                    continue;
                }
                match manager.shared_slot_target(replacement, clean, held) {
                    Some(SlotTarget::Cold) => return true,
                    Some(SlotTarget::Held) => targets_held = true,
                    Some(SlotTarget::Occupied) => {
                        targets_other = true;
                        last_occupied = Some(source_policy);
                    }
                    None => {}
                }
                // Clean requires every registered member to agree with its
                // first pair. Any disagreement hands the entire request back.
                if clean {
                    break;
                }
            }
            // The first mismatched authoritative cohort can retire a prepared
            // table that a later cohort in the same command intends to adopt.
            targets_held && targets_other && manager.prepared_destination == Some(held)
        })
    }

    /// Resolve only live table owners. Planning an abandoned write must not
    /// intern its policy or allocate a historical group ID.
    fn shared_slot_target(
        &self,
        replacement: &crate::update::PeerExportPolicyReplacement,
        clean: bool,
        held: usize,
    ) -> Option<SlotTarget> {
        let peer = replacement.peer;
        let source = self.grouped_member_of(peer)?;
        let source_group = self.group_ribs.get(&source)?;
        let source_key = self.update_groups.group_key(source)?;
        let policy = replacement.export_policy.as_ref();
        let ready = if clean {
            self.clean_policy_transition_peer_ready(peer)
        } else {
            self.shared_policy_transition_member_ready(peer)
        };
        if !ready || source_group.export_chain.as_ref() == policy || !source_key.is_unicast_only() {
            return None;
        }
        let input = self.installed_group_classifier_input(peer, policy);
        let mut key = self.no_policy_group_key(peer, input, false)?;
        key.chain = source_key.chain;
        if &key != source_key {
            return None;
        }
        key.chain = None;
        if policy.is_none() && self.update_groups.group_key(held) == Some(&key) {
            return Some(SlotTarget::Held);
        }
        for (&gid, group) in &self.group_ribs {
            self.replacement_checkpoint(false);
            if !group.members.is_empty()
                && group.export_chain.as_ref() == policy
                && self.update_groups.group_key(gid).is_some_and(|existing| {
                    key.chain = existing.chain;
                    &key == existing
                })
            {
                return Some(SlotTarget::Occupied);
            }
        }
        Some(SlotTarget::Cold)
    }

    pub(in crate::manager) fn mutation_targets_first_group(
        &self,
        update: &RibUpdate,
        gid: usize,
    ) -> bool {
        let targets = |replacements: &[crate::update::PeerExportPolicyReplacement]| {
            replacements.iter().any(|replacement| {
                replacement.export_policy.is_none()
                    && self.changed_membership_matches(
                        replacement.peer,
                        gid,
                        MembershipChange::ClearPolicy,
                    )
            })
        };
        match update.unmetered() {
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                ..
            } => {
                export_policy.is_none()
                    && self.changed_membership_matches(*peer, gid, MembershipChange::ClearPolicy)
            }
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            } => !reply.is_closed() && targets(replacements),
            RibUpdate::ApplyPacedExportPolicies {
                replacements,
                reply,
                ..
            } => !reply.is_closed() && targets(replacements),
            RibUpdate::ReplacePeerExportPolicies { replacements, .. }
            | RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. }
            | RibUpdate::RestorePacedExportPolicies { replacements, .. } => targets(replacements),
            RibUpdate::PeerSlowState {
                peer,
                session_id,
                slow: false,
            } => {
                peer.is_live()
                    && self.current_session_id(*peer) == Some(*session_id)
                    && self.slow_isolated_peers.contains(peer)
                    && self.changed_membership_matches(
                        *peer,
                        gid,
                        MembershipChange::RecoverSlowPeer,
                    )
            }
            RibUpdate::PeerFamilySendable {
                peer,
                session_id,
                family,
                add_path_send_limit,
            } => {
                peer.is_live()
                    && self.outbound_session_ids.get(peer) == Some(session_id)
                    && self.peer_sendable_families.contains_key(peer)
                    && self.live_sessions.get(peer).is_some_and(|sessions| {
                        sessions.iter().any(|record| {
                            record.session_id == *session_id
                                && !record.sendable_families.contains(family)
                        })
                    })
                    && self.changed_membership_matches(
                        *peer,
                        gid,
                        MembershipChange::ActivateFamily(*family, *add_path_send_limit),
                    )
            }
            RibUpdate::InstallConditionalAdvertisements { set, .. } => {
                self.removed_attachment_targets(gid, &set.attachments)
            }
            RibUpdate::RestoreConditionalAdvertisements { capture, .. } => {
                self.removed_attachment_targets(gid, &capture.attachments)
            }
            _ => false,
        }
    }

    fn removed_attachment_targets(
        &self,
        gid: usize,
        after: &BTreeMap<PeerEndpoint, Vec<Arc<str>>>,
    ) -> bool {
        self.outbound_peers.keys().copied().any(|peer| {
            self.peer_has_conditional_advertisements(peer)
                && peer
                    .endpoint()
                    .is_some_and(|endpoint| !after.contains_key(&endpoint))
                && self.changed_membership_matches(
                    peer,
                    gid,
                    MembershipChange::RemoveConditionalAttachment,
                )
        })
    }

    fn changed_membership_matches(
        &self,
        peer: PeerId,
        gid: usize,
        change: MembershipChange,
    ) -> bool {
        if !self.outbound_peers.contains_key(&peer)
            || self.grouped_member_of(peer) == Some(gid)
            || (!matches!(change, MembershipChange::ClearPolicy)
                && (!self.update_groups.members.contains_key(&peer)
                    || self.export_policy_for(peer).is_some()))
        {
            return false;
        }
        let mut input = self.installed_group_classifier_input(peer, None);
        match change {
            MembershipChange::ActivateFamily((afi, safi), limit) => {
                input.sendable_families.push((afi as u16, safi as u8));
                if let Some(limit) = limit {
                    input.add_path_send = limit > 0
                        || self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0;
                }
            }
            MembershipChange::RemoveConditionalAttachment => {
                input.conditional_advertisement = false;
            }
            MembershipChange::ClearPolicy | MembershipChange::RecoverSlowPeer => {}
        }
        self.no_policy_group_key(
            peer,
            input,
            matches!(change, MembershipChange::RecoverSlowPeer),
        )
        .is_some_and(|key| self.update_groups.group_key(gid) == Some(&key))
    }
}
