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

impl RibManager {
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
