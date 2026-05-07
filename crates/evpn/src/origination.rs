//! Local MAC origination state machine — RFC 7432 §15.1.
//!
//! Gate 7b shipped the *receive* side of the EVPN dataplane: remote
//! Type 2 routes flow through the RIB, project into a [`crate::RemoteMacTable`]
//! (per `crate::projection`), and the kernel learns them as
//! `extern_learn` FDB entries. Gate 7b+1 closes the loop on the
//! *originate* side: when the kernel learns a new local MAC on a bridge
//! port, the daemon must emit a BGP EVPN Type 2 route advertising that
//! MAC behind this VTEP. RFC 7432 §15.1 governs how the MAC Mobility
//! extended community sequence number evolves under contention.
//!
//! # What lives here
//!
//! [`LocalMacOriginator`] is a **pure deterministic state machine** with
//! one instance per [`crate::EvpnInstance`]. It knows nothing about
//! tokio, netlink, the RIB, or path attribute encoding. Callers feed it
//! three classes of events and it returns a [`Vec<OriginationAction>`]
//! the daemon translates into `RibUpdate::InjectEvpn` /
//! `RibUpdate::WithdrawEvpn`.
//!
//! Living in `crates/evpn` keeps the whole sequencer testable on macOS
//! dev builds and isolated from the netlink-only `crates/evpn-linux`
//! per ADR-0054 §1's portability rule.
//!
//! # Inputs
//!
//! - [`LocalMacOriginator::on_local_learned`] — kernel reported a MAC
//!   on a bridge port belonging to this instance. `current_remote` is
//!   the daemon's snapshot of the best-path *non-self* remote Type 2
//!   for `(VNI, MAC)`; the daemon is responsible for filtering out
//!   self-originated routes before passing the view in.
//! - [`LocalMacOriginator::on_local_aged`] — kernel aged or deleted a
//!   previously-learned local MAC.
//! - [`LocalMacOriginator::on_remote_changed`] — RIB best-path for some
//!   `(VNI, MAC)` we already track changed (a new remote announced or
//!   withdrew). Called by the daemon's RIB-event subscription per
//!   ADR-0054 §6's level-triggered model.
//!
//! # Sequence rules (RFC 7432 §15.1)
//!
//! The sequence number is the contention-resolution mechanism:
//!
//! 1. **First advertisement, no remote ever observed.** seq=0,
//!    [`OriginationAction::Inject::mobility_seq`] is `None` so the
//!    daemon omits the MAC Mobility extended community on the wire
//!    (RFC 7432 §7.7 — absent extcomm is semantically seq=0).
//! 2. **First advertisement, contender at seq=R.** seq=R+1, emitted
//!    with the extcomm. Routes lacking the extcomm count as R=0
//!    per §15.1.
//! 3. **Already advertising at seq=N, remote announces M ≥ N.** Bump
//!    to `max(M, N) + 1` and re-emit the Inject. RFC §15.1 step 3.
//! 4. **Local-port move on a previously-advertised MAC.** Bump to
//!    `N + 1` to signal the move to peers — keeps wire-side semantics
//!    consistent with FRR/Junos local-move handling.
//! 5. **Idempotent re-Learn** (same MAC, same port, same sticky flag,
//!    same observed remote-seq history) returns an empty action vec.
//!    Prevents kernel-flap from producing UPDATE storms.
//! 6. **`on_local_aged`** emits exactly one `Withdraw` if we currently
//!    advertise the MAC, then drops `originated_key`. The state entry
//!    is **kept** so a subsequent re-Learn preserves the seq ratchet.
//!
//! # Sticky bit (RFC 7432 §15.4)
//!
//! [`OriginationAction::Inject::sticky`] is plumbed through but the
//! operator-facing static-MAC config schema is deferred to a follow-up
//! ADR. Phase A keeps the field wire-correct so tests can exercise it;
//! the daemon driver in Phase C always passes `sticky = false` until
//! that schema lands.
//!
//! # Withdraw key
//!
//! Each state entry remembers the `EvpnRouteKey` of the route we last
//! sent, so withdraws are byte-for-byte the same NLRI the peer
//! installed. Reconstruction would be brittle if instance config flips
//! mid-flight (the same MAC under a re-keyed RD would fail to withdraw).

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::{EthernetTagId, EvpnRouteKey, MacAddress, RouteDistinguisher};

use crate::EvpnInstanceId;

/// What the daemon hands the originator describing the RIB's current
/// best-path *non-self* remote Type 2 for some `(VNI, MAC)`.
///
/// The daemon must filter out self-originated routes (next-hop ==
/// `instance.local_vtep_ip`) before passing this in, so the state
/// machine never sees its own re-Inject as a contender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMacView {
    /// MAC the remote view is for.
    pub mac: MacAddress,
    /// MAC Mobility extended community sequence (RFC 7432 §7.7) on the
    /// remote route, if any. `None` is treated as seq=0 per §15.1.
    pub mobility_sequence: Option<u32>,
    /// Sticky bit on the remote route's MAC Mobility extcomm.
    pub sticky: bool,
    /// Remote VTEP next-hop. Carried for daemon-side telemetry; the
    /// state machine does not consult it.
    pub next_hop: IpAddr,
}

/// Action the daemon-side adapter must execute against the RIB.
///
/// The state machine produces these as pure values — translation to
/// `RibUpdate::InjectEvpn` / `RibUpdate::WithdrawEvpn` happens in the
/// daemon binary where path attribute construction is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginationAction {
    /// Originate (or re-originate) a Type 2 MAC advertisement.
    Inject {
        /// Local MAC being advertised.
        mac: MacAddress,
        /// MAC Mobility sequence to emit.
        ///
        /// `None` means no extended community at all (RFC 7432 §7.7 —
        /// first advertisement with no contender has no extcomm).
        /// `Some(n)` means emit the extcomm with sequence `n`.
        mobility_seq: Option<u32>,
        /// Sticky bit (RFC 7432 §15.4) — defer-flag in Gate 7b+1, but
        /// plumbed for ADR-following completeness.
        sticky: bool,
        /// NLRI key. The daemon constructs the full path attribute
        /// vector from instance config and this key.
        key: EvpnRouteKey,
    },
    /// Withdraw a previously-Inject'd MAC advertisement.
    Withdraw {
        /// MAC being withdrawn (carried for telemetry; the key is
        /// authoritative).
        mac: MacAddress,
        /// Exact key the daemon previously injected.
        key: EvpnRouteKey,
    },
}

/// Per-MAC state the originator keeps.
///
/// `our_seq` ratchets monotonically per MAC across the entry's
/// lifetime. The entry is kept after withdraw so a future re-Learn
/// can re-use the ratchet — never starts back at zero once contended.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalMacOriginationState {
    /// Last-observed bridge-port ifindex for this MAC.
    ifindex: u32,
    /// Sequence we advertised (or would advertise) for this MAC.
    our_seq: u32,
    /// Highest remote sequence we have ever observed for this MAC.
    /// `None` = no remote contender has ever appeared.
    last_seen_remote_seq: Option<u32>,
    /// Sticky bit currently in force.
    sticky: bool,
    /// Key of the route we currently have outstanding. `Some` ⇒ we are
    /// advertising; `None` ⇒ withdrawn (or never advertised).
    originated_key: Option<EvpnRouteKey>,
}

impl LocalMacOriginationState {
    /// Should the rendered Inject carry a MAC Mobility extcomm?
    ///
    /// RFC 7432 §15.1 + §7.7: emit the extcomm whenever:
    ///
    /// 1. A remote contender has ever been observed, OR
    /// 2. `sticky == true` (sticky bit lives in the extcomm), OR
    /// 3. `our_seq > 0` (we've already advanced the ratchet — e.g.
    ///    via a local-port move — and need peers to see the bumped
    ///    seq so a subsequent stale-remote-seq=0 doesn't appear to
    ///    win against us on their side).
    ///
    /// Without case (3), a local-port move that bumped `our_seq` from
    /// 0 → 1 would still emit "no extcomm" on the wire, leaving peers
    /// with the old absent-extcomm semantics (seq=0). A later stale
    /// remote at seq=0 would tie with our hidden seq=1; neither
    /// `on_remote_changed` (because `remote_seq < our_seq`) nor a fresh
    /// re-Learn would correct the wire-visible state.
    fn rendered_seq(&self) -> Option<u32> {
        if self.last_seen_remote_seq.is_some() || self.sticky || self.our_seq > 0 {
            Some(self.our_seq)
        } else {
            None
        }
    }
}

/// Per-instance origination engine. One per `EvpnInstance`.
#[derive(Debug)]
pub struct LocalMacOriginator {
    instance_id: EvpnInstanceId,
    rd: RouteDistinguisher,
    by_mac: BTreeMap<MacAddress, LocalMacOriginationState>,
}

impl LocalMacOriginator {
    /// Build a fresh originator scoped to one EVPN instance.
    #[must_use]
    pub fn new(instance_id: EvpnInstanceId, rd: RouteDistinguisher) -> Self {
        Self {
            instance_id,
            rd,
            by_mac: BTreeMap::new(),
        }
    }

    /// VNI this originator owns.
    #[must_use]
    pub fn instance_id(&self) -> EvpnInstanceId {
        self.instance_id
    }

    /// Current count of locally-tracked MACs (advertising + withdrawn).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_mac.len()
    }

    /// `true` if this originator has no MACs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_mac.is_empty()
    }

    /// Number of MACs currently advertising (`originated_key` is `Some`).
    #[must_use]
    pub fn advertised_count(&self) -> usize {
        self.by_mac
            .values()
            .filter(|s| s.originated_key.is_some())
            .count()
    }

    /// Build the wire-shaped key for `mac`.
    ///
    /// Gate 7b+1 originates the IP-less Type 2 ("MAC-only") shape —
    /// `ip = None` — because the kernel-side observation channel
    /// (`RTNLGRP_NEIGH AF_BRIDGE`) does not surface host IPs. `ARP`/`ND`
    /// suppression learning is deferred.
    fn key(&self, mac: MacAddress) -> EvpnRouteKey {
        EvpnRouteKey::MacIp {
            rd: self.rd,
            ethernet_tag: EthernetTagId(0),
            mac,
            ip: None,
        }
    }

    /// Drain the current set of (advertising) state into a snapshot the
    /// daemon can replay on shutdown to issue a final withdraw burst.
    ///
    /// Caller decides whether the originator is being torn down or just
    /// flushed — this method does NOT clear state.
    pub fn outstanding_keys(&self) -> impl Iterator<Item = (MacAddress, EvpnRouteKey)> + '_ {
        self.by_mac
            .iter()
            .filter_map(|(&mac, s)| s.originated_key.map(|k| (mac, k)))
    }

    /// Clear all state and return the Withdraw actions that drain the
    /// currently-advertised set. Used by the daemon's coordinated
    /// shutdown drain.
    pub fn drain_to_withdraws(&mut self) -> Vec<OriginationAction> {
        let mut out = Vec::with_capacity(self.advertised_count());
        for (mac, state) in &mut self.by_mac {
            if let Some(key) = state.originated_key.take() {
                out.push(OriginationAction::Withdraw { mac: *mac, key });
            }
        }
        out
    }

    /// React to a kernel learn event for a local MAC.
    pub fn on_local_learned(
        &mut self,
        mac: MacAddress,
        ifindex: u32,
        sticky: bool,
        current_remote: Option<&RemoteMacView>,
    ) -> Vec<OriginationAction> {
        let key = self.key(mac);
        let prior = self.by_mac.get(&mac).cloned();

        // Step 1: integrate the remote view into last_seen_remote_seq.
        // RFC 7432 §15.1: route lacking MAC Mobility extcomm counts as
        // seq=0 for the purposes of this comparison.
        let prior_last_seen = prior.as_ref().and_then(|s| s.last_seen_remote_seq);
        let observed_now = current_remote.map(|v| v.mobility_sequence.unwrap_or(0));
        let new_last_seen = match (prior_last_seen, observed_now) {
            (None, None) => None,
            (Some(p), None) => Some(p),
            (None, Some(c)) => Some(c),
            (Some(p), Some(c)) => Some(p.max(c)),
        };

        // Step 2: figure out what seq we should advertise.
        let was_advertising = prior.as_ref().is_some_and(|s| s.originated_key.is_some());
        let prior_seq = prior.as_ref().map_or(0u32, |s| s.our_seq);
        let port_changed = prior.as_ref().is_some_and(|s| s.ifindex != ifindex);
        let sticky_changed = prior.as_ref().is_some_and(|s| s.sticky != sticky);

        // The "first advertisement ever" check is `prior.is_none()` —
        // a stricter condition than `!was_advertising`, because a MAC
        // that was previously advertised, then Aged, must preserve its
        // sequence ratchet on re-Learn (otherwise a peer that still
        // remembers our prior seq could win the contention).
        let is_first_ever = prior.is_none();
        let new_seq = match new_last_seen {
            None => {
                // No contender ever observed for this MAC.
                if is_first_ever {
                    0
                } else if was_advertising && (port_changed || sticky_changed) {
                    prior_seq + 1
                } else {
                    // Idempotent re-Learn or re-Learn after Aged with
                    // unchanged identity — preserve ratchet.
                    prior_seq
                }
            }
            Some(remote_seq) => {
                // A contender has been observed at some point.
                if is_first_ever {
                    remote_seq + 1
                } else if !was_advertising {
                    // Re-Learn after Aged with contention history —
                    // bump above contender AND above our prior seq.
                    (remote_seq + 1).max(prior_seq + 1)
                } else if remote_seq >= prior_seq {
                    remote_seq + 1
                } else if port_changed || sticky_changed {
                    prior_seq + 1
                } else {
                    prior_seq
                }
            }
        };

        // Step 3: idempotence — same observed state, no-op.
        if was_advertising
            && !port_changed
            && !sticky_changed
            && prior_seq == new_seq
            && prior_last_seen == new_last_seen
        {
            return Vec::new();
        }

        // Step 4: commit and emit.
        let new_state = LocalMacOriginationState {
            ifindex,
            our_seq: new_seq,
            last_seen_remote_seq: new_last_seen,
            sticky,
            originated_key: Some(key),
        };
        let mobility_seq = new_state.rendered_seq();
        self.by_mac.insert(mac, new_state);

        vec![OriginationAction::Inject {
            mac,
            mobility_seq,
            sticky,
            key,
        }]
    }

    /// React to a kernel age/delete event for a local MAC.
    pub fn on_local_aged(&mut self, mac: MacAddress) -> Vec<OriginationAction> {
        let Some(entry) = self.by_mac.get_mut(&mac) else {
            return Vec::new();
        };
        let Some(key) = entry.originated_key.take() else {
            return Vec::new();
        };
        // Keep the rest of the state — `our_seq` and
        // `last_seen_remote_seq` survive so re-Learn ratchets correctly.
        vec![OriginationAction::Withdraw { mac, key }]
    }

    /// React to a RIB best-path change for a tracked MAC.
    pub fn on_remote_changed(
        &mut self,
        mac: MacAddress,
        view: Option<&RemoteMacView>,
    ) -> Vec<OriginationAction> {
        let Some(entry) = self.by_mac.get_mut(&mac) else {
            // We don't track this MAC — nothing to defend.
            return Vec::new();
        };

        // Update last_seen_remote_seq from whatever the RIB shows now.
        if let Some(v) = view {
            let observed = v.mobility_sequence.unwrap_or(0);
            entry.last_seen_remote_seq = Some(match entry.last_seen_remote_seq {
                Some(p) => p.max(observed),
                None => observed,
            });
        }

        // If we're not advertising, nothing to bump — the next Learn
        // will read the updated last_seen and adjust there.
        let Some(key) = entry.originated_key else {
            return Vec::new();
        };

        // Compute whether to bump. RFC 7432 §15.1 step 3: contender at
        // M ≥ N triggers bump to max(M, N) + 1.
        let Some(v) = view else {
            return Vec::new();
        };
        let remote_seq = v.mobility_sequence.unwrap_or(0);
        if remote_seq < entry.our_seq {
            return Vec::new();
        }

        let new_seq = remote_seq.max(entry.our_seq) + 1;
        entry.our_seq = new_seq;
        let mobility_seq = entry.rendered_seq();
        let sticky = entry.sticky;

        vec![OriginationAction::Inject {
            mac,
            mobility_seq,
            sticky,
            key,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn rd(asn: u16, val: u32) -> RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        RouteDistinguisher::new(bytes)
    }

    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }

    fn fresh() -> LocalMacOriginator {
        LocalMacOriginator::new(vni(100), rd(65000, 100))
    }

    fn remote(seq: Option<u32>) -> RemoteMacView {
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: seq,
            sticky: false,
            next_hop: "10.0.0.99".parse().unwrap(),
        }
    }

    fn assert_inject(action: &OriginationAction, expected_seq: Option<u32>, expected_sticky: bool) {
        match action {
            OriginationAction::Inject {
                mobility_seq,
                sticky,
                ..
            } => {
                assert_eq!(*mobility_seq, expected_seq, "mobility_seq mismatch");
                assert_eq!(*sticky, expected_sticky, "sticky mismatch");
            }
            OriginationAction::Withdraw { .. } => {
                panic!("expected Inject, got Withdraw: {action:?}")
            }
        }
    }

    #[test]
    fn first_learned_no_remote_emits_seq_zero_no_extcomm() {
        let mut o = fresh();
        let actions = o.on_local_learned(mac(0xAA), 10, false, None);
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], None, false);
    }

    #[test]
    fn first_learned_with_remote_at_five_emits_seq_six_with_extcomm() {
        let mut o = fresh();
        let v = remote(Some(5));
        let actions = o.on_local_learned(mac(0xAA), 10, false, Some(&v));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(6), false);
    }

    #[test]
    fn first_learned_with_remote_no_extcomm_treats_as_seq_zero_emits_one() {
        // RFC 7432 §15.1: route lacking MAC Mobility extcomm is seq=0
        // for comparison — local advertisement bumps to 1.
        let mut o = fresh();
        let v = remote(None);
        let actions = o.on_local_learned(mac(0xAA), 10, false, Some(&v));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(1), false);
    }

    #[test]
    fn idempotent_relearn_returns_no_actions() {
        let mut o = fresh();
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        let actions = o.on_local_learned(mac(0xAA), 10, false, None);
        assert!(actions.is_empty(), "got {actions:?}");
    }

    #[test]
    fn aged_after_learned_emits_one_withdraw_with_stored_key() {
        let mut o = fresh();
        let learned = o.on_local_learned(mac(0xAA), 10, false, None);
        let inject_key = match &learned[0] {
            OriginationAction::Inject { key, .. } => *key,
            OriginationAction::Withdraw { .. } => panic!("learned step emitted Withdraw"),
        };
        let aged = o.on_local_aged(mac(0xAA));
        assert_eq!(aged.len(), 1);
        match &aged[0] {
            OriginationAction::Withdraw { key, mac: m } => {
                assert_eq!(*key, inject_key);
                assert_eq!(*m, mac(0xAA));
            }
            OriginationAction::Inject { .. } => panic!("aged step emitted Inject"),
        }
    }

    #[test]
    fn aged_for_unknown_mac_returns_no_actions_no_panic() {
        let mut o = fresh();
        let actions = o.on_local_aged(mac(0xBB));
        assert!(actions.is_empty());
    }

    #[test]
    fn mobility_race_bumps_when_remote_catches_up() {
        let mut o = fresh();
        // Advertise at seq=6 against remote at 5.
        let v = remote(Some(5));
        let _ = o.on_local_learned(mac(0xAA), 10, false, Some(&v));

        // Remote re-announces at 6 — ≥ our 6, must bump to 7.
        let v6 = remote(Some(6));
        let actions = o.on_remote_changed(mac(0xAA), Some(&v6));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(7), false);
    }

    #[test]
    fn step_up_bumps_far_when_remote_jumps() {
        let mut o = fresh();
        // First learn with no remote: seq=0, no extcomm.
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        // Remote announces at 100 — must jump to 101.
        let v = remote(Some(100));
        let actions = o.on_remote_changed(mac(0xAA), Some(&v));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(101), false);
    }

    #[test]
    fn sticky_pass_through_emits_extcomm_even_without_remote() {
        let mut o = fresh();
        let actions = o.on_local_learned(mac(0xAA), 10, /* sticky */ true, None);
        assert_eq!(actions.len(), 1);
        // Sticky forces the extcomm even at seq=0 (sticky bit lives in
        // the extcomm so we MUST emit it).
        assert_inject(&actions[0], Some(0), true);
    }

    #[test]
    fn aged_then_relearned_re_inject_clears_withdrawn_state() {
        let mut o = fresh();
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        let _ = o.on_local_aged(mac(0xAA));
        let actions = o.on_local_learned(mac(0xAA), 10, false, None);
        // After Aged then re-Learn with no remote: seq is preserved
        // (still 0, no contender ever seen) and we emit a fresh Inject.
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], None, false);
        assert_eq!(o.advertised_count(), 1);
    }

    #[test]
    fn local_port_move_bumps_seq_and_emits_extcomm() {
        let mut o = fresh();
        // Initial learn on port 10.
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        // Same MAC on port 11 — local move.
        let actions = o.on_local_learned(mac(0xAA), 11, false, None);
        assert_eq!(actions.len(), 1);
        // The bump from seq=0 → seq=1 must wake up the MAC Mobility
        // extcomm on the wire — otherwise peers still see absent-
        // extcomm semantics (seq=0) and a later stale remote at seq=0
        // would tie with our hidden seq=1, leaving neither side able
        // to win cleanly. Defensive bump per FRR/Junos practice.
        assert_inject(&actions[0], Some(1), false);
    }

    #[test]
    fn remote_changed_for_untracked_mac_no_action() {
        let mut o = fresh();
        let v = remote(Some(7));
        let actions = o.on_remote_changed(mac(0xCC), Some(&v));
        assert!(actions.is_empty());
    }

    #[test]
    fn remote_lower_than_ours_is_ignored() {
        let mut o = fresh();
        // Advertise at 10 against remote at 9.
        let v9 = remote(Some(9));
        let _ = o.on_local_learned(mac(0xAA), 10, false, Some(&v9));

        // Remote drops to 5 — we already win, no bump.
        let v5 = remote(Some(5));
        let actions = o.on_remote_changed(mac(0xAA), Some(&v5));
        assert!(actions.is_empty());
    }

    #[test]
    fn drain_to_withdraws_emits_one_per_advertising_mac() {
        let mut o = fresh();
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        let _ = o.on_local_learned(mac(0xBB), 11, false, None);
        let _ = o.on_local_learned(mac(0xCC), 12, false, None);
        // Pre-aged one — drain should NOT emit a second Withdraw for it.
        let _ = o.on_local_aged(mac(0xBB));

        let actions = o.drain_to_withdraws();
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], OriginationAction::Withdraw { .. }));
        assert!(matches!(actions[1], OriginationAction::Withdraw { .. }));
        assert_eq!(o.advertised_count(), 0);
    }

    #[test]
    fn ifindex_and_state_consistent_after_burst() {
        let mut o = fresh();

        // Three MACs, one with mobility, one with port move.
        let _ = o.on_local_learned(mac(0xAA), 10, false, None);
        let v = remote(Some(7));
        let _ = o.on_local_learned(mac(0xBB), 20, false, Some(&v));
        let _ = o.on_local_learned(mac(0xCC), 30, true, None);

        // Local move on AA.
        let _ = o.on_local_learned(mac(0xAA), 11, false, None);
        // Remote bump on BB.
        let v9 = remote(Some(9));
        let _ = o.on_remote_changed(mac(0xBB), Some(&v9));
        // Aged on CC.
        let _ = o.on_local_aged(mac(0xCC));

        assert_eq!(o.len(), 3);
        assert_eq!(o.advertised_count(), 2); // AA, BB still up; CC withdrawn

        let aa = o.by_mac.get(&mac(0xAA)).unwrap();
        assert_eq!(aa.our_seq, 1); // bumped from 0 on local move
        assert_eq!(aa.ifindex, 11);

        let bb = o.by_mac.get(&mac(0xBB)).unwrap();
        assert_eq!(bb.our_seq, 10); // 9 + 1
        assert_eq!(bb.last_seen_remote_seq, Some(9));

        let cc = o.by_mac.get(&mac(0xCC)).unwrap();
        assert!(cc.originated_key.is_none());
        assert!(cc.sticky);
    }

    enum InvariantOp {
        Learn {
            mac: MacAddress,
            ifindex: u32,
            sticky: bool,
            remote_seq: Option<u32>,
        },
        Aged {
            mac: MacAddress,
        },
        RemoteChanged {
            mac: MacAddress,
            remote_seq: Option<u32>,
        },
    }

    /// Monotonic invariant: across any sequence of operations, each
    /// MAC's `our_seq` only ever increases.
    #[test]
    fn our_seq_monotonically_increases() {
        use InvariantOp as Op;
        use std::collections::HashMap;

        let mut o = fresh();
        let mut last_seen: HashMap<MacAddress, u32> = HashMap::new();

        let macs = [mac(0x01), mac(0x02), mac(0x03)];

        // Sequence of ops chosen to exercise all three handlers.
        let ops = [
            Op::Learn {
                mac: mac(0x01),
                ifindex: 10,
                sticky: false,
                remote_seq: None,
            },
            Op::Learn {
                mac: mac(0x02),
                ifindex: 20,
                sticky: false,
                remote_seq: Some(3),
            },
            Op::RemoteChanged {
                mac: mac(0x02),
                remote_seq: Some(50),
            },
            Op::Learn {
                mac: mac(0x01),
                ifindex: 11,
                sticky: true,
                remote_seq: None,
            },
            Op::Aged { mac: mac(0x01) },
            Op::Learn {
                mac: mac(0x01),
                ifindex: 12,
                sticky: false,
                remote_seq: None,
            },
            Op::Learn {
                mac: mac(0x03),
                ifindex: 30,
                sticky: false,
                remote_seq: None,
            },
        ];

        for op in &ops {
            match op {
                Op::Learn {
                    mac,
                    ifindex,
                    sticky,
                    remote_seq,
                } => {
                    let v = remote_seq.map(|s| RemoteMacView {
                        mac: *mac,
                        mobility_sequence: Some(s),
                        sticky: false,
                        next_hop: "10.0.0.99".parse().unwrap(),
                    });
                    o.on_local_learned(*mac, *ifindex, *sticky, v.as_ref());
                }
                Op::Aged { mac } => {
                    o.on_local_aged(*mac);
                }
                Op::RemoteChanged { mac, remote_seq } => {
                    let v = remote_seq.map(|s| RemoteMacView {
                        mac: *mac,
                        mobility_sequence: Some(s),
                        sticky: false,
                        next_hop: "10.0.0.99".parse().unwrap(),
                    });
                    o.on_remote_changed(*mac, v.as_ref());
                }
            }
            for m in &macs {
                if let Some(s) = o.by_mac.get(m) {
                    let prev = last_seen.get(m).copied().unwrap_or(0);
                    assert!(
                        s.our_seq >= prev,
                        "MAC {m:?}: our_seq went {prev} → {} (regression)",
                        s.our_seq
                    );
                    last_seen.insert(*m, s.our_seq);
                }
            }
        }
    }

    /// Whenever `originated_key.is_some()`, the most recent action for
    /// that MAC was an Inject (not a Withdraw or no-op).
    #[test]
    fn originated_key_tracks_last_emitted_action() {
        let mut o = fresh();

        // Sequence: Learn → key Some, Aged → key None, Re-Learn → key Some.
        let l1 = o.on_local_learned(mac(0xAA), 10, false, None);
        assert!(matches!(l1[0], OriginationAction::Inject { .. }));
        assert!(o.by_mac.get(&mac(0xAA)).unwrap().originated_key.is_some());

        let w = o.on_local_aged(mac(0xAA));
        assert!(matches!(w[0], OriginationAction::Withdraw { .. }));
        assert!(o.by_mac.get(&mac(0xAA)).unwrap().originated_key.is_none());

        let l2 = o.on_local_learned(mac(0xAA), 10, false, None);
        assert!(matches!(l2[0], OriginationAction::Inject { .. }));
        assert!(o.by_mac.get(&mac(0xAA)).unwrap().originated_key.is_some());
    }
}
