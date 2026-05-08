//! MAC+IP Type 2 origination state machine — Gate 7b+2.
//!
//! Parallel to [`crate::origination::LocalMacOriginator`] but keyed on
//! `(MAC, IP)` rather than `MAC` alone. RFC 7432 §7.2 permits a Type 2
//! NLRI to carry an IP alongside the MAC; RFC 9135 §4.4 explicitly
//! permits MAC-only and MAC+IP advertisements for the same MAC to
//! coexist on the wire (remote VTEPs use MAC-only for L2 forwarding
//! and MAC+IP for ARP/ND suppression).
//!
//! Why a separate state machine rather than extending
//! [`crate::origination::LocalMacOriginator`]:
//!
//! - **Independent advertisements, independent ratchets** — this is an
//!   *implementation decision*, taken because RFC 9135 §4.4 treats
//!   MAC-only and MAC+IP as independent advertisements. Letting them
//!   share a sequence ratchet would couple two RFC-distinct chains to
//!   each other and would make a remote contender on the MAC+IP route
//!   bump our MAC-only sequence (and vice versa) without justification.
//!   We do **not** claim RFC 7432 §15.1 is keyed by full NLRI; we
//!   claim only that the chains are kept independent because the
//!   advertisements are independent.
//! - **No local-port move axis** — the `ifindex`-bump that
//!   [`crate::origination::LocalMacOriginator`] uses for local moves doesn't apply here.
//!   Bridge-resident IP bindings don't carry a port; an IP migrating
//!   to a new MAC surfaces as `IpRemoved(old_mac, ip)` followed by
//!   `IpAdded(new_mac, ip)` — natural withdraw-then-inject without
//!   the originator special-casing it.
//! - **MAC-aged cascade** — when the kernel ages a MAC, every
//!   `(MAC, *)` IP route must be withdrawn alongside the MAC-only
//!   route. [`LocalMacIpOriginator::on_local_mac_aged`] is that hook;
//!   without it the daemon would have to maintain its own reverse
//!   `MAC -> Vec<IP>` index and duplicate originator state.
//!
//! ## Decision deferred to slice 3 — MAC-only local-move cascade
//!
//! When a MAC moves locally (a bridge-port change picked up by the
//! existing [`crate::origination::LocalMacOriginator`] ratchet bump), should the
//! corresponding `(mac, *)` MAC+IP routes also re-emit at a bumped
//! sequence?
//!
//! - **Argument for**: the host moved locally, and the MAC+IP
//!   advertisement points at the same host. Peers should learn the
//!   same fact about both routes.
//! - **Argument against**: the host's IP didn't change; the move is
//!   really an L2 fact, and the MAC+IP route is more about ARP/ND
//!   suppression than about L2 reachability.
//!
//! Slice 2 (this module) does **not** decide. The cascade hook lives
//! at the daemon layer — slice 3 owns the call. Recording the
//! decision space here so it doesn't get lost.
//!
//! ## Sticky bit
//!
//! Same input shape as [`crate::origination::LocalMacOriginator`]: the daemon decides per
//! MAC (via ADR-0056 `sticky_macs`) and passes the same `sticky` to
//! both originators. A change in `sticky` re-emits at the same
//! sequence with the bit updated — mirrors the MAC-only flow even
//! though `sticky_macs` is restart-required today, so a future
//! hot-apply doesn't get a weird edge case.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::{EthernetTagId, EvpnRouteKey, MacAddress, RouteDistinguisher};

use crate::EvpnInstanceId;
use crate::origination::OriginationAction;

/// Composite key — `(MAC, IP)` — used as the per-instance map key.
/// A small newtype so `BTreeMap` lookups in the daemon don't risk
/// argument-order mistakes once slice 3 starts correlating multiple
/// maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacIpKey {
    /// MAC half of the binding.
    pub mac: MacAddress,
    /// IP half of the binding.
    pub ip: IpAddr,
}

impl MacIpKey {
    /// Build a `(MAC, IP)` key.
    #[must_use]
    pub const fn new(mac: MacAddress, ip: IpAddr) -> Self {
        Self { mac, ip }
    }
}

/// What the daemon hands the MAC+IP originator describing the RIB's
/// current best-path *non-self* remote Type 2 for some
/// `(VNI, MAC, IP)`.
///
/// Mirrors [`crate::origination::RemoteMacView`] one-for-one; the
/// only structural difference is the additional `ip` field. Daemon
/// applies the same self-NH filter (drop routes whose next-hop is
/// our own `local_vtep_ip`) before passing this in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMacIpView {
    /// MAC half of the contender route.
    pub mac: MacAddress,
    /// IP half of the contender route.
    pub ip: IpAddr,
    /// MAC Mobility extended community sequence (RFC 7432 §7.7) on
    /// the remote route, if any. `None` is treated as seq=0 per §15.1.
    pub mobility_sequence: Option<u32>,
    /// Sticky bit on the remote route's MAC Mobility extcomm.
    pub sticky: bool,
    /// Remote VTEP next-hop. Carried for daemon-side telemetry; the
    /// state machine does not consult it.
    pub next_hop: IpAddr,
}

/// Per-`(MAC, IP)` state the originator keeps.
///
/// `our_seq` ratchets monotonically across the entry's lifetime —
/// even after withdraw — so a future re-Learn never starts back at
/// zero once contended.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalMacIpOriginationState {
    /// Sequence we advertised (or would advertise) for this `(MAC, IP)`.
    our_seq: u32,
    /// Highest remote sequence we have ever observed for this
    /// `(MAC, IP)`. `None` = no remote contender has ever appeared.
    last_seen_remote_seq: Option<u32>,
    /// Sticky bit currently in force.
    sticky: bool,
    /// Key of the route we currently have outstanding. `Some` ⇒ we
    /// are advertising; `None` ⇒ withdrawn (or never advertised).
    originated_key: Option<EvpnRouteKey>,
}

impl LocalMacIpOriginationState {
    /// Should the rendered Inject carry a MAC Mobility extcomm? Same
    /// rule as [`crate::origination::LocalMacOriginator`]: emit whenever a remote
    /// contender has been observed, sticky is set, or `our_seq > 0`.
    /// See [`crate::origination::LocalMacOriginationState::rendered_seq`]
    /// for the rationale on the `our_seq > 0` case.
    fn rendered_seq(&self) -> Option<u32> {
        if self.last_seen_remote_seq.is_some() || self.sticky || self.our_seq > 0 {
            Some(self.our_seq)
        } else {
            None
        }
    }
}

/// Per-instance MAC+IP origination engine. One per
/// [`crate::EvpnInstance`], paired with the existing
/// [`crate::origination::LocalMacOriginator`].
#[derive(Debug)]
pub struct LocalMacIpOriginator {
    instance_id: EvpnInstanceId,
    rd: RouteDistinguisher,
    by_key: BTreeMap<MacIpKey, LocalMacIpOriginationState>,
}

impl LocalMacIpOriginator {
    /// Build a fresh originator scoped to one EVPN instance.
    #[must_use]
    pub fn new(instance_id: EvpnInstanceId, rd: RouteDistinguisher) -> Self {
        Self {
            instance_id,
            rd,
            by_key: BTreeMap::new(),
        }
    }

    /// VNI this originator owns.
    #[must_use]
    pub fn instance_id(&self) -> EvpnInstanceId {
        self.instance_id
    }

    /// Current count of locally-tracked `(MAC, IP)` pairs
    /// (advertising + withdrawn).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// `true` if this originator has no `(MAC, IP)` entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Number of `(MAC, IP)` pairs currently advertising
    /// (`originated_key` is `Some`).
    #[must_use]
    pub fn advertised_count(&self) -> usize {
        self.by_key
            .values()
            .filter(|s| s.originated_key.is_some())
            .count()
    }

    /// Build the wire-shaped key for `(mac, ip)`.
    fn key(&self, mac: MacAddress, ip: IpAddr) -> EvpnRouteKey {
        EvpnRouteKey::MacIp {
            rd: self.rd,
            ethernet_tag: EthernetTagId(0),
            mac,
            ip: Some(ip),
        }
    }

    /// Snapshot of the currently-advertised set, suitable for the
    /// daemon's coordinated-shutdown drain.
    pub fn outstanding_keys(&self) -> impl Iterator<Item = (MacIpKey, EvpnRouteKey)> + '_ {
        self.by_key
            .iter()
            .filter_map(|(&k, s)| s.originated_key.map(|key| (k, key)))
    }

    /// Clear advertising state and return Withdraw actions for every
    /// currently-advertised `(MAC, IP)`.
    pub fn drain_to_withdraws(&mut self) -> Vec<OriginationAction> {
        let mut out = Vec::with_capacity(self.advertised_count());
        for (k, state) in &mut self.by_key {
            if let Some(key) = state.originated_key.take() {
                out.push(OriginationAction::Withdraw { mac: k.mac, key });
            }
        }
        out
    }

    /// React to a kernel ARP/ND learn for an `(IP, MAC)` binding.
    ///
    /// Mirrors `LocalMacOriginator::on_local_learned` one for one,
    /// minus the `ifindex` axis. Same RFC §15.1 sequence rules,
    /// scoped to the per-`(MAC, IP)` ratchet.
    pub fn on_local_ip_learned(
        &mut self,
        mac: MacAddress,
        ip: IpAddr,
        sticky: bool,
        current_remote: Option<&RemoteMacIpView>,
    ) -> Vec<OriginationAction> {
        let composite = MacIpKey::new(mac, ip);
        let key = self.key(mac, ip);
        let prior = self.by_key.get(&composite).cloned();

        // Step 1: integrate the remote view into last_seen_remote_seq.
        let prior_last_seen = prior.as_ref().and_then(|s| s.last_seen_remote_seq);
        let observed_now = current_remote.map(|v| v.mobility_sequence.unwrap_or(0));
        let new_last_seen = match (prior_last_seen, observed_now) {
            (None, None) => None,
            (Some(p), None) => Some(p),
            (None, Some(c)) => Some(c),
            (Some(p), Some(c)) => Some(p.max(c)),
        };

        // Step 2: figure out what seq we should advertise.
        //
        // Divergence from `LocalMacOriginator`: we **do not** bump
        // `our_seq` on a sticky-bit change. MAC-only's logic bumps
        // sticky_changed alongside port_changed because both
        // represent meaningful L2 state changes (the MAC moved, the
        // operator changed pinning). For MAC+IP, sticky is closer to
        // an ARP/ND-suppression hint than to a mobility signal —
        // a sticky flip without an actual binding change shouldn't
        // ratchet up. Re-emit the route with the bit updated at the
        // same sequence; peers replace the stored attribute set.
        let was_advertising = prior.as_ref().is_some_and(|s| s.originated_key.is_some());
        let prior_seq = prior.as_ref().map_or(0u32, |s| s.our_seq);
        let sticky_changed = prior.as_ref().is_some_and(|s| s.sticky != sticky);

        // First-ever advertisement check is `prior.is_none()` — a
        // (MAC, IP) that was previously advertised then withdrawn
        // must preserve its ratchet, otherwise a peer that still
        // remembers our prior seq could win contention on re-Learn.
        let is_first_ever = prior.is_none();
        let new_seq = match new_last_seen {
            None => {
                if is_first_ever {
                    0
                } else {
                    // Idempotent re-Learn, sticky flip, or re-Learn
                    // after Aged with no contention history —
                    // preserve ratchet.
                    prior_seq
                }
            }
            Some(remote_seq) => {
                if is_first_ever {
                    remote_seq + 1
                } else if !was_advertising {
                    // Re-Learn after Aged with contention history —
                    // bump above contender AND above our prior seq.
                    // Mirrors MAC-only: a peer that still remembers
                    // our prior advertisement sees a fresh higher
                    // number rather than a tie.
                    (remote_seq + 1).max(prior_seq + 1)
                } else if remote_seq >= prior_seq {
                    remote_seq + 1
                } else {
                    prior_seq
                }
            }
        };

        // Step 3: idempotence — same observed state, no-op.
        if was_advertising
            && !sticky_changed
            && prior_seq == new_seq
            && prior_last_seen == new_last_seen
        {
            return Vec::new();
        }

        // Step 4: commit and emit.
        let new_state = LocalMacIpOriginationState {
            our_seq: new_seq,
            last_seen_remote_seq: new_last_seen,
            sticky,
            originated_key: Some(key),
        };
        let mobility_seq = new_state.rendered_seq();
        self.by_key.insert(composite, new_state);

        vec![OriginationAction::Inject {
            mac,
            mobility_seq,
            sticky,
            key,
        }]
    }

    /// React to a kernel ARP/ND age/delete for one `(IP, MAC)`
    /// binding. Withdraws only the matching entry; other IPs for the
    /// same MAC and the MAC-only route are unaffected.
    pub fn on_local_ip_aged(&mut self, mac: MacAddress, ip: IpAddr) -> Vec<OriginationAction> {
        let composite = MacIpKey::new(mac, ip);
        let Some(entry) = self.by_key.get_mut(&composite) else {
            return Vec::new();
        };
        let Some(key) = entry.originated_key.take() else {
            return Vec::new();
        };
        // Keep `our_seq` and `last_seen_remote_seq` so a future
        // re-Learn ratchets correctly.
        vec![OriginationAction::Withdraw { mac, key }]
    }

    /// Cascade hook: the kernel aged the MAC itself. Withdraw every
    /// `(MAC, *)` MAC+IP route in one shot. Without this hook the
    /// daemon would have to keep its own reverse `MAC -> Vec<IP>`
    /// index and duplicate originator state.
    ///
    /// Each per-IP entry retains its sequence ratchet — the MAC
    /// could re-appear later with the same IPs, and we don't want
    /// the contention history to reset.
    pub fn on_local_mac_aged(&mut self, mac: MacAddress) -> Vec<OriginationAction> {
        let mut out = Vec::new();
        for (k, state) in &mut self.by_key {
            if k.mac != mac {
                continue;
            }
            if let Some(key) = state.originated_key.take() {
                out.push(OriginationAction::Withdraw { mac, key });
            }
        }
        out
    }

    /// React to a RIB best-path change for a tracked `(MAC, IP)`.
    /// `view = None` means the remote contender disappeared — we
    /// keep our ratchet but no longer have a contender to bump
    /// against.
    pub fn on_remote_ip_changed(
        &mut self,
        mac: MacAddress,
        ip: IpAddr,
        view: Option<&RemoteMacIpView>,
    ) -> Vec<OriginationAction> {
        let composite = MacIpKey::new(mac, ip);
        let Some(entry) = self.by_key.get_mut(&composite) else {
            // We don't track this (MAC, IP) — nothing to defend.
            return Vec::new();
        };

        // Update last_seen_remote_seq from whatever the RIB shows
        // now. A `None` view (remote contender gone) leaves the
        // last-seen value as-is — the ratchet survives.
        if let Some(v) = view {
            let observed = v.mobility_sequence.unwrap_or(0);
            entry.last_seen_remote_seq = Some(match entry.last_seen_remote_seq {
                Some(p) => p.max(observed),
                None => observed,
            });
        }

        // If we're not advertising, nothing to bump.
        let Some(key) = entry.originated_key else {
            return Vec::new();
        };

        // Without a current contender, no bump.
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

    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fresh() -> LocalMacIpOriginator {
        LocalMacIpOriginator::new(vni(100), rd(65000, 100))
    }

    fn remote(seq: Option<u32>) -> RemoteMacIpView {
        RemoteMacIpView {
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
            mobility_sequence: seq,
            sticky: false,
            next_hop: ipa("10.0.0.99"),
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

    fn assert_withdraw(action: &OriginationAction) {
        assert!(
            matches!(action, OriginationAction::Withdraw { .. }),
            "expected Withdraw, got {action:?}"
        );
    }

    // --- on_local_ip_learned ---

    #[test]
    fn first_learn_no_remote_emits_seq_zero_no_extcomm() {
        let mut o = fresh();
        let actions = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        assert_eq!(actions.len(), 1);
        // First advertisement, no contender ever seen → no MAC
        // Mobility extcomm at all (RFC 7432 §7.7 absent-extcomm =
        // semantically seq=0).
        assert_inject(&actions[0], None, false);
    }

    #[test]
    fn first_learn_with_remote_seq_3_emits_seq_4_extcomm() {
        let mut o = fresh();
        let actions =
            o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(3))));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(4), false);
    }

    #[test]
    fn first_learn_with_remote_no_extcomm_treats_as_seq_0() {
        // Remote present but no MAC Mobility extcomm — RFC §15.1
        // counts that as seq=0 for tiebreak. So we emit seq=1.
        let mut o = fresh();
        let actions =
            o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(None)));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(1), false);
    }

    #[test]
    fn idempotent_relearn_returns_empty() {
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let actions = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        assert!(
            actions.is_empty(),
            "idempotent re-learn must return empty: {actions:?}"
        );
    }

    #[test]
    fn sticky_change_re_emits_at_same_seq_with_updated_bit() {
        // Re-learn with the same (mac, ip) but sticky toggled.
        // ADR-0056 makes sticky_macs restart-required so this won't
        // happen in practice, but the state machine handles it for
        // symmetry with LocalMacOriginator.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let actions = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), true, None);
        assert_eq!(actions.len(), 1);
        // No remote contender → seq stays at 0; sticky now true →
        // extcomm is emitted (rendered_seq enables it for sticky=true).
        assert_inject(&actions[0], Some(0), true);
    }

    // --- on_local_ip_aged ---

    #[test]
    fn ip_aged_emits_withdraw_for_advertised_entry() {
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let actions = o.on_local_ip_aged(mac(0xAA), ipa("192.0.2.10"));
        assert_eq!(actions.len(), 1);
        assert_withdraw(&actions[0]);
    }

    #[test]
    fn ip_aged_unknown_entry_is_no_op() {
        let mut o = fresh();
        let actions = o.on_local_ip_aged(mac(0xAA), ipa("192.0.2.10"));
        assert!(actions.is_empty());
    }

    #[test]
    fn ip_aged_then_relearned_preserves_ratchet() {
        // Load-bearing assertion: the ratchet does NOT reset to 0
        // after age. Specific behavior matches MAC-only's
        // `!was_advertising` branch — a re-Learn with contention
        // history bumps to `(remote+1).max(prior+1)` so a peer
        // that still remembers our prior seq sees a fresh higher
        // number rather than a tie.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(7))));
        // We injected at seq=8 above. Age + re-learn with no
        // contender on the wire (but contention history retained).
        let _ = o.on_local_ip_aged(mac(0xAA), ipa("192.0.2.10"));
        let actions = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        assert_eq!(actions.len(), 1);
        // (last_seen=7) + 1 = 8, max (prior=8) + 1 = 9.
        assert_inject(&actions[0], Some(9), false);
    }

    // --- on_local_mac_aged (cascade) ---

    #[test]
    fn mac_aged_cascades_withdraws_for_all_ips() {
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.11"), false, None);
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("2001:db8::1"), false, None);
        // Different MAC — must NOT be cascaded.
        let _ = o.on_local_ip_learned(mac(0xBB), ipa("192.0.2.20"), false, None);

        let actions = o.on_local_mac_aged(mac(0xAA));
        assert_eq!(actions.len(), 3, "expected 3 cascade withdraws");
        for a in &actions {
            assert_withdraw(a);
        }
        // The (BB, 192.0.2.20) entry must still be advertising.
        assert_eq!(o.advertised_count(), 1);
    }

    #[test]
    fn mac_aged_then_ip_relearn_preserves_ratchet() {
        // Cascade Withdraw must preserve our_seq so a later re-Learn
        // doesn't reset to 0 with a peer still remembering our seq.
        // Same `(remote+1).max(prior+1)` rule as the per-IP age
        // path — we inject at seq=9 (last_seen=7 + 1 = 8, prior=8
        // + 1 = 9, max = 9).
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(7))));
        let _ = o.on_local_mac_aged(mac(0xAA));
        let actions = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(9), false);
    }

    #[test]
    fn mac_aged_with_no_entries_is_no_op() {
        let mut o = fresh();
        assert!(o.on_local_mac_aged(mac(0xAA)).is_empty());
    }

    // --- on_remote_ip_changed ---

    #[test]
    fn remote_changed_higher_seq_bumps_our_advertisement() {
        // We advertise at seq=0, remote announces seq=5 → bump to 6.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let actions = o.on_remote_ip_changed(mac(0xAA), ipa("192.0.2.10"), Some(&remote(Some(5))));
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(6), false);
    }

    #[test]
    fn remote_changed_lower_seq_after_our_higher_is_no_op() {
        // We advertise at seq=10, remote at seq=3 (stale) → no bump.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(9))));
        // We're now at seq=10. A lower-seq update shouldn't bump us.
        let actions = o.on_remote_ip_changed(mac(0xAA), ipa("192.0.2.10"), Some(&remote(Some(3))));
        assert!(
            actions.is_empty(),
            "lower-seq remote must not bump our ratchet: {actions:?}"
        );
    }

    #[test]
    fn remote_disappeared_while_local_advertising_is_no_op() {
        // We advertise; remote contender goes away (view = None).
        // Our ratchet survives (so a future re-appearance can't bump
        // us back) but no Inject is needed — we're already winning.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(5))));
        let actions = o.on_remote_ip_changed(mac(0xAA), ipa("192.0.2.10"), None);
        assert!(
            actions.is_empty(),
            "remote-disappeared must not re-emit: {actions:?}"
        );
    }

    #[test]
    fn remote_disappeared_then_lower_seq_remote_returns_is_no_op() {
        // We advertised at seq=6 (after seeing remote=5).
        // Remote goes away. Now a different remote announces seq=4.
        // Stale; no bump.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, Some(&remote(Some(5))));
        let _ = o.on_remote_ip_changed(mac(0xAA), ipa("192.0.2.10"), None);
        let actions = o.on_remote_ip_changed(mac(0xAA), ipa("192.0.2.10"), Some(&remote(Some(4))));
        assert!(
            actions.is_empty(),
            "lower-seq comeback after disappearance must not bump: {actions:?}"
        );
    }

    #[test]
    fn remote_changed_for_untracked_macip_is_no_op() {
        let mut o = fresh();
        let actions = o.on_remote_ip_changed(mac(0xCC), ipa("192.0.2.99"), Some(&remote(Some(5))));
        assert!(actions.is_empty());
    }

    // --- drain_to_withdraws + outstanding_keys ---

    #[test]
    fn drain_emits_withdraw_for_each_advertised_entry() {
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let _ = o.on_local_ip_learned(mac(0xBB), ipa("2001:db8::1"), false, None);
        let actions = o.drain_to_withdraws();
        assert_eq!(actions.len(), 2);
        assert_eq!(o.advertised_count(), 0);
    }

    #[test]
    fn outstanding_keys_excludes_withdrawn_entries() {
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let _ = o.on_local_ip_learned(mac(0xBB), ipa("192.0.2.20"), false, None);
        let _ = o.on_local_ip_aged(mac(0xAA), ipa("192.0.2.10"));
        let outstanding: Vec<_> = o.outstanding_keys().collect();
        assert_eq!(outstanding.len(), 1);
        assert_eq!(outstanding[0].0.mac, mac(0xBB));
    }

    // --- ratchet independence between (MAC, IP) entries ---

    #[test]
    fn ratchet_is_independent_per_macip() {
        // Two (MAC, IP) entries for the same MAC. Bumping one must
        // not affect the other's sequence.
        let mut o = fresh();
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.10"), false, None);
        let _ = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.11"), false, None);

        let actions = o.on_remote_ip_changed(
            mac(0xAA),
            ipa("192.0.2.10"),
            Some(&RemoteMacIpView {
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
                mobility_sequence: Some(5),
                sticky: false,
                next_hop: ipa("10.0.0.99"),
            }),
        );
        // First key bumped to seq=6.
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0], Some(6), false);

        // Second key has no contender, so a re-learn must still
        // return empty (idempotent — sequence unchanged).
        let unchanged = o.on_local_ip_learned(mac(0xAA), ipa("192.0.2.11"), false, None);
        assert!(
            unchanged.is_empty(),
            "second (MAC, IP) ratchet must be untouched"
        );
    }
}
