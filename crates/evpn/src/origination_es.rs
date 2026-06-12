//! Type 1 / Type 4 EVPN origination state machines — Gate 8.
//!
//! Three pure-deterministic state machines producing
//! [`OriginationAction`]s for the three Ethernet-Segment-related
//! NLRI shapes:
//!
//! | Originator | Wire NLRI | Scope |
//! |---|---|---|
//! | [`LocalEsOriginator`] | Type 4 ES (RFC 7432 §7.4) | One per ESI |
//! | [`LocalEadPerEsOriginator`] | Type 1 EAD-per-ES (RFC 7432 §7.1) | One per ESI |
//! | [`LocalEadPerEviOriginator`] | Type 1 EAD-per-EVI (RFC 7432 §7.1) | One per `(ESI, VNI)` |
//!
//! All three live in `crates/evpn` for the same reasons the local-MAC
//! originators do: deterministic, no I/O, no tokio, testable on macOS
//! dev builds. Daemon-side wiring (slice 3) composes them per ESI
//! alongside the [`crate::DfElection`] state machine.
//!
//! ## Why no mobility sequencing
//!
//! Type 1 / Type 4 routes don't carry the MAC Mobility extended
//! community (RFC 7432 §7.7) — that field is Type 2-specific.
//! Contention between PEs advertising the same ESI is resolved by
//! DF election, not by a per-route ratchet. The originators here
//! emit and withdraw flat; idempotent re-emit on identical inputs
//! returns an empty action vector.
//!
//! ## DF role on per-EVI routes
//!
//! Type 1 EAD-per-EVI routes are the most directly DF-aware of the
//! three: under RFC 7432 §8.4, the route's ESI Label extended
//! community carries a 1-bit "single-active" / "all-active" flag
//! plus a 20-bit ESI label that downstream PEs use for
//! split-horizon. The state machine surfaces a `DfRole` input on
//! the per-EVI originator so slice 3's wiring can re-emit when DF
//! flips. The actual ESI Label extcomm encoding lives at the
//! daemon's `apply_actions` boundary (next to the existing
//! `build_originated_route` for Type 2) — slice 2 keeps the state
//! machine pure and just propagates the role into a future
//! attribute-construction call site.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnRouteKey, MacAddress, MplsLabel,
    RouteDistinguisher,
};

use crate::EvpnInstanceId;
use crate::origination::OriginationAction;
use crate::segment::DfRole;

// ---------------------------------------------------------------------------
// Type 4 — Ethernet Segment route
// ---------------------------------------------------------------------------

/// Type 4 (Ethernet Segment) origination — one route per ESI.
///
/// The Type 4 ES route announces "this PE participates in this
/// Ethernet Segment." Peer PEs reading the same ESI's Type 4 set
/// gather candidate originator IPs and run DF election against the
/// resulting list. Without Type 4 origination, a multihomed PE is
/// invisible to the rest of the fabric.
///
/// Reflection of peer Type 4 routes already exists in the
/// crate's RR mode (since v0.9.0); slice 2 adds local origination.
#[derive(Debug)]
pub struct LocalEsOriginator {
    rd: RouteDistinguisher,
    esi: EthernetSegmentIdentifier,
    originator_ip: IpAddr,
    /// Key of the route we currently have outstanding. `Some` ⇒ we
    /// are advertising; `None` ⇒ withdrawn (or never advertised).
    /// Used to suppress idempotent re-emit and to drive accurate
    /// drain on shutdown.
    originated_key: Option<EvpnRouteKey>,
}

impl LocalEsOriginator {
    /// Build a fresh originator for one ESI.
    #[must_use]
    pub fn new(
        rd: RouteDistinguisher,
        esi: EthernetSegmentIdentifier,
        originator_ip: IpAddr,
    ) -> Self {
        Self {
            rd,
            esi,
            originator_ip,
            originated_key: None,
        }
    }

    /// ESI this originator owns.
    #[must_use]
    pub fn esi(&self) -> EthernetSegmentIdentifier {
        self.esi
    }

    /// `true` while a Type 4 route is currently advertising for this
    /// ESI.
    #[must_use]
    pub fn is_advertising(&self) -> bool {
        self.originated_key.is_some()
    }

    /// Emit the Type 4 ES Inject. Idempotent — returns an empty
    /// vector if the route is already advertising.
    pub fn on_startup(&mut self) -> Vec<OriginationAction> {
        if self.originated_key.is_some() {
            return Vec::new();
        }
        let key = self.key();
        self.originated_key = Some(key);
        // Type 4 routes carry no MAC, but `OriginationAction::Inject`
        // requires one for the action shape. The synthetic
        // `MacAddress::new([0; 6])` is conventional for non-MAC
        // origination actions and ignored downstream because the key
        // is the authoritative identity.
        vec![OriginationAction::Inject {
            mac: MacAddress::new([0; 6]),
            mobility_seq: None,
            sticky: false,
            key,
        }]
    }

    /// Emit the Type 4 ES Withdraw. Idempotent — returns an empty
    /// vector if the route is not currently advertising.
    pub fn on_shutdown(&mut self) -> Vec<OriginationAction> {
        let Some(key) = self.originated_key.take() else {
            return Vec::new();
        };
        vec![OriginationAction::Withdraw {
            mac: MacAddress::new([0; 6]),
            key,
        }]
    }

    fn key(&self) -> EvpnRouteKey {
        EvpnRouteKey::Es {
            rd: self.rd,
            esi: self.esi,
            originator_ip: self.originator_ip,
        }
    }
}

// ---------------------------------------------------------------------------
// Type 1 — EAD per-ES route
// ---------------------------------------------------------------------------

/// Type 1 EAD-per-ES origination — one route per ESI with
/// Ethernet Tag set to `MAX_ET`.
///
/// EAD-per-ES is the per-ESI route that signals "this ES is alive at
/// this PE" to the fabric, independent of any specific EVI. It pairs
/// with the per-EVI variant (one route per `(ESI, VNI)`) that the
/// fabric uses for mass-withdraw signalling on `AS_PATH` change.
///
/// The route carries the **ESI label** in its label field — a 20-bit
/// MPLS label downstream PEs use to identify split-horizon traffic
/// from this ES. Slice 2's state machine carries the label as
/// configured input; the daemon (slice 3) is responsible for
/// allocation and lifecycle.
#[derive(Debug)]
pub struct LocalEadPerEsOriginator {
    rd: RouteDistinguisher,
    esi: EthernetSegmentIdentifier,
    /// ESI label allocated for this ES. Operator-fixed under Gate 8;
    /// dynamic allocation is a Gate 8b concern.
    esi_label: MplsLabel,
    originated_key: Option<EvpnRouteKey>,
}

impl LocalEadPerEsOriginator {
    #[must_use]
    pub fn new(
        rd: RouteDistinguisher,
        esi: EthernetSegmentIdentifier,
        esi_label: MplsLabel,
    ) -> Self {
        Self {
            rd,
            esi,
            esi_label,
            originated_key: None,
        }
    }

    #[must_use]
    pub fn esi(&self) -> EthernetSegmentIdentifier {
        self.esi
    }

    #[must_use]
    pub fn is_advertising(&self) -> bool {
        self.originated_key.is_some()
    }

    #[must_use]
    pub fn esi_label(&self) -> MplsLabel {
        self.esi_label
    }

    /// Emit the EAD-per-ES Inject. Idempotent.
    pub fn on_startup(&mut self) -> Vec<OriginationAction> {
        if self.originated_key.is_some() {
            return Vec::new();
        }
        let key = self.key();
        self.originated_key = Some(key);
        vec![OriginationAction::Inject {
            mac: MacAddress::new([0; 6]),
            mobility_seq: None,
            sticky: false,
            key,
        }]
    }

    /// Emit the EAD-per-ES Withdraw. Idempotent.
    pub fn on_shutdown(&mut self) -> Vec<OriginationAction> {
        let Some(key) = self.originated_key.take() else {
            return Vec::new();
        };
        vec![OriginationAction::Withdraw {
            mac: MacAddress::new([0; 6]),
            key,
        }]
    }

    fn key(&self) -> EvpnRouteKey {
        EvpnRouteKey::EadPerEs {
            rd: self.rd,
            esi: self.esi,
            ethernet_tag: EthernetTagId::MAX_ET,
        }
    }
}

// ---------------------------------------------------------------------------
// Type 1 — EAD per-EVI route
// ---------------------------------------------------------------------------

/// Type 1 EAD-per-EVI origination — one route per `(ESI, VNI)`.
///
/// EAD-per-EVI is the per-fabric, per-EVI signalling route. Per
/// RFC 7432 §14, the wire encoding does **not** carry the ESI Label
/// extcomm; that flag rides on the EAD-per-ES route only. The Gate 8
/// EAD-per-EVI shape is therefore role-independent: a `(ESI, VNI)`
/// route looks the same whether the local PE is DF or `NonDF`.
///
/// `on_vni_role_changed` still updates the internal `(VNI, DfRole)`
/// table so that:
///
/// - the first call for a `(ESI, VNI)` pair emits an Inject (the
///   route appears on the wire); and
/// - Gate 8b can layer aliasing extcomms / DF-role-aware origination
///   on top without re-shaping the originator's external surface.
///
/// Subsequent role flips for an already-advertising VNI are
/// **suppressed at the wire level** — the role state updates in
/// place, but no Withdraw / Inject pair is emitted, since the
/// reconstructed route would be byte-identical and the churn would
/// only cost peers a refresh cycle. The Prometheus
/// `evpn_df_role_changes_total` counter is the operator-facing
/// signal for the flip; the wire stays quiet.
#[derive(Debug)]
pub struct LocalEadPerEviOriginator {
    rd: RouteDistinguisher,
    esi: EthernetSegmentIdentifier,
    /// Per-VNI RD overrides. Gate 8's daemon wiring fills this from
    /// the matching `[[evpn_instances]]` entries so each EAD-per-EVI
    /// route carries the same RD as the EVI it represents.
    rd_for_vni: BTreeMap<EvpnInstanceId, RouteDistinguisher>,
    /// Per-`(ESI, VNI)` MPLS label / VNI value carried on the route.
    label_for_vni: BTreeMap<EvpnInstanceId, MplsLabel>,
    /// Currently-advertised state per `(ESI, VNI)`. Tracks the
    /// `(EvpnRouteKey, DfRole)` pair so a role flip can detect the
    /// change.
    by_vni: BTreeMap<EvpnInstanceId, EadPerEviState>,
}

#[derive(Debug, Clone, Copy)]
struct EadPerEviState {
    key: EvpnRouteKey,
    role: DfRole,
}

impl LocalEadPerEviOriginator {
    #[must_use]
    pub fn new(rd: RouteDistinguisher, esi: EthernetSegmentIdentifier) -> Self {
        Self {
            rd,
            esi,
            rd_for_vni: BTreeMap::new(),
            label_for_vni: BTreeMap::new(),
            by_vni: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn esi(&self) -> EthernetSegmentIdentifier {
        self.esi
    }

    /// Set the per-VNI label table — typically called once at
    /// originator construction time from the operator's `[[evpn_instances]]`
    /// VNI → label mapping. Idempotent across identical inputs.
    pub fn set_labels(&mut self, labels: BTreeMap<EvpnInstanceId, MplsLabel>) {
        self.label_for_vni = labels;
    }

    /// Set per-VNI RD values. If a VNI is absent, the constructor RD
    /// is used as a fallback for backwards-compatible tests and
    /// single-RD callers.
    pub fn set_rds(&mut self, rds: BTreeMap<EvpnInstanceId, RouteDistinguisher>) {
        self.rd_for_vni = rds;
    }

    /// Number of `(ESI, VNI)` pairs currently advertising.
    #[must_use]
    pub fn advertised_count(&self) -> usize {
        self.by_vni.len()
    }

    /// React to a `(VNI, DfRole)` update from the orchestrator.
    ///
    /// Action surface:
    ///
    /// - **First appearance**: emits one Inject so the EAD-per-EVI
    ///   route lands on the wire.
    /// - **Idempotent repeat** (same role): empty vector.
    /// - **Role flip** for an already-advertising VNI: empty vector
    ///   in Gate 8 — the EAD-per-EVI wire shape is role-independent
    ///   (RFC 7432 §14), so a re-emit would be byte-identical churn.
    ///   The internal role state still updates so Gate 8b can layer
    ///   wire-shape changes on top without altering the call site.
    pub fn on_vni_role_changed(
        &mut self,
        vni: EvpnInstanceId,
        role: DfRole,
    ) -> Vec<OriginationAction> {
        let key = self.key_for(vni);
        let prior = self.by_vni.get(&vni).copied();
        if let Some(prior) = prior {
            if prior.role != role {
                // Role flip on an already-advertising VNI. Update
                // state but emit nothing — see the doc comment for
                // the rationale (EAD-per-EVI wire shape is
                // role-independent in Gate 8).
                self.by_vni.insert(vni, EadPerEviState { key, role });
            }
            // Either idempotent or a state-only flip — no actions.
            return Vec::new();
        }
        // First appearance: route advertises now.
        self.by_vni.insert(vni, EadPerEviState { key, role });
        vec![OriginationAction::Inject {
            mac: MacAddress::new([0; 6]),
            mobility_seq: None,
            sticky: false,
            key,
        }]
    }

    /// Withdraw a `(ESI, VNI)` advertisement. Used when the VNI is
    /// removed from the ES's member-VNI list, or when the
    /// orchestrator drains a single VNI without tearing down the
    /// whole ES.
    pub fn on_vni_removed(&mut self, vni: EvpnInstanceId) -> Vec<OriginationAction> {
        let Some(state) = self.by_vni.remove(&vni) else {
            return Vec::new();
        };
        vec![OriginationAction::Withdraw {
            mac: MacAddress::new([0; 6]),
            key: state.key,
        }]
    }

    /// Drain on shutdown: emit Withdraws for every advertising
    /// `(ESI, VNI)` and clear state.
    pub fn drain_to_withdraws(&mut self) -> Vec<OriginationAction> {
        let drained = std::mem::take(&mut self.by_vni);
        drained
            .into_values()
            .map(|state| OriginationAction::Withdraw {
                mac: MacAddress::new([0; 6]),
                key: state.key,
            })
            .collect()
    }

    /// Snapshot of currently-advertising keys (for shutdown drain
    /// observability or operator-facing CLI).
    pub fn outstanding_keys(&self) -> impl Iterator<Item = (EvpnInstanceId, EvpnRouteKey)> + '_ {
        self.by_vni.iter().map(|(&vni, s)| (vni, s.key))
    }

    /// Wire-shaped key for one `(ESI, VNI)` advertisement.
    ///
    /// RFC 7432 §6.1 (VLAN-based service: "The Ethernet Tag ID in all
    /// EVPN routes MUST be set to 0") and RFC 8365 §5.1.3 (VXLAN: the
    /// Ethernet Tag field in the EAD-per-EVI route MUST be zero; the
    /// VNI travels in the route's label field) pin the Ethernet Tag to
    /// 0 — matching the tag our Type 2 MAC/IP routes carry, so remote
    /// receivers can join the `(ESI, EthernetTag)` aliasing /
    /// eligible-set keys (RFC 7432 §8.4, §14.1.2). FRR does the same
    /// (`BGP_EVPN_AD_EVI_ETH_TAG == 0`).
    ///
    /// With the tag fixed at 0, per-VNI route distinctness rides on
    /// the per-VNI RD (`set_rds`); the daemon always populates it from
    /// the `[[evpn_instances]]` table, whose RDs are validated unique.
    fn key_for(&self, vni: EvpnInstanceId) -> EvpnRouteKey {
        EvpnRouteKey::EadPerEvi {
            rd: self.rd_for_vni.get(&vni).copied().unwrap_or(self.rd),
            esi: self.esi,
            ethernet_tag: EthernetTagId(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(asn: u16, val: u32) -> RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        RouteDistinguisher::new(bytes)
    }

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn assert_inject(action: &OriginationAction) {
        assert!(
            matches!(action, OriginationAction::Inject { .. }),
            "expected Inject, got {action:?}"
        );
    }

    fn assert_withdraw(action: &OriginationAction) {
        assert!(
            matches!(action, OriginationAction::Withdraw { .. }),
            "expected Withdraw, got {action:?}"
        );
    }

    // --- LocalEsOriginator (Type 4) ---

    #[test]
    fn es_origin_emits_inject_on_first_startup() {
        let mut o = LocalEsOriginator::new(rd(65000, 100), esi(1), ipa("10.0.0.1"));
        let actions = o.on_startup();
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0]);
        assert!(o.is_advertising());
    }

    #[test]
    fn es_origin_idempotent_repeat_returns_empty() {
        let mut o = LocalEsOriginator::new(rd(65000, 100), esi(1), ipa("10.0.0.1"));
        let _ = o.on_startup();
        let actions = o.on_startup();
        assert!(
            actions.is_empty(),
            "second startup must be idempotent: {actions:?}"
        );
    }

    #[test]
    fn es_origin_emits_withdraw_on_shutdown() {
        let mut o = LocalEsOriginator::new(rd(65000, 100), esi(1), ipa("10.0.0.1"));
        let _ = o.on_startup();
        let actions = o.on_shutdown();
        assert_eq!(actions.len(), 1);
        assert_withdraw(&actions[0]);
        assert!(!o.is_advertising());
    }

    #[test]
    fn es_origin_shutdown_without_startup_is_no_op() {
        let mut o = LocalEsOriginator::new(rd(65000, 100), esi(1), ipa("10.0.0.1"));
        assert!(o.on_shutdown().is_empty());
    }

    #[test]
    fn es_origin_key_carries_originator_ip() {
        let want_rd = rd(65000, 100);
        let want_esi = esi(1);
        let mut o = LocalEsOriginator::new(want_rd, want_esi, ipa("10.0.0.42"));
        let actions = o.on_startup();
        let OriginationAction::Inject { key, .. } = &actions[0] else {
            panic!("expected Inject, got {:?}", actions[0]);
        };
        let EvpnRouteKey::Es {
            rd: got_rd,
            esi: got_esi,
            originator_ip,
        } = *key
        else {
            panic!("expected EvpnRouteKey::Es, got {key:?}");
        };
        assert_eq!(got_rd, want_rd);
        assert_eq!(got_esi, want_esi);
        assert_eq!(originator_ip, ipa("10.0.0.42"));
    }

    // --- LocalEadPerEsOriginator (Type 1 EAD per-ES) ---

    #[test]
    fn ead_per_es_origin_emits_inject_on_startup() {
        let mut o = LocalEadPerEsOriginator::new(rd(65000, 100), esi(1), MplsLabel::new(8000));
        let actions = o.on_startup();
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0]);
    }

    #[test]
    fn ead_per_es_idempotent_repeat() {
        let mut o = LocalEadPerEsOriginator::new(rd(65000, 100), esi(1), MplsLabel::new(8000));
        let _ = o.on_startup();
        assert!(o.on_startup().is_empty());
    }

    #[test]
    fn ead_per_es_key_uses_max_et() {
        // RFC 7432 §7.1: per-ES uses MAX_ET (0xFFFFFFFF) to
        // discriminate from per-EVI.
        let mut o = LocalEadPerEsOriginator::new(rd(65000, 100), esi(1), MplsLabel::new(8000));
        let actions = o.on_startup();
        let OriginationAction::Inject { key, .. } = &actions[0] else {
            panic!("expected Inject, got {:?}", actions[0]);
        };
        let EvpnRouteKey::EadPerEs { ethernet_tag, .. } = *key else {
            panic!("expected EvpnRouteKey::EadPerEs, got {key:?}");
        };
        assert_eq!(ethernet_tag, EthernetTagId::MAX_ET);
    }

    #[test]
    fn ead_per_es_shutdown() {
        let mut o = LocalEadPerEsOriginator::new(rd(65000, 100), esi(1), MplsLabel::new(8000));
        let _ = o.on_startup();
        let actions = o.on_shutdown();
        assert_eq!(actions.len(), 1);
        assert_withdraw(&actions[0]);
        assert!(!o.is_advertising());
    }

    // --- LocalEadPerEviOriginator (Type 1 EAD per-EVI) ---

    #[test]
    fn ead_per_evi_first_role_emits_inject() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let actions = o.on_vni_role_changed(vni(100), DfRole::Df);
        assert_eq!(actions.len(), 1);
        assert_inject(&actions[0]);
        assert_eq!(o.advertised_count(), 1);
    }

    #[test]
    fn ead_per_evi_idempotent_same_role() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let actions = o.on_vni_role_changed(vni(100), DfRole::Df);
        assert!(
            actions.is_empty(),
            "same-role re-emit must be idempotent: {actions:?}"
        );
    }

    #[test]
    fn ead_per_evi_role_flip_emits_no_wire_actions_in_gate_8() {
        // Per RFC 7432 §14 the EAD-per-EVI wire shape carries no
        // role-dependent extcomm, so Gate 8 emits no Withdraw /
        // Inject pair on a flip — only the internal role state
        // updates. Gate 8b will layer aliasing extcomms on top and
        // re-introduce wire-side actions then.
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let actions = o.on_vni_role_changed(vni(100), DfRole::NonDf);
        assert!(actions.is_empty(), "got {actions:?}");
        // Internal state still tracks the new role for Gate 8b.
        assert_eq!(o.advertised_count(), 1);
    }

    #[test]
    fn ead_per_evi_multiple_vnis_independent() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let _ = o.on_vni_role_changed(vni(200), DfRole::NonDf);
        assert_eq!(o.advertised_count(), 2);
        // Flipping VNI 100 doesn't touch VNI 200's state and emits
        // no wire actions in Gate 8 (role-independent shape).
        let actions = o.on_vni_role_changed(vni(100), DfRole::NonDf);
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(o.advertised_count(), 2);
    }

    #[test]
    fn ead_per_evi_vni_removed_emits_withdraw() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let actions = o.on_vni_removed(vni(100));
        assert_eq!(actions.len(), 1);
        assert_withdraw(&actions[0]);
        assert_eq!(o.advertised_count(), 0);
    }

    #[test]
    fn ead_per_evi_vni_removed_unknown_no_op() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        assert!(o.on_vni_removed(vni(100)).is_empty());
    }

    #[test]
    fn ead_per_evi_drain_emits_withdraw_for_each() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let _ = o.on_vni_role_changed(vni(200), DfRole::NonDf);
        let _ = o.on_vni_role_changed(vni(300), DfRole::Df);
        let actions = o.drain_to_withdraws();
        assert_eq!(actions.len(), 3);
        for a in &actions {
            assert_withdraw(a);
        }
        assert_eq!(o.advertised_count(), 0);
    }

    #[test]
    fn ead_per_evi_outstanding_keys_lists_advertising() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let _ = o.on_vni_role_changed(vni(200), DfRole::NonDf);
        let outstanding: Vec<_> = o.outstanding_keys().collect();
        assert_eq!(outstanding.len(), 2);
    }

    #[test]
    fn ead_per_evi_key_uses_ethernet_tag_zero() {
        // RFC 7432 §6.1 / RFC 8365 §5.1.3: VLAN-based service pins the
        // Ethernet Tag to 0 on ALL EVPN routes; the VNI rides in the
        // route's label field, never the tag. Regression guard for the
        // M65-era bug where the tag carried the VNI and the route could
        // never join a remote receiver's `(ESI, tag 0)` aliasing key.
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let actions = o.on_vni_role_changed(vni(100), DfRole::Df);
        let OriginationAction::Inject { key, .. } = &actions[0] else {
            panic!("expected Inject, got {:?}", actions[0]);
        };
        let EvpnRouteKey::EadPerEvi { ethernet_tag, .. } = *key else {
            panic!("expected EvpnRouteKey::EadPerEvi, got {key:?}");
        };
        assert_eq!(ethernet_tag.0, 0);
    }

    #[test]
    fn ead_per_evi_key_joins_type2_eligibility_and_alias_indexes() {
        // The cross-rustbgpd join that PR #442's "bonus finding" showed
        // was structurally broken: a rustbgpd-originated EAD-per-EVI
        // must land on the same `(ESI, EthernetTag)` key as a
        // rustbgpd-originated Type 2 MAC/IP route, or the receive-side
        // all-active aliasing (`AliasIndex`) and ADR-0083 single-active
        // eligible-set (`SingleActiveEligibleIndex`) joins can never
        // resolve a rustbgpd peer as an alternative/backup PE.
        use crate::aliasing::{
            AliasEadPerEvi, AliasIndex, EadPerEsMode, SingleActiveEligibleIndex,
        };
        use crate::origination::LocalMacOriginator;

        let segment = esi(1);
        let remote_pe: IpAddr = ipa("10.0.0.2");

        // The EAD-per-EVI key as the segment originator emits it.
        let mut ead = LocalEadPerEviOriginator::new(rd(65000, 100), segment);
        let mut rds = BTreeMap::new();
        rds.insert(vni(100), rd(65000, 100));
        ead.set_rds(rds);
        let actions = ead.on_vni_role_changed(vni(100), DfRole::Df);
        let OriginationAction::Inject { key, .. } = &actions[0] else {
            panic!("expected Inject, got {:?}", actions[0]);
        };
        let EvpnRouteKey::EadPerEvi {
            esi: ead_esi,
            ethernet_tag: ead_tag,
            ..
        } = *key
        else {
            panic!("expected EvpnRouteKey::EadPerEvi, got {key:?}");
        };

        // The Type 2 key as the local-MAC originator emits it.
        let mut macs = LocalMacOriginator::new(vni(100), rd(65000, 100));
        let mac = MacAddress::new([0x02, 0, 0, 0, 0, 0x01]);
        let mac_actions = macs.on_local_learned(mac, 1, false, None);
        let OriginationAction::Inject { key: mac_key, .. } = &mac_actions[0] else {
            panic!("expected Inject, got {:?}", mac_actions[0]);
        };
        let EvpnRouteKey::MacIp {
            ethernet_tag: mac_tag,
            ..
        } = *mac_key
        else {
            panic!("expected EvpnRouteKey::MacIp, got {mac_key:?}");
        };

        // All-active aliasing: the EAD-per-EVI row must resolve under
        // the Type 2's (ESI, tag) lookup key.
        let alias_index = AliasIndex::build([AliasEadPerEvi {
            esi: ead_esi,
            ethernet_tag: ead_tag,
            vtep_ip: remote_pe,
        }]);
        assert_eq!(
            alias_index.vtep_ips_for(segment, mac_tag),
            Some(&[remote_pe][..]),
            "EAD-per-EVI tag {ead_tag:?} must join the Type 2 tag {mac_tag:?}",
        );

        // ADR-0083 single-active eligibility: same join, both route
        // types advertised by the remote PE.
        let eligible = SingleActiveEligibleIndex::build(
            [EadPerEsMode {
                esi: segment,
                vtep_ip: remote_pe,
                single_active: true,
            }],
            [AliasEadPerEvi {
                esi: ead_esi,
                ethernet_tag: ead_tag,
                vtep_ip: remote_pe,
            }],
        );
        assert_eq!(
            eligible.eligible_pes(segment, mac_tag),
            Some(&[remote_pe][..]),
            "EAD-per-EVI tag {ead_tag:?} must make the eligible set for the Type 2 tag {mac_tag:?}",
        );
    }

    #[test]
    fn ead_per_evi_key_uses_per_vni_rd_when_available() {
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let mut rds = BTreeMap::new();
        rds.insert(vni(100), rd(65000, 100));
        rds.insert(vni(200), rd(65000, 200));
        o.set_rds(rds);

        let actions = o.on_vni_role_changed(vni(200), DfRole::Df);
        let OriginationAction::Inject { key, .. } = &actions[0] else {
            panic!("expected Inject, got {:?}", actions[0]);
        };
        let EvpnRouteKey::EadPerEvi {
            rd, ethernet_tag, ..
        } = *key
        else {
            panic!("expected EvpnRouteKey::EadPerEvi, got {key:?}");
        };
        assert_eq!(rd, self::rd(65000, 200));
        // Tag stays 0 (RFC 7432 §6.1); the per-VNI RD is what keeps
        // the two member VNIs' routes distinct.
        assert_eq!(ethernet_tag.0, 0);
    }

    #[test]
    fn ead_per_evi_set_labels_persists_across_role_changes() {
        // Operator sets per-VNI labels at construction; subsequent
        // role changes should not clear or re-shape them.
        let mut o = LocalEadPerEviOriginator::new(rd(65000, 100), esi(1));
        let mut labels = BTreeMap::new();
        labels.insert(vni(100), MplsLabel::new(100));
        labels.insert(vni(200), MplsLabel::new(200));
        o.set_labels(labels.clone());
        let _ = o.on_vni_role_changed(vni(100), DfRole::Df);
        let _ = o.on_vni_role_changed(vni(100), DfRole::NonDf);
        // Public read accessor isn't exposed today, but
        // `set_labels` is plumbed for slice 3's path-attribute
        // construction. The smoke is that the role flips don't
        // panic / clear state.
        assert_eq!(o.advertised_count(), 1);
    }
}
