//! Differential oracle for update-group staging (design risk 1).
//!
//! Every scenario runs twice through the REAL manager task: once with
//! grouping live and once with the `test_force_ungrouped` hook putting
//! every peer on the per-peer path — the correctness oracle. The
//! per-peer outbound streams must be IDENTICAL message for message
//! (announces normalized by sort; intra-message ordering is `HashSet`
//! iteration order and deliberately not part of the contract).
//!
//! The one scenario compared by FINAL ADVERTISED STATE instead of exact
//! streams is the dirty-member resync: a grouped member keeps no
//! per-peer advertised record, so its resync deliberately over-emits
//! (full-table announce + tombstone over-withdraw — the safe
//! direction) where the per-peer path diffs against Adj-RIB-Out. The
//! folded end state must still be identical.

use std::collections::BTreeMap;

use rustbgpd_policy::{
    NeighborSetMatch, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications,
};
use rustbgpd_wire::RtcNlri;

use super::*;
use crate::route::{RouteOrigin, RtcRibRoute, VpnRibRouteKey};

pub(super) const SESSION: u64 = 1;

/// An iBGP-learned route fixture: `LOCAL_PREF` ranks it, optional
/// communities ride along (e.g. `COMMUNITY_LLGR_STALE`).
pub(super) fn ibgp_route(
    prefix: Ipv4Prefix,
    src: Ipv4Addr,
    local_pref: u32,
    communities: Vec<u32>,
) -> Route {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(local_pref),
    ];
    if !communities.is_empty() {
        attributes.push(PathAttribute::Communities(communities));
    }
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(src),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(src),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

pub(super) fn pfx(a: u8, b: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 200, a, b), 24)
}

/// A `VPNv4` NLRI fixture: RD 65000:n, inner prefix 10.210.n.0/24, one
/// BOS label. The label is route *data* (not key), so a relabel of the
/// same `n` is the ADR-0077 same-peer-relabel re-advertise case.
pub(super) fn vpn_nlri(n: u8, label: u32) -> VpnNlri {
    VpnNlri {
        labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, n]),
        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 210, n, 0), 24).unwrap(),
    }
}

fn vpn_key(n: u8, label: u32) -> VpnRibRouteKey {
    VpnRibRouteKey {
        nlri_key: vpn_nlri(n, label).key(),
        path_id: 0,
    }
}

/// An iBGP-learned VPN route fixture; `LOCAL_PREF` ranks it in the VPN
/// selection chain, extended communities (RTs) ride along when given.
pub(super) fn vpn_route(
    nlri: VpnNlri,
    src: Ipv4Addr,
    local_pref: u32,
    extended_communities: Vec<u64>,
) -> VpnRibRoute {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(local_pref),
    ];
    if !extended_communities.is_empty() {
        attributes.push(PathAttribute::ExtendedCommunities(
            extended_communities
                .into_iter()
                .map(ExtendedCommunity::new)
                .collect(),
        ));
    }
    VpnRibRoute {
        nlri,
        next_hop: IpAddr::V4(src),
        link_local_next_hop: None,
        peer: IpAddr::V4(src),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: src,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

/// RT-Constrain default-NLRI advertisement from a peer (RFC 4684
/// wildcard interest — membership passes every RT).
pub(super) fn rtc_default(src: Ipv4Addr) -> RtcRibRoute {
    RtcRibRoute {
        nlri: RtcNlri::DEFAULT,
        next_hop: IpAddr::V4(src),
        peer: IpAddr::V4(src),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: src,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn vpn_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)]
}

pub(super) fn vpn_rtc_sendable() -> Vec<(Afi, Safi)> {
    vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::RtConstrain),
    ]
}

fn permit_all_with(modifications: RouteModifications) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications,
        }],
        default_action: PolicyAction::Permit,
    }])
}

pub(super) fn deny_prefix_chain(prefix: Ipv4Prefix) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(prefix)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// Deny several prefixes, permit the rest — a multi-statement variant of
/// [`deny_prefix_chain`] so a second regroup lands on a *different* chain
/// (a content-equal reinstall is key-stable and would not regroup).
pub(super) fn deny_prefixes_chain(prefixes: &[Ipv4Prefix]) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: prefixes
            .iter()
            .map(|prefix| PolicyStatement {
                prefix: Some(Prefix::V4(*prefix)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications::default(),
            })
            .collect(),
        default_action: PolicyAction::Permit,
    }])
}

/// One outbound message, normalized: announces carry everything the
/// wire path consumes (route identity, next hop, source, attributes,
/// aligned next-hop-override flag), sorted so intra-message iteration
/// order is not compared.
/// (prefix, path id, next hop, source peer, attributes, nh-override).
pub(super) type NormAnnounce = (
    Prefix,
    u32,
    IpAddr,
    IpAddr,
    Vec<PathAttribute>,
    Option<NextHopAction>,
);

/// One normalized VPN announce: (RD+prefix key, full NLRI incl. label
/// stack, next hop, source peer, attributes). Keys/NLRI are `Debug`
/// strings — `VpnRouteKey` has no `Display` and only sort stability
/// matters here.
pub(super) type NormVpnAnnounce = (String, String, IpAddr, IpAddr, Vec<PathAttribute>);

#[derive(Debug, PartialEq, Clone)]
pub(super) struct NormMsg {
    /// A new transport generation replaced the prior connection for this
    /// peer. Wire state is connection-scoped, so folding must discard the
    /// predecessor session's advertisements before consuming the new dump.
    pub(super) session_start: Option<u64>,
    pub(super) announce: Vec<NormAnnounce>,
    pub(super) withdraw: Vec<(Prefix, u32)>,
    pub(super) end_of_rib: Vec<(Afi, Safi)>,
    pub(super) vpn_announce: Vec<NormVpnAnnounce>,
    pub(super) vpn_withdraw: Vec<(String, u32)>,
}

fn normalize(update: &OutboundRouteUpdate) -> NormMsg {
    let mut announce: Vec<_> = update
        .announce
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                r.prefix,
                r.path_id,
                r.next_hop,
                r.peer,
                (*r.attributes).clone(),
                update.next_hop_override.get(i).cloned().flatten(),
            )
        })
        .collect();
    // `Prefix`/`Afi`/`Safi` don't implement `Ord` — sort textually
    // (comparison stability is all that matters here).
    announce.sort_by_key(|entry| (entry.0.to_string(), entry.1));
    let mut withdraw = update.withdraw.clone();
    withdraw.sort_by_key(|(prefix, path_id)| (prefix.to_string(), *path_id));
    let mut end_of_rib = update.end_of_rib.clone();
    end_of_rib.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
    let mut vpn_announce: Vec<NormVpnAnnounce> = update
        .vpn_announce
        .iter()
        .map(|r| {
            (
                format!("{:?}", r.nlri.key()),
                format!("{:?}", r.nlri),
                r.next_hop,
                r.peer,
                (*r.attributes).clone(),
            )
        })
        .collect();
    vpn_announce.sort_by(|a, b| a.0.cmp(&b.0));
    let mut vpn_withdraw: Vec<(String, u32)> = update
        .vpn_withdraw
        .iter()
        .map(|key| (format!("{:?}", key.nlri_key), key.path_id))
        .collect();
    vpn_withdraw.sort();
    NormMsg {
        session_start: None,
        announce,
        withdraw,
        end_of_rib,
        vpn_announce,
        vpn_withdraw,
    }
}

pub(super) type Streams = BTreeMap<IpAddr, Vec<NormMsg>>;

/// Fold a stream into the final advertised state (announce replaces,
/// withdraw removes; unknown withdraws are RFC 4271 no-ops).
/// (next hop, source peer, attributes, nh-override).
pub(super) type FoldedEntry = (IpAddr, IpAddr, Vec<PathAttribute>, Option<NextHopAction>);
pub(super) type FoldedState = BTreeMap<IpAddr, HashMap<(Prefix, u32), FoldedEntry>>;

pub(super) fn fold(streams: &Streams) -> FoldedState {
    let mut state = FoldedState::new();
    for (peer, msgs) in streams {
        let table = state.entry(*peer).or_default();
        for msg in msgs {
            if msg.session_start.is_some() {
                table.clear();
            }
            for (prefix, path_id) in &msg.withdraw {
                table.remove(&(*prefix, *path_id));
            }
            for (prefix, path_id, nh, src, attrs, nh_override) in &msg.announce {
                table.insert(
                    (*prefix, *path_id),
                    (*nh, *src, attrs.clone(), nh_override.clone()),
                );
            }
        }
    }
    state
}

/// VPN counterpart of [`fold`]: final advertised VPN state per peer,
/// keyed by RD+prefix identity (`path_id` 0 only in these scenarios).
pub(super) type FoldedVpnState =
    BTreeMap<IpAddr, HashMap<String, (String, IpAddr, IpAddr, Vec<PathAttribute>)>>;

pub(super) fn fold_vpn(streams: &Streams) -> FoldedVpnState {
    let mut state = FoldedVpnState::new();
    for (peer, msgs) in streams {
        let table = state.entry(*peer).or_default();
        for msg in msgs {
            if msg.session_start.is_some() {
                table.clear();
            }
            for (key, _) in &msg.vpn_withdraw {
                table.remove(key);
            }
            for (key, nlri, nh, src, attrs) in &msg.vpn_announce {
                table.insert(key.clone(), (nlri.clone(), *nh, *src, attrs.clone()));
            }
        }
    }
    state
}

pub(super) struct Oracle {
    tx: mpsc::Sender<RibUpdate>,
    outs: BTreeMap<IpAddr, mpsc::Receiver<OutboundRouteUpdate>>,
    handle: tokio::task::JoinHandle<()>,
    /// Messages drained so far (incremental collection so the VPN
    /// invariant checker can fold mid-scenario); `finish` drains the
    /// remainder into it and returns the whole stream set.
    collected: Streams,
}

/// Session features that disqualify a peer from shared single-best staging.
/// The fault corpus varies these only at stamped `PeerUp` boundaries, matching
/// production OPEN negotiation rather than inventing live capability changes.
#[derive(Clone, Debug, Default)]
pub(super) struct OraclePeerFeatures {
    pub(super) add_path_send_max: u32,
    pub(super) negotiated_orf_recv: Vec<(Afi, Safi)>,
}

impl Oracle {
    pub(super) fn spawn(force_ungrouped: bool, cluster_id: Option<Ipv4Addr>) -> Self {
        let (tx, rx) = mpsc::channel(512);
        let mut manager =
            RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        Self {
            tx,
            outs: BTreeMap::new(),
            handle,
            collected: Streams::new(),
        }
    }

    async fn peer_up(
        &mut self,
        peer: Ipv4Addr,
        is_ebgp: bool,
        route_reflector_client: bool,
        export_policy: Option<PolicyChain>,
        capacity: usize,
    ) {
        self.peer_up_families(
            peer,
            is_ebgp,
            route_reflector_client,
            export_policy,
            capacity,
            ipv4_sendable(),
        )
        .await;
    }

    pub(super) async fn peer_up_families(
        &mut self,
        peer: Ipv4Addr,
        is_ebgp: bool,
        route_reflector_client: bool,
        export_policy: Option<PolicyChain>,
        capacity: usize,
        sendable_families: Vec<(Afi, Safi)>,
    ) {
        self.peer_up_families_generation(
            peer,
            SESSION,
            is_ebgp,
            route_reflector_client,
            export_policy,
            capacity,
            sendable_families,
        )
        .await;
    }

    // Mirrors the production PeerUp event so schedules can state every
    // grouping input and the session generation at the call site.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors every grouping input in the production PeerUp event"
    )]
    pub(super) async fn peer_up_families_generation(
        &mut self,
        peer: Ipv4Addr,
        session_id: u64,
        is_ebgp: bool,
        route_reflector_client: bool,
        export_policy: Option<PolicyChain>,
        capacity: usize,
        sendable_families: Vec<(Afi, Safi)>,
    ) {
        self.peer_up_families_generation_with_features(
            peer,
            session_id,
            is_ebgp,
            route_reflector_client,
            export_policy,
            capacity,
            sendable_families,
            OraclePeerFeatures::default(),
        )
        .await;
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fault oracle mirrors PeerUp plus negotiated feature changes at a stamped session boundary"
    )]
    pub(super) async fn peer_up_families_generation_with_features(
        &mut self,
        peer: Ipv4Addr,
        session_id: u64,
        is_ebgp: bool,
        route_reflector_client: bool,
        export_policy: Option<PolicyChain>,
        capacity: usize,
        sendable_families: Vec<(Afi, Safi)>,
        features: OraclePeerFeatures,
    ) {
        let (out_tx, out_rx) = mpsc::channel(capacity);
        let add_path_send_families = if features.add_path_send_max > 0 {
            sendable_families
                .iter()
                .copied()
                .filter(|(_, safi)| *safi == Safi::Unicast)
                .collect()
        } else {
            Vec::new()
        };
        self.tx
            .send(RibUpdate::PeerUp {
                per_client_best: false,
                session_id,
                peer: IpAddr::V4(peer),
                peer_asn: if is_ebgp { 65010 } else { 65000 },
                peer_router_id: peer,
                outbound_tx: out_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                orr_vantage: None,
                add_path_send_families,
                add_path_send_max: features.add_path_send_max,
                negotiated_orf_recv: features.negotiated_orf_recv,
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .unwrap();
        // A re-registration (e.g. GR re-establish) replaces the
        // receiver; drain the predecessor first so its messages stay in
        // the collected stream.
        if let Some(mut old_rx) = self.outs.insert(IpAddr::V4(peer), out_rx) {
            let msgs = self.collected.entry(IpAddr::V4(peer)).or_default();
            while let Ok(update) = old_rx.try_recv() {
                msgs.push(normalize(&update));
            }
            msgs.push(NormMsg {
                session_start: Some(session_id),
                announce: vec![],
                withdraw: vec![],
                end_of_rib: vec![],
                vpn_announce: vec![],
                vpn_withdraw: vec![],
            });
        }
        self.quiesce().await;
    }

    pub(super) async fn peer_add_path_limits(
        &mut self,
        peer: Ipv4Addr,
        session_id: u64,
        limit: u32,
    ) {
        self.tx
            .send(RibUpdate::PeerAddPathLimits {
                peer: IpAddr::V4(peer),
                session_id,
                limits: vec![((Afi::Ipv4, Safi::Unicast), limit)],
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    pub(super) async fn peer_orf_update(
        &mut self,
        peer: Ipv4Addr,
        session_id: u64,
        entries: Vec<AddressPrefixOrf>,
    ) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::PeerOrfUpdate {
                peer: IpAddr::V4(peer),
                session_id,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                when: WhenToRefresh::Immediate,
                entries,
                reply: reply_tx,
            })
            .await
            .unwrap();
        let result = reply_rx.await.unwrap();
        self.quiesce().await;
        result
    }

    pub(super) async fn peer_down(&mut self, peer: Ipv4Addr) {
        self.peer_down_generation(peer, SESSION).await;
    }

    pub(super) async fn peer_down_generation(&mut self, peer: Ipv4Addr, session_id: u64) {
        self.tx
            .send(RibUpdate::PeerDown {
                peer: IpAddr::V4(peer),
                session_id,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    pub(super) async fn routes(
        &mut self,
        from: Ipv4Addr,
        announce: Vec<Route>,
        withdraw: Vec<Ipv4Prefix>,
    ) {
        self.routes_generation(from, SESSION, announce, withdraw)
            .await;
    }

    pub(super) async fn routes_generation(
        &mut self,
        from: Ipv4Addr,
        session_id: u64,
        announce: Vec<Route>,
        withdraw: Vec<Ipv4Prefix>,
    ) {
        self.tx
            .send(RibUpdate::RoutesReceived {
                session_id,
                peer: IpAddr::V4(from),
                announced: announce,
                withdrawn: withdraw.into_iter().map(|p| (Prefix::V4(p), 0)).collect(),
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    async fn vpn_routes(
        &mut self,
        from: Ipv4Addr,
        announce: Vec<VpnRibRoute>,
        withdraw: Vec<VpnRibRouteKey>,
    ) {
        self.vpn_routes_generation(from, SESSION, announce, withdraw)
            .await;
    }

    pub(super) async fn vpn_routes_generation(
        &mut self,
        from: Ipv4Addr,
        session_id: u64,
        announce: Vec<VpnRibRoute>,
        withdraw: Vec<VpnRibRouteKey>,
    ) {
        self.tx
            .send(RibUpdate::VpnRoutesReceived {
                peer: IpAddr::V4(from),
                session_id,
                announced: announce,
                withdrawn: withdraw,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    /// RFC 4684 RT-Constrain advertisement from a peer — rebuilds the
    /// peer's RT membership (the per-peer VPN filter).
    pub(super) async fn rtc_routes(&mut self, from: Ipv4Addr, announce: Vec<RtcRibRoute>) {
        self.rtc_routes_full_generation(from, SESSION, announce, vec![])
            .await;
        self.quiesce().await;
    }

    /// RTC announce + withdraw, WITHOUT quiescing — racing scenarios
    /// queue this back-to-back with route updates.
    pub(super) async fn rtc_routes_full(
        &mut self,
        from: Ipv4Addr,
        announce: Vec<RtcRibRoute>,
        withdraw: Vec<crate::route::RtcRibRouteKey>,
    ) {
        self.rtc_routes_full_generation(from, SESSION, announce, withdraw)
            .await;
    }

    pub(super) async fn rtc_routes_full_generation(
        &mut self,
        from: Ipv4Addr,
        session_id: u64,
        announce: Vec<RtcRibRoute>,
        withdraw: Vec<crate::route::RtcRibRouteKey>,
    ) {
        self.tx
            .send(RibUpdate::RtcRoutesReceived {
                peer: IpAddr::V4(from),
                session_id,
                announced: announce,
                withdrawn: withdraw,
            })
            .await
            .unwrap();
    }

    /// VPN announce WITHOUT quiescing (racing scenarios).
    async fn vpn_routes_no_quiesce(&mut self, from: Ipv4Addr, announce: Vec<VpnRibRoute>) {
        self.tx
            .send(RibUpdate::VpnRoutesReceived {
                peer: IpAddr::V4(from),
                session_id: SESSION,
                announced: announce,
                withdrawn: vec![],
            })
            .await
            .unwrap();
    }

    /// RFC 4724 graceful restart: routes (SAFI-132 interest included)
    /// are preserved stale for the returning session.
    async fn graceful_restart(&mut self, peer: Ipv4Addr) {
        self.tx
            .send(RibUpdate::PeerGracefulRestart {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
                restart_time: 120,
                stale_routes_time: 300,
                gr_families: vpn_rtc_sendable(),
                peer_llgr_capable: false,
                peer_llgr_families: vec![],
                llgr_stale_time: 0,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    /// Total export-policy evaluations recorded by every installed
    /// chain since install (ADR-0096 live counters) — the zero-eval
    /// assertion's window.
    async fn export_policy_evals(&mut self) -> u64 {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryExportPolicyTermHits {
                peer: None,
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().iter().map(|row| row.evals).sum()
    }

    /// Export-policy evaluations visible through one installed peer handle.
    /// Grouped peers intentionally alias the same group counter instance, so
    /// summing every per-peer row would multiply one real evaluation by the
    /// number of members and cannot measure a zero-evaluation delta.
    async fn export_policy_evals_for(&mut self, peer: Ipv4Addr) -> u64 {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryExportPolicyTermHits {
                peer: Some(IpAddr::V4(peer)),
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().iter().map(|row| row.evals).sum()
    }

    /// Drain every receiver into the collected streams (no await — only
    /// messages already sent).
    fn drain_collected(&mut self) {
        for (peer, rx) in &mut self.outs {
            let msgs = self.collected.entry(*peer).or_default();
            while let Ok(update) = rx.try_recv() {
                msgs.push(normalize(&update));
            }
        }
    }

    /// The design §5 invariant checker: recompute `adv(m)` from manager
    /// state (`{ e ∈ group table : e.peer ≠ m ∧ pass_m(e) }` for a
    /// VPN-grouped member, the per-peer Adj-RIB-Out otherwise) for every
    /// peer and compare against the folded emitted VPN state.
    async fn check_vpn_invariant(&mut self, label: &str) {
        self.quiesce().await;
        self.drain_collected();
        let folded = fold_vpn(&self.collected);
        let peers: Vec<IpAddr> = self.outs.keys().copied().collect();
        for peer in peers {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.tx
                .send(RibUpdate::TestQueryVpnAdvertised {
                    peer,
                    reply: reply_tx,
                })
                .await
                .unwrap();
            let advertised = reply_rx.await.unwrap();
            let adv: BTreeMap<String, IpAddr> = advertised.into_iter().collect();
            let fold: BTreeMap<String, IpAddr> = folded
                .get(&peer)
                .map(|table| {
                    table
                        .iter()
                        .map(|(key, (_, _, src, _))| (key.clone(), *src))
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(
                adv, fold,
                "VPN invariant adv(m) != folded emitted state for {peer} at step: {label}"
            );
        }
    }

    /// The peer's update-group membership label (`group:N` or the
    /// ungrouped reason).
    pub(super) async fn group_label(&mut self, peer: Ipv4Addr) -> String {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryPeerUpdateGroup {
                peer: IpAddr::V4(peer),
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    async fn group_snapshot(&mut self) -> crate::update::UpdateGroupSnapshot {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryUpdateGroupSnapshot { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    async fn outbound_health(&mut self) -> (usize, usize, usize, usize, usize, usize) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::TestQueryOutboundHealth { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub(super) async fn replace_policy(
        &mut self,
        peer: Ipv4Addr,
        export_policy: Option<PolicyChain>,
    ) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::ReplacePeerExportPolicy {
                peer: IpAddr::V4(peer),
                export_policy,
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
    }

    /// RFC 2918 ROUTE-REFRESH from the peer: the grouped path replays
    /// the group table, the per-peer path re-runs full staging.
    async fn route_refresh(&mut self, peer: Ipv4Addr, afi: Afi, safi: Safi) {
        self.tx
            .send(RibUpdate::RouteRefreshRequest {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
                afi,
                safi,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    async fn refresh_outbound(&mut self, peer: Ipv4Addr) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::RefreshPeerOutbound {
                peer: IpAddr::V4(peer),
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
    }

    /// Return the current Loc-RIB best routes after a FIFO round trip on
    /// the primary channel. The reply is also an ordering barrier for all
    /// prior updates and their resulting outbound sends.
    pub(super) async fn best_routes(&mut self) -> Vec<Route> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    /// Round-trip a query on the primary channel: the run loop only
    /// handles it after every prior update (and its route chunks) has
    /// been fully processed, so all resulting outbound sends have
    /// happened by the time the reply arrives.
    pub(super) async fn quiesce(&mut self) {
        let _ = self.best_routes().await;
    }

    /// Drain one pending message from a peer's channel (channel-fill
    /// scenarios). The message stays in the collected stream so folded
    /// comparisons and the VPN invariant checker see the whole history.
    pub(super) async fn drain_one(&mut self, peer: Ipv4Addr) -> OutboundRouteUpdate {
        let update = self
            .outs
            .get_mut(&IpAddr::V4(peer))
            .expect("peer registered")
            .recv()
            .await
            .expect("message pending");
        self.collected
            .entry(IpAddr::V4(peer))
            .or_default()
            .push(normalize(&update));
        update
    }

    /// After a FIFO barrier, drain only one peer's currently available
    /// messages. Each update is normalized once and retained in the full
    /// collected history as well as returned to the operation-level oracle.
    pub(super) async fn drain_peer_available(&mut self, peer: Ipv4Addr) -> Vec<NormMsg> {
        self.quiesce().await;
        let peer = IpAddr::V4(peer);
        let rx = self.outs.get_mut(&peer).expect("peer registered");
        let mut drained = Vec::new();
        while let Ok(update) = rx.try_recv() {
            drained.push(normalize(&update));
        }
        self.collected
            .entry(peer)
            .or_default()
            .extend(drained.iter().cloned());
        drained
    }

    /// Drain every currently available message without waiting for a send.
    /// Fault schedules use this after a virtual-time retry because a correct
    /// no-op resync is also allowed to emit nothing.
    pub(super) fn drain_available(&mut self) {
        self.drain_collected();
    }

    /// Collect every message every peer has received so far, including
    /// those drained mid-scenario by `drain_one` and the invariant
    /// checker — the returned streams are the complete emission history.
    pub(super) async fn terminal_health(&mut self) -> (usize, usize, usize, usize, usize, usize) {
        self.quiesce().await;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::TestQueryOutboundHealth { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub(super) async fn finish(mut self) -> Streams {
        self.quiesce().await;
        self.drain_collected();
        for peer in self.outs.keys() {
            self.collected.entry(*peer).or_default();
        }
        drop(self.tx);
        self.handle.await.unwrap();
        self.collected
    }
}

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const D: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const E: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const F: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

async fn run_grouped_and_ungrouped<S>(
    cluster_id: Option<Ipv4Addr>,
    scenario: S,
) -> (Streams, Streams)
where
    S: AsyncFn(&mut Oracle),
{
    let mut grouped = Oracle::spawn(false, cluster_id);
    scenario(&mut grouped).await;
    let grouped = grouped.finish().await;
    let mut ungrouped = Oracle::spawn(true, cluster_id);
    scenario(&mut ungrouped).await;
    let ungrouped = ungrouped.finish().await;
    (grouped, ungrouped)
}

#[tokio::test]
async fn update_group_snapshot_is_side_effect_free_and_runtime_exact() {
    let mut oracle = Oracle::spawn(false, None);
    oracle.peer_up(A, false, true, None, 64).await;
    oracle.peer_up(B, false, true, None, 64).await;
    let labels_before = (oracle.group_label(A).await, oracle.group_label(B).await);
    let evals_before = oracle.export_policy_evals().await;
    let health_before = oracle.outbound_health().await;

    let first = oracle.group_snapshot().await;
    let second = oracle.group_snapshot().await;

    assert_eq!(first, second, "snapshot must be deterministic");
    assert_eq!(first.peers.len(), 2);
    assert!(first.peers.iter().all(|row| {
        row.runtime_membership.starts_with("group:")
            && row.classification == crate::update::classify_update_group(row.input.clone())
    }));
    assert_eq!(
        labels_before,
        (oracle.group_label(A).await, oracle.group_label(B).await)
    );
    assert_eq!(evals_before, oracle.export_policy_evals().await);
    assert_eq!(health_before, oracle.outbound_health().await);
    oracle.finish().await;
}

#[tokio::test]
async fn runtime_group_key_ignores_non_staging_families() {
    let mut oracle = Oracle::spawn(false, None);
    oracle
        .peer_up_families(
            A,
            false,
            true,
            None,
            64,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)],
        )
        .await;
    oracle.peer_up(B, false, true, None, 64).await;
    assert_eq!(oracle.group_label(A).await, oracle.group_label(B).await);
    oracle.finish().await;
}

/// The kitchen-sink exact-stream scenario: initial dump, best change,
/// best withdraw, split horizon (source inside the group), source-flip
/// X→Y→X, policy-modified attributes, next-hop-override flags,
/// RR-client vs non-client groups, eBGP LLGR suppression, member join
/// mid-stream, leave, regroup on policy change (content-equal reinstall
/// AND a genuine change), and a GShut-style forced refresh.
#[tokio::test]
async fn oracle_streams_identical_across_rr_mix() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let modifying_chain = || {
        permit_all_with(RouteModifications {
            set_med: Some(77),
            communities_add: vec![0xFDE8_0001],
            set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 99,
            )))),
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        // Three RR clients (one group), a non-client (second group), an
        // eBGP peer with an attribute-modifying chain (third group).
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 64).await;
        o.peer_up(D, false, false, None, 64).await;
        o.peer_up(E, true, false, Some(modifying_chain()), 64).await;

        // Initial announces from a member: split horizon inside the group.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;

        // Source flip X→Y (B takes over p1 with higher LOCAL_PREF)...
        o.routes(B, vec![ibgp_route(pfx(1, 0), B, 200, vec![])], vec![])
            .await;
        // ... and flip back Y→X (B withdraws its path).
        o.routes(B, vec![], vec![pfx(1, 0)]).await;

        // Attribute change on the standing best (same source).
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 150, vec![])], vec![])
            .await;

        // LLGR-stale-tagged route: suppressed toward the eBGP peer
        // (no LLGR capability), advertised to iBGP members.
        o.routes(
            B,
            vec![ibgp_route(
                pfx(3, 0),
                B,
                100,
                vec![rustbgpd_wire::COMMUNITY_LLGR_STALE],
            )],
            vec![],
        )
        .await;

        // Late joiner into the client group: replay, not restage.
        o.peer_up(F, false, true, None, 64).await;

        // RFC 2918 route refresh, both group shapes: a grouped RR
        // client with own-sourced entries (split-horizon exclusion in
        // the replay) and the eBGP peer whose chain modifies attributes
        // + sets a next-hop override (the replay must reproduce both
        // from the staged residue without re-running policy).
        o.route_refresh(A, Afi::Ipv4, Safi::Unicast).await;
        o.route_refresh(E, Afi::Ipv4, Safi::Unicast).await;

        // Best withdraw: p1 goes away entirely.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;

        // Member leaves (its p3 route falls out of the Loc-RIB too).
        o.peer_down(B).await;

        // Regroup fast path: a content-equal chain reinstall on E must
        // emit nothing on either path.
        o.replace_policy(E, Some(modifying_chain())).await;

        // Genuine regroup: C moves to a deny-p2 group — one-shot diff
        // withdraws p2 and leaves everything else untouched.
        o.replace_policy(C, Some(deny_prefix_chain(pfx(2, 0))))
            .await;

        // GShut-style forced re-emission (RefreshPeerOutbound).
        o.refresh_outbound(D).await;

        // A genuine best change immediately after the acknowledged force
        // proves the force-only pass was consumed synchronously. Grouped
        // force assembly deliberately ignores pass deltas; allowing the flag
        // to leak into this pass would violate that invariant (LAN-345).
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 175, vec![])], vec![])
            .await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        grouped, ungrouped,
        "grouped and per-peer outbound streams must be identical"
    );
    // Sanity: the scenario actually produced traffic.
    assert!(
        grouped.values().any(|msgs| !msgs.is_empty()),
        "scenario must exercise outbound traffic"
    );
}

/// Dirty-member resync (channel-full → tombstones → timer resync).
/// Streams intentionally differ (the grouped resync over-emits — the
/// safe direction); the folded final advertised state must be
/// identical, and the withdraw of the prefix that went away while
/// dirty must reach the wire on both paths.
#[tokio::test]
async fn oracle_dirty_resync_converges_to_identical_state() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // p2 announce fails for C → C goes dirty.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // p1 withdrawn WHILE C is dirty → tombstone; C's channel still full.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    // The dirty member must have (over-)withdrawn the tombstoned p1 on
    // the grouped path: its folded table must not contain p1 (fold
    // starts after the pre-drained p1 announce, so a leftover p1 key
    // could only come from a resync bug).
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "tombstoned prefix must not survive the grouped resync"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "the update lost to the full channel must be recovered by the resync"
    );
}

/// A failed forced refresh is retained for retry and marks the peer dirty.
/// Genuine churn can arrive before that retry, so this deliberately exercises
/// the allowed `force && dirty && !best_changed.is_empty()` state: dirty group
/// assembly must include the pass tombstones while force still replays the
/// current table.
#[tokio::test]
async fn oracle_failed_force_then_churn_converges_to_identical_state() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 1).await;
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // The standing p1 announce fills C's only queue slot.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // Forced replay fails against the full channel, retaining force and
        // marking C dirty for the timer retry.
        o.refresh_outbound(C).await;
        // Before retry, p1 is withdrawn and p2 becomes best. This is the
        // nonempty best-change pass that force-only assembly may never see,
        // but force+dirty must heal.
        o.routes(
            A,
            vec![ibgp_route(pfx(2, 0), A, 100, vec![])],
            vec![pfx(1, 0)],
        )
        .await;

        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "failed force plus churn must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(!c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)));
    assert!(c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)));
}

/// A source-flip member-scoped withdraw lost to a full channel: the
/// member is the delta's NEW source (its own route displaces another
/// peer's), so its emission is a pure withdraw while the key stays IN
/// the group table — tombstones (which only track table withdrawals)
/// never see it. It must ride the member's extra-withdraw residue or
/// the stale route strands until the next covering event.
#[tokio::test]
async fn oracle_source_flip_withdraw_lost_to_full_channel_recovers() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 from A lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // Source flip ONTO the jammed member: C's own route displaces
        // A's as best. C's member-scoped emission is a pure withdraw —
        // lost to the full channel, and NOT a table withdrawal.
        o.routes(C, vec![ibgp_route(pfx(1, 0), C, 200, vec![])], vec![])
            .await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "the source-flip withdraw lost to the full channel must be recovered by the resync"
    );
}

/// A source flip staged while the member is ALREADY dirty: the member's
/// pass takes the resync arm (never the per-member matrix), so the only
/// record of its member-scoped withdraw is the one taken at STAGING —
/// the key stays IN the group table (invisible to tombstones) and the
/// resync announces table ∖ own-sourced, so nothing later can withdraw
/// the displaced route.
#[tokio::test]
async fn oracle_source_flip_onto_already_dirty_member_withdraws_stale_route() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 from A lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // p2 announce fails for C → C goes dirty BEFORE the flip pass.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // Free the channel: the flip pass's resync will SUCCEED, so a
        // withdraw not recorded by staging time is lost for good.
        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");

        // Source flip ONTO the already-dirty member: C's own route
        // displaces A's as best. C's pass takes the resync arm, which
        // announces table ∖ own-sourced — the displaced p1(A) can only
        // reach the withdraw set via the extras recorded at staging.
        o.routes(C, vec![ibgp_route(pfx(1, 0), C, 200, vec![])], vec![])
            .await;

        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "a source flip staged onto an already-dirty member must withdraw the displaced route"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "the update lost to the full channel must be recovered by the resync"
    );
}

/// Regroup-while-dirty variant of the flip-onto-dirty-member scenario:
/// the member regroups before its resync drains. The regroup baseline
/// snapshot filters own-sourced entries, so the flipped key is absent
/// from it — only the extras recorded at staging (which must SURVIVE
/// the regroup) can put the displaced route in the one-shot diff's
/// withdraw set. p1 is the ONLY staged key, so every intermediate
/// resync assembles empty and nothing else covers the withdraw.
#[tokio::test]
async fn oracle_regroup_while_dirty_after_source_flip_withdraws_stale_route() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 from A lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // Attribute change on p1: the re-announce fails for C → dirty,
        // with p1 the only staged key.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 150, vec![])], vec![])
            .await;
        // Source flip ONTO the dirty member (channel still full).
        o.routes(C, vec![ibgp_route(pfx(1, 0), C, 200, vec![])], vec![])
            .await;
        // Regroup C before its resync drains: the baseline snapshot
        // excludes own-sourced p1.
        o.replace_policy(C, Some(deny_prefix_chain(pfx(9, 0))))
            .await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "the extras recorded at staging must survive the regroup and withdraw the stale route"
    );
}

/// Retention-guard check: the source flips onto the dirty member and
/// back BEFORE its resync runs. The staging-time extras record for the
/// flip must be dropped by the resync's `member_retains` guard once the
/// key is again another peer's (the full-table announce covers it) —
/// the member ends with p1(A) advertised and no spurious withdraw ever
/// reaches its wire.
#[tokio::test]
async fn oracle_source_flip_back_before_resync_keeps_route_without_spurious_withdraw() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 from A lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // p2 announce fails for C → C goes dirty.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // Source flip ONTO the dirty member (channel still full)...
        o.routes(C, vec![ibgp_route(pfx(1, 0), C, 200, vec![])], vec![])
            .await;
        // ... and flip back to A before the resync runs.
        o.routes(C, vec![], vec![pfx(1, 0)]).await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    let p1_entry = c_final.get(&(Prefix::V4(pfx(1, 0)), 0));
    assert_eq!(
        p1_entry.map(|(_, src, _, _)| *src),
        Some(IpAddr::V4(A)),
        "after the flip-back the member must retain p1 sourced from A"
    );
    // The retention guard must have dropped the staged extra withdraw:
    // no withdraw of p1 ever reaches C's wire.
    let spurious = grouped[&IpAddr::V4(C)]
        .iter()
        .any(|msg| msg.withdraw.contains(&(Prefix::V4(pfx(1, 0)), 0)));
    assert!(
        !spurious,
        "flip-back before resync must not put a spurious withdraw on the wire"
    );
}

/// Regression (stale-route leak): a grouped member whose regroup resync
/// SEND FAILS is dirty with `pending_regroup_baseline` holding the ONLY
/// record of its true wire state (a grouped member keeps no per-family
/// Adj-RIB-Out). A SECOND regroup before it drains must UNION the fresh
/// group-view snapshot onto that baseline, not overwrite it — a blind
/// overwrite drops wire keys absent from BOTH the new snapshot and the
/// new group's table, so they are never withdrawn and leak.
///
/// Sequence: C in sync on wire {p1,p2} → jam its cap-1 channel with p3 →
/// regroup A→B (policy denies p1; resync send fails → C dirty, baseline
/// = {p1,p2,p3}) → regroup B→C (policy denies p1,p3) before C drains →
/// drain + fire the resync timer. p1 is in the first baseline, absent
/// from the second group view (denied by B) AND from group C's table
/// (denied by C) — it MUST be withdrawn, not stranded on C's wire.
#[tokio::test]
async fn oracle_second_regroup_while_dirty_unions_baseline_no_leak() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await; // route source
        o.peer_up(C, false, true, None, 1).await; // observed, cap-1 channel
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // Sync C to wire {p1,p2}: each lands and is drained, so the
        // channel empties between sends and C never goes dirty here.
        for n in 1..=2u8 {
            o.routes(A, vec![ibgp_route(pfx(n, 0), A, 100, vec![])], vec![])
                .await;
            o.drain_one(C).await;
        }

        // Jam: p3 (a distinct prefix) lands in the cap-1 channel and is
        // NOT drained, so the next resync send fails against a full queue.
        o.routes(A, vec![ibgp_route(pfx(3, 0), A, 100, vec![])], vec![])
            .await;

        // Regroup A→B (deny p1): baseline captures wire {p1,p2,p3}; the
        // resync send fails against the full channel → C stays dirty.
        o.replace_policy(C, Some(deny_prefixes_chain(&[pfx(1, 0)])))
            .await;
        // Regroup B→C (deny p1,p3) BEFORE C drains: must UNION onto the
        // retained {p1,p2,p3} baseline, not overwrite with {p2,p3}.
        o.replace_policy(C, Some(deny_prefixes_chain(&[pfx(1, 0), pfx(3, 0)])))
            .await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    // The leak: p1 was on C's wire, is absent from group C's table, and
    // is absent from the second group-view snapshot. A baseline overwrite
    // never withdraws it (it never reaches the withdraw candidate set);
    // the union does.
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "stale-route leak: p1 was never withdrawn — the second regroup \
         overwrote the wire baseline instead of unioning it"
    );
    // member_retains must keep a route still in group C's table advertised.
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "p2 (still in group C's table) must stay advertised"
    );
    // And the whole grouped end state must converge with the per-peer
    // oracle, which tracks wire state in Adj-RIB-Out and cannot leak.
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "grouped final advertised state must converge with the per-peer oracle"
    );
}

/// Under-advertise heal (LAN-346), grouped→grouped: a member misses an
/// ANNOUNCE while dirty (the group table gains p3 but the send fails),
/// then regroups. The regroup baseline is a snapshot of the group table
/// — INTENDED state, which already contains p3 — so an equality diff
/// against it suppresses the p3 announce the member never received and
/// the route goes permanently missing. The successful resync after the
/// regroup must put p3 on the member's wire.
#[tokio::test]
async fn oracle_announce_missed_while_dirty_heals_across_regroup() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        // C gets a capacity-1 channel so a jammed send fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // Sync C to wire {p1}.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.drain_one(C).await;
        // Jam: p2 lands in the cap-1 channel and is NOT drained.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // p3 announce fails for C → dirty; the group table holds p3 but
        // C's wire never saw it. The regroup baseline snapshot below
        // will contain p3 anyway (intended state, not wire state).
        o.routes(A, vec![ibgp_route(pfx(3, 0), A, 100, vec![])], vec![])
            .await;
        // Regroup C while dirty (grouped→grouped).
        o.replace_policy(C, Some(deny_prefix_chain(pfx(9, 0))))
            .await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(3, 0)), 0)),
        "the announce missed while dirty must not be equality-suppressed \
         against the regroup baseline — p3 must reach the wire"
    );
}

/// Under-advertise heal (LAN-346), grouped→ungrouped: same missed
/// announce, but the dirty member's membership flips to the per-peer
/// path. The baseline seeded into the Adj-RIB-Out contains the never-
/// sent p3, so the per-peer equality diff suppresses it the same way.
/// The per-peer resync must put p3 on the wire.
#[tokio::test]
async fn oracle_announce_missed_while_dirty_heals_across_move_to_per_peer_path() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        // C gets a capacity-1 channel so a jammed send fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // Sync C to wire {p1}.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.drain_one(C).await;
        // Jam: p2 lands in the cap-1 channel and is NOT drained.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // p3 announce fails for C → dirty; C's wire never saw p3.
        o.routes(A, vec![ibgp_route(pfx(3, 0), A, 100, vec![])], vec![])
            .await;
        // C's chain becomes peer-context-dependent (verdicts unchanged):
        // a grouped→per-peer move while dirty.
        o.replace_policy(C, Some(peer_context_permit_chain())).await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(3, 0)), 0)),
        "the announce missed while dirty must not be equality-suppressed \
         against the seeded Adj-RIB-Out — p3 must reach the wire"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0))
            && c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "routes already delivered must stay advertised"
    );
}

/// Suppression pin: a CLEAN member's regroup one-shot diff must keep
/// equality-suppressing unchanged routes — the dirty-member announce
/// heal must not regress the clean path into a full-table re-announce.
#[tokio::test]
async fn oracle_clean_member_regroup_suppresses_unchanged_announces() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 64).await;

        // C in sync on wire {p1, p2} — never dirty (ample capacity).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;

        // Clean regroup: the one-shot diff must assemble empty.
        o.replace_policy(C, Some(deny_prefix_chain(pfx(9, 0))))
            .await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_msgs = &grouped[&IpAddr::V4(C)];
    for prefix in [pfx(1, 0), pfx(2, 0)] {
        let announces = c_msgs
            .iter()
            .flat_map(|msg| &msg.announce)
            .filter(|(p, _, _, _, _, _)| *p == Prefix::V4(prefix))
            .count();
        assert_eq!(
            announces, 1,
            "clean member must not re-announce unchanged {prefix} across a regroup"
        );
    }
    assert!(
        c_msgs.iter().all(|msg| msg.withdraw.is_empty()),
        "clean regroup with no verdict change must not withdraw anything"
    );
}

/// A permit-everything chain carrying a peer-context guard: the
/// neighbor-set deny matches an ASN no test peer uses, so verdicts are
/// unchanged, but `requires_peer_context` moves the peer off the
/// grouped path — the grouped→per-peer membership transition.
pub(super) fn peer_context_permit_chain() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: Some(NeighborSetMatch {
                addresses: vec![],
                remote_asns: vec![65099],
                peer_groups: vec![],
            }),
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// A grouped member that goes dirty, misses a withdraw (recorded as a
/// group tombstone), and then moves to the per-peer path (its chain
/// becomes peer-context-dependent) carries the tombstone as extra
/// (over-)withdraw residue. The withdrawn key is in neither the
/// Loc-RIB nor the Adj-RIB-Out seeded from the regroup baseline, so
/// the residue is the ONLY record of the stale route — the per-peer
/// resync must emit its withdraw, or the route strands on the wire
/// until the session bounces.
#[tokio::test]
async fn oracle_dirty_leaver_extras_withdraw_on_per_peer_path() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        // C gets a capacity-1 channel so a jammed send fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // Sync C to wire {p1, p2}: each lands and is drained, so the
        // channel empties between sends and C never goes dirty here.
        for n in 1..=2u8 {
            o.routes(A, vec![ibgp_route(pfx(n, 0), A, 100, vec![])], vec![])
                .await;
            o.drain_one(C).await;
        }
        // Jam: p3 lands in the cap-1 channel and is NOT drained.
        o.routes(A, vec![ibgp_route(pfx(3, 0), A, 100, vec![])], vec![])
            .await;
        // p1 withdrawn: C's emission fails against the full channel →
        // dirty, with the withdrawal recorded as a group tombstone.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;
        // C's chain becomes peer-context-dependent (verdicts
        // unchanged): a grouped→per-peer move while dirty — the
        // tombstone rides C's extra-withdraw residue across it.
        o.replace_policy(C, Some(peer_context_permit_chain())).await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "the withdraw missed while dirty must reach the wire after the move to the per-peer path"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "p2 (still best) must stay advertised"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(3, 0)), 0)),
        "p3 (still best) must stay advertised"
    );
}

/// Regroup-while-dirty where the tombstoned keys survive ONLY in the
/// carried extra-withdraw residue and every family's resync
/// enumeration is empty: the Loc-RIB emptied while the member was
/// dirty, the destination group's table is therefore empty, and the
/// regroup baseline snapshot is empty. The resync must still emit the
/// residue withdraws instead of dropping them on the empty-enumeration
/// early exit.
#[tokio::test]
async fn oracle_regroup_while_dirty_empty_enumeration_emits_residue_withdraws() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        // C gets a capacity-1 channel so a jammed send fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // Sync C to wire {p1}.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.drain_one(C).await;
        // Jam: p2 lands in the cap-1 channel and is NOT drained.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // p1 withdrawn: C's emission fails → dirty; tombstone {p1}.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;
        // p2 withdrawn too: the Loc-RIB and the group table are now
        // both empty; tombstones {p1, p2}. C's resync attempt fails
        // against the still-full channel.
        o.routes(A, vec![], vec![pfx(2, 0)]).await;
        // Regroup while dirty: the baseline snapshot and the new
        // group's table are both empty — the tombstones survive only
        // as C's carried extra-withdraw residue.
        o.replace_policy(C, Some(deny_prefix_chain(pfx(9, 0))))
            .await;

        // Free the channel and let the resync timer fire.
        o.drain_one(C).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "the residue withdraw of p1 must be emitted, not dropped on the empty-enumeration exit"
    );
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "the residue withdraw of p2 must be emitted, not dropped on the empty-enumeration exit"
    );
}

/// A second peer joining an existing group whose chain sets a next-hop
/// override: the join replay must reproduce the override flags without
/// re-running policy (they ride the group table residue).
#[tokio::test]
async fn oracle_nh_override_survives_group_join_replay() {
    let chain = || {
        permit_all_with(RouteModifications {
            set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 42,
            )))),
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(D, true, false, Some(chain()), 64).await;
        o.routes(A, vec![ibgp_route(pfx(9, 0), A, 100, vec![])], vec![])
            .await;
        // E joins D's group (same eBGP + content-equal chain): its
        // initial dump replays the staged route WITH the nh override.
        o.peer_up(E, true, false, Some(chain()), 64).await;
    };
    let (grouped, ungrouped) =
        run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
    assert_eq!(grouped, ungrouped);
    // Belt and braces: E's dump carries the override flag on both paths.
    let e_msgs = &grouped[&IpAddr::V4(E)];
    let announced_with_flag = e_msgs.iter().flat_map(|m| &m.announce).any(|entry| {
        entry.5
            == Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 42,
            ))))
    });
    assert!(
        announced_with_flag,
        "join replay must reproduce the next-hop-override flag"
    );
}

/// The VPN kitchen-sink exact-stream scenario (update-groups v2 slice
/// 1): initial VPN dump, flood, source-flip X→Y→X, same-peer relabel
/// (ADR-0077 re-advertise), attr mutate, withdraw, split horizon
/// (source inside the group), late joiner replay, RFC 7313 VPN route
/// refresh, member leave, regroup on policy change (content-equal
/// reinstall AND a genuine deny), and a GShut-style forced refresh —
/// grouped vs forced-ungrouped per-peer VPN streams must be identical.
#[tokio::test]
async fn oracle_vpn_streams_identical_across_group_lifecycle() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let modifying_chain = || {
        permit_all_with(RouteModifications {
            set_med: Some(77),
            communities_add: vec![0xFDE8_0001],
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        // Three RR clients (one group), a non-client (second group), an
        // iBGP peer with an attribute-modifying chain (third group) —
        // all VPN-capable, none RTC.
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(C, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(D, false, false, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(E, false, true, Some(modifying_chain()), 64, vpn_sendable())
            .await;

        // Flood from a member: split horizon inside the group.
        o.vpn_routes(
            A,
            vec![
                vpn_route(vpn_nlri(1, 100), A, 100, vec![]),
                vpn_route(vpn_nlri(2, 200), A, 100, vec![]),
            ],
            vec![],
        )
        .await;

        // Source flip X→Y (B takes over identity 1 with higher LP)...
        o.vpn_routes(B, vec![vpn_route(vpn_nlri(1, 100), B, 200, vec![])], vec![])
            .await;
        // ... and flip back Y→X (B withdraws its path).
        o.vpn_routes(B, vec![], vec![vpn_key(1, 100)]).await;

        // Same-peer relabel: identity 2 keeps its key, the label stack
        // changes — must re-advertise (label is data, not key).
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(2, 999), A, 100, vec![])], vec![])
            .await;

        // Attribute change on the standing best (same source).
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(2, 999), A, 150, vec![])], vec![])
            .await;

        // Late joiner into the client group: replay, not restage.
        o.peer_up_families(F, false, true, None, 64, vpn_sendable())
            .await;

        // RFC 7313 VPN route refresh, both group shapes: a grouped RR
        // client with own-sourced entries (split-horizon exclusion in
        // the replay) and the modified-chain peer (the replay must
        // reproduce the modified attributes from the staged residue
        // without re-running policy).
        o.route_refresh(A, Afi::Ipv4, Safi::MplsVpn).await;
        o.route_refresh(E, Afi::Ipv4, Safi::MplsVpn).await;

        // Withdraw identity 1 entirely.
        o.vpn_routes(A, vec![], vec![vpn_key(1, 100)]).await;

        // Member leaves (its VPN paths fall out of the Loc-RIB too).
        o.peer_down(B).await;

        // Regroup fast path: content-equal chain reinstall — no emission.
        o.replace_policy(E, Some(modifying_chain())).await;

        // Genuine regroup: C moves to a group whose chain denies the
        // identity-2 inner prefix — the one-shot diff withdraws it.
        o.replace_policy(
            C,
            Some(deny_prefix_chain(Ipv4Prefix::new(
                Ipv4Addr::new(10, 210, 2, 0),
                24,
            ))),
        )
        .await;

        // GShut-style forced re-emission (RefreshPeerOutbound).
        o.refresh_outbound(D).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        grouped, ungrouped,
        "grouped and per-peer outbound VPN streams must be identical"
    );
    assert!(
        grouped
            .values()
            .any(|msgs| msgs.iter().any(|m| !m.vpn_announce.is_empty())),
        "scenario must exercise VPN outbound traffic"
    );
}

/// VPN dirty-member resync (channel-full → VPN tombstones → timer
/// resync): streams intentionally differ (the grouped resync over-emits
/// — the safe direction); the folded final advertised VPN state must be
/// identical, the withdraw of the identity that went away while dirty
/// must reach the wire, and the jammed announce must be recovered.
#[tokio::test]
async fn oracle_vpn_dirty_resync_converges_to_identical_state() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_sendable())
            .await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up_families(C, false, true, None, 1, vpn_sendable())
            .await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.vpn_announce.is_empty() && !eor.end_of_rib.is_empty());

        // Identity 1 lands in C's channel (fills it).
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(1, 100), A, 100, vec![])], vec![])
            .await;
        // Identity 2 announce fails for C → C goes dirty.
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(2, 200), A, 100, vec![])], vec![])
            .await;
        // Identity 1 withdrawn WHILE C is dirty → VPN tombstone.
        o.vpn_routes(A, vec![], vec![vpn_key(1, 100)]).await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(
            first.vpn_announce.len(),
            1,
            "identity 1 was delivered before the jam"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold_vpn(&grouped),
        fold_vpn(&ungrouped),
        "final advertised VPN state must converge on both paths"
    );
    let c_final = fold_vpn(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    let key1 = format!("{:?}", vpn_nlri(1, 100).key());
    let key2 = format!("{:?}", vpn_nlri(2, 200).key());
    assert!(
        !c_final.contains_key(&key1),
        "tombstoned VPN identity must not survive the grouped resync"
    );
    assert!(
        c_final.contains_key(&key2),
        "the update lost to the full channel must be recovered by the resync"
    );
}

/// VPN sibling of the source-flip-lost-withdraw scenario: the jammed
/// member's own VPN route displaces another peer's for the same RD +
/// prefix identity, its member-scoped withdraw is lost to the full
/// channel, and the key stays IN the group table (invisible to VPN
/// tombstones) — the resync must still withdraw it.
#[tokio::test]
async fn oracle_vpn_source_flip_withdraw_lost_to_full_channel_recovers() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_sendable())
            .await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up_families(C, false, true, None, 1, vpn_sendable())
            .await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.vpn_announce.is_empty() && !eor.end_of_rib.is_empty());

        // Identity 1 from A lands in C's channel (fills it).
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(1, 100), A, 100, vec![])], vec![])
            .await;
        // Source flip ONTO the jammed member: C's own path displaces
        // A's. C's member-scoped emission is a pure withdraw — lost to
        // the full channel, and NOT a table withdrawal.
        o.vpn_routes(C, vec![vpn_route(vpn_nlri(1, 100), C, 200, vec![])], vec![])
            .await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(
            first.vpn_announce.len(),
            1,
            "identity 1 was delivered before the jam"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        // The adv(m) invariant recomputed from manager state must match
        // the folded emitted streams once the resync has run.
        o.check_vpn_invariant("post source-flip resync").await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold_vpn(&grouped),
        fold_vpn(&ungrouped),
        "final advertised VPN state must converge on both paths"
    );
    let c_final = fold_vpn(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    let key1 = format!("{:?}", vpn_nlri(1, 100).key());
    assert!(
        !c_final.contains_key(&key1),
        "the source-flip VPN withdraw lost to the full channel must be recovered by the resync"
    );
}

/// RTC-negotiated peers group AND stage VPN (v2 slice 2), with the RFC
/// 4684 RT membership filter `Φ_m` applied per member at emit. A
/// wildcard-interest member receives the VPN table; a strict-empty-
/// membership member receives nothing — byte-identically to the
/// per-peer path (if Φ were dropped at any emit seam, the group table
/// would leak routes to the empty-membership peer and the streams
/// would diverge).
#[tokio::test]
async fn oracle_rtc_negotiated_vpn_filtered_at_emit() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        // Source peer: VPN-capable, no RTC (its group DOES stage VPN).
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        // Two RTC-negotiated RR clients: B advertises wildcard interest,
        // C advertises nothing (strict empty membership).
        o.peer_up_families(B, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.peer_up_families(C, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.rtc_routes(B, vec![rtc_default(B)]).await;

        // VPN flood with an RT extended community + a unicast route
        // (the unicast dimension must keep grouping for RTC peers).
        o.vpn_routes(
            A,
            vec![vpn_route(
                vpn_nlri(7, 700),
                A,
                100,
                vec![0x0002_FDE8_0000_002A],
            )],
            vec![],
        )
        .await;
        o.routes(A, vec![ibgp_route(pfx(7, 0), A, 100, vec![])], vec![])
            .await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        grouped, ungrouped,
        "RTC-negotiated peers' Φ-filtered group emit must match the per-peer path"
    );
    let vpn_count = |streams: &Streams, peer: Ipv4Addr| {
        streams[&IpAddr::V4(peer)]
            .iter()
            .map(|m| m.vpn_announce.len())
            .sum::<usize>()
    };
    assert!(
        vpn_count(&grouped, B) > 0,
        "wildcard-interest RTC peer receives the VPN route"
    );
    assert_eq!(
        vpn_count(&grouped, C),
        0,
        "strict-empty-membership RTC peer receives no VPN routes"
    );
    // And the unicast dimension still groups the RTC peers (the gate is
    // VPN-staging-only, not a membership disqualifier).
    let mut grouped_oracle = Oracle::spawn(false, cluster);
    scenario(&mut grouped_oracle).await;
    let label_b = grouped_oracle.group_label(B).await;
    let label_c = grouped_oracle.group_label(C).await;
    assert!(
        label_b.starts_with("group:") && label_b == label_c,
        "RTC peers must still share a unicast update group (got {label_b} / {label_c})"
    );
    drop(grouped_oracle.finish().await);
}

/// iBGP full mesh (no cluster id): plain split horizon suppresses
/// iBGP-learned routes toward every iBGP peer; locally-injected and
/// eBGP-origin routes still flow. Exercises the no-RR key shape.
#[tokio::test]
async fn oracle_plain_ibgp_split_horizon_identical() {
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, false, None, 64).await;
        o.peer_up(B, false, false, None, 64).await;
        o.peer_up(E, true, false, None, 64).await;
        // iBGP-learned: suppressed toward A/B (split horizon, no RR),
        // advertised to the eBGP peer.
        o.routes(A, vec![ibgp_route(pfx(4, 0), A, 100, vec![])], vec![])
            .await;
        // An eBGP-origin route from E flows to the iBGP peers.
        let mut ebgp = ibgp_route(pfx(5, 0), E, 100, vec![]);
        ebgp.origin_type = RouteOrigin::Ebgp;
        o.routes(E, vec![ebgp], vec![]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_eq!(grouped, ungrouped);
}

// ---------------------------------------------------------------------
// RTC churn (update-groups v2 slice 2): the RT-pass emit dimension.
// ---------------------------------------------------------------------

/// RT extended community `65000:n` (two-octet-AS route target).
const fn rt_ec(n: u64) -> u64 {
    0x0002_FDE8_0000_0000 | n
}

/// RTC interest NLRI covering exactly RT `65000:n` (full /96 prefix).
fn rtc_nlri_for(n: u64) -> RtcNlri {
    RtcNlri::new(65000, rt_ec(n), 96).unwrap()
}

fn rtc_key_for(n: u64) -> crate::route::RtcRibRouteKey {
    crate::route::RtcRibRouteKey {
        nlri: rtc_nlri_for(n),
        path_id: 0,
    }
}

/// A SAFI-132 advertisement of interest in RT `65000:n` from a peer.
fn rtc_interest(src: Ipv4Addr, n: u64) -> RtcRibRoute {
    RtcRibRoute {
        nlri: rtc_nlri_for(n),
        ..rtc_default(src)
    }
}

/// The RTC-churn kitchen sink (design §5): membership widen / narrow /
/// default add+remove / strict-empty, RT flip via route attr change,
/// RFC 7313 refresh under heterogeneous memberships, GR re-establish
/// with preserved SAFI-132 state, membership change racing a source
/// flip in the same manager queue, and a regroup join with pre-existing
/// membership — exact per-peer streams grouped vs forced-ungrouped,
/// with the adv(m) invariant checked after every step.
#[tokio::test]
async fn oracle_rtc_churn_streams_identical() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let modifying_chain = || {
        permit_all_with(RouteModifications {
            set_med: Some(42),
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        // A: VPN source (no RTC). B/C/D: RTC RR clients, one group.
        // E: RTC RR client with a modifying chain — its own group.
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.peer_up_families(C, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.peer_up_families(D, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.peer_up_families(
            E,
            false,
            true,
            Some(modifying_chain()),
            64,
            vpn_rtc_sendable(),
        )
        .await;

        // Memberships: B{RT1}, C{default}, D strict-empty, E{RT2}.
        o.rtc_routes(B, vec![rtc_interest(B, 1)]).await;
        o.rtc_routes(C, vec![rtc_default(C)]).await;
        o.rtc_routes(E, vec![rtc_interest(E, 2)]).await;
        o.check_vpn_invariant("memberships installed").await;

        // Flood: identities across the RT pool (incl. RT-less id 4,
        // which only the default membership may receive).
        o.vpn_routes(
            A,
            vec![
                vpn_route(vpn_nlri(1, 100), A, 100, vec![rt_ec(1)]),
                vpn_route(vpn_nlri(2, 200), A, 100, vec![rt_ec(2)]),
                vpn_route(vpn_nlri(3, 300), A, 100, vec![rt_ec(1), rt_ec(2)]),
                vpn_route(vpn_nlri(4, 400), A, 100, vec![]),
                vpn_route(vpn_nlri(5, 500), A, 100, vec![rt_ec(3)]),
            ],
            vec![],
        )
        .await;
        o.check_vpn_invariant("initial flood").await;

        // Membership widen: B += RT2 (id 2 newly passes; id 3 already
        // held via RT1 — no re-announce).
        o.rtc_routes(B, vec![rtc_interest(B, 2)]).await;
        o.check_vpn_invariant("widen B += RT2").await;

        // Membership narrow: B −= RT1 (id 1 withdrawn; id 3 retained
        // via RT2).
        o.rtc_routes_full(B, vec![], vec![rtc_key_for(1)]).await;
        o.quiesce().await;
        o.check_vpn_invariant("narrow B -= RT1").await;

        // RT flip via route attr change: id 1 moves RT1 → RT2 (into
        // Φ_B/Φ_E, C re-announces the changed attrs, D silent); id 5
        // moves RT3 → RT1 (out of everyone's Φ but C's default).
        o.vpn_routes(
            A,
            vec![
                vpn_route(vpn_nlri(1, 100), A, 100, vec![rt_ec(2)]),
                vpn_route(vpn_nlri(5, 500), A, 100, vec![rt_ec(1)]),
            ],
            vec![],
        )
        .await;
        o.check_vpn_invariant("RT flip via attr change").await;

        // Default-NLRI remove: C collapses to strict empty (withdraws
        // everything), then re-declares interest in RT2.
        o.rtc_routes_full(
            C,
            vec![],
            vec![crate::route::RtcRibRouteKey {
                nlri: RtcNlri::DEFAULT,
                path_id: 0,
            }],
        )
        .await;
        o.quiesce().await;
        o.check_vpn_invariant("default removed from C").await;
        o.rtc_routes(C, vec![rtc_interest(C, 2)]).await;
        o.check_vpn_invariant("C += RT2").await;

        // RFC 7313 refresh under heterogeneous memberships.
        o.route_refresh(B, Afi::Ipv4, Safi::MplsVpn).await;
        o.route_refresh(C, Afi::Ipv4, Safi::MplsVpn).await;
        o.route_refresh(D, Afi::Ipv4, Safi::MplsVpn).await;
        o.check_vpn_invariant("heterogeneous VPN refresh").await;

        // GR re-establish: B's SAFI-132 interest survives as stale and
        // the re-derived Φ gates the initial-dump replay.
        o.graceful_restart(B).await;
        o.peer_up_families(B, false, true, None, 64, vpn_rtc_sendable())
            .await;
        o.check_vpn_invariant("GR re-establish of B").await;

        // Membership change racing a source flip in the same queue
        // (FIFO-deterministic; no quiesce between).
        o.rtc_routes_full(D, vec![rtc_interest(D, 2)], vec![]).await;
        o.vpn_routes_no_quiesce(A, vec![vpn_route(vpn_nlri(2, 201), A, 150, vec![rt_ec(2)])])
            .await;
        o.quiesce().await;
        o.check_vpn_invariant("membership racing source flip").await;

        // Regroup join with pre-existing membership: E's chain reverts
        // to the group default — the one-shot diff runs under Φ_E.
        o.replace_policy(E, None).await;
        o.check_vpn_invariant("E regroups with pre-existing membership")
            .await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        grouped, ungrouped,
        "grouped Φ-filtered emit and per-peer RTC streams must be identical"
    );
    assert!(
        grouped
            .values()
            .any(|msgs| msgs.iter().any(|m| !m.vpn_announce.is_empty())),
        "scenario must exercise VPN outbound traffic"
    );
}

/// Membership change WHILE dirty (design §2.3): the grouped path skips
/// the delta walk (Φ updated; the pending resync emits against current
/// Φ, over-withdrawing Φ-failing keys — the backstop term). Streams
/// legitimately differ; the folded final VPN state must converge, the
/// Φ-failing key must be withdrawn, and the jammed announce recovered.
#[tokio::test]
async fn oracle_rtc_membership_change_while_dirty_converges() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_rtc_sendable())
            .await;
        // C: capacity-2 channel — the RTC-capable initial dump takes
        // two messages (the default-RTC dump, then the EoR), so two
        // slots keep C clean until the deliberate jam below.
        o.peer_up_families(C, false, true, None, 2, vpn_rtc_sendable())
            .await;
        let dump = o.drain_one(C).await;
        assert!(dump.vpn_announce.is_empty(), "got {:?}", normalize(&dump));
        let eor = o.drain_one(C).await;
        assert!(!eor.end_of_rib.is_empty(), "got {:?}", normalize(&eor));
        // C interested in RT1 + RT2 (no VPN routes yet — no emission).
        o.rtc_routes(C, vec![rtc_interest(C, 1), rtc_interest(C, 2)])
            .await;
        o.rtc_routes(B, vec![rtc_default(B)]).await;

        // id 1 + id 2 land in C's channel; id 3 fills the second slot.
        o.vpn_routes(
            A,
            vec![
                vpn_route(vpn_nlri(1, 100), A, 100, vec![rt_ec(1)]),
                vpn_route(vpn_nlri(2, 200), A, 100, vec![rt_ec(2)]),
            ],
            vec![],
        )
        .await;
        o.vpn_routes(
            A,
            vec![vpn_route(vpn_nlri(3, 300), A, 100, vec![rt_ec(1)])],
            vec![],
        )
        .await;
        // id 4 announce fails for C → C goes dirty.
        o.vpn_routes(
            A,
            vec![vpn_route(vpn_nlri(4, 400), A, 100, vec![rt_ec(1)])],
            vec![],
        )
        .await;
        // Membership narrows WHILE dirty: C −= RT2 (id 2 must not
        // survive the resync).
        o.rtc_routes_full(C, vec![], vec![rtc_key_for(2)]).await;
        o.quiesce().await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(
            first.vpn_announce.len(),
            2,
            "ids 1+2 were delivered before the jam"
        );
        let second = o.drain_one(C).await;
        assert_eq!(second.vpn_announce.len(), 1, "id 3 was delivered too");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.check_vpn_invariant("post-resync").await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold_vpn(&grouped),
        fold_vpn(&ungrouped),
        "final advertised VPN state must converge on both paths"
    );
    let c_final = fold_vpn(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    let key = |n: u8, label: u32| format!("{:?}", vpn_nlri(n, label).key());
    assert!(
        c_final.contains_key(&key(1, 100)),
        "Φ-passing id 1 must survive"
    );
    assert!(
        !c_final.contains_key(&key(2, 200)),
        "the key that left Φ while dirty must be withdrawn by the resync backstop"
    );
    assert!(c_final.contains_key(&key(3, 300)), "id 3 must survive");
    assert!(
        c_final.contains_key(&key(4, 400)),
        "the update lost to the full channel must be recovered by the resync"
    );
}

/// Kill criterion (b), design §6.2: a single member's membership flip
/// at 100k staged VPN routes emits ONLY the minimal RFC 4684 delta —
/// one message, announce-only on widen / withdraw-only on narrow, with
/// ZERO export-policy evaluations (the ADR-0096 live eval counters of
/// every installed chain are unchanged) and the group table untouched.
#[expect(
    clippy::cast_possible_truncation,
    reason = "synthetic RD/prefix bytes are deliberate low-byte extractions"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rtc_membership_flip_at_scale_emits_delta_only_zero_evals() {
    const N: u32 = 100_000;
    const RT_POOL: u64 = 64;
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let chain = || permit_all_with(RouteModifications::default());
    let mut o = Oracle::spawn(false, cluster);
    o.peer_up_families(A, false, true, None, 512, vpn_sendable())
        .await;
    // B (default interest) and C ({RT1}) group together: content-equal
    // chains, same sendable set.
    o.peer_up_families(B, false, true, Some(chain()), 512, vpn_rtc_sendable())
        .await;
    o.peer_up_families(C, false, true, Some(chain()), 512, vpn_rtc_sendable())
        .await;
    o.rtc_routes(B, vec![rtc_default(B)]).await;
    o.rtc_routes(C, vec![rtc_interest(C, 1)]).await;

    // Flood N identities over an RT pool of 64, in chunks.
    let mut i = 0u32;
    while i < N {
        let hi = (i + 512).min(N);
        let batch: Vec<VpnRibRoute> = (i..hi)
            .map(|k| {
                vpn_route(
                    VpnNlri {
                        labels: vec![MplsLabelEntry::try_new(16 + (k % 1000), 0, true).unwrap()],
                        route_distinguisher: RouteDistinguisher([
                            0,
                            0,
                            0xFD,
                            0xE8,
                            (k >> 24) as u8,
                            (k >> 16) as u8,
                            (k >> 8) as u8,
                            k as u8,
                        ]),
                        prefix: VpnPrefix::v4(
                            Ipv4Addr::new(
                                10u8.wrapping_add((k >> 16) as u8),
                                (k >> 8) as u8,
                                k as u8,
                                0,
                            ),
                            24,
                        )
                        .unwrap(),
                    },
                    A,
                    100,
                    vec![rt_ec(u64::from(k) % RT_POOL)],
                )
            })
            .collect();
        i = hi;
        o.vpn_routes_no_quiesce(A, batch).await;
    }
    o.quiesce().await;
    o.drain_collected();
    let msgs_before = o.collected.get(&IpAddr::V4(C)).map_or(0, Vec::len);
    // B and C share one group counter instance. Observe one representative
    // member: summing both operator-visible aliases would double-count the
    // same real group evaluation after each RTC reflection.
    let evals_before = o.export_policy_evals_for(C).await;
    assert!(evals_before > 0, "the flood must have evaluated the chain");

    let per_rt = |n: u64| (0..N).filter(|k| u64::from(*k) % RT_POOL == n).count();

    // Widen: C += RT2 → exactly one announce-only message of the RT2
    // share, zero evals.
    o.rtc_routes(C, vec![rtc_interest(C, 2)]).await;
    o.quiesce().await;
    o.drain_collected();
    let c_msgs = &o.collected[&IpAddr::V4(C)];
    assert_eq!(
        c_msgs.len(),
        msgs_before + 1,
        "membership widen must emit exactly one message"
    );
    let widen = &c_msgs[msgs_before];
    assert_eq!(widen.vpn_announce.len(), per_rt(2), "announce-only delta");
    assert!(widen.vpn_withdraw.is_empty(), "widen must not withdraw");
    // The VPN membership delta itself runs ZERO evaluations. The +1 is
    // the SAFI-132 route itself: C's new interest NLRI reflects to B
    // (one RTC staging eval) — identical on the per-peer path, and not
    // a VPN restage.
    assert_eq!(
        o.export_policy_evals_for(C).await,
        evals_before + 1,
        "membership widen must add only the SAFI-132 reflection eval, zero VPN evals"
    );

    // Narrow: C −= RT1 → exactly one withdraw-only message.
    o.rtc_routes_full(C, vec![], vec![rtc_key_for(1)]).await;
    o.quiesce().await;
    o.drain_collected();
    let c_msgs = &o.collected[&IpAddr::V4(C)];
    assert_eq!(c_msgs.len(), msgs_before + 2);
    let narrow = &c_msgs[msgs_before + 1];
    assert!(narrow.vpn_announce.is_empty(), "narrow must not announce");
    assert_eq!(narrow.vpn_withdraw.len(), per_rt(1), "withdraw-only delta");
    // A SAFI-132 withdraw stages no eval (withdraw-if-present precedes
    // the policy check), so the narrow is exactly zero evals.
    assert_eq!(
        o.export_policy_evals_for(C).await,
        evals_before + 1,
        "membership narrow must run ZERO export-policy evaluations"
    );

    o.check_vpn_invariant("post narrow").await;
    drop(o.finish().await);
}
