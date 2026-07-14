//! Authoritative per-session outbound encoding profile and message builder.
//!
//! The RIB-facing exportability gate is deliberately deferred to LAN-361.
//! This module establishes its prerequisite: live emission and exact probes
//! consume one immutable snapshot of every negotiated, socket, configured,
//! and runtime input that can change the outbound wire form.

use super::{
    Afi, AsPath, AsPathSegment, BgpLsRibRoute, BgpLsRouteKey, BgpRole, EvpnRibRoute, EvpnRoute,
    EvpnRouteKey, FlowSpecKey, FlowSpecRoute, FlowSpecRule, IpAddr, Ipv4Addr, Ipv4NlriEntry,
    Ipv4UnicastMode, Ipv6Addr, LabeledRibRoute, LabeledRibRouteKey, MpReachNlri, MpUnreachNlri,
    NlriEntry, PathAttribute, PeerSession, Prefix, RemovePrivateAs, Route, RtcRibRoute,
    RtcRibRouteKey, Safi, TransportConfig, UpdateMessage, VpnRibRoute, VpnRibRouteKey,
    is_ipv6_link_local, is_private_asn,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportErrorCode,
    ExactExportResult, ExactExportSnapshot,
};
use rustbgpd_wire::EncodeError;
use rustc_hash::FxHashMap;

/// Immutable inputs that determine one established session's outbound wire
/// representation. A complete replacement is published for runtime changes;
/// readers never observe a mixture of old and new fields.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the immutable wire profile records independent negotiated capabilities and runtime flags"
)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SessionExportProfile {
    owner_id: u64,
    generation: u64,
    local_asn: u32,
    local_router_id: Ipv4Addr,
    local_role: Option<BgpRole>,
    route_server_client: bool,
    remove_private_as: RemovePrivateAs,
    cluster_id: Option<Ipv4Addr>,
    configured_local_ipv6_nexthop: Option<Ipv6Addr>,
    /// Current encoding rules consume the remote ASN only through this class.
    /// Any future rule that depends on the ASN value must add the negotiated
    /// remote ASN to this immutable profile before sharing wire results.
    is_ebgp: bool,
    four_octet_as: bool,
    extended_messages: bool,
    extended_nexthop_ipv4: bool,
    add_path_send_families: Arc<[(Afi, Safi)]>,
    peer_llgr_families: Arc<[(Afi, Safi)]>,
    local_addr: Option<IpAddr>,
    scoped_link_local_peer: bool,
    advertise_graceful_shutdown: bool,
}

impl std::fmt::Debug for SessionExportProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionExportProfile")
            .field("owner_id", &self.owner_id)
            .field("generation", &self.generation)
            .field("local_asn", &self.local_asn)
            .field("local_router_id", &self.local_router_id)
            .field("local_role", &self.local_role)
            .field("route_server_client", &self.route_server_client)
            .field("remove_private_as", &self.remove_private_as)
            .field("cluster_id", &self.cluster_id)
            .field(
                "configured_local_ipv6_nexthop",
                &self.configured_local_ipv6_nexthop,
            )
            .field("is_ebgp", &self.is_ebgp)
            .field("four_octet_as", &self.four_octet_as)
            .field("extended_messages", &self.extended_messages)
            .field("extended_nexthop_ipv4", &self.extended_nexthop_ipv4)
            .field("add_path_send_families", &self.add_path_send_families)
            .field("peer_llgr_families", &self.peer_llgr_families)
            .field("local_addr", &self.local_addr)
            .field("scoped_link_local_peer", &self.scoped_link_local_peer)
            .field(
                "advertise_graceful_shutdown",
                &self.advertise_graceful_shutdown,
            )
            .finish()
    }
}

impl SessionExportProfile {
    /// Whether two profiles produce identical bytes for the same candidate.
    ///
    /// Snapshot identity, generation, and the negotiated message ceiling do
    /// not affect the bytes. Cloning and normalizing those fields before using
    /// the derived full-struct equality keeps newly-added wire inputs in this
    /// proof by default instead of requiring a parallel allow-list. Remote ASN
    /// identity is deliberately absent because current rules consume only the
    /// stored eBGP/iBGP class; a value-dependent rule must restore it here.
    fn has_same_wire_encoding(&self, other: &Self) -> bool {
        let mut this = self.clone();
        let mut other = other.clone();
        for profile in [&mut this, &mut other] {
            profile.owner_id = 0;
            profile.generation = 0;
            profile.extended_messages = false;
        }
        this == other
    }

    pub(super) fn capture(session: &PeerSession) -> Self {
        let local_addr = session
            .read_half
            .as_ref()
            .and_then(|half| half.local_addr().ok())
            .map(|addr| addr.ip());
        let scoped_link_local_peer = matches!(session.peer_ip, IpAddr::V6(v6) if is_ipv6_link_local(&v6))
            && session.config.peer_interface.is_some()
            && session.config.peer_scope_id.is_some();
        Self {
            owner_id: 0,
            generation: 0,
            local_asn: session.config.peer.local_asn,
            local_router_id: session.config.peer.local_router_id,
            local_role: session.config.peer.local_role,
            route_server_client: session.config.route_server_client,
            remove_private_as: session.config.remove_private_as,
            cluster_id: session.config.cluster_id,
            configured_local_ipv6_nexthop: session.config.local_ipv6_nexthop,
            is_ebgp: session.negotiated.as_ref().map_or_else(
                || session.config.peer.remote_asn != session.config.peer.local_asn,
                |neg| neg.peer_asn != session.config.peer.local_asn,
            ),
            four_octet_as: session
                .negotiated
                .as_ref()
                .is_some_and(|neg| neg.four_octet_as),
            extended_messages: session
                .negotiated
                .as_ref()
                .is_some_and(|neg| neg.peer_extended_message),
            extended_nexthop_ipv4: session.negotiated.as_ref().is_some_and(|neg| {
                neg.extended_nexthop_families
                    .get(&(Afi::Ipv4, Safi::Unicast))
                    .is_some_and(|afi| *afi == Afi::Ipv6)
            }),
            add_path_send_families: Arc::from(
                session
                    .negotiated
                    .as_ref()
                    .map(|neg| {
                        neg.add_path_families
                            .iter()
                            .filter_map(|(&family, mode)| {
                                matches!(
                                    mode,
                                    rustbgpd_wire::AddPathMode::Send
                                        | rustbgpd_wire::AddPathMode::Both
                                )
                                .then_some(family)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            ),
            peer_llgr_families: Arc::from(
                session
                    .negotiated
                    .as_ref()
                    .filter(|neg| neg.peer_llgr_capable)
                    .map(|neg| {
                        neg.peer_llgr_families
                            .iter()
                            .map(|entry| (entry.afi, entry.safi))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            ),
            local_addr,
            scoped_link_local_peer,
            advertise_graceful_shutdown: session.advertise_graceful_shutdown,
        }
    }

    pub(super) fn initial(
        config: &TransportConfig,
        local_addr: Option<IpAddr>,
        advertise_graceful_shutdown: bool,
    ) -> Self {
        let peer_ip = config.remote_addr.ip();
        Self {
            owner_id: 0,
            generation: 0,
            local_asn: config.peer.local_asn,
            local_router_id: config.peer.local_router_id,
            local_role: config.peer.local_role,
            route_server_client: config.route_server_client,
            remove_private_as: config.remove_private_as,
            cluster_id: config.cluster_id,
            configured_local_ipv6_nexthop: config.local_ipv6_nexthop,
            is_ebgp: config.peer.remote_asn != config.peer.local_asn,
            four_octet_as: false,
            extended_messages: false,
            extended_nexthop_ipv4: false,
            add_path_send_families: Arc::from(Vec::new()),
            peer_llgr_families: Arc::from(Vec::new()),
            local_addr,
            scoped_link_local_peer: matches!(peer_ip, IpAddr::V6(v6) if is_ipv6_link_local(&v6))
                && config.peer_interface.is_some()
                && config.peer_scope_id.is_some(),
            advertise_graceful_shutdown,
        }
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn four_octet_as(&self) -> bool {
        self.four_octet_as
    }

    pub(super) fn is_ebgp(&self) -> bool {
        self.is_ebgp
    }

    pub(super) fn add_path_send(&self, family: (Afi, Safi)) -> bool {
        self.add_path_send_families.contains(&family)
    }

    pub(crate) fn max_message_len(&self) -> usize {
        usize::from(if self.extended_messages {
            rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
        } else {
            rustbgpd_wire::MAX_MESSAGE_LEN
        })
    }

    pub(super) fn use_extended_nexthop_ipv4(&self) -> bool {
        self.extended_nexthop_ipv4
    }

    pub(super) const fn is_scoped_link_local_peer(&self) -> bool {
        self.scoped_link_local_peer
    }

    pub(super) fn local_ipv4(&self) -> Ipv4Addr {
        self.local_addr
            .and_then(|addr| match addr {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or(self.local_router_id)
    }

    pub(super) fn local_ipv6(&self) -> Option<Ipv6Addr> {
        self.local_addr.and_then(|addr| match addr {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
    }

    pub(super) fn usable_ipv4_extended_nexthop_ipv6(
        &self,
        candidate: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        candidate.filter(|addr| {
            rustbgpd_wire::is_valid_ipv6_nexthop(addr)
                || (self.scoped_link_local_peer && is_ipv6_link_local(addr))
        })
    }

    pub(super) fn usable_ipv6_unicast_next_hop(candidate: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        candidate.filter(rustbgpd_wire::is_valid_ipv6_nexthop)
    }

    pub(super) fn ipv4_mp_reach_link_local_next_hop(
        &self,
        next_hop: IpAddr,
        route: &Route,
    ) -> Option<Ipv6Addr> {
        match next_hop {
            IpAddr::V6(v6) if self.scoped_link_local_peer && is_ipv6_link_local(&v6) => Some(v6),
            _ if next_hop == route.next_hop => route.link_local_next_hop,
            _ => None,
        }
    }

    pub(super) fn route_link_local_next_hop_for_selected_primary(
        next_hop: IpAddr,
        route: &Route,
    ) -> Option<Ipv6Addr> {
        (next_hop == route.next_hop)
            .then_some(route.link_local_next_hop)
            .flatten()
    }

    fn peer_accepts_llgr_stale(&self, family: (Afi, Safi)) -> bool {
        self.peer_llgr_families.contains(&family)
    }

    fn apply_llgr_stale_export_form(
        &self,
        attrs: &mut Vec<PathAttribute>,
        family: (Afi, Safi),
        is_ebgp: bool,
    ) {
        if is_ebgp || self.peer_accepts_llgr_stale(family) {
            return;
        }
        let is_llgr_stale = attrs.iter().any(|attr| {
            matches!(attr, PathAttribute::Communities(comms)
                if comms.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE))
        });
        if !is_llgr_stale {
            return;
        }
        let mut has_local_pref = false;
        for attr in attrs.iter_mut() {
            match attr {
                PathAttribute::LocalPref(local_pref) => {
                    *local_pref = 0;
                    has_local_pref = true;
                }
                PathAttribute::Communities(comms)
                    if !comms.contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT) =>
                {
                    comms.push(rustbgpd_wire::COMMUNITY_NO_EXPORT);
                }
                _ => {}
            }
        }
        if !has_local_pref {
            attrs.push(PathAttribute::LocalPref(0));
        }
    }

    fn attach_graceful_shutdown_if_enabled(&self, attrs: &mut Vec<PathAttribute>) {
        if !self.advertise_graceful_shutdown {
            return;
        }
        for attr in attrs.iter_mut() {
            if let PathAttribute::Communities(comms) = attr {
                if !comms.contains(&rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN) {
                    comms.push(rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN);
                }
                return;
            }
        }
        attrs.push(PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
        ]));
    }

    /// Prepare the classic unicast attribute set using only this immutable
    /// profile and the post-policy route candidate.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps the ordered outbound attribute transformation in one auditable pass"
    )]
    pub(super) fn prepare_unicast_attributes(
        &self,
        route: &Route,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Vec<PathAttribute> {
        let is_ebgp = self.is_ebgp();
        let force_next_hop_self =
            matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
        let policy_set_specific = matches!(
            nh_override,
            Some(rustbgpd_policy::NextHopAction::Specific(_))
        );
        let route_server_client = self.route_server_client;
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !route_server_client => {
                    let cleaned =
                        remove_private_asns(as_path, self.remove_private_as, self.local_asn);
                    let mut new_segments = vec![AsPathSegment::AsSequence(vec![self.local_asn])];
                    for segment in &cleaned.segments {
                        match segment {
                            AsPathSegment::AsSequence(asns) => {
                                if let Some(AsPathSegment::AsSequence(first)) =
                                    new_segments.first_mut()
                                {
                                    first.extend(asns);
                                }
                            }
                            AsPathSegment::AsSet(asns) => {
                                new_segments.push(AsPathSegment::AsSet(asns.clone()));
                            }
                        }
                    }
                    attrs.push(PathAttribute::AsPath(AsPath {
                        segments: new_segments,
                    }));
                }
                PathAttribute::NextHop(_) => {
                    if policy_set_specific {
                        attrs.push(attr.clone());
                    } else if force_next_hop_self || (is_ebgp && !route_server_client) {
                        attrs.push(PathAttribute::NextHop(local_ipv4));
                    } else {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_) => {}
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => attrs.push(attr.clone()),
            }
        }
        if !is_ebgp
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }
        if is_ebgp
            && matches!(
                self.local_role,
                Some(BgpRole::Provider | BgpRole::Peer | BgpRole::RouteServer)
            )
            && !has_otc(&attrs)
        {
            attrs.push(PathAttribute::OnlyToCustomer(self.local_asn));
        }
        if matches!(route.prefix, Prefix::V4(_))
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::NextHop(_)))
        {
            let next_hop = match nh_override {
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(next_hop))) => {
                    Some(*next_hop)
                }
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(_))) => {
                    tracing::warn!(
                        prefix = %route.prefix,
                        "export policy set IPv6 next-hop for classic IPv4 NLRI; \
                         requires Extended Next Hop (RFC 8950) — using default next-hop instead"
                    );
                    if is_ebgp && !route_server_client {
                        Some(local_ipv4)
                    } else {
                        match route.next_hop {
                            IpAddr::V4(next_hop) => Some(next_hop),
                            IpAddr::V6(_) => None,
                        }
                    }
                }
                Some(rustbgpd_policy::NextHopAction::Self_) => Some(local_ipv4),
                _ if is_ebgp && !route_server_client => Some(local_ipv4),
                _ => match route.next_hop {
                    IpAddr::V4(next_hop) => Some(next_hop),
                    IpAddr::V6(_) => None,
                },
            };
            if let Some(next_hop) = next_hop {
                attrs.push(PathAttribute::NextHop(next_hop));
            }
        }
        if is_ebgp
            && !route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.local_asn])],
            }));
        }
        self.apply_reflector_attributes(
            &mut attrs,
            route.origin_type,
            route.peer_router_id,
            is_ebgp,
        );
        let family = match route.prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, family, is_ebgp);
        attrs
    }

    fn prepare_mp_attributes(
        &self,
        attributes: &[PathAttribute],
        origin_type: rustbgpd_rib::RouteOrigin,
        peer_router_id: Ipv4Addr,
        family: (Afi, Safi),
    ) -> Vec<PathAttribute> {
        let is_ebgp = self.is_ebgp();
        let mut attrs = Vec::new();
        for attr in attributes {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.route_server_client => {
                    let cleaned =
                        remove_private_asns(as_path, self.remove_private_as, self.local_asn);
                    let mut new_segments = vec![AsPathSegment::AsSequence(vec![self.local_asn])];
                    for segment in &cleaned.segments {
                        match segment {
                            AsPathSegment::AsSequence(asns) => {
                                if let Some(AsPathSegment::AsSequence(first)) =
                                    new_segments.first_mut()
                                {
                                    first.extend(asns);
                                }
                            }
                            AsPathSegment::AsSet(asns) => {
                                new_segments.push(AsPathSegment::AsSet(asns.clone()));
                            }
                        }
                    }
                    attrs.push(PathAttribute::AsPath(AsPath {
                        segments: new_segments,
                    }));
                }
                PathAttribute::NextHop(_)
                | PathAttribute::MpReachNlri(_)
                | PathAttribute::MpUnreachNlri(_) => {}
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => attrs.push(attr.clone()),
            }
        }
        if !is_ebgp
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }
        if is_ebgp
            && !self.route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.local_asn])],
            }));
        }
        self.apply_reflector_attributes(&mut attrs, origin_type, peer_router_id, is_ebgp);
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, family, is_ebgp);
        attrs
    }

    fn apply_reflector_attributes(
        &self,
        attrs: &mut Vec<PathAttribute>,
        origin_type: rustbgpd_rib::RouteOrigin,
        peer_router_id: Ipv4Addr,
        is_ebgp: bool,
    ) {
        if is_ebgp || origin_type != rustbgpd_rib::RouteOrigin::Ibgp {
            return;
        }
        let Some(cluster_id) = self.cluster_id else {
            return;
        };
        if !attrs
            .iter()
            .any(|attr| matches!(attr, PathAttribute::OriginatorId(_)))
        {
            attrs.push(PathAttribute::OriginatorId(peer_router_id));
        }
        if let Some(ids) = attrs.iter_mut().find_map(|attr| match attr {
            PathAttribute::ClusterList(ids) => Some(ids),
            _ => None,
        }) {
            ids.insert(0, cluster_id);
        } else {
            attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
        }
    }

    pub(super) fn prepare_flowspec_attributes(&self, route: &FlowSpecRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            (route.afi, Safi::FlowSpec),
        )
    }

    pub(super) fn prepare_evpn_attributes(&self, route: &EvpnRibRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            (Afi::L2Vpn, Safi::Evpn),
        )
    }

    pub(super) fn prepare_bgpls_attributes(&self, route: &BgpLsRibRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            route.family.to_afi_safi(),
        )
    }

    pub(super) fn prepare_vpn_attributes(&self, route: &VpnRibRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            route.afi_safi(),
        )
    }

    pub(super) fn prepare_labeled_attributes(&self, route: &LabeledRibRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            route.afi_safi(),
        )
    }

    pub(super) fn prepare_rtc_attributes(&self, route: &RtcRibRoute) -> Vec<PathAttribute> {
        self.prepare_mp_attributes(
            &route.attributes,
            route.origin_type,
            route.peer_router_id,
            (Afi::Ipv4, Safi::RtConstrain),
        )
    }

    pub(super) fn rtc_next_hop(&self, route: &RtcRibRoute) -> IpAddr {
        if route.next_hop.is_unspecified() {
            self.local_addr.unwrap_or(IpAddr::V4(self.local_ipv4()))
        } else {
            route.next_hop
        }
    }

    pub(super) fn prepare_flowspec_candidate(
        &self,
        route: &FlowSpecRoute,
    ) -> PreparedMpCandidate<FlowSpecRule> {
        PreparedMpCandidate {
            afi: route.afi,
            safi: Safi::FlowSpec,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            link_local_next_hop: None,
            attrs: self.prepare_flowspec_attributes(route),
            nlri: route.rule.clone(),
        }
    }

    pub(super) fn prepare_evpn_candidate(
        &self,
        route: &EvpnRibRoute,
    ) -> PreparedMpCandidate<EvpnRoute> {
        PreparedMpCandidate {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: route.next_hop,
            link_local_next_hop: None,
            attrs: self.prepare_evpn_attributes(route),
            nlri: route.route.clone(),
        }
    }

    pub(super) fn prepare_bgpls_candidate(
        &self,
        route: &BgpLsRibRoute,
    ) -> PreparedMpCandidate<rustbgpd_wire::bgpls::BgpLsNlri> {
        let (afi, safi) = route.family.to_afi_safi();
        PreparedMpCandidate {
            afi,
            safi,
            next_hop: route.next_hop,
            link_local_next_hop: None,
            attrs: self.prepare_bgpls_attributes(route),
            nlri: route.nlri.clone(),
        }
    }

    pub(super) fn prepare_vpn_candidate(
        &self,
        route: &VpnRibRoute,
    ) -> PreparedMpCandidate<rustbgpd_wire::VpnNlriEntry> {
        let (afi, safi) = route.afi_safi();
        PreparedMpCandidate {
            afi,
            safi,
            next_hop: route.next_hop,
            link_local_next_hop: route.link_local_next_hop,
            attrs: self.prepare_vpn_attributes(route),
            nlri: rustbgpd_wire::VpnNlriEntry {
                path_id: route.path_id,
                nlri: route.nlri.clone(),
            },
        }
    }

    pub(super) fn prepare_labeled_candidate(
        &self,
        route: &LabeledRibRoute,
    ) -> PreparedMpCandidate<rustbgpd_wire::LabeledNlriEntry> {
        let (afi, safi) = route.afi_safi();
        PreparedMpCandidate {
            afi,
            safi,
            next_hop: route.next_hop,
            link_local_next_hop: route.link_local_next_hop,
            attrs: self.prepare_labeled_attributes(route),
            nlri: rustbgpd_wire::LabeledNlriEntry {
                path_id: route.path_id,
                nlri: route.nlri.clone(),
            },
        }
    }

    pub(super) fn prepare_rtc_candidate(
        &self,
        route: &RtcRibRoute,
    ) -> PreparedMpCandidate<rustbgpd_wire::RtcNlri> {
        PreparedMpCandidate {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            next_hop: self.rtc_next_hop(route),
            link_local_next_hop: None,
            attrs: self.prepare_rtc_attributes(route),
            nlri: route.nlri,
        }
    }

    #[cfg(test)]
    pub(super) fn with_test_ebgp(mut self, is_ebgp: bool) -> Self {
        self.is_ebgp = is_ebgp;
        self
    }

    /// Prepare one post-policy unicast route from this profile. Live grouping
    /// and exact preflight both consume this result, including policy next-hop
    /// override, socket/config next-hop selection, ENHE, and link-local form.
    #[allow(dead_code, reason = "crate-private high-level LAN-361 probe bridge")]
    pub(crate) fn prepare_unicast_candidate(
        &self,
        route: &Route,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Result<PreparedUnicastCandidate, ExportProbeError> {
        let attrs =
            self.prepare_unicast_attribute_bundle(route, self.local_ipv4(), next_hop_override);
        self.finish_unicast_candidate(route, next_hop_override, attrs)
    }

    pub(super) fn prepare_unicast_attribute_bundle(
        &self,
        route: &Route,
        local_ipv4: Ipv4Addr,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> PreparedUnicastAttributes {
        let with_next_hop =
            Arc::new(self.prepare_unicast_attributes(route, local_ipv4, next_hop_override));
        let without_next_hop = Arc::new(
            with_next_hop
                .iter()
                .filter(|attr| !matches!(attr, PathAttribute::NextHop(_)))
                .cloned()
                .collect(),
        );
        PreparedUnicastAttributes {
            with_next_hop,
            without_next_hop,
        }
    }

    fn route_origin_key(origin: rustbgpd_rib::RouteOrigin) -> u8 {
        match origin {
            rustbgpd_rib::RouteOrigin::Ebgp => 0,
            rustbgpd_rib::RouteOrigin::Ibgp => 1,
            rustbgpd_rib::RouteOrigin::Local => 2,
        }
    }

    fn prepared_attr_cache_key(
        &self,
        route: &Route,
        local_ipv4: Ipv4Addr,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> PreparedAttrCacheKey {
        PreparedAttrCacheKey {
            attrs_ptr: Arc::as_ptr(&route.attributes) as usize,
            is_ipv4: matches!(route.prefix, Prefix::V4(_)),
            route_next_hop: route.next_hop,
            origin_type: Self::route_origin_key(route.origin_type),
            peer_router_id: route.peer_router_id,
            is_ebgp: self.is_ebgp(),
            local_ipv4,
            next_hop_override: next_hop_override.into(),
        }
    }

    /// Return the prepared attributes for one unicast route, memoized by every
    /// route/profile input that changes attribute construction. Both live
    /// envelope encoding and exact precommit probes use this implementation.
    pub(super) fn prepared_unicast_attributes_cached<'a>(
        &self,
        cache: &'a mut PreparedAttrCache,
        route: &Route,
        local_ipv4: Ipv4Addr,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> &'a PreparedUnicastAttributes {
        let key = self.prepared_attr_cache_key(route, local_ipv4, next_hop_override);
        cache.entry(key).or_insert_with(|| {
            self.prepare_unicast_attribute_bundle(route, local_ipv4, next_hop_override)
        })
    }

    pub(super) fn finish_unicast_candidate(
        &self,
        route: &Route,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
        attrs: PreparedUnicastAttributes,
    ) -> Result<PreparedUnicastCandidate, ExportProbeError> {
        let local_ipv4 = self.local_ipv4();
        match route.prefix {
            Prefix::V4(_prefix) if self.use_extended_nexthop_ipv4() => {
                let force_self = matches!(
                    next_hop_override,
                    Some(rustbgpd_policy::NextHopAction::Self_)
                );
                let ebgp_ipv6 = self.usable_ipv4_extended_nexthop_ipv6(
                    self.configured_local_ipv6_nexthop.or(self.local_ipv6()),
                );
                let next_hop = match next_hop_override {
                    Some(rustbgpd_policy::NextHopAction::Specific(addr)) => *addr,
                    _ if force_self => self.local_addr.unwrap_or(IpAddr::V4(local_ipv4)),
                    _ if self.is_ebgp() && !self.route_server_client => {
                        IpAddr::V6(ebgp_ipv6.ok_or(ExportProbeError::MissingIpv6NextHop)?)
                    }
                    _ => route.next_hop,
                };
                Ok(PreparedUnicastCandidate::Mp {
                    afi: Afi::Ipv4,
                    next_hop,
                    link_local_next_hop: self.ipv4_mp_reach_link_local_next_hop(next_hop, route),
                    attrs: attrs.without_next_hop,
                    entry: NlriEntry {
                        path_id: route.path_id,
                        prefix: route.prefix,
                    },
                    ipv4_mode: Ipv4UnicastMode::MpReach,
                })
            }
            Prefix::V4(prefix) => {
                if self.scoped_link_local_peer {
                    return Err(ExportProbeError::Ipv4RequiresExtendedNextHop);
                }
                Ok(PreparedUnicastCandidate::Ipv4Body {
                    attrs: attrs.with_next_hop,
                    entry: Ipv4NlriEntry {
                        path_id: route.path_id,
                        prefix,
                    },
                })
            }
            Prefix::V6(_) => {
                let usable_local = Self::usable_ipv6_unicast_next_hop(
                    self.configured_local_ipv6_nexthop.or(self.local_ipv6()),
                );
                let force_self = matches!(
                    next_hop_override,
                    Some(rustbgpd_policy::NextHopAction::Self_)
                );
                let next_hop = match next_hop_override {
                    Some(rustbgpd_policy::NextHopAction::Specific(addr)) => *addr,
                    _ if self.is_ebgp() && !self.route_server_client => {
                        IpAddr::V6(usable_local.ok_or(ExportProbeError::MissingIpv6NextHop)?)
                    }
                    _ if force_self => usable_local.map_or(route.next_hop, IpAddr::V6),
                    _ => route.next_hop,
                };
                Ok(PreparedUnicastCandidate::Mp {
                    afi: Afi::Ipv6,
                    next_hop,
                    link_local_next_hop: Self::route_link_local_next_hop_for_selected_primary(
                        next_hop, route,
                    ),
                    attrs: attrs.with_next_hop,
                    entry: NlriEntry {
                        path_id: route.path_id,
                        prefix: route.prefix,
                    },
                    ipv4_mode: Ipv4UnicastMode::Body,
                })
            }
        }
    }

    fn probe_prepared_unicast_announcement(
        &self,
        route: &Route,
        next_hop_override: Option<&rustbgpd_policy::NextHopAction>,
        attrs: PreparedUnicastAttributes,
    ) -> Result<ExactExportProbe, ExportProbeError> {
        match self.finish_unicast_candidate(route, next_hop_override, attrs)? {
            PreparedUnicastCandidate::Ipv4Body { attrs, entry } => self
                .probe_ipv4_body(std::slice::from_ref(&entry), &[], &attrs)
                .map_err(Into::into),
            PreparedUnicastCandidate::Mp {
                afi,
                next_hop,
                link_local_next_hop,
                attrs,
                entry,
                ipv4_mode,
            } => self
                .probe_mp_reach(
                    afi,
                    Safi::Unicast,
                    next_hop,
                    link_local_next_hop,
                    &attrs,
                    ReachNlri::Unicast(std::slice::from_ref(&entry)),
                    ipv4_mode,
                )
                .map_err(Into::into),
        }
    }

    #[allow(
        dead_code,
        clippy::too_many_lines,
        reason = "crate-private high-level LAN-361 probe bridge enumerates every supported family"
    )]
    pub(crate) fn probe_announcement(
        &self,
        candidate: ExportCandidate<'_>,
    ) -> Result<ExactExportProbe, ExportProbeError> {
        match candidate {
            ExportCandidate::Unicast {
                route,
                next_hop_override,
            } => {
                let attrs = self.prepare_unicast_attribute_bundle(
                    route,
                    self.local_ipv4(),
                    next_hop_override,
                );
                self.probe_prepared_unicast_announcement(route, next_hop_override, attrs)
            }
            ExportCandidate::FlowSpec(route) => {
                let prepared = self.prepare_flowspec_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::FlowSpec(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
            ExportCandidate::Evpn(route) => {
                let prepared = self.prepare_evpn_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::Evpn(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
            ExportCandidate::BgpLs(route) => {
                let prepared = self.prepare_bgpls_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::BgpLs(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
            ExportCandidate::Vpn(route) => {
                let prepared = self.prepare_vpn_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::Vpn(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
            ExportCandidate::Labeled(route) => {
                let prepared = self.prepare_labeled_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::Labeled(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
            ExportCandidate::Rtc(route) => {
                let prepared = self.prepare_rtc_candidate(route);
                self.probe_mp_reach(
                    prepared.afi,
                    prepared.safi,
                    prepared.next_hop,
                    prepared.link_local_next_hop,
                    &prepared.attrs,
                    ReachNlri::Rtc(std::slice::from_ref(&prepared.nlri)),
                    Ipv4UnicastMode::Body,
                )
                .map_err(Into::into)
            }
        }
    }

    #[allow(dead_code, reason = "crate-private high-level LAN-361 probe bridge")]
    pub(crate) fn probe_withdrawal(
        &self,
        withdrawal: ExportWithdrawal<'_>,
    ) -> Result<ExactExportProbe, ExportProbeError> {
        match self.prepare_withdrawal(withdrawal)? {
            PreparedWithdrawal::Ipv4Body(entry) => self
                .probe_ipv4_body(&[], std::slice::from_ref(&entry), &[])
                .map_err(Into::into),
            PreparedWithdrawal::Unicast(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::Unicast(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::FlowSpec(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::FlowSpec(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::Evpn(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::Evpn(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::BgpLs(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::BgpLs(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::Vpn(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::Vpn(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::Labeled(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::Labeled(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
            PreparedWithdrawal::Rtc(prepared) => self
                .probe_mp_unreach(
                    prepared.afi,
                    prepared.safi,
                    UnreachNlri::Rtc(std::slice::from_ref(&prepared.nlri)),
                    prepared.ipv4_mode,
                )
                .map_err(Into::into),
        }
    }

    /// Resolve one real Adj-RIB-Out identity into its authoritative wire
    /// family, encoding mode, and NLRI representation. Live batching and the
    /// exact one-route probe both consume this typed result.
    pub(super) fn prepare_withdrawal(
        &self,
        withdrawal: ExportWithdrawal<'_>,
    ) -> Result<PreparedWithdrawal, ExportProbeError> {
        Ok(match withdrawal {
            ExportWithdrawal::Unicast { prefix, path_id } => match prefix {
                Prefix::V4(prefix) if self.use_extended_nexthop_ipv4() => {
                    PreparedWithdrawal::Unicast(PreparedMpWithdrawal {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        ipv4_mode: Ipv4UnicastMode::MpReach,
                        nlri: NlriEntry {
                            path_id,
                            prefix: Prefix::V4(prefix),
                        },
                    })
                }
                Prefix::V4(prefix) => {
                    if self.scoped_link_local_peer {
                        return Err(ExportProbeError::Ipv4RequiresExtendedNextHop);
                    }
                    PreparedWithdrawal::Ipv4Body(Ipv4NlriEntry { path_id, prefix })
                }
                Prefix::V6(_) => PreparedWithdrawal::Unicast(PreparedMpWithdrawal::new(
                    Afi::Ipv6,
                    Safi::Unicast,
                    NlriEntry { path_id, prefix },
                )),
            },
            ExportWithdrawal::FlowSpec(key) => PreparedWithdrawal::FlowSpec(
                PreparedMpWithdrawal::new(key.afi, Safi::FlowSpec, key.rule.clone()),
            ),
            ExportWithdrawal::Evpn(key) => PreparedWithdrawal::Evpn(PreparedMpWithdrawal::new(
                Afi::L2Vpn,
                Safi::Evpn,
                evpn_route_from_key(*key),
            )),
            ExportWithdrawal::BgpLs(key) => PreparedWithdrawal::BgpLs(PreparedMpWithdrawal::new(
                Afi::BgpLs,
                key.family.to_afi_safi().1,
                bgpls_nlri_from_key(key),
            )),
            ExportWithdrawal::Vpn(key) => PreparedWithdrawal::Vpn(PreparedMpWithdrawal::new(
                key.afi_safi().0,
                Safi::MplsVpn,
                vpn_withdraw_entry(key),
            )),
            ExportWithdrawal::Labeled(key) => {
                PreparedWithdrawal::Labeled(PreparedMpWithdrawal::new(
                    key.afi_safi().0,
                    Safi::LabeledUnicast,
                    labeled_withdraw_entry(key),
                ))
            }
            ExportWithdrawal::Rtc(key) => PreparedWithdrawal::Rtc(PreparedMpWithdrawal::new(
                Afi::Ipv4,
                Safi::RtConstrain,
                key.nlri,
            )),
        })
    }

    pub(super) fn build_ipv4_body(
        &self,
        announced: &[Ipv4NlriEntry],
        withdrawn: &[Ipv4NlriEntry],
        attrs: &[PathAttribute],
    ) -> Result<UpdateMessage, EncodeError> {
        self.probe_ipv4_body(announced, withdrawn, attrs)
            .map(ExactExportProbe::into_message)
    }

    pub(crate) fn probe_ipv4_body(
        &self,
        announced: &[Ipv4NlriEntry],
        withdrawn: &[Ipv4NlriEntry],
        attrs: &[PathAttribute],
    ) -> Result<ExactExportProbe, EncodeError> {
        let message = UpdateMessage::try_build(
            announced,
            withdrawn,
            attrs,
            self.four_octet_as(),
            self.add_path_send((Afi::Ipv4, Safi::Unicast)),
            Ipv4UnicastMode::Body,
        )?;
        Ok(self.exact_probe(message))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "MP_REACH wire framing has independent family, next-hop, attribute, and NLRI inputs"
    )]
    pub(super) fn build_mp_reach(
        &self,
        afi: Afi,
        safi: Safi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        nlri: ReachNlri<'_>,
        ipv4_mode: Ipv4UnicastMode,
    ) -> Result<UpdateMessage, EncodeError> {
        self.probe_mp_reach(
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            base_attrs,
            nlri,
            ipv4_mode,
        )
        .map(ExactExportProbe::into_message)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "MP_REACH exact probe mirrors the authoritative builder inputs"
    )]
    pub(crate) fn probe_mp_reach(
        &self,
        afi: Afi,
        safi: Safi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        nlri: ReachNlri<'_>,
        ipv4_mode: Ipv4UnicastMode,
    ) -> Result<ExactExportProbe, EncodeError> {
        let mut attrs = base_attrs.to_vec();
        attrs.push(PathAttribute::MpReachNlri(nlri.into_mp_reach(
            afi,
            safi,
            next_hop,
            link_local_next_hop,
        )));
        let message = UpdateMessage::try_build(
            &[],
            &[],
            &attrs,
            self.four_octet_as(),
            self.add_path_send((afi, safi)),
            ipv4_mode,
        )?;
        Ok(self.exact_probe(message))
    }

    pub(super) fn build_mp_unreach(
        &self,
        afi: Afi,
        safi: Safi,
        nlri: UnreachNlri<'_>,
        ipv4_mode: Ipv4UnicastMode,
    ) -> Result<UpdateMessage, EncodeError> {
        self.probe_mp_unreach(afi, safi, nlri, ipv4_mode)
            .map(ExactExportProbe::into_message)
    }

    pub(crate) fn probe_mp_unreach(
        &self,
        afi: Afi,
        safi: Safi,
        nlri: UnreachNlri<'_>,
        ipv4_mode: Ipv4UnicastMode,
    ) -> Result<ExactExportProbe, EncodeError> {
        let attrs = vec![PathAttribute::MpUnreachNlri(
            nlri.into_mp_unreach(afi, safi),
        )];
        let message = UpdateMessage::try_build(
            &[],
            &[],
            &attrs,
            self.four_octet_as(),
            self.add_path_send((afi, safi)),
            ipv4_mode,
        )?;
        Ok(self.exact_probe(message))
    }

    fn exact_probe(&self, message: UpdateMessage) -> ExactExportProbe {
        ExactExportProbe {
            encoded_len: message.encoded_len(),
            max_len: self.max_message_len(),
            generation: self.generation,
            message,
        }
    }

    pub(super) fn build_end_of_rib(
        &self,
        afi: Afi,
        safi: Safi,
    ) -> Result<UpdateMessage, EncodeError> {
        if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
            self.build_ipv4_body(&[], &[], &[])
        } else {
            self.build_mp_unreach(afi, safi, UnreachNlri::Unicast(&[]), Ipv4UnicastMode::Body)
        }
    }
}

/// Real post-policy announcement inputs accepted by the exact probe bridge.
#[allow(dead_code, reason = "crate-private high-level LAN-361 probe bridge")]
#[derive(Clone, Copy)]
pub(crate) enum ExportCandidate<'a> {
    Unicast {
        route: &'a Route,
        next_hop_override: Option<&'a rustbgpd_policy::NextHopAction>,
    },
    FlowSpec(&'a FlowSpecRoute),
    Evpn(&'a EvpnRibRoute),
    BgpLs(&'a BgpLsRibRoute),
    Vpn(&'a VpnRibRoute),
    Labeled(&'a LabeledRibRoute),
    Rtc(&'a RtcRibRoute),
}

/// Real Adj-RIB-Out withdrawal identities accepted by the exact probe bridge.
#[allow(dead_code, reason = "crate-private high-level LAN-361 probe bridge")]
#[derive(Clone, Copy)]
pub(crate) enum ExportWithdrawal<'a> {
    Unicast { prefix: Prefix, path_id: u32 },
    FlowSpec(&'a FlowSpecKey),
    Evpn(&'a EvpnRouteKey),
    BgpLs(&'a BgpLsRouteKey),
    Vpn(&'a VpnRibRouteKey),
    Labeled(&'a LabeledRibRouteKey),
    Rtc(&'a RtcRibRouteKey),
}

pub(super) struct PreparedMpWithdrawal<T> {
    pub(super) afi: Afi,
    pub(super) safi: Safi,
    pub(super) ipv4_mode: Ipv4UnicastMode,
    pub(super) nlri: T,
}

impl<T> PreparedMpWithdrawal<T> {
    fn new(afi: Afi, safi: Safi, nlri: T) -> Self {
        Self {
            afi,
            safi,
            ipv4_mode: Ipv4UnicastMode::Body,
            nlri,
        }
    }
}

pub(super) enum PreparedWithdrawal {
    Ipv4Body(Ipv4NlriEntry),
    Unicast(PreparedMpWithdrawal<NlriEntry>),
    FlowSpec(PreparedMpWithdrawal<FlowSpecRule>),
    Evpn(PreparedMpWithdrawal<EvpnRoute>),
    BgpLs(PreparedMpWithdrawal<rustbgpd_wire::bgpls::BgpLsNlri>),
    Vpn(PreparedMpWithdrawal<rustbgpd_wire::VpnNlriEntry>),
    Labeled(PreparedMpWithdrawal<rustbgpd_wire::LabeledNlriEntry>),
    Rtc(PreparedMpWithdrawal<rustbgpd_wire::RtcNlri>),
}

#[allow(
    dead_code,
    reason = "high-level probe consumes metadata beyond live grouping"
)]
pub(crate) enum PreparedUnicastCandidate {
    Ipv4Body {
        attrs: Arc<Vec<PathAttribute>>,
        entry: Ipv4NlriEntry,
    },
    Mp {
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        attrs: Arc<Vec<PathAttribute>>,
        entry: NlriEntry,
        ipv4_mode: Ipv4UnicastMode,
    },
}

#[derive(Clone)]
pub(super) struct PreparedUnicastAttributes {
    pub(super) with_next_hop: Arc<Vec<PathAttribute>>,
    pub(super) without_next_hop: Arc<Vec<PathAttribute>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum NextHopOverrideKey {
    None,
    Self_,
    Specific(IpAddr),
}

impl From<Option<&rustbgpd_policy::NextHopAction>> for NextHopOverrideKey {
    fn from(value: Option<&rustbgpd_policy::NextHopAction>) -> Self {
        match value {
            None => Self::None,
            Some(rustbgpd_policy::NextHopAction::Self_) => Self::Self_,
            Some(rustbgpd_policy::NextHopAction::Specific(addr)) => Self::Specific(*addr),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct PreparedAttrCacheKey {
    attrs_ptr: usize,
    is_ipv4: bool,
    route_next_hop: IpAddr,
    origin_type: u8,
    peer_router_id: Ipv4Addr,
    is_ebgp: bool,
    local_ipv4: Ipv4Addr,
    next_hop_override: NextHopOverrideKey,
}

pub(super) type PreparedAttrCache = FxHashMap<PreparedAttrCacheKey, PreparedUnicastAttributes>;

pub(super) struct PreparedMpCandidate<T> {
    pub(super) afi: Afi,
    pub(super) safi: Safi,
    pub(super) next_hop: IpAddr,
    pub(super) link_local_next_hop: Option<Ipv6Addr>,
    pub(super) attrs: Vec<PathAttribute>,
    pub(super) nlri: T,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExportProbeError {
    Encode(EncodeError),
    MissingIpv6NextHop,
    Ipv4RequiresExtendedNextHop,
}

impl From<EncodeError> for ExportProbeError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl std::fmt::Display for ExportProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(error) => error.fmt(formatter),
            Self::MissingIpv6NextHop => formatter.write_str("no usable local IPv6 next-hop"),
            Self::Ipv4RequiresExtendedNextHop => formatter
                .write_str("IPv4 on a scoped link-local session requires Extended Next Hop"),
        }
    }
}

pub(super) fn vpn_withdraw_entry(key: &VpnRibRouteKey) -> rustbgpd_wire::VpnNlriEntry {
    rustbgpd_wire::VpnNlriEntry {
        path_id: key.path_id,
        nlri: rustbgpd_wire::VpnNlri {
            labels: vec![],
            route_distinguisher: key.nlri_key.route_distinguisher,
            prefix: key.nlri_key.prefix,
        },
    }
}

pub(super) fn labeled_withdraw_entry(key: &LabeledRibRouteKey) -> rustbgpd_wire::LabeledNlriEntry {
    rustbgpd_wire::LabeledNlriEntry {
        path_id: key.path_id,
        nlri: rustbgpd_wire::LabeledNlri {
            labels: vec![],
            prefix: key.prefix,
        },
    }
}

pub(super) fn bgpls_nlri_from_key(key: &BgpLsRouteKey) -> rustbgpd_wire::bgpls::BgpLsNlri {
    rustbgpd_wire::bgpls::BgpLsNlri {
        nlri_type: key.nlri.nlri_type,
        route_distinguisher: key.nlri.route_distinguisher,
        payload: key.nlri.payload.clone(),
    }
}

pub(super) fn evpn_route_from_key(key: EvpnRouteKey) -> EvpnRoute {
    use rustbgpd_wire::{
        EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnImet, EvpnIpPrefixRoute, EvpnMacIp, MplsLabel,
    };
    let zero_label = MplsLabel::new(0);
    match key {
        EvpnRouteKey::EadPerEs {
            rd,
            esi,
            ethernet_tag,
        } => EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd,
            esi,
            ethernet_tag,
            label: zero_label,
        }),
        EvpnRouteKey::EadPerEvi {
            rd,
            esi,
            ethernet_tag,
        } => EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd,
            esi,
            ethernet_tag,
            label: zero_label,
        }),
        EvpnRouteKey::MacIp {
            rd,
            ethernet_tag,
            mac,
            ip,
        } => EvpnRoute::MacIp(EvpnMacIp {
            rd,
            esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
            ethernet_tag,
            mac,
            ip,
            label1: zero_label,
            label2: None,
        }),
        EvpnRouteKey::Imet {
            rd,
            ethernet_tag,
            originator_ip,
        } => EvpnRoute::Imet(EvpnImet {
            rd,
            ethernet_tag,
            originator_ip,
        }),
        EvpnRouteKey::Es {
            rd,
            esi,
            originator_ip,
        } => EvpnRoute::Es(EvpnEs {
            rd,
            esi,
            originator_ip,
        }),
        EvpnRouteKey::IpPrefix {
            rd,
            ethernet_tag,
            prefix,
        } => {
            let gateway = match prefix {
                rustbgpd_wire::EvpnIpPrefixValue::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                rustbgpd_wire::EvpnIpPrefixValue::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                rd,
                esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
                ethernet_tag,
                prefix,
                gateway,
                label: zero_label,
            })
        }
    }
}

/// Exact result consumed by live builders now and the RIB precommit gate in
/// LAN-361. Length is measured from the same constructed message, never from
/// an estimator.
pub(crate) struct ExactExportProbe {
    pub(crate) message: UpdateMessage,
    pub(crate) encoded_len: usize,
    pub(crate) max_len: usize,
    pub(crate) generation: u64,
}

impl ExactExportProbe {
    fn into_message(self) -> UpdateMessage {
        debug_assert_eq!(self.encoded_len, self.message.encoded_len());
        debug_assert!(matches!(self.max_len, 4_096 | 65_535));
        let _generation = self.generation;
        self.message
    }
}

/// The single `MP_REACH` builder accepts every outbound family so live chunks
/// and future one-NLRI exportability probes cannot diverge by construction.
pub(crate) enum ReachNlri<'a> {
    Unicast(&'a [NlriEntry]),
    FlowSpec(&'a [FlowSpecRule]),
    Evpn(&'a [EvpnRoute]),
    BgpLs(&'a [rustbgpd_wire::bgpls::BgpLsNlri]),
    Labeled(&'a [rustbgpd_wire::LabeledNlriEntry]),
    Vpn(&'a [rustbgpd_wire::VpnNlriEntry]),
    Rtc(&'a [rustbgpd_wire::RtcNlri]),
}

impl ReachNlri<'_> {
    fn into_mp_reach(
        self,
        afi: Afi,
        safi: Safi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
    ) -> MpReachNlri {
        let mut value = MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        match self {
            Self::Unicast(entries) => value.announced = entries.to_vec(),
            Self::FlowSpec(entries) => value.flowspec_announced = entries.to_vec(),
            Self::Evpn(entries) => value.evpn_announced = entries.to_vec(),
            Self::BgpLs(entries) => value.bgpls_announced = entries.to_vec(),
            Self::Labeled(entries) => value.labeled_announced = entries.to_vec(),
            Self::Vpn(entries) => value.vpn_announced = entries.to_vec(),
            Self::Rtc(entries) => value.rtc_announced = entries.to_vec(),
        }
        value
    }
}

/// The withdrawal sibling of [`ReachNlri`].
pub(crate) enum UnreachNlri<'a> {
    Unicast(&'a [NlriEntry]),
    FlowSpec(&'a [FlowSpecRule]),
    Evpn(&'a [EvpnRoute]),
    BgpLs(&'a [rustbgpd_wire::bgpls::BgpLsNlri]),
    Labeled(&'a [rustbgpd_wire::LabeledNlriEntry]),
    Vpn(&'a [rustbgpd_wire::VpnNlriEntry]),
    Rtc(&'a [rustbgpd_wire::RtcNlri]),
}

impl UnreachNlri<'_> {
    fn into_mp_unreach(self, afi: Afi, safi: Safi) -> MpUnreachNlri {
        let mut value = MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        };
        match self {
            Self::Unicast(entries) => value.withdrawn = entries.to_vec(),
            Self::FlowSpec(entries) => value.flowspec_withdrawn = entries.to_vec(),
            Self::Evpn(entries) => value.evpn_withdrawn = entries.to_vec(),
            Self::BgpLs(entries) => value.bgpls_withdrawn = entries.to_vec(),
            Self::Labeled(entries) => value.labeled_withdrawn = entries.to_vec(),
            Self::Vpn(entries) => value.vpn_withdrawn = entries.to_vec(),
            Self::Rtc(entries) => value.rtc_withdrawn = entries.to_vec(),
        }
        value
    }
}

/// Replaceable owner of immutable export-profile snapshots.
pub(crate) struct SessionExportEncoder {
    owner_id: u64,
    current: RwLock<Arc<SessionExportProfile>>,
}

static NEXT_EXPORT_ENCODER_ID: AtomicU64 = AtomicU64::new(1);

impl ExactExportEncoder for SessionExportEncoder {
    fn owner_id(&self) -> u64 {
        self.owner_id
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        SessionExportEncoder::snapshot(self)
    }
}

fn exact_export_result(
    probe: Result<ExactExportProbe, ExportProbeError>,
) -> Result<ExactExportResult, ExactExportError> {
    let probe = probe.map_err(|error| {
        let code = match &error {
            ExportProbeError::Encode(_) => ExactExportErrorCode::Encoding,
            ExportProbeError::MissingIpv6NextHop => ExactExportErrorCode::MissingIpv6NextHop,
            ExportProbeError::Ipv4RequiresExtendedNextHop => {
                ExactExportErrorCode::Ipv4RequiresExtendedNextHop
            }
        };
        ExactExportError::new(code, error)
    })?;
    if probe.encoded_len > probe.max_len {
        return Err(ExactExportError::new(
            ExactExportErrorCode::MessageTooLong,
            format_args!(
                "encoded UPDATE is {} bytes; negotiated maximum is {} bytes",
                probe.encoded_len, probe.max_len
            ),
        ));
    }
    Ok(ExactExportResult {
        encoded_len: probe.encoded_len,
        max_len: probe.max_len,
        generation: probe.generation,
    })
}

impl ExactExportSnapshot for SessionExportProfile {
    fn owner_id(&self) -> u64 {
        self.owner_id
    }

    fn generation(&self) -> u64 {
        SessionExportProfile::generation(self)
    }

    fn probe_announcement(
        &self,
        candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        let candidate = match candidate {
            ExactExportCandidate::Unicast {
                route,
                next_hop_override,
            } => ExportCandidate::Unicast {
                route,
                next_hop_override,
            },
            ExactExportCandidate::FlowSpec(route) => ExportCandidate::FlowSpec(route),
            ExactExportCandidate::Evpn(route) => ExportCandidate::Evpn(route),
            ExactExportCandidate::BgpLs(route) => ExportCandidate::BgpLs(route),
            ExactExportCandidate::Vpn(route) => ExportCandidate::Vpn(route),
            ExactExportCandidate::Labeled(route) => ExportCandidate::Labeled(route),
            ExactExportCandidate::Rtc(route) => ExportCandidate::Rtc(route),
        };
        exact_export_result(SessionExportProfile::probe_announcement(self, candidate))
    }

    fn probe_announcements(
        &self,
        candidates: &[ExactExportCandidate<'_>],
    ) -> Vec<Result<ExactExportResult, ExactExportError>> {
        let mut prepared_attr_cache = PreparedAttrCache::default();
        let local_ipv4 = self.local_ipv4();
        candidates
            .iter()
            .copied()
            .map(|candidate| match candidate {
                ExactExportCandidate::Unicast {
                    route,
                    next_hop_override,
                } => {
                    let attrs = self
                        .prepared_unicast_attributes_cached(
                            &mut prepared_attr_cache,
                            route,
                            local_ipv4,
                            next_hop_override,
                        )
                        .clone();
                    exact_export_result(self.probe_prepared_unicast_announcement(
                        route,
                        next_hop_override,
                        attrs,
                    ))
                }
                _ => <Self as ExactExportSnapshot>::probe_announcement(self, candidate),
            })
            .collect()
    }

    fn reuse_successful_probes(
        &self,
        source: &dyn ExactExportSnapshot,
        encoded_lengths: &[usize],
    ) -> Option<Vec<Result<ExactExportResult, ExactExportError>>> {
        let source = source.as_any().downcast_ref::<Self>()?;
        if !self.has_same_wire_encoding(source) {
            return None;
        }

        let max_len = self.max_message_len();
        Some(
            encoded_lengths
                .iter()
                .copied()
                .map(|encoded_len| {
                    if encoded_len > max_len {
                        Err(ExactExportError::new(
                            ExactExportErrorCode::MessageTooLong,
                            format_args!(
                                "encoded UPDATE is {encoded_len} bytes; negotiated maximum is {max_len} bytes"
                            ),
                        ))
                    } else {
                        Ok(ExactExportResult {
                            encoded_len,
                            max_len,
                            generation: self.generation,
                        })
                    }
                })
                .collect(),
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SessionExportEncoder {
    pub(super) fn new(mut profile: SessionExportProfile) -> Self {
        let owner_id = NEXT_EXPORT_ENCODER_ID.fetch_add(1, Ordering::Relaxed);
        profile.owner_id = owner_id;
        Self {
            owner_id,
            current: RwLock::new(Arc::new(profile)),
        }
    }

    pub(super) fn publish(&self, mut profile: SessionExportProfile) -> Arc<SessionExportProfile> {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        profile.owner_id = self.owner_id;
        profile.generation = current.generation();
        if **current == profile {
            return Arc::clone(&current);
        }
        profile.generation = current.generation().saturating_add(1);
        let profile = Arc::new(profile);
        *current = Arc::clone(&profile);
        profile
    }

    pub(crate) fn snapshot(&self) -> Arc<SessionExportProfile> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// Build the authoritative exact-export encoder used by the manager fanout
/// microbench. Each call returns a distinct session owner with the fixed
/// established iBGP/RR profile modelled by that benchmark.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
#[must_use]
pub fn fanout_bench_export_encoder() -> Arc<dyn ExactExportEncoder> {
    fanout_bench_encoder(false, false, Some(Ipv4Addr::new(10, 255, 255, 255)))
}

/// Build the authoritative exact-export encoder for one synthetic eBGP route-
/// server client. The constructor derives the same wire-relevant eBGP/iBGP
/// classification as a live negotiated session.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
#[must_use]
pub fn fanout_bench_route_server_export_encoder(remote_asn: u32) -> Arc<dyn ExactExportEncoder> {
    fanout_bench_encoder(remote_asn != 64_512, true, None)
}

#[cfg(feature = "bench-internals")]
fn fanout_bench_encoder(
    is_ebgp: bool,
    route_server_client: bool,
    cluster_id: Option<Ipv4Addr>,
) -> Arc<dyn ExactExportEncoder> {
    Arc::new(SessionExportEncoder::new(SessionExportProfile {
        owner_id: 0,
        generation: 0,
        local_asn: 64_512,
        local_router_id: Ipv4Addr::new(10, 255, 255, 255),
        local_role: None,
        route_server_client,
        remove_private_as: RemovePrivateAs::Disabled,
        cluster_id,
        configured_local_ipv6_nexthop: None,
        is_ebgp,
        four_octet_as: true,
        extended_messages: false,
        extended_nexthop_ipv4: false,
        add_path_send_families: Arc::from(Vec::new()),
        peer_llgr_families: Arc::from(Vec::new()),
        local_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))),
        scoped_link_local_peer: false,
        advertise_graceful_shutdown: false,
    }))
}

impl PeerSession {
    /// Publish a complete profile replacement and return the immutable
    /// snapshot that the next outbound envelope must use throughout.
    pub(super) fn publish_export_profile(&self) -> Arc<SessionExportProfile> {
        self.export_encoder
            .publish(SessionExportProfile::capture(self))
    }
}

pub(super) fn has_otc(attrs: &[PathAttribute]) -> bool {
    attrs.iter().any(|attr| match attr {
        PathAttribute::OnlyToCustomer(_) => true,
        PathAttribute::Unknown(raw) => {
            raw.type_code == rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER
        }
        _ => false,
    })
}

/// Remove private ASNs from an `AS_PATH` according to the configured mode.
pub(super) fn remove_private_asns(
    as_path: &AsPath,
    mode: RemovePrivateAs,
    local_asn: u32,
) -> AsPath {
    match mode {
        RemovePrivateAs::Disabled => as_path.clone(),
        RemovePrivateAs::Remove => {
            if as_path.all_private() {
                AsPath {
                    segments: as_path
                        .segments
                        .iter()
                        .filter_map(|segment| {
                            let filtered: Vec<u32> = match segment {
                                AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => {
                                    asns.iter()
                                        .copied()
                                        .filter(|asn| !is_private_asn(*asn))
                                        .collect()
                                }
                            };
                            (!filtered.is_empty()).then_some(match segment {
                                AsPathSegment::AsSequence(_) => AsPathSegment::AsSequence(filtered),
                                AsPathSegment::AsSet(_) => AsPathSegment::AsSet(filtered),
                            })
                        })
                        .collect(),
                }
            } else {
                as_path.clone()
            }
        }
        RemovePrivateAs::All => AsPath {
            segments: as_path
                .segments
                .iter()
                .filter_map(|segment| {
                    let filtered: Vec<u32> = match segment {
                        AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns
                            .iter()
                            .copied()
                            .filter(|asn| !is_private_asn(*asn))
                            .collect(),
                    };
                    (!filtered.is_empty()).then_some(match segment {
                        AsPathSegment::AsSequence(_) => AsPathSegment::AsSequence(filtered),
                        AsPathSegment::AsSet(_) => AsPathSegment::AsSet(filtered),
                    })
                })
                .collect(),
        },
        RemovePrivateAs::Replace => AsPath {
            segments: as_path
                .segments
                .iter()
                .map(|segment| match segment {
                    AsPathSegment::AsSequence(asns) => AsPathSegment::AsSequence(
                        asns.iter()
                            .map(|asn| {
                                if is_private_asn(*asn) {
                                    local_asn
                                } else {
                                    *asn
                                }
                            })
                            .collect(),
                    ),
                    AsPathSegment::AsSet(asns) => AsPathSegment::AsSet(
                        asns.iter()
                            .map(|asn| {
                                if is_private_asn(*asn) {
                                    local_asn
                                } else {
                                    *asn
                                }
                            })
                            .collect(),
                    ),
                })
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TcpAoAlgorithm, TcpAoConfig};
    use rustbgpd_fsm::{NegotiatedSession, PeerConfig};
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::{Ipv4Prefix, encode_message};
    use tokio::sync::mpsc;

    fn config_with_auth_secret(secret: &str) -> TransportConfig {
        let peer = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
        let mut config = TransportConfig::new(peer, "10.0.0.2:179".parse().unwrap());
        config.md5_password = Some(secret.into());
        config.tcp_ao = Some(
            TcpAoConfig {
                key: secret.into(),
                send_id: 7,
                recv_id: 9,
                algorithm: TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            }
            .into(),
        );
        config
    }

    fn capture_dynamic_profile(negotiated_remote_asn: u32) -> SessionExportProfile {
        let peer = PeerConfig::new(65_001, 0, Ipv4Addr::new(10, 0, 0, 1));
        let config = TransportConfig::new(peer, "10.0.0.2:179".parse().unwrap());
        let (_command_tx, command_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mut session = PeerSession::new(
            config,
            BgpMetrics::new(),
            command_rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mut negotiated = NegotiatedSession::default();
        negotiated.peer_asn = negotiated_remote_asn;
        session.negotiated = Some(negotiated);
        SessionExportProfile::capture(&session)
    }

    #[test]
    fn export_profile_never_retains_or_formats_transport_auth_secrets() {
        const SENTINEL: &str = "lan-380-profile-must-not-retain-this-secret";
        let config = config_with_auth_secret(SENTINEL);
        let profile = SessionExportProfile::initial(&config, None, false);

        let rendered = format!("{profile:?}");
        assert!(!rendered.contains(SENTINEL));
        assert!(!rendered.contains("tcp_ao"));
        assert!(!rendered.contains("md5"));
    }

    #[test]
    fn live_capture_classifies_dynamic_peer_from_negotiated_asn() {
        let ebgp = capture_dynamic_profile(65_002);
        let ibgp = capture_dynamic_profile(65_001);

        assert!(
            ebgp.is_ebgp(),
            "dynamic remote_asn=0 must use the negotiated eBGP ASN"
        );
        assert!(
            !ibgp.is_ebgp(),
            "dynamic remote_asn=0 must preserve a negotiated same-AS session"
        );
    }

    #[test]
    fn profile_publish_is_complete_immutable_and_generation_stable() {
        let config = config_with_auth_secret("not-retained");
        let encoder =
            SessionExportEncoder::new(SessionExportProfile::initial(&config, None, false));
        let old = encoder.snapshot();
        assert_eq!(old.generation(), 0);

        let mut replacement = SessionExportProfile::initial(&config, None, true);
        replacement.remove_private_as = RemovePrivateAs::All;
        replacement.configured_local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
        let published = encoder.publish(replacement);
        let current = encoder.snapshot();

        assert_eq!(published.generation(), 1);
        assert!(Arc::ptr_eq(&published, &current));
        assert_eq!(old.generation(), 0, "old Arc remains immutable");
        assert!(!old.advertise_graceful_shutdown);
        assert!(current.advertise_graceful_shutdown);
        assert_eq!(current.remove_private_as, RemovePrivateAs::All);
        assert_eq!(
            current.configured_local_ipv6_nexthop,
            Some("2001:db8::1".parse().unwrap())
        );

        let same = encoder.publish((*current).clone());
        assert!(Arc::ptr_eq(&same, &current));
        assert_eq!(same.generation(), 1, "wire-equal publish is idempotent");

        let mut changed = (*same).clone();
        changed.remove_private_as = RemovePrivateAs::Replace;
        let changed = encoder.publish(changed);
        assert_eq!(changed.generation(), 2, "one wire change increments once");
    }

    #[test]
    fn old_snapshot_remains_exact_while_new_generation_publishes() {
        let config = config_with_auth_secret("not-retained");
        let encoder = Arc::new(SessionExportEncoder::new(SessionExportProfile::initial(
            &config, None, false,
        )));
        let old = encoder.snapshot();
        let entry = [Ipv4NlriEntry {
            path_id: 0x0102_0304,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }];
        let old_before = encoded(old.build_ipv4_body(&entry, &[], &[]).unwrap());

        let mut replacement = (*old).clone();
        replacement.add_path_send_families = Arc::from(vec![(Afi::Ipv4, Safi::Unicast)]);
        let publisher = Arc::clone(&encoder);
        let new = std::thread::spawn(move || publisher.publish(replacement))
            .join()
            .unwrap();

        let old_after = encoded(old.build_ipv4_body(&entry, &[], &[]).unwrap());
        let new_bytes = encoded(new.build_ipv4_body(&entry, &[], &[]).unwrap());
        assert_eq!(old.generation(), 0);
        assert_eq!(new.generation(), 1);
        assert_eq!(
            old_before, old_after,
            "one envelope stays pinned to old Arc"
        );
        assert_ne!(
            old_after, new_bytes,
            "new Add-Path profile changes wire bytes"
        );
        assert!(Arc::ptr_eq(&new, &encoder.snapshot()));
    }

    #[test]
    fn object_safe_exact_export_bridge_preserves_identity_and_generation() {
        let config = config_with_auth_secret("not-retained");
        let encoder: Arc<dyn ExactExportEncoder> = Arc::new(SessionExportEncoder::new(
            SessionExportProfile::initial(&config, None, false),
        ));
        let snapshot = encoder.snapshot();
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 7,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };
        let candidate = ExactExportCandidate::Unicast {
            route: &route,
            next_hop_override: None,
        };

        assert_eq!(
            candidate.key(),
            rustbgpd_rib::ExactExportKey::Unicast(route.prefix, route.path_id)
        );
        let result = snapshot.probe_announcement(candidate).unwrap();
        assert_eq!(result.generation, snapshot.generation());
        assert!(result.encoded_len <= result.max_len);
        assert!(snapshot.as_any().is::<SessionExportProfile>());
    }

    #[test]
    fn successful_exact_probe_reuse_reowns_identity_generation_and_ceiling() {
        let config = config_with_auth_secret("not-retained");
        let mut source = SessionExportProfile::initial(&config, None, false);
        source.owner_id = 11;
        source.generation = 3;
        let mut target = source.clone();
        target.owner_id = 29;
        target.generation = 17;

        let reused = target
            .reuse_successful_probes(&source, &[1_234, 2_345])
            .expect("identity-only differences preserve wire equivalence");

        assert_eq!(
            reused,
            vec![
                Ok(ExactExportResult {
                    encoded_len: 1_234,
                    max_len: usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
                    generation: 17,
                }),
                Ok(ExactExportResult {
                    encoded_len: 2_345,
                    max_len: usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
                    generation: 17,
                }),
            ],
            "batch order and cardinality are preserved with target-owned metadata"
        );
    }

    #[test]
    fn distinct_ebgp_remote_asns_share_wire_results_but_ibgp_does_not() {
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![64_520])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
                PathAttribute::LocalPref(100),
            ]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        };
        let wire_bytes = |profile: &SessionExportProfile| {
            encoded(
                profile
                    .probe_announcement(ExportCandidate::Unicast {
                        route: &route,
                        next_hop_override: None,
                    })
                    .expect("the route-server candidate encodes")
                    .into_message(),
            )
        };

        for route_server_client in [false, true] {
            let mut source_config = config_with_auth_secret("not-retained");
            source_config.route_server_client = route_server_client;
            source_config.peer.remote_asn = 65_002;
            let mut target_config = source_config.clone();
            target_config.peer.remote_asn = 65_003;
            let mut ibgp_config = source_config.clone();
            ibgp_config.peer.remote_asn = ibgp_config.peer.local_asn;

            let source = SessionExportProfile::initial(&source_config, None, false);
            let target = SessionExportProfile::initial(&target_config, None, false);
            let ibgp = SessionExportProfile::initial(&ibgp_config, None, false);
            assert!(source.is_ebgp());
            assert!(target.is_ebgp());
            assert!(!ibgp.is_ebgp());

            if !route_server_client {
                let attrs = source.prepare_unicast_attributes(&route, source.local_ipv4(), None);
                assert!(
                    attrs.iter().any(|attr| matches!(
                        attr,
                        PathAttribute::AsPath(AsPath { segments })
                            if matches!(
                                segments.first(),
                                Some(AsPathSegment::AsSequence(asns))
                                    if asns.first() == Some(&source.local_asn)
                            )
                    )),
                    "the ordinary eBGP fixture must exercise local-AS prepend"
                );
                assert!(
                    attrs.iter().any(|attr| matches!(
                        attr,
                        PathAttribute::NextHop(next_hop) if *next_hop == source.local_ipv4()
                    )),
                    "the ordinary eBGP fixture must exercise next-hop-self rewriting"
                );
            }

            let source_bytes = wire_bytes(&source);
            assert_eq!(
                source_bytes,
                wire_bytes(&target),
                "remote ASN identity does not change bytes within either eBGP profile"
            );
            assert!(
                target
                    .reuse_successful_probes(&source, &[source_bytes.len()])
                    .is_some(),
                "distinct eBGP remote ASNs reuse a successful exact result"
            );
            assert_ne!(
                source_bytes,
                wire_bytes(&ibgp),
                "the eBGP/iBGP classification remains wire-relevant"
            );
            assert!(
                ibgp.reuse_successful_probes(&source, &[source_bytes.len()])
                    .is_none(),
                "eBGP results must not cross the iBGP boundary"
            );
        }
    }

    #[test]
    fn successful_probe_reuse_is_monotone_at_target_ceiling() {
        let config = config_with_auth_secret("not-retained");
        let mut source = SessionExportProfile::initial(&config, None, false);
        source.extended_messages = true;
        source.owner_id = 11;
        source.generation = 3;
        let mut target = source.clone();
        target.extended_messages = false;
        target.owner_id = 29;
        target.generation = 17;
        let max_len = usize::from(rustbgpd_wire::MAX_MESSAGE_LEN);

        let results = target
            .reuse_successful_probes(&source, &[max_len - 1, max_len, max_len + 1])
            .expect("the message ceiling does not affect encoded bytes");
        for (encoded_len, result) in [max_len - 1, max_len].into_iter().zip(&results[..2]) {
            assert_eq!(
                result,
                &Ok(ExactExportResult {
                    encoded_len,
                    max_len,
                    generation: 17,
                }),
                "every encoded length through the target ceiling is accepted"
            );
        }
        let error = results[2]
            .as_ref()
            .expect_err("the first encoded length above the target ceiling is rejected");

        assert_eq!(error.code(), ExactExportErrorCode::MessageTooLong);
        assert!(error.detail().contains(&(max_len + 1).to_string()));
        assert!(error.detail().contains(&max_len.to_string()));
    }

    #[test]
    fn failed_source_probe_exposes_no_reusable_encoded_length() {
        let config = config_with_auth_secret("not-retained");
        let source = SessionExportProfile::initial(&config, None, false);
        let mut target = source.clone();
        target.extended_messages = true;
        let source_result: Result<ExactExportResult, ExactExportError> =
            Err(ExactExportError::new(
                ExactExportErrorCode::MessageTooLong,
                "source 4K ceiling rejected the candidate",
            ));

        let reused = source_result.ok().and_then(|successful| {
            target.reuse_successful_probes(&source, &[successful.encoded_len])
        });

        assert!(
            reused.is_none(),
            "a failed source probe has no successful length to cache or reuse"
        );
    }

    #[test]
    fn successful_exact_probe_reuse_refuses_wire_profile_differences() {
        type ProfileMutation = fn(&mut SessionExportProfile);

        let config = config_with_auth_secret("not-retained");
        let target = SessionExportProfile::initial(&config, None, false);
        let cases: [(&str, ProfileMutation); 8] = [
            ("local ASN", |profile| profile.local_asn += 1),
            ("router ID", |profile| {
                profile.local_router_id = Ipv4Addr::new(192, 0, 2, 99);
            }),
            ("route-server mode", |profile| {
                profile.route_server_client = !profile.route_server_client;
            }),
            ("four-octet ASN encoding", |profile| {
                profile.four_octet_as = !profile.four_octet_as;
            }),
            ("extended next hop", |profile| {
                profile.extended_nexthop_ipv4 = !profile.extended_nexthop_ipv4;
            }),
            ("Add-Path", |profile| {
                profile.add_path_send_families = Arc::from(vec![(Afi::Ipv4, Safi::Unicast)]);
            }),
            ("local address", |profile| {
                profile.local_addr = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
            }),
            ("graceful shutdown", |profile| {
                profile.advertise_graceful_shutdown = !profile.advertise_graceful_shutdown;
            }),
        ];

        for (name, mutate) in cases {
            let mut source = target.clone();
            mutate(&mut source);
            assert!(
                target.reuse_successful_probes(&source, &[1_234]).is_none(),
                "must not reuse across a {name} difference"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one cache-key matrix keeps scalar equivalence and every memo dimension together"
    )]
    fn batched_exact_probe_matches_scalar_and_memoizes_only_complete_attr_keys() {
        let config = config_with_auth_secret("not-retained");
        let profile = SessionExportProfile::initial(&config, None, false);
        let shared_attributes = Arc::new(vec![
            PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
            PathAttribute::LocalPref(100),
        ]);
        let routes = (0..64)
            .map(|index| Route {
                prefix: Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(203, 0, u8::try_from(index).unwrap(), 0),
                    24,
                )),
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                attributes: Arc::clone(&shared_attributes),
                received_at: std::time::Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
                peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                aspa_context: rustbgpd_wire::AspaValidationContext::default(),
            })
            .collect::<Vec<_>>();
        let candidates = routes
            .iter()
            .map(|route| ExactExportCandidate::Unicast {
                route,
                next_hop_override: None,
            })
            .collect::<Vec<_>>();

        let scalar = candidates
            .iter()
            .copied()
            .map(|candidate| {
                <SessionExportProfile as ExactExportSnapshot>::probe_announcement(
                    &profile, candidate,
                )
            })
            .collect::<Vec<_>>();
        let batched = profile.probe_announcements(&candidates);
        assert_eq!(batched, scalar, "batch must preserve scalar result order");

        let mut cache = PreparedAttrCache::default();
        let local_ipv4 = profile.local_ipv4();
        for route in &routes {
            profile.prepared_unicast_attributes_cached(&mut cache, route, local_ipv4, None);
        }
        assert_eq!(
            cache.len(),
            1,
            "shared complete keys prepare attributes once"
        );

        let mut different_next_hop = routes[0].clone();
        different_next_hop.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        profile.prepared_unicast_attributes_cached(
            &mut cache,
            &different_next_hop,
            local_ipv4,
            None,
        );
        assert_eq!(cache.len(), 2, "route next hop is part of the cache key");

        profile.prepared_unicast_attributes_cached(
            &mut cache,
            &routes[0],
            local_ipv4,
            Some(&rustbgpd_policy::NextHopAction::Self_),
        );
        assert_eq!(cache.len(), 3, "next-hop action is part of the cache key");

        let mut different_afi = routes[0].clone();
        different_afi.prefix = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
            "2001:db8::".parse().unwrap(),
            64,
        ));
        profile.prepared_unicast_attributes_cached(&mut cache, &different_afi, local_ipv4, None);
        assert_eq!(cache.len(), 4, "address family is part of the cache key");

        let mut different_origin = routes[0].clone();
        different_origin.origin_type = rustbgpd_rib::RouteOrigin::Ebgp;
        profile.prepared_unicast_attributes_cached(&mut cache, &different_origin, local_ipv4, None);
        assert_eq!(cache.len(), 5, "route origin is part of the cache key");

        let mut different_router_id = routes[0].clone();
        different_router_id.peer_router_id = Ipv4Addr::new(192, 0, 2, 99);
        profile.prepared_unicast_attributes_cached(
            &mut cache,
            &different_router_id,
            local_ipv4,
            None,
        );
        assert_eq!(cache.len(), 6, "peer router ID is part of the cache key");

        for (expected_len, address) in [
            (7, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100))),
            (8, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 101))),
        ] {
            profile.prepared_unicast_attributes_cached(
                &mut cache,
                &routes[0],
                local_ipv4,
                Some(&rustbgpd_policy::NextHopAction::Specific(address)),
            );
            assert_eq!(
                cache.len(),
                expected_len,
                "specific next-hop address is part of the cache key"
            );
        }
    }

    fn encoded(message: UpdateMessage) -> Vec<u8> {
        encode_message(&super::super::Message::Update(message))
            .unwrap()
            .to_vec()
    }
}
