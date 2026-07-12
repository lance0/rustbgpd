use super::{
    Afi, AsPath, AsPathSegment, BgpLsRibRoute, BgpLsRouteKey, BgpRole, EvpnRibRoute, EvpnRoute,
    EvpnRouteKey, FlowSpecRoute, FlowSpecRule, IpAddr, Ipv4Addr, Ipv4NlriEntry, Ipv4UnicastMode,
    Ipv6Addr, LabeledRibRoute, Message, MpReachNlri, MpUnreachNlri, NlriEntry, OutboundRouteUpdate,
    PathAttribute, PeerSession, Prefix, RemovePrivateAs, Route, RouteRefreshMessage,
    RouteRefreshSubtype, RtcRibRoute, Safi, UpdateMessage, VpnRibRoute, debug, info,
    is_ipv6_link_local, is_private_asn, warn,
};
use std::sync::Arc;

// The per-batch outbound maps (`PreparedAttrCacheKey` cache + the
// `AttrGroupKey` UPDATE-grouping indices) use FxHash rather than the
// default SipHash: keying is once per announced route, and SipHash on
// these wide keys was the top prepare+encode line in the RR fanout
// flamegraph. HashDoS tradeoff (deliberate), mirroring the route-map
// rationale block at the top of `rib::adj_rib_in`: the key material
// (attribute Arc pointers, next hops, router ids) derives from route
// data of explicitly configured peers, each map lives only for one
// `send_route_update` batch, and per-peer route count is bounded by
// enforced `max_prefixes` — so a collision chain is short-lived and
// capped. A peer able to craft colliding attribute sets already has
// strictly higher-impact vectors (churn flood, hijack).
use rustc_hash::FxHashMap as HashMap;
fn has_otc(attrs: &[PathAttribute]) -> bool {
    attrs.iter().any(|attr| match attr {
        PathAttribute::OnlyToCustomer(_) => true,
        PathAttribute::Unknown(raw) => {
            raw.type_code == rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER
        }
        _ => false,
    })
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
struct PreparedAttrCacheKey {
    attrs_ptr: usize,
    is_ipv4: bool,
    route_next_hop: IpAddr,
    origin_type: u8,
    peer_router_id: Ipv4Addr,
    is_ebgp: bool,
    local_ipv4: Ipv4Addr,
    nh_override: NextHopOverrideKey,
}
#[derive(Clone)]
struct PreparedAttrCacheValue {
    with_next_hop: Arc<Vec<PathAttribute>>,
    without_next_hop: Arc<Vec<PathAttribute>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AttrGroupKey {
    attrs_ptr: usize,
    next_hop: Option<IpAddr>,
    link_local_next_hop: Option<Ipv6Addr>,
}
struct V4BodyGroup {
    attrs: Arc<Vec<PathAttribute>>,
    prefixes: Vec<Ipv4NlriEntry>,
}
struct MpGroup {
    attrs: Arc<Vec<PathAttribute>>,
    next_hop: IpAddr,
    link_local_next_hop: Option<Ipv6Addr>,
    prefixes: Vec<NlriEntry>,
}
impl PeerSession {
    fn usable_ipv4_extended_nexthop_ipv6(&self, candidate: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        // The link-local relaxation is only valid for IPv4-over-IPv6 ENHE on a
        // configured scoped peer. IPv6 unicast keeps using
        // `usable_ipv6_unicast_next_hop`, which rejects link-local primaries.
        candidate.filter(|addr| {
            rustbgpd_wire::is_valid_ipv6_nexthop(addr)
                || (self.is_scoped_link_local_peer() && is_ipv6_link_local(addr))
        })
    }
    fn usable_ipv6_unicast_next_hop(candidate: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        candidate.filter(rustbgpd_wire::is_valid_ipv6_nexthop)
    }
    fn ipv4_mp_reach_link_local_next_hop(
        &self,
        next_hop: IpAddr,
        route: &Route,
    ) -> Option<Ipv6Addr> {
        match next_hop {
            IpAddr::V6(v6) if self.is_scoped_link_local_peer() && is_ipv6_link_local(&v6) => {
                Some(v6)
            }
            _ if next_hop == route.next_hop => route.link_local_next_hop,
            _ => None,
        }
    }
    fn route_link_local_next_hop_for_selected_primary(
        next_hop: IpAddr,
        route: &Route,
    ) -> Option<Ipv6Addr> {
        if next_hop == route.next_hop {
            route.link_local_next_hop
        } else {
            None
        }
    }
    fn peer_accepts_llgr_stale(&self, family: (Afi, Safi)) -> bool {
        self.negotiated.as_ref().is_some_and(|neg| {
            neg.peer_llgr_capable
                && neg
                    .peer_llgr_families
                    .iter()
                    .any(|f| (f.afi, f.safi) == family)
        })
    }
    /// RFC 9494 §4.6 outbound form for an LLGR-stale route toward a peer
    /// that did NOT advertise the LLGR capability for the family. The RIB
    /// staging gate suppresses such routes toward eBGP peers entirely, so
    /// the only LLGR-stale routes that legitimately arrive here for a
    /// non-LLGR peer are iBGP — permitted by the §4.6 intra-AS exception
    /// only with `NO_EXPORT` attached and `LOCAL_PREF` set to zero. The
    /// `LLGR_STALE` community itself "MUST NOT be removed when the route
    /// is further advertised", so it rides through unchanged (toward
    /// LLGR peers too). This lives beside the other per-peer attribute
    /// rewrites (eBGP `LOCAL_PREF` strip, `ORIGINATOR_ID`/`CLUSTER_LIST`,
    /// `GShut` attach) rather than at RIB staging.
    ///
    /// Detection is by the `LLGR_STALE` community rather than the RIB's
    /// `is_llgr_stale` flag — deliberately: the community is the superset.
    /// A route *received* already tagged by an upstream LLGR helper carries
    /// only the community (the local flag is never set for it), yet §4.6
    /// applies to it all the same. For locally promoted routes the flag and
    /// community are coupled by construction (promotion injects the
    /// community; the flag is never set anywhere else), and that coupling
    /// is pinned by `llgr_stale_flag_implies_community_across_mutations` in
    /// `rustbgpd-rib::adj_rib_in`.
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
    /// RFC 8326 initiator: when `advertise_graceful_shutdown` is set
    /// (via gRPC `SetGracefulShutdown`), ensure every outbound update
    /// carries the `GRACEFUL_SHUTDOWN` community. If the route already
    /// has a `Communities` attribute, the value is folded in; otherwise
    /// a new `Communities` attribute is added. Idempotent — re-applying
    /// to an already-tagged route is a no-op.
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
    fn route_origin_key(origin: rustbgpd_rib::RouteOrigin) -> u8 {
        match origin {
            rustbgpd_rib::RouteOrigin::Ebgp => 0,
            rustbgpd_rib::RouteOrigin::Ibgp => 1,
            rustbgpd_rib::RouteOrigin::Local => 2,
        }
    }
    fn prepared_attr_cache_key(
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> PreparedAttrCacheKey {
        PreparedAttrCacheKey {
            attrs_ptr: Arc::as_ptr(&route.attributes) as usize,
            is_ipv4: matches!(route.prefix, Prefix::V4(_)),
            route_next_hop: route.next_hop,
            origin_type: Self::route_origin_key(route.origin_type),
            peer_router_id: route.peer_router_id,
            is_ebgp,
            local_ipv4,
            nh_override: nh_override.into(),
        }
    }
    fn prepared_outbound_attributes_cached<'a>(
        &'a self,
        cache: &'a mut HashMap<PreparedAttrCacheKey, PreparedAttrCacheValue>,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> &'a PreparedAttrCacheValue {
        let key = Self::prepared_attr_cache_key(route, is_ebgp, local_ipv4, nh_override);
        cache.entry(key).or_insert_with(|| {
            let with_next_hop =
                Arc::new(self.prepare_outbound_attributes(route, is_ebgp, local_ipv4, nh_override));
            let without_next_hop = Arc::new(
                with_next_hop
                    .iter()
                    .filter(|attr| !matches!(attr, PathAttribute::NextHop(_)))
                    .cloned()
                    .collect(),
            );
            PreparedAttrCacheValue {
                with_next_hop,
                without_next_hop,
            }
        })
    }
    pub(super) fn otc_egress_blocks_unicast(&self, route: &Route) -> bool {
        has_otc(&route.attributes)
            && matches!(
                self.config.peer.local_role,
                Some(BgpRole::Customer | BgpRole::Peer | BgpRole::RouteServerClient)
            )
    }
    fn record_otc_egress_block(&mut self, route: &Route) {
        debug!(
            peer = %self.peer_label,
            prefix = %route.prefix,
            "not advertising unicast route with OTC to Provider/Peer/RouteServer"
        );
        self.record_otc_routes_blocked(
            rustbgpd_telemetry::reason_labels::OtcBlockReason::EgressToUpstreamViaOtc,
            1,
        );
        if !self.event_sink().wants_otc_route_blocked() {
            return;
        }
        let otc_value = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::OnlyToCustomer(asn) => Some(*asn),
                PathAttribute::Unknown(raw)
                    if raw.type_code == rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER
                        && raw.data.len() == 4 =>
                {
                    Some(u32::from_be_bytes([
                        raw.data[0],
                        raw.data[1],
                        raw.data[2],
                        raw.data[3],
                    ]))
                }
                _ => None,
            });
        let as_path_string = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::AsPath(path) => Some(path.to_aspath_string()),
                _ => None,
            })
            .unwrap_or_default();
        self.event_sink()
            .publish_otc_route_blocked(&crate::event_sink::OtcRouteBlockedEvent {
                peer: self.peer_ip,
                direction: crate::event_sink::OtcDirection::Egress,
                reason: rustbgpd_telemetry::reason_labels::OtcBlockReason::EgressToUpstreamViaOtc,
                prefixes: vec![route.prefix.to_string()],
                local_role: self.config.peer.local_role,
                remote_role: self
                    .negotiated
                    .as_ref()
                    .and_then(|session| session.remote_role),
                otc_value,
                as_path: as_path_string,
            });
    }
    /// Send an outbound route update as wire UPDATE messages.
    ///
    /// Encodes each piece (`BoRR` markers, withdrawals, announcements,
    /// `FlowSpec`, EVPN, `EoR` markers, `EoRR` markers) and pushes the bytes
    /// onto the writer task's bulk channel via [`Self::enqueue_bulk`].
    /// Returns synchronously — there's no awaiting on TCP writes here
    /// after the writer-task split (ADR-0051).
    #[expect(
        clippy::too_many_lines,
        clippy::needless_pass_by_value,
        reason = "export pipeline keeps policy, ORF, and advertisement ordering in one pass"
    )]
    pub(super) fn send_route_update(&mut self, update: OutboundRouteUpdate) {
        for route in &update.otc_blocked {
            self.record_otc_egress_block(route);
        }
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);
        let peer_err = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_enhanced_route_refresh);
        // Check if Add-Path send is negotiated (we can send path IDs to this peer)
        let add_path_ipv4_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv4, Safi::Unicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        let add_path_ipv6_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv6, Safi::Unicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        // VPNv4/VPNv6 (SAFI 128) negotiate Add-Path per family (RFC 7911);
        // when send is negotiated, EVERY VPN NLRI to this peer carries the
        // 4-octet path ID — announcements and withdrawals alike.
        let add_path_vpnv4_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv4, Safi::MplsVpn))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        let add_path_vpnv6_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv6, Safi::MplsVpn))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        // Labeled-unicast (SAFI 4) negotiates Add-Path per family the same
        // way; when send is negotiated, EVERY labeled NLRI to this peer
        // carries the 4-octet path ID — announcements and withdrawals alike.
        let add_path_labeled_v4_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv4, Safi::LabeledUnicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        let add_path_labeled_v6_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv6, Safi::LabeledUnicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        // ROUTE-REFRESH *requests* toward the peer (RFC 2918), asked for by
        // the RIB manager (outbound-registration failover: the survivor's
        // Adj-RIB-In must be re-learned from the peer). The manager only
        // sets a flag — family selection happens HERE, over the session's
        // authoritative negotiated set, because the manager sees only the
        // sendable (outbound) subset while the refresh repopulates inbound
        // state. Gated on the negotiated capability, mirroring
        // `PeerCommand::SendRouteRefresh`; a peer without the capability
        // cannot be asked, so the staleness window lasts until its next
        // natural re-advertisement — surfaced by the warning.
        if update.request_refresh_all_negotiated {
            let peer_route_refresh = self
                .negotiated
                .as_ref()
                .is_some_and(|n| n.peer_route_refresh);
            if peer_route_refresh {
                for (afi, safi) in self.negotiated_families.clone() {
                    let msg = Message::RouteRefresh(RouteRefreshMessage::new(afi, safi));
                    if let Err(e) = self.enqueue_bulk(&msg) {
                        warn!(
                            peer = %self.peer_label,
                            error = %e,
                            "failed to send ROUTE-REFRESH request"
                        );
                        return;
                    }
                    info!(
                        peer = %self.peer_label,
                        ?afi,
                        ?safi,
                        "sent ROUTE-REFRESH request (RIB-manager initiated)"
                    );
                    self.metrics
                        .record_message_sent(&self.peer_label, "route_refresh");
                }
            } else {
                warn!(
                    peer = %self.peer_label,
                    "ROUTE-REFRESH request skipped — peer lacks the Route Refresh \
                     capability; inbound routes recover only on the peer's natural \
                     re-advertisement"
                );
            }
        }
        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::BoRR))
            {
                let msg = Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(
                    afi, safi, subtype,
                ));
                if let Err(e) = self.enqueue_bulk(&msg) {
                    warn!(
                        peer = %self.peer_label,
                        error = %e,
                        "failed to send Beginning-of-RIB-Refresh"
                    );
                    return;
                }
                self.metrics
                    .record_message_sent(&self.peer_label, "route_refresh");
            }
        }
        let use_extended_nexthop_ipv4 = self.use_extended_nexthop_ipv4();
        // Extract TCP local addresses for NEXT_HOP rewrite
        let local_addr = self
            .read_half
            .as_ref()
            .and_then(|h| h.local_addr().ok())
            .map(|a| a.ip());
        let local_ipv4 = local_addr
            .and_then(|a| match a {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or(self.config.peer.local_router_id);
        let local_ipv6 = local_addr.and_then(|a| match a {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        });
        let mut prepared_attr_cache: HashMap<PreparedAttrCacheKey, PreparedAttrCacheValue> =
            HashMap::default();
        // Split withdrawals by address family, filtering by negotiated families
        let mut v4_withdraw: Vec<Ipv4NlriEntry> = Vec::new();
        let mut v6_withdraw: Vec<NlriEntry> = Vec::new();
        for &(ref prefix, path_id) in &update.withdraw {
            if !self.is_family_negotiated(prefix) {
                continue;
            }
            match prefix {
                Prefix::V4(v4) => v4_withdraw.push(Ipv4NlriEntry {
                    path_id,
                    prefix: *v4,
                }),
                v6 @ Prefix::V6(_) => v6_withdraw.push(NlriEntry {
                    path_id,
                    prefix: *v6,
                }),
            }
        }
        // Send IPv4 withdrawals via body NLRI or IPv4 MP_UNREACH_NLRI,
        // depending on Extended Next Hop negotiation.
        if !v4_withdraw.is_empty() {
            if self.is_scoped_link_local_peer() && !use_extended_nexthop_ipv4 {
                warn!(
                    peer = %self.peer_label,
                    "not sending IPv4 withdrawals to scoped link-local peer without negotiated Extended Next Hop"
                );
            } else {
                let max_len = usize::from(self.outbound_max_message_len());
                let ok = if use_extended_nexthop_ipv4 {
                    self.send_v4_chunked(&v4_withdraw, max_len, "withdraw", |chunk| {
                        let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                            afi: Afi::Ipv4,
                            safi: Safi::Unicast,
                            withdrawn: chunk
                                .iter()
                                .map(|entry| NlriEntry {
                                    path_id: entry.path_id,
                                    prefix: Prefix::V4(entry.prefix),
                                })
                                .collect(),
                            flowspec_withdrawn: vec![],
                            evpn_withdrawn: vec![],
                            bgpls_withdrawn: vec![],
                            labeled_withdrawn: vec![],
                            vpn_withdrawn: vec![],
                            rtc_withdrawn: vec![],
                        })];
                        UpdateMessage::build(
                            &[],
                            &[],
                            &attrs,
                            four_octet_as,
                            add_path_ipv4_send,
                            Ipv4UnicastMode::MpReach,
                        )
                    })
                } else {
                    self.send_v4_chunked(&v4_withdraw, max_len, "withdraw", |chunk| {
                        UpdateMessage::build(
                            &[],
                            chunk,
                            &[],
                            four_octet_as,
                            add_path_ipv4_send,
                            Ipv4UnicastMode::Body,
                        )
                    })
                };
                if !ok {
                    return;
                }
            }
        }
        // Send IPv6 withdrawals via `MP_UNREACH_NLRI`, chunked to the
        // negotiated message ceiling just like IPv4. A large Add-Path
        // withdrawal set must not be handed to `enqueue_bulk` as one
        // oversized message after the RIB has already committed it.
        if !v6_withdraw.is_empty() {
            let max_len = usize::from(self.outbound_max_message_len());
            if !self.send_mp_chunked(
                &v6_withdraw,
                max_len,
                "IPv6 unicast",
                "withdrawal",
                |chunk| {
                    let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        withdrawn: chunk.to_vec(),
                        flowspec_withdrawn: vec![],
                        evpn_withdrawn: vec![],
                        bgpls_withdrawn: vec![],
                        labeled_withdrawn: vec![],
                        vpn_withdrawn: vec![],
                        rtc_withdrawn: vec![],
                    })];
                    UpdateMessage::try_build(
                        &[],
                        &[],
                        &attrs,
                        four_octet_as,
                        add_path_ipv6_send,
                        Ipv4UnicastMode::Body,
                    )
                },
            ) {
                return;
            }
        }
        // Split announcements by address family, filtering by negotiated families
        let mut v4_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        let mut v6_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        for (i, route) in update.announce.iter().enumerate() {
            if !self.is_family_negotiated(&route.prefix) {
                continue;
            }
            if self.otc_egress_blocks_unicast(route) {
                // Defense-in-depth for legacy/manual RIB producers. Normal
                // RIB staging already removed this route before commit and
                // carried it in `otc_blocked` above.
                self.record_otc_egress_block(route);
                continue;
            }
            let nh_override = update.next_hop_override.get(i).and_then(|o| o.as_ref());
            match route.prefix {
                Prefix::V4(_) => v4_routes.push((route, nh_override)),
                Prefix::V6(_) => v6_routes.push((route, nh_override)),
            }
        }
        // Send IPv4 announcements via body NLRI or IPv4 MP_REACH_NLRI,
        // depending on Extended Next Hop negotiation.
        if use_extended_nexthop_ipv4 {
            let ebgp_ipv6_nh = self
                .usable_ipv4_extended_nexthop_ipv6(self.config.local_ipv6_nexthop.or(local_ipv6));
            let mut v4_group_index: HashMap<AttrGroupKey, usize> = HashMap::default();
            let mut v4_groups: Vec<MpGroup> = Vec::new();
            for (route, nh_override_ref) in &v4_routes {
                let nh_override = *nh_override_ref;
                let attrs = Arc::clone(
                    &self
                        .prepared_outbound_attributes_cached(
                            &mut prepared_attr_cache,
                            route,
                            is_ebgp,
                            local_ipv4,
                            nh_override,
                        )
                        .without_next_hop,
                );
                let force_nh_self =
                    matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
                let next_hop = match nh_override {
                    Some(rustbgpd_policy::NextHopAction::Specific(addr)) => *addr,
                    _ if force_nh_self => local_addr.unwrap_or(IpAddr::V4(local_ipv4)),
                    _ if is_ebgp && !self.config.route_server_client => {
                        let Some(v6) = ebgp_ipv6_nh else {
                            warn!(
                                peer = %self.peer_label,
                                prefix = %route.prefix,
                                "cannot send IPv4 route with Extended Next Hop: no usable local IPv6 next-hop"
                            );
                            continue;
                        };
                        IpAddr::V6(v6)
                    }
                    _ => route.next_hop,
                };
                let entry = NlriEntry {
                    path_id: route.path_id,
                    prefix: route.prefix,
                };
                let link_local_next_hop = self.ipv4_mp_reach_link_local_next_hop(next_hop, route);
                let key = AttrGroupKey {
                    attrs_ptr: Arc::as_ptr(&attrs) as usize,
                    next_hop: Some(next_hop),
                    link_local_next_hop,
                };
                if let Some(&idx) = v4_group_index.get(&key) {
                    v4_groups[idx].prefixes.push(entry);
                } else {
                    v4_group_index.insert(key, v4_groups.len());
                    v4_groups.push(MpGroup {
                        attrs,
                        next_hop,
                        link_local_next_hop,
                        prefixes: vec![entry],
                    });
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for group in &v4_groups {
                let base_attrs = group.attrs.as_ref();
                let next_hop = group.next_hop;
                let link_local_next_hop = group.link_local_next_hop;
                if !self.send_v4_chunked(&group.prefixes, max_len, "announce", |chunk| {
                    let mut attrs = base_attrs.clone();
                    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        next_hop,
                        link_local_next_hop,
                        announced: chunk.to_vec(),
                        flowspec_announced: vec![],
                        evpn_announced: vec![],
                        bgpls_announced: vec![],
                        labeled_announced: vec![],
                        vpn_announced: vec![],
                        rtc_announced: vec![],
                    }));
                    UpdateMessage::build(
                        &[],
                        &[],
                        &attrs,
                        four_octet_as,
                        add_path_ipv4_send,
                        Ipv4UnicastMode::MpReach,
                    )
                }) {
                    return;
                }
            }
        } else if self.is_scoped_link_local_peer() {
            if !v4_routes.is_empty() {
                warn!(
                    peer = %self.peer_label,
                    "not sending IPv4 routes to scoped link-local peer without negotiated Extended Next Hop"
                );
            }
        } else {
            let mut v4_group_index: HashMap<AttrGroupKey, usize> = HashMap::default();
            let mut v4_groups: Vec<V4BodyGroup> = Vec::new();
            for (route, nh_override) in &v4_routes {
                let attrs = Arc::clone(
                    &self
                        .prepared_outbound_attributes_cached(
                            &mut prepared_attr_cache,
                            route,
                            is_ebgp,
                            local_ipv4,
                            *nh_override,
                        )
                        .with_next_hop,
                );
                if let Prefix::V4(v4) = route.prefix {
                    let entry = Ipv4NlriEntry {
                        path_id: route.path_id,
                        prefix: v4,
                    };
                    let key = AttrGroupKey {
                        attrs_ptr: Arc::as_ptr(&attrs) as usize,
                        next_hop: None,
                        link_local_next_hop: None,
                    };
                    if let Some(&idx) = v4_group_index.get(&key) {
                        v4_groups[idx].prefixes.push(entry);
                    } else {
                        v4_group_index.insert(key, v4_groups.len());
                        v4_groups.push(V4BodyGroup {
                            attrs,
                            prefixes: vec![entry],
                        });
                    }
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for group in &v4_groups {
                let attrs = group.attrs.as_ref();
                if !self.send_v4_chunked(&group.prefixes, max_len, "announce", |chunk| {
                    UpdateMessage::build(
                        chunk,
                        &[],
                        attrs,
                        four_octet_as,
                        add_path_ipv4_send,
                        Ipv4UnicastMode::Body,
                    )
                }) {
                    return;
                }
            }
        }
        // Resolve IPv6 eBGP next-hop: config override > socket address > suppress.
        // The RIB already filters unsendable families via sendable_families, so
        // v6_routes should be empty here for eBGP peers without a valid IPv6 NH.
        // The is_family_negotiated filter above is retained as a safety net.
        let ebgp_ipv6_nh: Option<Ipv6Addr> =
            Self::usable_ipv6_unicast_next_hop(self.config.local_ipv6_nexthop.or(local_ipv6));
        // Group by (attributes, next-hop) so routes with different next-hops
        // get separate UPDATEs with correct MP_REACH_NLRI next-hop values.
        let mut v6_group_index: HashMap<AttrGroupKey, usize> = HashMap::default();
        let mut v6_groups: Vec<MpGroup> = Vec::new();
        for (route, nh_override_ref) in &v6_routes {
            let nh_override = *nh_override_ref;
            let attrs = Arc::clone(
                &self
                    .prepared_outbound_attributes_cached(
                        &mut prepared_attr_cache,
                        route,
                        is_ebgp,
                        local_ipv4,
                        nh_override,
                    )
                    .with_next_hop,
            );
            let force_nh_self = matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
            let nh = if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = nh_override {
                // Policy explicitly set a next-hop — use it
                *addr
            } else if is_ebgp && !self.config.route_server_client {
                // Non-transparent eBGP uses next-hop-self unless policy set
                // an explicit next-hop. If no usable local IPv6 next-hop is
                // available, drop the route rather than advertising the peer's
                // original next-hop by mistake.
                let Some(v6) = ebgp_ipv6_nh else {
                    debug_assert!(
                        false,
                        "RIB sent IPv6 route to eBGP peer with no valid IPv6 next-hop and no explicit policy override"
                    );
                    warn!(
                        peer = %self.peer_label,
                        prefix = %route.prefix,
                        "dropping IPv6 route: no usable local IPv6 next-hop and no explicit export next-hop override"
                    );
                    continue;
                };
                IpAddr::V6(v6)
            } else if force_nh_self {
                // For next-hop-self on non-eBGP paths, use local IPv6 address
                // when available; otherwise leave the stored next-hop in place.
                if let Some(v6) = ebgp_ipv6_nh {
                    IpAddr::V6(v6)
                } else {
                    route.next_hop
                }
            } else {
                route.next_hop
            };
            let nlri_entry = NlriEntry {
                path_id: route.path_id,
                prefix: route.prefix,
            };
            let key = AttrGroupKey {
                attrs_ptr: Arc::as_ptr(&attrs) as usize,
                next_hop: Some(nh),
                link_local_next_hop: Self::route_link_local_next_hop_for_selected_primary(
                    nh, route,
                ),
            };
            if let Some(&idx) = v6_group_index.get(&key) {
                v6_groups[idx].prefixes.push(nlri_entry);
            } else {
                v6_group_index.insert(key, v6_groups.len());
                v6_groups.push(MpGroup {
                    attrs,
                    next_hop: nh,
                    link_local_next_hop: Self::route_link_local_next_hop_for_selected_primary(
                        nh, route,
                    ),
                    prefixes: vec![nlri_entry],
                });
            }
        }
        let max_len = usize::from(self.outbound_max_message_len());
        for group in &v6_groups {
            let base_attrs = group.attrs.as_ref();
            let next_hop = group.next_hop;
            let link_local_next_hop = group.link_local_next_hop;
            if !self.send_mp_chunked(
                &group.prefixes,
                max_len,
                "IPv6 unicast",
                "announcement",
                |chunk| {
                    let mut attrs = base_attrs.clone();
                    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        next_hop,
                        link_local_next_hop,
                        announced: chunk.to_vec(),
                        flowspec_announced: vec![],
                        evpn_announced: vec![],
                        bgpls_announced: vec![],
                        labeled_announced: vec![],
                        vpn_announced: vec![],
                        rtc_announced: vec![],
                    }));
                    UpdateMessage::try_build(
                        &[],
                        &[],
                        &attrs,
                        four_octet_as,
                        add_path_ipv6_send,
                        Ipv4UnicastMode::Body,
                    )
                },
            ) {
                return;
            }
        }
        // Send FlowSpec withdrawals via MP_UNREACH_NLRI, grouped by AFI
        if !update.flowspec_withdraw.is_empty() {
            let mut fs_withdrawals = [
                (Afi::Ipv4, Vec::<FlowSpecRule>::new()),
                (Afi::Ipv6, Vec::<FlowSpecRule>::new()),
            ];
            for key in &update.flowspec_withdraw {
                let Some((_, rules)) = fs_withdrawals.iter_mut().find(|(afi, _)| *afi == key.afi)
                else {
                    warn!(afi = ?key.afi, "ignoring FlowSpec withdrawal with non-IP AFI");
                    continue;
                };
                rules.push(key.rule.clone());
            }
            for (afi, rules) in fs_withdrawals {
                if rules.is_empty() {
                    continue;
                }
                let max_len = usize::from(self.outbound_max_message_len());
                if !self.send_mp_chunked(&rules, max_len, "FlowSpec", "withdrawal", |chunk| {
                    let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                        afi,
                        safi: Safi::FlowSpec,
                        withdrawn: vec![],
                        flowspec_withdrawn: chunk.to_vec(),
                        evpn_withdrawn: vec![],
                        bgpls_withdrawn: vec![],
                        labeled_withdrawn: vec![],
                        vpn_withdrawn: vec![],
                        rtc_withdrawn: vec![],
                    })];
                    UpdateMessage::try_build(
                        &[],
                        &[],
                        &attrs,
                        four_octet_as,
                        false,
                        Ipv4UnicastMode::Body,
                    )
                }) {
                    return;
                }
            }
        }
        // Send EVPN withdrawals via MP_UNREACH_NLRI, chunked so each UPDATE
        // fits the negotiated maximum message length (4096 / 65535 with
        // RFC 8654 Extended Messages). A bulk withdrawal of an entire fabric
        // can otherwise exceed the limit and `enqueue_bulk` returns
        // `MessageTooLong`, dropping the rest of the update.
        if !update.evpn_withdraw.is_empty() {
            let routes: Vec<EvpnRoute> = update
                .evpn_withdraw
                .iter()
                .map(|key| evpn_route_from_key(*key))
                .collect();
            let max_len = usize::from(self.outbound_max_message_len());
            if !self.send_evpn_unreach_chunked(&routes, four_octet_as, max_len) {
                return;
            }
        }
        // Send BGP-LS withdrawals via MP_UNREACH_NLRI, grouped by SAFI and
        // chunked so the RIB never commits a route that transport could not
        // enqueue.
        if !update.bgpls_withdraw.is_empty() {
            let mut base_routes = Vec::new();
            let mut vpn_routes = Vec::new();
            for key in &update.bgpls_withdraw {
                let nlri = bgpls_nlri_from_key(key);
                match key.family {
                    rustbgpd_rib::BgpLsFamily::LinkState
                        if self
                            .negotiated_families
                            .contains(&(Afi::BgpLs, Safi::BgpLs)) =>
                    {
                        base_routes.push(nlri);
                    }
                    rustbgpd_rib::BgpLsFamily::LinkStateVpn
                        if self
                            .negotiated_families
                            .contains(&(Afi::BgpLs, Safi::BgpLsVpn)) =>
                    {
                        vpn_routes.push(nlri);
                    }
                    _ => {}
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            if !base_routes.is_empty()
                && !self.send_bgpls_unreach_chunked(
                    Safi::BgpLs,
                    &base_routes,
                    four_octet_as,
                    max_len,
                )
            {
                return;
            }
            if !vpn_routes.is_empty()
                && !self.send_bgpls_unreach_chunked(
                    Safi::BgpLsVpn,
                    &vpn_routes,
                    four_octet_as,
                    max_len,
                )
            {
                return;
            }
        }
        // Send VPNv4/VPNv6 withdrawals via MP_UNREACH_NLRI, grouped by AFI
        // and chunked. RFC 8277 §2.4 withdraw-mode NLRI carries a 3-octet
        // compatibility field instead of a label stack, so the rebuilt NLRI
        // carries no labels (the withdraw encoder ignores them).
        if !update.vpn_withdraw.is_empty() {
            let mut v4_routes = Vec::new();
            let mut v6_routes = Vec::new();
            for key in &update.vpn_withdraw {
                let entry = rustbgpd_wire::VpnNlriEntry {
                    path_id: key.path_id,
                    nlri: rustbgpd_wire::VpnNlri {
                        labels: vec![],
                        route_distinguisher: key.nlri_key.route_distinguisher,
                        prefix: key.nlri_key.prefix,
                    },
                };
                let family = key.afi_safi();
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                match family.0 {
                    Afi::Ipv4 => v4_routes.push(entry),
                    Afi::Ipv6 => v6_routes.push(entry),
                    Afi::L2Vpn | Afi::BgpLs => {}
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (afi, routes, add_path) in [
                (Afi::Ipv4, v4_routes, add_path_vpnv4_send),
                (Afi::Ipv6, v6_routes, add_path_vpnv6_send),
            ] {
                if !routes.is_empty()
                    && !self.send_vpn_unreach_chunked(
                        afi,
                        &routes,
                        four_octet_as,
                        add_path,
                        max_len,
                    )
                {
                    return;
                }
            }
        }
        // Send labeled-unicast withdrawals via MP_UNREACH_NLRI, grouped by
        // AFI and chunked. RFC 8277 §2.4 withdraw-mode NLRI carries a
        // 3-octet compatibility field instead of a label stack, so the
        // rebuilt NLRI carries no labels (the withdraw encoder ignores
        // them).
        if !update.labeled_withdraw.is_empty() {
            let mut v4_routes = Vec::new();
            let mut v6_routes = Vec::new();
            for key in &update.labeled_withdraw {
                let entry = rustbgpd_wire::LabeledNlriEntry {
                    path_id: key.path_id,
                    nlri: rustbgpd_wire::LabeledNlri {
                        labels: vec![],
                        prefix: key.prefix,
                    },
                };
                let family = key.afi_safi();
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                match family.0 {
                    Afi::Ipv4 => v4_routes.push(entry),
                    Afi::Ipv6 => v6_routes.push(entry),
                    Afi::L2Vpn | Afi::BgpLs => {}
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (afi, routes, add_path) in [
                (Afi::Ipv4, v4_routes, add_path_labeled_v4_send),
                (Afi::Ipv6, v6_routes, add_path_labeled_v6_send),
            ] {
                if !routes.is_empty()
                    && !self.send_labeled_unreach_chunked(
                        afi,
                        &routes,
                        four_octet_as,
                        add_path,
                        max_len,
                    )
                {
                    return;
                }
            }
        }
        // Send RT-Constrain withdrawals via MP_UNREACH_NLRI. One codec for
        // both directions (RFC 4684 has no withdraw-mode split); single
        // family tuple (AFI 1 only).
        if !update.rtc_withdraw.is_empty()
            && self
                .negotiated_families
                .contains(&(Afi::Ipv4, Safi::RtConstrain))
        {
            let routes: Vec<rustbgpd_wire::RtcNlri> =
                update.rtc_withdraw.iter().map(|key| key.nlri).collect();
            let max_len = usize::from(self.outbound_max_message_len());
            if !self.send_rtc_unreach_chunked(&routes, four_octet_as, max_len) {
                return;
            }
        }
        // Send EVPN announcements via MP_REACH_NLRI, grouped by (next-hop, attributes)
        // and chunked so each UPDATE fits the negotiated maximum message length.
        if !update.evpn_announce.is_empty() {
            #[allow(
                clippy::type_complexity,
                reason = "EVPN UPDATE grouping keeps next-hop, attributes, and route batch identity explicit"
            )]
            let mut evpn_groups: Vec<(IpAddr, Vec<PathAttribute>, Vec<EvpnRoute>)> = Vec::new();
            for evpn_route in &update.evpn_announce {
                let attrs = self.prepare_outbound_attributes_evpn(evpn_route, is_ebgp);
                // Determine the next-hop for the reflected route. In RR mode
                // we preserve the originating VTEP's loopback as next-hop so
                // downstream VTEPs can build the VXLAN tunnel correctly.
                let nh = evpn_route.next_hop;
                if let Some(group) = evpn_groups
                    .iter_mut()
                    .find(|(g_nh, g_attrs, _)| *g_nh == nh && *g_attrs == attrs)
                {
                    group.2.push(evpn_route.route.clone());
                } else {
                    evpn_groups.push((nh, attrs, vec![evpn_route.route.clone()]));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (next_hop, attrs, routes) in evpn_groups {
                if !self.send_evpn_reach_chunked(next_hop, &attrs, &routes, four_octet_as, max_len)
                {
                    return;
                }
            }
        }
        // Send BGP-LS announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked.
        if !update.bgpls_announce.is_empty() {
            #[allow(
                clippy::type_complexity,
                reason = "BGP-LS UPDATE grouping keeps family, next-hop, attributes, and route batch identity explicit"
            )]
            let mut bgpls_groups: Vec<(
                rustbgpd_rib::BgpLsFamily,
                IpAddr,
                Vec<PathAttribute>,
                Vec<rustbgpd_wire::bgpls::BgpLsNlri>,
            )> = Vec::new();
            for bgpls_route in &update.bgpls_announce {
                let safi = bgpls_route.family.to_afi_safi().1;
                if !self.negotiated_families.contains(&(Afi::BgpLs, safi)) {
                    continue;
                }
                let attrs = self.prepare_outbound_attributes_bgpls(bgpls_route, is_ebgp);
                let nh = bgpls_route.next_hop;
                if let Some(group) = bgpls_groups.iter_mut().find(|(family, g_nh, g_attrs, _)| {
                    *family == bgpls_route.family && *g_nh == nh && *g_attrs == attrs
                }) {
                    group.3.push(bgpls_route.nlri.clone());
                } else {
                    bgpls_groups.push((
                        bgpls_route.family,
                        nh,
                        attrs,
                        vec![bgpls_route.nlri.clone()],
                    ));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (family, next_hop, attrs, routes) in bgpls_groups {
                if !self.send_bgpls_reach_chunked(
                    family.to_afi_safi().1,
                    next_hop,
                    &attrs,
                    &routes,
                    four_octet_as,
                    max_len,
                ) {
                    return;
                }
            }
        }
        // Send VPNv4/VPNv6 announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked. ADR-0077 §6: the
        // original NLRI (RD + MPLS label stack) and the stored VPN next-hop
        // pass through reflection verbatim.
        if !update.vpn_announce.is_empty() {
            #[allow(
                clippy::type_complexity,
                reason = "VPN UPDATE grouping keeps family, next-hop, attributes, and route batch identity explicit"
            )]
            let mut vpn_groups: Vec<(
                (Afi, Safi),
                IpAddr,
                Option<Ipv6Addr>,
                Vec<PathAttribute>,
                Vec<rustbgpd_wire::VpnNlriEntry>,
            )> = Vec::new();
            for vpn_route in &update.vpn_announce {
                let family = vpn_route.afi_safi();
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                let attrs = self.prepare_outbound_attributes_vpn(vpn_route, is_ebgp);
                let nh = vpn_route.next_hop;
                // RFC 4659 two-address IPv6 next-hop: the link-local half
                // is grouped alongside the global next-hop so it survives
                // reflection (LAN-217).
                let ll = vpn_route.link_local_next_hop;
                let entry = rustbgpd_wire::VpnNlriEntry {
                    path_id: vpn_route.path_id,
                    nlri: vpn_route.nlri.clone(),
                };
                if let Some(group) =
                    vpn_groups
                        .iter_mut()
                        .find(|(g_family, g_nh, g_ll, g_attrs, _)| {
                            *g_family == family && *g_nh == nh && *g_ll == ll && *g_attrs == attrs
                        })
                {
                    group.4.push(entry);
                } else {
                    vpn_groups.push((family, nh, ll, attrs, vec![entry]));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for ((afi, _), next_hop, link_local_next_hop, attrs, routes) in vpn_groups {
                let add_path = match afi {
                    Afi::Ipv4 => add_path_vpnv4_send,
                    _ => add_path_vpnv6_send,
                };
                if !self.send_vpn_reach_chunked(
                    afi,
                    next_hop,
                    link_local_next_hop,
                    &attrs,
                    &routes,
                    four_octet_as,
                    add_path,
                    max_len,
                ) {
                    return;
                }
            }
        }
        // Send labeled-unicast announcements via MP_REACH_NLRI, grouped by
        // (family, next-hop, attributes) and chunked. ADR-0077 §4/§6: the
        // stored MPLS label stack and next-hop pass through reflection
        // verbatim — transport never rewrites either.
        if !update.labeled_announce.is_empty() {
            #[allow(
                clippy::type_complexity,
                reason = "labeled UPDATE grouping keeps family, next-hop, attributes, and route batch identity explicit"
            )]
            let mut labeled_groups: Vec<(
                (Afi, Safi),
                IpAddr,
                Option<Ipv6Addr>,
                Vec<PathAttribute>,
                Vec<rustbgpd_wire::LabeledNlriEntry>,
            )> = Vec::new();
            for labeled_route in &update.labeled_announce {
                let family = labeled_route.afi_safi();
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                let attrs = self.prepare_outbound_attributes_labeled(labeled_route, is_ebgp);
                let nh = labeled_route.next_hop;
                // RFC 8950 two-address IPv6 next-hop: the link-local half
                // is grouped alongside the global next-hop so it survives
                // reflection (LAN-190).
                let ll = labeled_route.link_local_next_hop;
                let entry = rustbgpd_wire::LabeledNlriEntry {
                    path_id: labeled_route.path_id,
                    nlri: labeled_route.nlri.clone(),
                };
                if let Some(group) =
                    labeled_groups
                        .iter_mut()
                        .find(|(g_family, g_nh, g_ll, g_attrs, _)| {
                            *g_family == family && *g_nh == nh && *g_ll == ll && *g_attrs == attrs
                        })
                {
                    group.4.push(entry);
                } else {
                    labeled_groups.push((family, nh, ll, attrs, vec![entry]));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for ((afi, _), next_hop, link_local_next_hop, attrs, routes) in labeled_groups {
                let add_path = match afi {
                    Afi::Ipv4 => add_path_labeled_v4_send,
                    _ => add_path_labeled_v6_send,
                };
                if !self.send_labeled_reach_chunked(
                    afi,
                    next_hop,
                    link_local_next_hop,
                    &attrs,
                    &routes,
                    four_octet_as,
                    add_path,
                    max_len,
                ) {
                    return;
                }
            }
        }
        // Send RT-Constrain announcements via MP_REACH_NLRI, grouped by
        // (next-hop, attributes) and chunked. The stored next-hop passes
        // through reflection unchanged; the one exception is the locally-
        // originated default NLRI, whose next-hop is stored unspecified and
        // emitted as the session-local address (mirroring next-hop-self).
        if !update.rtc_announce.is_empty()
            && self
                .negotiated_families
                .contains(&(Afi::Ipv4, Safi::RtConstrain))
        {
            let mut rtc_groups: Vec<(IpAddr, Vec<PathAttribute>, Vec<rustbgpd_wire::RtcNlri>)> =
                Vec::new();
            for rtc_route in &update.rtc_announce {
                let attrs = self.prepare_outbound_attributes_rtc(rtc_route, is_ebgp);
                let nh = if rtc_route.next_hop.is_unspecified() {
                    local_addr.unwrap_or(IpAddr::V4(local_ipv4))
                } else {
                    rtc_route.next_hop
                };
                if let Some(group) = rtc_groups
                    .iter_mut()
                    .find(|(g_nh, g_attrs, _)| *g_nh == nh && *g_attrs == attrs)
                {
                    group.2.push(rtc_route.nlri);
                } else {
                    rtc_groups.push((nh, attrs, vec![rtc_route.nlri]));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (next_hop, attrs, routes) in rtc_groups {
                if !self.send_rtc_reach_chunked(next_hop, &attrs, &routes, four_octet_as, max_len) {
                    return;
                }
            }
        }
        // Send FlowSpec announcements via MP_REACH_NLRI, grouped by (AFI, attributes)
        if !update.flowspec_announce.is_empty() {
            let mut fs_groups: Vec<(Afi, Vec<PathAttribute>, Vec<FlowSpecRule>)> = Vec::new();
            for fs_route in &update.flowspec_announce {
                let attrs = self.prepare_outbound_attributes_flowspec(fs_route, is_ebgp);
                if let Some(group) = fs_groups
                    .iter_mut()
                    .find(|(a, ga, _)| *a == fs_route.afi && *ga == attrs)
                {
                    group.2.push(fs_route.rule.clone());
                } else {
                    fs_groups.push((fs_route.afi, attrs, vec![fs_route.rule.clone()]));
                }
            }
            let max_len = usize::from(self.outbound_max_message_len());
            for (afi, attrs, rules) in &fs_groups {
                if !self.send_mp_chunked(rules, max_len, "FlowSpec", "announcement", |chunk| {
                    let mut attrs = attrs.clone();
                    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                        afi: *afi,
                        safi: Safi::FlowSpec,
                        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // NH len = 0 for FlowSpec
                        link_local_next_hop: None,
                        announced: vec![],
                        flowspec_announced: chunk.to_vec(),
                        evpn_announced: vec![],
                        bgpls_announced: vec![],
                        labeled_announced: vec![],
                        vpn_announced: vec![],
                        rtc_announced: vec![],
                    }));
                    UpdateMessage::try_build(
                        &[],
                        &[],
                        &attrs,
                        four_octet_as,
                        false,
                        Ipv4UnicastMode::Body,
                    )
                }) {
                    return;
                }
            }
        }
        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::EoRR))
            {
                let msg = Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(
                    afi, safi, subtype,
                ));
                if let Err(e) = self.enqueue_bulk(&msg) {
                    warn!(
                        peer = %self.peer_label,
                        error = %e,
                        "failed to send End-of-RIB-Refresh"
                    );
                    return;
                }
                self.metrics
                    .record_message_sent(&self.peer_label, "route_refresh");
            }
        }
        // Send End-of-RIB markers
        for (afi, safi) in &update.end_of_rib {
            if peer_err
                && update
                    .refresh_markers
                    .iter()
                    .any(|(m_afi, m_safi, subtype)| {
                        *m_afi == *afi
                            && *m_safi == *safi
                            && matches!(
                                subtype,
                                RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR
                            )
                    })
            {
                continue;
            }
            let msg = if let (Afi::Ipv4, Safi::Unicast) = (afi, safi) {
                // IPv4 Unicast EoR: empty UPDATE (no NLRI, no withdrawn, no attrs)
                UpdateMessage::build(&[], &[], &[], four_octet_as, false, Ipv4UnicastMode::Body)
            } else {
                // MP EoR: UPDATE with empty MP_UNREACH_NLRI (IPv6 unicast, FlowSpec, etc.)
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi: *afi,
                    safi: *safi,
                    withdrawn: vec![],
                    flowspec_withdrawn: vec![],
                    evpn_withdrawn: vec![],
                    bgpls_withdrawn: vec![],
                    labeled_withdrawn: vec![],
                    vpn_withdrawn: vec![],
                    rtc_withdrawn: vec![],
                })];
                UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                )
            };
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send End-of-RIB for {afi:?}/{safi:?}");
                return;
            }
            info!(peer = %self.peer_label, afi = ?afi, safi = ?safi, "sent End-of-RIB");
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }
    }
    /// Split `entries` into as many wire UPDATEs as needed so each
    /// `build`-produced message fits `max_len`, enqueueing each in order.
    /// `UpdateMessage::build` emits one message regardless of size, so a large
    /// same-attribute IPv4 group (e.g. 1000 /24s ≈ 4114 bytes) exceeds the
    /// 4096-byte limit: `enqueue_bulk` rejects it and the session logs and
    /// abandons the rest of the batch, and — the actual defect — that partial
    /// delivery is never reported back across the RIB/session boundary, so the
    /// RIB believes the whole group was advertised. Chunking keeps every prefix
    /// on the wire. On overflow the chunk halves down to one entry; a lone
    /// entry that still cannot fit tears the session down (see below). `kind`
    /// names the traffic for the failure log. Returns false on a send failure
    /// so the caller stops. Used by all four IPv4-unicast paths (body/MP
    /// announce and withdrawal); the per-family helpers below follow the same
    /// shape.
    fn send_v4_chunked<E, F>(
        &mut self,
        entries: &[E],
        max_len: usize,
        kind: &'static str,
        mut build: F,
    ) -> bool
    where
        F: FnMut(&[E]) -> UpdateMessage,
    {
        // Optimistic starting chunk: aim to fill the negotiated message (4096,
        // or the 65535-byte Extended Message) rather than a fixed count, then
        // let the encoded_len() check and halving correct for attribute size,
        // variable prefix lengths, and Add-Path path-IDs. `max_len / 2` is a
        // probe, not an exact byte budget.
        let mut chunk_size: usize = entries.len().min(max_len / 2).max(1);
        let mut idx: usize = 0;
        while idx < entries.len() {
            let end = (idx + chunk_size).min(entries.len());
            let msg = build(&entries[idx..end]);
            let encoded_len = msg.encoded_len();
            if encoded_len > max_len {
                if chunk_size <= 1 {
                    // A single entry plus its attributes exceeds the negotiated
                    // maximum. The RIB has already committed this batch to
                    // logical Adj-RIB-Out and this local encode failure is
                    // invisible to the dirty/resync path, so just returning
                    // would leave the wire permanently behind the RIB with the
                    // session still Established. Tear the session down instead
                    // (matching the BGP-LS/VPN chunkers): reconnect rebuilds
                    // Adj-RIB-Out from scratch, so the peer is visibly unhealthy
                    // rather than falsely advertised. A route that is
                    // intrinsically un-sendable will loop until withdrawn; the
                    // durable fix is an exportability check before Adj-RIB-Out
                    // commit.
                    warn!(
                        peer = %self.peer_label,
                        size = encoded_len,
                        max = max_len,
                        "single IPv4 {kind} entry exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            if let Err(e) = self.enqueue_bulk(&Message::Update(msg)) {
                warn!(peer = %self.peer_label, error = %e, "failed to send IPv4 {kind} UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }

    /// Fallible size-aware sender for `MP_REACH/MP_UNREACH` families whose
    /// structured NLRI codec can reject an individual entry (notably
    /// `FlowSpec`). Both an encoded-size overflow and a structured-build error
    /// shrink a multi-entry probe. A single entry that still fails is the
    /// existing wire/RIB invariant breach: tear the session down so it cannot
    /// remain Established with logical Adj-RIB-Out ahead of the wire. LAN-361
    /// will move that single-entry decision before the RIB commit.
    fn send_mp_chunked<E, F>(
        &mut self,
        entries: &[E],
        max_len: usize,
        family: &'static str,
        kind: &'static str,
        mut build: F,
    ) -> bool
    where
        F: FnMut(&[E]) -> Result<UpdateMessage, rustbgpd_wire::EncodeError>,
    {
        let mut chunk_size = entries.len().min(max_len / 2).max(1);
        let mut idx = 0;
        while idx < entries.len() {
            let end = (idx + chunk_size).min(entries.len());
            let candidate = build(&entries[idx..end]);
            let needs_smaller = candidate
                .as_ref()
                .map_or(true, |message| message.encoded_len() > max_len);
            if needs_smaller {
                if chunk_size > 1 {
                    chunk_size = (chunk_size / 2).max(1);
                    continue;
                }
                match candidate {
                    Ok(message) => warn!(
                        peer = %self.peer_label,
                        size = message.encoded_len(),
                        max = max_len,
                        "single {family} {kind} exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    ),
                    Err(error) => warn!(
                        peer = %self.peer_label,
                        %error,
                        max = max_len,
                        "single {family} {kind} cannot be encoded — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    ),
                }
                self.trigger_outbound_saturation_teardown();
                return false;
            }
            let message = candidate.expect("successful MP build checked above");
            if let Err(error) = self.enqueue_bulk(&Message::Update(message)) {
                warn!(peer = %self.peer_label, %error, "failed to send {family} {kind} UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }

    /// Send a batch of EVPN announcements as one or more `MP_REACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    /// Starts with a generous chunk size and halves on `MessageTooLong`,
    /// down to a single route. Returns `false` on send error so the caller
    /// can abort the whole route batch the same way the unicast path does.
    fn send_evpn_reach_chunked(
        &mut self,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[EvpnRoute],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        // Initial chunk size: 1000 fits comfortably under the 65535-byte
        // Extended Messages limit even for Type 5/IPv6 routes (~60 B each)
        // and shrinks on overflow for the standard 4096-byte limit.
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let mut attrs = base_attrs.to_vec();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::L2Vpn,
                safi: Safi::Evpn,
                next_hop,
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: routes[idx..end].to_vec(),
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    // Single-route oversize: a single EVPN route plus its
                    // attribute set exceeds the negotiated maximum BGP
                    // message length. Previously the loop logged + skipped
                    // and continued, returning `true` — a silent desync
                    // because RIB has already committed the route to
                    // Adj-RIB-Out and now believes the peer holds it.
                    // Failing the send path lets the dirty-resync mechanism
                    // notice and retry; if the route is structurally
                    // un-sendable the peer will observe the discrepancy
                    // rather than rustbgpd lying about the advertise state.
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN route exceeds maximum message length — failing send so resync can retry"
                    );
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send EVPN announce UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of EVPN withdrawals as one or more `MP_UNREACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_evpn_unreach_chunked(
        &mut self,
        routes: &[EvpnRoute],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi: Afi::L2Vpn,
                safi: Safi::Evpn,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: routes[idx..end].to_vec(),
                bgpls_withdrawn: vec![],
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![],
                rtc_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN withdrawal exceeds maximum message length — failing send so resync can retry"
                    );
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send EVPN withdrawal UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of BGP-LS announcements as one or more `MP_REACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_bgpls_reach_chunked(
        &mut self,
        safi: Safi,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::bgpls::BgpLsNlri],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let mut attrs = base_attrs.to_vec();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::BgpLs,
                safi,
                next_hop,
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: routes[idx..end].to_vec(),
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single BGP-LS route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send BGP-LS announce UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of BGP-LS withdrawals as one or more `MP_UNREACH_NLRI`
    /// UPDATEs, splitting so each encoded message fits `max_len` bytes.
    fn send_bgpls_unreach_chunked(
        &mut self,
        safi: Safi,
        routes: &[rustbgpd_wire::bgpls::BgpLsNlri],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi: Afi::BgpLs,
                safi,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: routes[idx..end].to_vec(),
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![],
                rtc_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single BGP-LS withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send BGP-LS withdrawal UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of VPNv4/VPNv6 announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    ///
    /// The `MP_REACH_NLRI` next-hop is the route's stored VPN next-hop,
    /// preserved verbatim (ADR-0077 §6): SAFI 128 reflection never applies
    /// next-hop-self, so any next-hop-self behavior (policy override or eBGP
    /// default rewrite) is deliberately inert for this family — rewriting it
    /// would break the remote PE's transport-label resolution toward the
    /// originating PE.
    #[expect(
        clippy::too_many_arguments,
        reason = "VPN chunked sender adds the RFC 7911 add_path flag to the shared chunking shape"
    )]
    fn send_vpn_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::VpnNlriEntry],
        four_octet_as: bool,
        add_path: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let mut attrs = base_attrs.to_vec();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi,
                safi: Safi::MplsVpn,
                next_hop,
                link_local_next_hop,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: routes[idx..end].to_vec(),
                rtc_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single VPN route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send VPN announce UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of VPNv4/VPNv6 withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    fn send_vpn_unreach_chunked(
        &mut self,
        afi: Afi,
        routes: &[rustbgpd_wire::VpnNlriEntry],
        four_octet_as: bool,
        add_path: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi,
                safi: Safi::MplsVpn,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: vec![],
                labeled_withdrawn: vec![],
                vpn_withdrawn: routes[idx..end].to_vec(),
                rtc_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single VPN withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send VPN withdrawal UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of labeled-unicast announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. Mirrors the VPN sender minus the RD-prefixed
    /// next-hop (RFC 8277 uses the ordinary host next-hop forms).
    #[expect(
        clippy::too_many_arguments,
        reason = "chunked family senders keep family, next-hop, attrs, and Add-Path mode explicit"
    )]
    fn send_labeled_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        four_octet_as: bool,
        add_path: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let mut attrs = base_attrs.to_vec();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi,
                safi: Safi::LabeledUnicast,
                next_hop,
                link_local_next_hop,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                vpn_announced: vec![],
                labeled_announced: routes[idx..end].to_vec(),
                rtc_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single labeled route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send labeled announce UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of labeled-unicast withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. RFC 8277 §2.4: the withdraw encoder emits the
    /// 3-octet compatibility field, never a label stack.
    fn send_labeled_unreach_chunked(
        &mut self,
        afi: Afi,
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        four_octet_as: bool,
        add_path: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi,
                safi: Safi::LabeledUnicast,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: vec![],
                vpn_withdrawn: vec![],
                labeled_withdrawn: routes[idx..end].to_vec(),
                rtc_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single labeled withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send labeled withdrawal UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of RT-Constrain announcements as one or more
    /// `MP_REACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes. Mirrors the VPN sender minus label handling.
    fn send_rtc_reach_chunked(
        &mut self,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::RtcNlri],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let mut attrs = base_attrs.to_vec();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::RtConstrain,
                next_hop,
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: routes[idx..end].to_vec(),
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single RTC route exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send RTC announce UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Send a batch of RT-Constrain withdrawals as one or more
    /// `MP_UNREACH_NLRI` UPDATEs, splitting so each encoded message fits
    /// `max_len` bytes.
    fn send_rtc_unreach_chunked(
        &mut self,
        routes: &[rustbgpd_wire::RtcNlri],
        four_octet_as: bool,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi: Afi::Ipv4,
                safi: Safi::RtConstrain,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: vec![],
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![],
                rtc_withdrawn: routes[idx..end].to_vec(),
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                false,
                Ipv4UnicastMode::Body,
            );
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single RTC withdrawal exceeds maximum message length — sending Cease/Out-of-Resources and tearing down"
                    );
                    self.trigger_outbound_saturation_teardown();
                    return false;
                }
                chunk_size = (chunk_size / 2).max(1);
                continue;
            }
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.enqueue_bulk(&wire_msg) {
                warn!(peer = %self.peer_label, error = %e, "failed to send RTC withdrawal UPDATE");
                return false;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            idx = end;
        }
        true
    }
    /// Prepare path attributes for outbound advertisement.
    ///
    /// For standard eBGP: prepend our ASN, set `NEXT_HOP` to local addr, strip
    /// `LOCAL_PREF`. For route-server clients, preserve `AS_PATH` and
    /// `NEXT_HOP` by default. For iBGP: ensure `LOCAL_PREF` present (default
    /// 100), pass `NEXT_HOP` through.
    #[expect(
        clippy::too_many_lines,
        reason = "route-refresh helper keeps per-family replay and EoR emission ordering explicit"
    )]
    pub(super) fn prepare_outbound_attributes(
        &self,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Vec<PathAttribute> {
        let force_next_hop_self =
            matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
        let policy_set_specific = matches!(
            nh_override,
            Some(rustbgpd_policy::NextHopAction::Specific(_))
        );
        let route_server_client = self.config.route_server_client;
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !route_server_client => {
                    // Apply private AS removal before prepending our ASN
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    // Prepend our ASN
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
                            AsPathSegment::AsSequence(asns) => {
                                // Merge into first sequence if possible
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
                        // Policy explicitly set a next-hop — preserve it
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
                    // Strip LOCAL_PREF for eBGP
                }
                // Strip MP_REACH/MP_UNREACH — rebuilt per-UPDATE, not copied
                PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_) => {}
                // Strip ORIGINATOR_ID and CLUSTER_LIST on eBGP outbound
                // (optional non-transitive, must not leave the AS)
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => {
                    attrs.push(attr.clone());
                }
            }
        }
        // For iBGP, ensure LOCAL_PREF is present (default 100)
        if !is_ebgp
            && !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }
        if is_ebgp
            && matches!(
                self.config.peer.local_role,
                Some(BgpRole::Provider | BgpRole::Peer | BgpRole::RouteServer)
            )
            && !has_otc(&attrs)
        {
            attrs.push(PathAttribute::OnlyToCustomer(self.config.peer.local_asn));
        }
        // Ensure classic IPv4 body-NLRI exports carry a NEXT_HOP. This also
        // preserves the route's original next hop for transparent route-server
        // clients when the attribute was absent on the stored route.
        if matches!(route.prefix, Prefix::V4(_))
            && !attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_)))
        {
            let next_hop = match nh_override {
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(nh))) => Some(*nh),
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(_))) => {
                    // IPv6 next-hop is not encodable in classic IPv4 NEXT_HOP
                    // attribute. Requires RFC 8950 Extended Next Hop negotiation.
                    // Fall through to default next-hop selection.
                    tracing::warn!(
                        prefix = %route.prefix,
                        "export policy set IPv6 next-hop for classic IPv4 NLRI; \
                         requires Extended Next Hop (RFC 8950) — using default next-hop instead"
                    );
                    if is_ebgp && !route_server_client {
                        Some(local_ipv4)
                    } else {
                        match route.next_hop {
                            IpAddr::V4(nh) => Some(nh),
                            IpAddr::V6(_) => None,
                        }
                    }
                }
                Some(rustbgpd_policy::NextHopAction::Self_) => Some(local_ipv4),
                _ if is_ebgp && !route_server_client => Some(local_ipv4),
                _ => match route.next_hop {
                    IpAddr::V4(nh) => Some(nh),
                    IpAddr::V6(_) => None,
                },
            };
            if let Some(next_hop) = next_hop {
                attrs.push(PathAttribute::NextHop(next_hop));
            }
        }
        // For standard eBGP, ensure AS_PATH is present (even if empty).
        if is_ebgp
            && !route_server_client
            && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        // Route reflector attribute manipulation (RFC 4456 §8):
        // Only when reflecting an iBGP-learned route to an iBGP target do we
        // set ORIGINATOR_ID and prepend CLUSTER_LIST. Locally originated and
        // eBGP-learned routes are advertised normally and are not "reflected"
        // in the RFC 4456 sense.
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            // ORIGINATOR_ID: set to source peer's router-id if not already present
            if !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            // CLUSTER_LIST: prepend our cluster_id
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        let family = match route.prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, family, is_ebgp);
        attrs
    }
    /// Prepare path attributes for outbound `FlowSpec` advertisement.
    ///
    /// `FlowSpec` has no `NEXT_HOP`. For eBGP: prepend ASN, strip `LOCAL_PREF`.
    /// For iBGP: ensure `LOCAL_PREF`. Route reflector attributes handled same
    /// as unicast. Route-server clients skip automatic eBGP `AS_PATH` rewriting,
    /// matching transparent unicast behavior.
    pub(super) fn prepare_outbound_attributes_flowspec(
        &self,
        route: &FlowSpecRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in &route.attributes {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    // Apply private AS removal before prepending our ASN
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                // No NEXT_HOP for FlowSpec — skip; also skip MP framing attrs
                PathAttribute::NextHop(_)
                | PathAttribute::MpReachNlri(_)
                | PathAttribute::MpUnreachNlri(_) => {}
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => {
                    attrs.push(attr.clone());
                }
            }
        }
        if !is_ebgp
            && !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }
        if is_ebgp
            && !self.config.route_server_client
            && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        // Route reflector attribute manipulation for FlowSpec (same as unicast)
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, (route.afi, Safi::FlowSpec), is_ebgp);
        attrs
    }
    /// Prepare outbound attributes for a reflected EVPN route. Mirrors
    /// [`Self::prepare_outbound_attributes_flowspec`] — route reflectors
    /// don't rewrite the `NEXT_HOP` (that's what preserves the VTEP loopback
    /// for VXLAN tunnel construction), don't strip `LOCAL_PREF` across iBGP,
    /// and add `ORIGINATOR_ID` / `CLUSTER_LIST` per RFC 4456 when reflecting.
    pub(super) fn prepare_outbound_attributes_evpn(
        &self,
        route: &EvpnRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                // NEXT_HOP is carried in MP_REACH_NLRI for EVPN; strip the
                // legacy NEXT_HOP attribute if present. Strip MP framing too.
                PathAttribute::NextHop(_)
                | PathAttribute::MpReachNlri(_)
                | PathAttribute::MpUnreachNlri(_) => {}
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => {
                    attrs.push(attr.clone());
                }
            }
        }
        if !is_ebgp
            && !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }
        if is_ebgp
            && !self.config.route_server_client
            && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        // RFC 4456 RR attribute manipulation — ORIGINATOR_ID + CLUSTER_LIST
        // when reflecting iBGP routes.
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, (Afi::L2Vpn, Safi::Evpn), is_ebgp);
        attrs
    }
    /// Prepare outbound attributes for a reflected BGP-LS route. Mirrors
    /// EVPN/FlowSpec: `NEXT_HOP` and MP framing live in `MP_REACH_NLRI`, not in
    /// the attribute set, while RR attributes are added for iBGP reflection.
    pub(super) fn prepare_outbound_attributes_bgpls(
        &self,
        route: &BgpLsRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                _ => {
                    attrs.push(attr.clone());
                }
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
            && !self.config.route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, route.family.to_afi_safi(), is_ebgp);
        attrs
    }

    /// Prepare outbound attributes for a reflected VPNv4/VPNv6 route. Mirrors
    /// EVPN/BGP-LS: `NEXT_HOP` and MP framing live in `MP_REACH_NLRI`, not in
    /// the attribute set, while RR attributes are added for iBGP reflection.
    ///
    /// ADR-0077 §6: the VPN next-hop is never rewritten here — any
    /// next-hop-self configuration is deliberately inert for SAFI 128, since
    /// the reflected next-hop must stay the originating PE for transport-label
    /// resolution. Route Targets ride through untouched as extended
    /// communities in the generic pass-through arm.
    pub(super) fn prepare_outbound_attributes_vpn(
        &self,
        route: &VpnRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                _ => {
                    attrs.push(attr.clone());
                }
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
            && !self.config.route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, route.afi_safi(), is_ebgp);
        attrs
    }

    /// Prepare outbound attributes for a reflected labeled-unicast route.
    /// Mirrors the VPN version: RFC 4456 `ORIGINATOR_ID`/`CLUSTER_LIST`
    /// reflection semantics are identical, and the next-hop lives in
    /// `MP_REACH_NLRI` (chosen by the caller), never in the attribute set.
    ///
    /// ADR-0077 §4/§6: the labeled next-hop is never rewritten here — any
    /// next-hop-self configuration is deliberately inert for SAFI 4, since
    /// the reflected next-hop must stay the originating speaker for
    /// transport-label resolution. The MPLS label stack rides in the NLRI
    /// and passes through verbatim.
    pub(super) fn prepare_outbound_attributes_labeled(
        &self,
        route: &LabeledRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                _ => {
                    attrs.push(attr.clone());
                }
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
            && !self.config.route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, route.afi_safi(), is_ebgp);
        attrs
    }

    /// Prepare outbound attributes for a reflected RT-Constrain route.
    /// Mirrors the VPN version: RFC 4456 `ORIGINATOR_ID`/`CLUSTER_LIST`
    /// reflection semantics are identical, and the next-hop lives in
    /// `MP_REACH_NLRI` (chosen by the caller), never in the attribute set.
    pub(super) fn prepare_outbound_attributes_rtc(
        &self,
        route: &RtcRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();
        for attr in route.attributes.iter() {
            match attr {
                PathAttribute::AsPath(as_path) if is_ebgp && !self.config.route_server_client => {
                    let cleaned = remove_private_asns(
                        as_path,
                        self.config.remove_private_as,
                        self.config.peer.local_asn,
                    );
                    let mut new_segments =
                        vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                    for seg in &cleaned.segments {
                        match seg {
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
                _ => {
                    attrs.push(attr.clone());
                }
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
            && !self.config.route_server_client
            && !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|attr| matches!(attr, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }
        self.attach_graceful_shutdown_if_enabled(&mut attrs);
        self.apply_llgr_stale_export_form(&mut attrs, route.afi_safi(), is_ebgp);
        attrs
    }
}
/// Build a BGP-LS NLRI from an Adj-RIB-Out key, used when emitting
/// `MP_UNREACH_NLRI` withdrawals. The key stores the opaque bytes required by
/// RFC 9552, including the optional VPN Route Distinguisher.
fn bgpls_nlri_from_key(key: &BgpLsRouteKey) -> rustbgpd_wire::bgpls::BgpLsNlri {
    rustbgpd_wire::bgpls::BgpLsNlri {
        nlri_type: key.nlri.nlri_type,
        route_distinguisher: key.nlri.route_distinguisher,
        payload: key.nlri.payload.clone(),
    }
}
/// Build a minimal `EvpnRoute` from a key, used when emitting `MP_UNREACH_NLRI`
/// withdrawals. The receiver identifies the route by its key fields; any
/// labels / optional fields the key doesn't capture are zeroed.
fn evpn_route_from_key(key: EvpnRouteKey) -> EvpnRoute {
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
/// Remove private ASNs from an `AS_PATH` according to the given mode.
///
/// - `Remove` — strip all ASNs only if every ASN in the path is private.
/// - `All` — unconditionally remove all private ASNs; drop empty segments.
/// - `Replace` — replace each private ASN with `local_asn`.
/// - `Disabled` — return the path unchanged.
pub(super) fn remove_private_asns(
    as_path: &AsPath,
    mode: RemovePrivateAs,
    local_asn: u32,
) -> AsPath {
    match mode {
        RemovePrivateAs::Disabled => as_path.clone(),
        RemovePrivateAs::Remove => {
            if as_path.all_private() {
                // Strip all private ASNs (produces empty path)
                let segments: Vec<_> = as_path
                    .segments
                    .iter()
                    .filter_map(|seg| {
                        let filtered: Vec<u32> = match seg {
                            AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns
                                .iter()
                                .copied()
                                .filter(|a| !is_private_asn(*a))
                                .collect(),
                        };
                        if filtered.is_empty() {
                            None
                        } else {
                            Some(match seg {
                                AsPathSegment::AsSequence(_) => AsPathSegment::AsSequence(filtered),
                                AsPathSegment::AsSet(_) => AsPathSegment::AsSet(filtered),
                            })
                        }
                    })
                    .collect();
                AsPath { segments }
            } else {
                as_path.clone()
            }
        }
        RemovePrivateAs::All => {
            let segments: Vec<_> = as_path
                .segments
                .iter()
                .filter_map(|seg| {
                    let filtered: Vec<u32> = match seg {
                        AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns
                            .iter()
                            .copied()
                            .filter(|a| !is_private_asn(*a))
                            .collect(),
                    };
                    if filtered.is_empty() {
                        None
                    } else {
                        Some(match seg {
                            AsPathSegment::AsSequence(_) => AsPathSegment::AsSequence(filtered),
                            AsPathSegment::AsSet(_) => AsPathSegment::AsSet(filtered),
                        })
                    }
                })
                .collect();
            AsPath { segments }
        }
        RemovePrivateAs::Replace => {
            let segments = as_path
                .segments
                .iter()
                .map(|seg| match seg {
                    AsPathSegment::AsSequence(asns) => AsPathSegment::AsSequence(
                        asns.iter()
                            .map(|a| if is_private_asn(*a) { local_asn } else { *a })
                            .collect(),
                    ),
                    AsPathSegment::AsSet(asns) => AsPathSegment::AsSet(
                        asns.iter()
                            .map(|a| if is_private_asn(*a) { local_asn } else { *a })
                            .collect(),
                    ),
                })
                .collect();
            AsPath { segments }
        }
    }
}
