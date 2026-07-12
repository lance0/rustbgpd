use super::export::{
    ExportWithdrawal, PreparedUnicastAttributes, PreparedUnicastCandidate, PreparedWithdrawal,
    ReachNlri, SessionExportProfile, UnreachNlri, has_otc,
};
use super::{
    Afi, BgpRole, EvpnRoute, FlowSpecRule, IpAddr, Ipv4Addr, Ipv4NlriEntry, Ipv4UnicastMode,
    Ipv6Addr, Message, NlriEntry, OutboundRouteUpdate, PathAttribute, PeerSession, Prefix, Route,
    RouteRefreshMessage, RouteRefreshSubtype, Safi, UpdateMessage, debug, info, warn,
};
#[cfg(test)]
use super::{FlowSpecRoute, LabeledRibRoute, RtcRibRoute, VpnRibRoute};
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
        profile: &'a SessionExportProfile,
        cache: &'a mut HashMap<PreparedAttrCacheKey, PreparedUnicastAttributes>,
        route: &Route,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> &'a PreparedUnicastAttributes {
        let is_ebgp = profile.is_ebgp();
        let key = Self::prepared_attr_cache_key(route, is_ebgp, local_ipv4, nh_override);
        cache.entry(key).or_insert_with(|| {
            profile.prepare_unicast_attribute_bundle(route, local_ipv4, nh_override)
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
        // Production only reads the profile published by lifecycle/runtime
        // seams, so its generation remains stable between real changes.
        #[cfg(test)]
        self.publish_export_profile();
        let export = self.export_encoder.snapshot();
        for route in &update.otc_blocked {
            self.record_otc_egress_block(route);
        }
        let peer_err = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_enhanced_route_refresh);
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
        let use_extended_nexthop_ipv4 = export.use_extended_nexthop_ipv4();
        let local_ipv4 = export.local_ipv4();
        let mut prepared_attr_cache: HashMap<PreparedAttrCacheKey, PreparedUnicastAttributes> =
            HashMap::default();
        // Split withdrawals by address family, filtering by negotiated families
        let mut v4_body_withdraw: Vec<Ipv4NlriEntry> = Vec::new();
        let mut v4_mp_withdraw: Vec<NlriEntry> = Vec::new();
        let mut v4_mp_wire = None;
        let mut v6_withdraw: Vec<NlriEntry> = Vec::new();
        let mut v6_wire = None;
        for &(ref prefix, path_id) in &update.withdraw {
            if !self.is_family_negotiated(prefix) {
                continue;
            }
            match export.prepare_withdrawal(ExportWithdrawal::Unicast {
                prefix: *prefix,
                path_id,
            }) {
                Ok(PreparedWithdrawal::Ipv4Body(entry)) => v4_body_withdraw.push(entry),
                Ok(PreparedWithdrawal::Unicast(prepared)) => {
                    let wire = (prepared.afi, prepared.safi, prepared.ipv4_mode);
                    if prepared.afi == Afi::Ipv4 {
                        v4_mp_wire = Some(wire);
                        v4_mp_withdraw.push(prepared.nlri);
                    } else {
                        v6_wire = Some(wire);
                        v6_withdraw.push(prepared.nlri);
                    }
                }
                Ok(_) => unreachable!("unicast withdrawal must prepare as unicast"),
                Err(error) => warn!(
                    peer = %self.peer_label,
                    %prefix,
                    %error,
                    "not sending unicast withdrawal: exact export preparation failed"
                ),
            }
        }
        if !v4_body_withdraw.is_empty() {
            let max_len = export.max_message_len();
            if !self.send_v4_chunked(&v4_body_withdraw, max_len, "withdraw", |chunk| {
                export
                    .build_ipv4_body(&[], chunk, &[])
                    .expect("IPv4 body withdrawal construction was previously infallible")
            }) {
                return;
            }
        }
        if let Some((afi, safi, ipv4_mode)) = v4_mp_wire {
            let max_len = export.max_message_len();
            if !self.send_mp_chunked(
                &v4_mp_withdraw,
                max_len,
                "IPv4 unicast",
                "withdrawal",
                |chunk| export.build_mp_unreach(afi, safi, UnreachNlri::Unicast(chunk), ipv4_mode),
            ) {
                return;
            }
        }
        // Send IPv6 withdrawals via `MP_UNREACH_NLRI`, chunked to the
        // negotiated message ceiling just like IPv4. A large Add-Path
        // withdrawal set must not be handed to `enqueue_bulk` as one
        // oversized message after the RIB has already committed it.
        if let Some((afi, safi, ipv4_mode)) = v6_wire {
            let max_len = export.max_message_len();
            if !self.send_mp_chunked(
                &v6_withdraw,
                max_len,
                "IPv6 unicast",
                "withdrawal",
                |chunk| export.build_mp_unreach(afi, safi, UnreachNlri::Unicast(chunk), ipv4_mode),
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
            let mut v4_group_index: HashMap<AttrGroupKey, usize> = HashMap::default();
            let mut v4_groups: Vec<MpGroup> = Vec::new();
            for (route, nh_override_ref) in &v4_routes {
                let nh_override = *nh_override_ref;
                let cached_attrs = Self::prepared_outbound_attributes_cached(
                    &export,
                    &mut prepared_attr_cache,
                    route,
                    local_ipv4,
                    nh_override,
                )
                .clone();
                let prepared =
                    match export.finish_unicast_candidate(route, nh_override, cached_attrs) {
                        Ok(PreparedUnicastCandidate::Mp {
                            next_hop,
                            link_local_next_hop,
                            attrs,
                            entry,
                            ..
                        }) => (attrs, next_hop, link_local_next_hop, entry),
                        Ok(PreparedUnicastCandidate::Ipv4Body { .. }) => {
                            unreachable!("ENHE profile must prepare IPv4 as MP_REACH")
                        }
                        Err(error) => {
                            warn!(
                                peer = %self.peer_label,
                                prefix = %route.prefix,
                                %error,
                                "cannot prepare IPv4 route with Extended Next Hop"
                            );
                            continue;
                        }
                    };
                let (attrs, next_hop, link_local_next_hop, entry) = prepared;
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
            let max_len = export.max_message_len();
            for group in &v4_groups {
                let base_attrs = group.attrs.as_ref();
                let next_hop = group.next_hop;
                let link_local_next_hop = group.link_local_next_hop;
                if !self.send_v4_chunked(&group.prefixes, max_len, "announce", |chunk| {
                    export
                        .build_mp_reach(
                            Afi::Ipv4,
                            Safi::Unicast,
                            next_hop,
                            link_local_next_hop,
                            base_attrs,
                            ReachNlri::Unicast(chunk),
                            Ipv4UnicastMode::MpReach,
                        )
                        .expect("IPv4 MP_REACH construction was previously infallible")
                }) {
                    return;
                }
            }
        } else if export.is_scoped_link_local_peer() {
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
                let cached_attrs = Self::prepared_outbound_attributes_cached(
                    &export,
                    &mut prepared_attr_cache,
                    route,
                    local_ipv4,
                    *nh_override,
                )
                .clone();
                if let Ok(PreparedUnicastCandidate::Ipv4Body { attrs, entry }) =
                    export.finish_unicast_candidate(route, *nh_override, cached_attrs)
                {
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
            let max_len = export.max_message_len();
            for group in &v4_groups {
                let attrs = group.attrs.as_ref();
                if !self.send_v4_chunked(&group.prefixes, max_len, "announce", |chunk| {
                    export
                        .build_ipv4_body(chunk, &[], attrs)
                        .expect("IPv4 body announcement construction was previously infallible")
                }) {
                    return;
                }
            }
        }
        // Resolve IPv6 eBGP next-hop: config override > socket address > suppress.
        // The RIB already filters unsendable families via sendable_families, so
        // v6_routes should be empty here for eBGP peers without a valid IPv6 NH.
        // The is_family_negotiated filter above is retained as a safety net.
        // Group by (attributes, next-hop) so routes with different next-hops
        // get separate UPDATEs with correct MP_REACH_NLRI next-hop values.
        let mut v6_group_index: HashMap<AttrGroupKey, usize> = HashMap::default();
        let mut v6_groups: Vec<MpGroup> = Vec::new();
        for (route, nh_override_ref) in &v6_routes {
            let nh_override = *nh_override_ref;
            let cached_attrs = Self::prepared_outbound_attributes_cached(
                &export,
                &mut prepared_attr_cache,
                route,
                local_ipv4,
                nh_override,
            )
            .clone();
            let prepared = match export.finish_unicast_candidate(route, nh_override, cached_attrs) {
                Ok(PreparedUnicastCandidate::Mp {
                    next_hop,
                    link_local_next_hop,
                    attrs,
                    entry,
                    ..
                }) => (attrs, next_hop, link_local_next_hop, entry),
                Ok(PreparedUnicastCandidate::Ipv4Body { .. }) => {
                    unreachable!("IPv6 must prepare as MP_REACH")
                }
                Err(error) => {
                    warn!(
                        peer = %self.peer_label,
                        prefix = %route.prefix,
                        %error,
                        "dropping IPv6 route: exact export preparation failed"
                    );
                    continue;
                }
            };
            let (attrs, nh, link_local_next_hop, nlri_entry) = prepared;
            let key = AttrGroupKey {
                attrs_ptr: Arc::as_ptr(&attrs) as usize,
                next_hop: Some(nh),
                link_local_next_hop,
            };
            if let Some(&idx) = v6_group_index.get(&key) {
                v6_groups[idx].prefixes.push(nlri_entry);
            } else {
                v6_group_index.insert(key, v6_groups.len());
                v6_groups.push(MpGroup {
                    attrs,
                    next_hop: nh,
                    link_local_next_hop,
                    prefixes: vec![nlri_entry],
                });
            }
        }
        let max_len = export.max_message_len();
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
                    export.build_mp_reach(
                        Afi::Ipv6,
                        Safi::Unicast,
                        next_hop,
                        link_local_next_hop,
                        base_attrs,
                        ReachNlri::Unicast(chunk),
                        Ipv4UnicastMode::Body,
                    )
                },
            ) {
                return;
            }
        }
        // Send FlowSpec withdrawals via MP_UNREACH_NLRI, grouped by AFI
        if !update.flowspec_withdraw.is_empty() {
            type FlowSpecWithdrawalGroup = Option<(Afi, Safi, Ipv4UnicastMode, Vec<FlowSpecRule>)>;
            // Preserve the established deterministic wire order: IPv4, then IPv6.
            let mut fs_withdrawals: [FlowSpecWithdrawalGroup; 2] = [None, None];
            for key in &update.flowspec_withdraw {
                let PreparedWithdrawal::FlowSpec(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::FlowSpec(key))
                    .expect("FlowSpec withdrawal preparation is infallible")
                else {
                    unreachable!("FlowSpec key must prepare as FlowSpec")
                };
                let slot = match prepared.afi {
                    Afi::Ipv4 => &mut fs_withdrawals[0],
                    Afi::Ipv6 => &mut fs_withdrawals[1],
                    Afi::L2Vpn | Afi::BgpLs => {
                        warn!(afi = ?prepared.afi, "ignoring FlowSpec withdrawal with non-IP AFI");
                        continue;
                    }
                };
                if let Some((_, _, _, rules)) = slot {
                    rules.push(prepared.nlri);
                } else {
                    *slot = Some((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                    ));
                }
            }
            for (afi, safi, ipv4_mode, rules) in fs_withdrawals.into_iter().flatten() {
                let max_len = export.max_message_len();
                if !self.send_mp_chunked(&rules, max_len, "FlowSpec", "withdrawal", |chunk| {
                    export.build_mp_unreach(afi, safi, UnreachNlri::FlowSpec(chunk), ipv4_mode)
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
            let mut routes = Vec::with_capacity(update.evpn_withdraw.len());
            let mut wire = None;
            for key in &update.evpn_withdraw {
                let PreparedWithdrawal::Evpn(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Evpn(key))
                    .expect("EVPN withdrawal preparation is infallible")
                else {
                    unreachable!("EVPN key must prepare as EVPN")
                };
                wire = Some((prepared.afi, prepared.safi, prepared.ipv4_mode));
                routes.push(prepared.nlri);
            }
            let max_len = export.max_message_len();
            let (afi, safi, ipv4_mode) = wire.expect("non-empty EVPN withdrawal batch");
            if !self.send_evpn_unreach_chunked(&export, afi, safi, ipv4_mode, &routes, max_len) {
                return;
            }
        }
        // Send BGP-LS withdrawals via MP_UNREACH_NLRI, grouped by SAFI and
        // chunked so the RIB never commits a route that transport could not
        // enqueue.
        if !update.bgpls_withdraw.is_empty() {
            let mut groups = Vec::<(
                Afi,
                Safi,
                Ipv4UnicastMode,
                Vec<rustbgpd_wire::bgpls::BgpLsNlri>,
            )>::new();
            for key in &update.bgpls_withdraw {
                let PreparedWithdrawal::BgpLs(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::BgpLs(key))
                    .expect("BGP-LS withdrawal preparation is infallible")
                else {
                    unreachable!("BGP-LS key must prepare as BGP-LS")
                };
                if !self
                    .negotiated_families
                    .contains(&(prepared.afi, prepared.safi))
                {
                    continue;
                }
                if let Some((_, _, _, routes)) = groups.iter_mut().find(|(afi, safi, mode, _)| {
                    (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                }) {
                    routes.push(prepared.nlri);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(_, safi, _, _)| match safi {
                Safi::BgpLs => 0,
                Safi::BgpLsVpn => 1,
                _ => 2,
            });
            for (afi, safi, ipv4_mode, routes) in groups {
                if !self.send_bgpls_unreach_chunked(afi, safi, ipv4_mode, &routes, &export, max_len)
                {
                    return;
                }
            }
        }
        // Send VPNv4/VPNv6 withdrawals via MP_UNREACH_NLRI, grouped by AFI
        // and chunked. RFC 8277 §2.4 withdraw-mode NLRI carries a 3-octet
        // compatibility field instead of a label stack, so the rebuilt NLRI
        // carries no labels (the withdraw encoder ignores them).
        if !update.vpn_withdraw.is_empty() {
            let mut groups =
                Vec::<(Afi, Safi, Ipv4UnicastMode, Vec<rustbgpd_wire::VpnNlriEntry>)>::new();
            for key in &update.vpn_withdraw {
                let PreparedWithdrawal::Vpn(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Vpn(key))
                    .expect("VPN withdrawal preparation is infallible")
                else {
                    unreachable!("VPN key must prepare as VPN")
                };
                let family = (prepared.afi, prepared.safi);
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                if let Some((_, _, _, routes)) = groups.iter_mut().find(|(afi, safi, mode, _)| {
                    (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                }) {
                    routes.push(prepared.nlri);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(afi, _, _, _)| match afi {
                Afi::Ipv4 => 0,
                Afi::Ipv6 => 1,
                Afi::L2Vpn | Afi::BgpLs => 2,
            });
            for (afi, safi, ipv4_mode, routes) in groups {
                if !self.send_vpn_unreach_chunked(afi, safi, ipv4_mode, &routes, &export, max_len) {
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
            let mut groups = Vec::<(
                Afi,
                Safi,
                Ipv4UnicastMode,
                Vec<rustbgpd_wire::LabeledNlriEntry>,
            )>::new();
            for key in &update.labeled_withdraw {
                let PreparedWithdrawal::Labeled(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Labeled(key))
                    .expect("labeled withdrawal preparation is infallible")
                else {
                    unreachable!("labeled key must prepare as labeled unicast")
                };
                let family = (prepared.afi, prepared.safi);
                if !self.negotiated_families.contains(&family) {
                    continue;
                }
                if let Some((_, _, _, routes)) = groups.iter_mut().find(|(afi, safi, mode, _)| {
                    (*afi, *safi, *mode) == (prepared.afi, prepared.safi, prepared.ipv4_mode)
                }) {
                    routes.push(prepared.nlri);
                } else {
                    groups.push((
                        prepared.afi,
                        prepared.safi,
                        prepared.ipv4_mode,
                        vec![prepared.nlri],
                    ));
                }
            }
            let max_len = export.max_message_len();
            groups.sort_by_key(|(afi, _, _, _)| match afi {
                Afi::Ipv4 => 0,
                Afi::Ipv6 => 1,
                Afi::L2Vpn | Afi::BgpLs => 2,
            });
            for (afi, safi, ipv4_mode, routes) in groups {
                if !self
                    .send_labeled_unreach_chunked(afi, safi, ipv4_mode, &routes, &export, max_len)
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
            let mut routes = Vec::with_capacity(update.rtc_withdraw.len());
            let mut wire = None;
            for key in &update.rtc_withdraw {
                let PreparedWithdrawal::Rtc(prepared) = export
                    .prepare_withdrawal(ExportWithdrawal::Rtc(key))
                    .expect("RTC withdrawal preparation is infallible")
                else {
                    unreachable!("RTC key must prepare as RTC")
                };
                wire = Some((prepared.afi, prepared.safi, prepared.ipv4_mode));
                routes.push(prepared.nlri);
            }
            let max_len = export.max_message_len();
            let (afi, safi, ipv4_mode) = wire.expect("non-empty RTC withdrawal batch");
            if !self.send_rtc_unreach_chunked(&export, afi, safi, ipv4_mode, &routes, max_len) {
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
                let prepared = export.prepare_evpn_candidate(evpn_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                if let Some(group) = evpn_groups
                    .iter_mut()
                    .find(|(g_nh, g_attrs, _)| *g_nh == nh && *g_attrs == attrs)
                {
                    group.2.push(prepared.nlri);
                } else {
                    evpn_groups.push((nh, attrs, vec![prepared.nlri]));
                }
            }
            let max_len = export.max_message_len();
            for (next_hop, attrs, routes) in evpn_groups {
                if !self.send_evpn_reach_chunked(&export, next_hop, &attrs, &routes, max_len) {
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
                let prepared = export.prepare_bgpls_candidate(bgpls_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                if let Some(group) = bgpls_groups.iter_mut().find(|(family, g_nh, g_attrs, _)| {
                    *family == bgpls_route.family && *g_nh == nh && *g_attrs == attrs
                }) {
                    group.3.push(prepared.nlri);
                } else {
                    bgpls_groups.push((bgpls_route.family, nh, attrs, vec![prepared.nlri]));
                }
            }
            let max_len = export.max_message_len();
            for (family, next_hop, attrs, routes) in bgpls_groups {
                if !self.send_bgpls_reach_chunked(
                    family.to_afi_safi().1,
                    next_hop,
                    &attrs,
                    &routes,
                    &export,
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
                let prepared = export.prepare_vpn_candidate(vpn_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                let ll = prepared.link_local_next_hop;
                let entry = prepared.nlri;
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
            let max_len = export.max_message_len();
            for ((afi, _), next_hop, link_local_next_hop, attrs, routes) in vpn_groups {
                if !self.send_vpn_reach_chunked(
                    afi,
                    next_hop,
                    link_local_next_hop,
                    &attrs,
                    &routes,
                    &export,
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
                let prepared = export.prepare_labeled_candidate(labeled_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                let ll = prepared.link_local_next_hop;
                let entry = prepared.nlri;
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
            let max_len = export.max_message_len();
            for ((afi, _), next_hop, link_local_next_hop, attrs, routes) in labeled_groups {
                if !self.send_labeled_reach_chunked(
                    afi,
                    next_hop,
                    link_local_next_hop,
                    &attrs,
                    &routes,
                    &export,
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
                let prepared = export.prepare_rtc_candidate(rtc_route);
                let attrs = prepared.attrs;
                let nh = prepared.next_hop;
                if let Some(group) = rtc_groups
                    .iter_mut()
                    .find(|(g_nh, g_attrs, _)| *g_nh == nh && *g_attrs == attrs)
                {
                    group.2.push(prepared.nlri);
                } else {
                    rtc_groups.push((nh, attrs, vec![prepared.nlri]));
                }
            }
            let max_len = export.max_message_len();
            for (next_hop, attrs, routes) in rtc_groups {
                if !self.send_rtc_reach_chunked(&export, next_hop, &attrs, &routes, max_len) {
                    return;
                }
            }
        }
        // Send FlowSpec announcements via MP_REACH_NLRI, grouped by (AFI, attributes)
        if !update.flowspec_announce.is_empty() {
            let mut fs_groups: Vec<(Afi, Vec<PathAttribute>, Vec<FlowSpecRule>)> = Vec::new();
            for fs_route in &update.flowspec_announce {
                let prepared = export.prepare_flowspec_candidate(fs_route);
                let attrs = prepared.attrs;
                if let Some(group) = fs_groups
                    .iter_mut()
                    .find(|(a, ga, _)| *a == prepared.afi && *ga == attrs)
                {
                    group.2.push(prepared.nlri);
                } else {
                    fs_groups.push((prepared.afi, attrs, vec![prepared.nlri]));
                }
            }
            let max_len = export.max_message_len();
            for (afi, attrs, rules) in &fs_groups {
                if !self.send_mp_chunked(rules, max_len, "FlowSpec", "announcement", |chunk| {
                    export.build_mp_reach(
                        *afi,
                        Safi::FlowSpec,
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        None,
                        attrs,
                        ReachNlri::FlowSpec(chunk),
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
            let msg = export
                .build_end_of_rib(*afi, *safi)
                .expect("empty End-of-RIB construction is infallible");
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
    /// The exact profile builder emits one message regardless of size, so a large
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
        // `max_len` is a byte budget, not an entry count. Keep every
        // clone/encode probe bounded even when Extended Messages are
        // negotiated, but grow beyond the conservative first 1,024 entries
        // after an exact build proves that candidate fits. Remember the
        // successful lower and failed upper bounds: after 1,024 succeeds and
        // 2,048 fails, for example, probe 1,536, then binary-search between
        // the proven bounds rather than retrying 2,048 or regressing below
        // 1,024. Exact build/length checks still guard every enqueue.
        const MAX_PROBE_ENTRIES: usize = 4096;
        let mut chunk_size = entries.len().clamp(1, 1024);
        let max_probe = entries.len().clamp(1, MAX_PROBE_ENTRIES);
        let mut successful_lower: usize = 0;
        let mut failed_upper: Option<usize> = None;
        let mut idx = 0;
        while idx < entries.len() {
            let end = (idx + chunk_size).min(entries.len());
            let probe_size = end - idx;
            let candidate = build(&entries[idx..end]);
            let needs_smaller = candidate
                .as_ref()
                .map_or(true, |message| message.encoded_len() > max_len);
            if needs_smaller {
                if probe_size > 1 {
                    failed_upper =
                        Some(failed_upper.map_or(probe_size, |upper| upper.min(probe_size)));
                    if successful_lower.saturating_add(1) >= probe_size {
                        // Entry sizes can vary within a family. A count that
                        // fitted an earlier slice is not proof for this one.
                        successful_lower = 0;
                    }
                    chunk_size = if successful_lower + 1 < probe_size {
                        successful_lower + (probe_size - successful_lower) / 2
                    } else {
                        (probe_size / 2).max(1)
                    };
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
            if idx < entries.len() {
                successful_lower = successful_lower.max(probe_size);
                chunk_size = match failed_upper {
                    Some(upper) if successful_lower + 1 < upper => {
                        successful_lower + (upper - successful_lower) / 2
                    }
                    Some(_) => successful_lower,
                    None => successful_lower.saturating_mul(2).min(max_probe),
                };
            }
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
        profile: &SessionExportProfile,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[EvpnRoute],
        max_len: usize,
    ) -> bool {
        // Initial chunk size: 1000 fits comfortably under the 65535-byte
        // Extended Messages limit even for Type 5/IPv6 routes (~60 B each)
        // and shrinks on overflow for the standard 4096-byte limit.
        let mut chunk_size = routes.len().clamp(1, 1000);
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_reach(
                    Afi::L2Vpn,
                    Safi::Evpn,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::Evpn(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("EVPN MP_REACH construction was previously infallible");
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    // Single-route oversize: a single EVPN route plus its
                    // attribute set exceeds the negotiated maximum BGP
                    // message length. Previously the loop logged + skipped
                    // and continued, returning `true` — a silent desync
                    // because RIB has already committed the route to
                    // Adj-RIB-Out and now believes the peer holds it.
                    // The caller cannot report this synchronous failure back
                    // across the RIB/session boundary. Use the established
                    // Cease/8 hard teardown so the stream cannot remain
                    // Established with Adj-RIB-Out ahead of the wire.
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN route exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_saturation_teardown();
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
        profile: &SessionExportProfile,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[EvpnRoute],
        max_len: usize,
    ) -> bool {
        let mut chunk_size = routes.len().clamp(1, 1000);
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Evpn(&routes[idx..end]), ipv4_mode)
                .expect("EVPN MP_UNREACH construction was previously infallible");
            if msg.encoded_len() > max_len {
                if chunk_size <= 1 {
                    warn!(
                        peer = %self.peer_label,
                        size = msg.encoded_len(),
                        max = max_len,
                        "single EVPN withdrawal exceeds maximum message length — tearing down the session so Adj-RIB-Out is rebuilt on reconnect"
                    );
                    self.trigger_outbound_saturation_teardown();
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
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_reach(
                    Afi::BgpLs,
                    safi,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::BgpLs(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("BGP-LS MP_REACH construction was previously infallible");
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
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::bgpls::BgpLsNlri],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::BgpLs(&routes[idx..end]), ipv4_mode)
                .expect("BGP-LS MP_UNREACH construction was previously infallible");
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the MP_REACH chunker receives each wire component explicitly"
    )]
    fn send_vpn_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::VpnNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_reach(
                    afi,
                    Safi::MplsVpn,
                    next_hop,
                    link_local_next_hop,
                    base_attrs,
                    ReachNlri::Vpn(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("VPN MP_REACH construction was previously infallible");
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
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::VpnNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Vpn(&routes[idx..end]), ipv4_mode)
                .expect("VPN MP_UNREACH construction was previously infallible");
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the MP_REACH chunker receives each wire component explicitly"
    )]
    fn send_labeled_reach_chunked(
        &mut self,
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_reach(
                    afi,
                    Safi::LabeledUnicast,
                    next_hop,
                    link_local_next_hop,
                    base_attrs,
                    ReachNlri::Labeled(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("labeled-unicast MP_REACH construction was previously infallible");
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
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::LabeledNlriEntry],
        profile: &SessionExportProfile,
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_unreach(
                    afi,
                    safi,
                    UnreachNlri::Labeled(&routes[idx..end]),
                    ipv4_mode,
                )
                .expect("labeled-unicast MP_UNREACH construction was previously infallible");
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
        profile: &SessionExportProfile,
        next_hop: IpAddr,
        base_attrs: &[PathAttribute],
        routes: &[rustbgpd_wire::RtcNlri],
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_reach(
                    Afi::Ipv4,
                    Safi::RtConstrain,
                    next_hop,
                    None,
                    base_attrs,
                    ReachNlri::Rtc(&routes[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .expect("RTC MP_REACH construction was previously infallible");
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
        profile: &SessionExportProfile,
        afi: Afi,
        safi: Safi,
        ipv4_mode: Ipv4UnicastMode,
        routes: &[rustbgpd_wire::RtcNlri],
        max_len: usize,
    ) -> bool {
        let mut chunk_size: usize = 1000;
        let mut idx: usize = 0;
        while idx < routes.len() {
            let end = (idx + chunk_size).min(routes.len());
            let msg = profile
                .build_mp_unreach(afi, safi, UnreachNlri::Rtc(&routes[idx..end]), ipv4_mode)
                .expect("RTC MP_UNREACH construction was previously infallible");
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
    // Test-facing compatibility helpers delegate to the same immutable
    // profile preparation used by live emission. They republish first because
    // focused fixtures intentionally mutate config/negotiation fields directly.
    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes(
        &self,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_unicast_attributes(route, local_ipv4, nh_override)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_flowspec(
        &self,
        route: &FlowSpecRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_flowspec_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_vpn(
        &self,
        route: &VpnRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_vpn_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_labeled(
        &self,
        route: &LabeledRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_labeled_attributes(route)
    }

    #[cfg(test)]
    pub(super) fn prepare_outbound_attributes_rtc(
        &self,
        route: &RtcRibRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        SessionExportProfile::capture(self)
            .with_test_ebgp(is_ebgp)
            .prepare_rtc_attributes(route)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rustbgpd_fsm::PeerConfig;
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, MacAddress, MplsLabel, Origin,
        RouteDistinguisher, notification::NotificationCode, notification::cease_subcode,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    fn make_test_session() -> PeerSession {
        let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.families = vec![(Afi::L2Vpn, Safi::Evpn)];
        let config =
            crate::config::TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let (_command_tx, command_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        PeerSession::new(
            config,
            rustbgpd_telemetry::BgpMetrics::new(),
            command_rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            false,
        )
    }

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn read_message(stream: &mut TcpStream) -> Message {
        let mut header = [0_u8; 19];
        stream.read_exact(&mut header).await.unwrap();
        let message_len = usize::from(u16::from_be_bytes([header[16], header[17]]));
        let mut body = vec![0_u8; message_len - header.len()];
        stream.read_exact(&mut body).await.unwrap();
        let mut complete = header.to_vec();
        complete.extend_from_slice(&body);
        let mut bytes = Bytes::from(complete);
        rustbgpd_wire::decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
    }

    /// A single EVPN NLRI that cannot fit the negotiated message ceiling is
    /// not a recoverable batch error: the RIB has already committed the
    /// logical advertisement or withdrawal. Pin both private helper branches
    /// with an artificial ceiling so even the otherwise-unreachable valid
    /// withdrawal overflow emits a final Cease/8 and hard-closes the stream.
    #[tokio::test]
    async fn evpn_single_entry_overflow_tears_down_announce_and_withdraw() {
        let route = EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0, 0, 0xaa, 0xbb, 0xcc]),
            ip: Some(IpAddr::V6("2001:db8::1".parse().unwrap())),
            label1: MplsLabel::new(10_000),
            label2: None,
        });

        for announce in [true, false] {
            let mut session = make_test_session();
            let (client, mut server) = connected_stream_pair().await;
            session.test_install_stream(client);
            let profile = SessionExportProfile::capture(&session).with_test_ebgp(true);

            let sent = if announce {
                session.send_evpn_reach_chunked(
                    &profile,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    &[PathAttribute::Origin(Origin::Igp)],
                    std::slice::from_ref(&route),
                    1,
                )
            } else {
                session.send_evpn_unreach_chunked(
                    &profile,
                    Afi::L2Vpn,
                    Safi::Evpn,
                    Ipv4UnicastMode::Body,
                    std::slice::from_ref(&route),
                    1,
                )
            };
            assert!(!sent, "overflowing EVPN send must fail closed");
            assert!(session.read_half.is_none());
            assert!(session.writer_bulk_tx.is_none());
            assert!(session.writer_priority_tx.is_none());

            let Message::Notification(notification) = read_message(&mut server).await else {
                panic!("overflowing EVPN send must emit a NOTIFICATION");
            };
            assert_eq!(notification.code, NotificationCode::Cease);
            assert_eq!(notification.subcode, cease_subcode::OUT_OF_RESOURCES);

            let join = session
                .writer_join
                .take()
                .expect("teardown keeps writer join handle for run-loop observation");
            let result = timeout(Duration::from_secs(2), join)
                .await
                .expect("writer exits after EVPN overflow")
                .expect("writer task must not panic");
            assert!(matches!(
                result,
                Err(super::super::writer::WriterExit::TornDown)
            ));
            let mut trailing = [0_u8; 1];
            assert_eq!(
                timeout(Duration::from_secs(1), server.read(&mut trailing))
                    .await
                    .expect("writer hard-close reaches EOF")
                    .unwrap(),
                0,
                "Cease/8 must be the final frame"
            );
        }
    }
}
