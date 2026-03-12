use std::collections::HashMap;
use std::sync::Arc;

use super::{
    Afi, AsPath, AsPathSegment, FlowSpecRoute, FlowSpecRule, IpAddr, Ipv4Addr, Ipv4NlriEntry,
    Ipv4UnicastMode, Ipv6Addr, Message, MpReachNlri, MpUnreachNlri, NlriEntry, OutboundRouteUpdate,
    PathAttribute, PeerSession, Prefix, RemovePrivateAs, Route, RouteRefreshMessage,
    RouteRefreshSubtype, Safi, UpdateMessage, info, is_private_asn, warn,
};

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
}

struct V4BodyGroup {
    attrs: Arc<Vec<PathAttribute>>,
    prefixes: Vec<Ipv4NlriEntry>,
}

struct MpGroup {
    attrs: Arc<Vec<PathAttribute>>,
    next_hop: IpAddr,
    prefixes: Vec<NlriEntry>,
}

impl PeerSession {
    fn peer_accepts_llgr_stale(&self, family: (Afi, Safi)) -> bool {
        self.negotiated.as_ref().is_some_and(|neg| {
            neg.peer_llgr_capable
                && neg
                    .peer_llgr_families
                    .iter()
                    .any(|f| (f.afi, f.safi) == family)
        })
    }

    fn strip_llgr_stale_if_needed(&self, attrs: &mut Vec<PathAttribute>, family: (Afi, Safi)) {
        if self.peer_accepts_llgr_stale(family) {
            return;
        }
        attrs.retain_mut(|attr| match attr {
            PathAttribute::Communities(comms) => {
                comms.retain(|&c| c != rustbgpd_wire::COMMUNITY_LLGR_STALE);
                !comms.is_empty()
            }
            _ => true,
        });
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

    /// Send an outbound route update as wire UPDATE messages.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn send_route_update(&mut self, update: OutboundRouteUpdate) {
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
                if let Err(e) = self.send_message(&msg).await {
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
            .stream
            .as_ref()
            .and_then(|s| s.local_addr().ok())
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
            HashMap::new();

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
            let msg = if use_extended_nexthop_ipv4 {
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    withdrawn: v4_withdraw
                        .iter()
                        .map(|entry| NlriEntry {
                            path_id: entry.path_id,
                            prefix: Prefix::V4(entry.prefix),
                        })
                        .collect(),
                    flowspec_withdrawn: vec![],
                })];
                UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::MpReach,
                )
            } else {
                UpdateMessage::build(
                    &[],
                    &v4_withdraw,
                    &[],
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::Body,
                )
            };
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send withdrawal UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Send IPv6 withdrawals via `MP_UNREACH_NLRI`
        if !v6_withdraw.is_empty() {
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                withdrawn: v6_withdraw,
                flowspec_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path_ipv6_send,
                Ipv4UnicastMode::Body,
            );
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 withdrawal UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Split announcements by address family, filtering by negotiated families
        let mut v4_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        let mut v6_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        for (i, route) in update.announce.iter().enumerate() {
            if !self.is_family_negotiated(&route.prefix) {
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
                .config
                .local_ipv6_nexthop
                .or(local_ipv6)
                .filter(rustbgpd_wire::is_valid_ipv6_nexthop);
            let mut v4_group_index: HashMap<AttrGroupKey, usize> = HashMap::new();
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
                let key = AttrGroupKey {
                    attrs_ptr: Arc::as_ptr(&attrs) as usize,
                    next_hop: Some(next_hop),
                };
                if let Some(&idx) = v4_group_index.get(&key) {
                    v4_groups[idx].prefixes.push(entry);
                } else {
                    v4_group_index.insert(key, v4_groups.len());
                    v4_groups.push(MpGroup {
                        attrs,
                        next_hop,
                        prefixes: vec![entry],
                    });
                }
            }

            for group in v4_groups {
                let mut attrs = group.attrs.as_ref().clone();
                attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    next_hop: group.next_hop,
                    announced: group.prefixes,
                    flowspec_announced: vec![],
                }));
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::MpReach,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        } else {
            let mut v4_group_index: HashMap<AttrGroupKey, usize> = HashMap::new();
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

            for group in &v4_groups {
                let msg = UpdateMessage::build(
                    &group.prefixes,
                    &[],
                    group.attrs.as_ref(),
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        }

        // Resolve IPv6 eBGP next-hop: config override > socket address > suppress.
        // The RIB already filters unsendable families via sendable_families, so
        // v6_routes should be empty here for eBGP peers without a valid IPv6 NH.
        // The is_family_negotiated filter above is retained as a safety net.
        let ebgp_ipv6_nh: Option<Ipv6Addr> = self
            .config
            .local_ipv6_nexthop
            .or(local_ipv6)
            .filter(rustbgpd_wire::is_valid_ipv6_nexthop);

        // Group by (attributes, next-hop) so routes with different next-hops
        // get separate UPDATEs with correct MP_REACH_NLRI next-hop values.
        let mut v6_group_index: HashMap<AttrGroupKey, usize> = HashMap::new();
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
            };
            if let Some(&idx) = v6_group_index.get(&key) {
                v6_groups[idx].prefixes.push(nlri_entry);
            } else {
                v6_group_index.insert(key, v6_groups.len());
                v6_groups.push(MpGroup {
                    attrs,
                    next_hop: nh,
                    prefixes: vec![nlri_entry],
                });
            }
        }

        for group in v6_groups {
            let mut attrs = group.attrs.as_ref().clone();
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: group.next_hop,
                announced: group.prefixes,
                flowspec_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path_ipv6_send,
                Ipv4UnicastMode::Body,
            );
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 announce UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Send FlowSpec withdrawals via MP_UNREACH_NLRI, grouped by AFI
        if !update.flowspec_withdraw.is_empty() {
            let mut v4_fs_withdraw: Vec<FlowSpecRule> = Vec::new();
            let mut v6_fs_withdraw: Vec<FlowSpecRule> = Vec::new();
            for rule in &update.flowspec_withdraw {
                // Determine AFI from the rule's destination prefix component
                let afi = if rule
                    .destination_prefix()
                    .is_some_and(|p| matches!(p, Prefix::V6(_)))
                {
                    Afi::Ipv6
                } else {
                    Afi::Ipv4
                };
                match afi {
                    Afi::Ipv4 => v4_fs_withdraw.push(rule.clone()),
                    Afi::Ipv6 => v6_fs_withdraw.push(rule.clone()),
                }
            }
            for (afi, rules) in [(Afi::Ipv4, v4_fs_withdraw), (Afi::Ipv6, v6_fs_withdraw)] {
                if rules.is_empty() {
                    continue;
                }
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi,
                    safi: Safi::FlowSpec,
                    withdrawn: vec![],
                    flowspec_withdrawn: rules,
                })];
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send FlowSpec withdrawal UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
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
            for (afi, mut attrs, rules) in fs_groups {
                attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                    afi,
                    safi: Safi::FlowSpec,
                    next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // NH len = 0 for FlowSpec
                    announced: vec![],
                    flowspec_announced: rules,
                }));
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send FlowSpec announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
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
                if let Err(e) = self.send_message(&msg).await {
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
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send End-of-RIB for {afi:?}/{safi:?}");
                return;
            }
            info!(peer = %self.peer_label, afi = ?afi, safi = ?safi, "sent End-of-RIB");
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }
    }

    /// Prepare path attributes for outbound advertisement.
    ///
    /// For standard eBGP: prepend our ASN, set `NEXT_HOP` to local addr, strip
    /// `LOCAL_PREF`. For route-server clients, preserve `AS_PATH` and
    /// `NEXT_HOP` by default. For iBGP: ensure `LOCAL_PREF` present (default
    /// 100), pass `NEXT_HOP` through.
    #[expect(clippy::too_many_lines)]
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
                PathAttribute::AsPath(as_path) => {
                    if is_ebgp && !route_server_client {
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
                    } else {
                        attrs.push(attr.clone());
                    }
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
        self.strip_llgr_stale_if_needed(&mut attrs, family);

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
                PathAttribute::AsPath(as_path) => {
                    if is_ebgp && !self.config.route_server_client {
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
                    } else {
                        attrs.push(attr.clone());
                    }
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

        self.strip_llgr_stale_if_needed(&mut attrs, (route.afi, Safi::FlowSpec));

        attrs
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
