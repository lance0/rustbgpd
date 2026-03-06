use super::{
    Afi, Event, FlowSpecRoute, FlowSpecRule, Instant, IpAddr, Ipv4Addr, NotificationCode,
    NotificationMessage, PathAttribute, PeerSession, Prefix, RibUpdate, Route, Safi, cease_subcode,
    debug, info, resolve_import_nexthop, warn,
};

impl PeerSession {
    /// Check whether a prefix's address family is among the negotiated families.
    /// Negotiated maximum message length: 65535 if Extended Messages was
    /// negotiated, otherwise 4096.
    pub(super) fn max_message_len(&self) -> u16 {
        if self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_extended_message)
        {
            rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
        } else {
            rustbgpd_wire::MAX_MESSAGE_LEN
        }
    }

    pub(super) fn is_family_negotiated(&self, prefix: &Prefix) -> bool {
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.negotiated_families.contains(&family)
    }

    pub(super) fn use_extended_nexthop_ipv4(&self) -> bool {
        self.negotiated.as_ref().is_some_and(|n| {
            n.extended_nexthop_families
                .get(&(Afi::Ipv4, Safi::Unicast))
                .is_some_and(|afi| *afi == Afi::Ipv6)
        })
    }

    /// Parse an UPDATE message, validate attributes, apply import policy,
    /// enforce max-prefix limit, send routes to RIB, and feed the
    /// appropriate event to the FSM.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn process_update(&mut self, update: rustbgpd_wire::UpdateMessage) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);

        // Build Add-Path receive families for MP attribute decode context.
        let add_path_recv_families: Vec<(Afi, Safi)> = self
            .negotiated
            .as_ref()
            .map(|n| {
                n.add_path_families
                    .iter()
                    .filter(|(_, m)| {
                        matches!(
                            m,
                            rustbgpd_wire::AddPathMode::Receive | rustbgpd_wire::AddPathMode::Both
                        )
                    })
                    .map(|(&family, _)| family)
                    .collect()
            })
            .unwrap_or_default();

        // Check if Add-Path receive is negotiated for IPv4 unicast (body NLRI)
        let add_path_ipv4 = add_path_recv_families.contains(&(Afi::Ipv4, Safi::Unicast));

        // 1. Structural decode
        let parsed = match update.parse(four_octet_as, add_path_ipv4, &add_path_recv_families) {
            Ok(p) => p,
            Err(e) => {
                warn!(peer = %self.peer_label, error = %e, "UPDATE decode error");
                self.drive_fsm(Event::DecodeError(e)).await;
                return;
            }
        };

        // 2. Semantic validation
        let has_mp_nlri = parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(_)));
        let has_body_nlri = !parsed.announced.is_empty();
        let has_nlri = has_body_nlri || has_mp_nlri;
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);

        if let Err(update_err) = rustbgpd_wire::validate::validate_update_attributes(
            &parsed.attributes,
            has_nlri,
            has_body_nlri,
            is_ebgp,
        ) {
            warn!(
                peer = %self.peer_label,
                subcode = update_err.subcode,
                "UPDATE validation error"
            );
            let notif = NotificationMessage::new(
                NotificationCode::UpdateMessage,
                update_err.subcode,
                bytes::Bytes::from(update_err.data),
            );
            self.drive_fsm(Event::UpdateValidationError(notif)).await;
            return;
        }

        // 3. End-of-RIB detection (RFC 4724 §2)
        if parsed.announced.is_empty() && parsed.withdrawn.is_empty() {
            // IPv4 EoR: empty UPDATE (no NLRI, no withdrawn, no attributes)
            if parsed.attributes.is_empty() {
                info!(peer = %self.peer_label, family = "ipv4_unicast", "received End-of-RIB");
                let _ = self.rib_tx.try_send(RibUpdate::EndOfRib {
                    peer: self.peer_ip,
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                });
                self.drive_fsm(Event::UpdateReceived).await;
                return;
            }
            // MP EoR: UPDATE with only an empty MP_UNREACH_NLRI (IPv6 unicast, FlowSpec, etc.)
            if parsed.attributes.len() == 1
                && let Some(PathAttribute::MpUnreachNlri(mp)) = parsed.attributes.first()
                && mp.withdrawn.is_empty()
                && mp.flowspec_withdrawn.is_empty()
            {
                info!(
                    peer = %self.peer_label,
                    afi = ?mp.afi,
                    safi = ?mp.safi,
                    "received End-of-RIB"
                );
                let _ = self.rib_tx.try_send(RibUpdate::EndOfRib {
                    peer: self.peer_ip,
                    afi: mp.afi,
                    safi: mp.safi,
                });
                self.drive_fsm(Event::UpdateReceived).await;
                return;
            }
        }

        // 4. Build routes from body NLRI (IPv4) and MP-BGP NLRI
        let body_next_hop: IpAddr = parsed
            .attributes
            .iter()
            .find_map(|a| {
                if let PathAttribute::NextHop(nh) = a {
                    Some(IpAddr::V4(*nh))
                } else {
                    None
                }
            })
            .unwrap_or(match self.peer_ip {
                IpAddr::V4(v4) => IpAddr::V4(v4),
                IpAddr::V6(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            });

        let now = Instant::now();
        let route_origin = if is_ebgp {
            rustbgpd_rib::RouteOrigin::Ebgp
        } else {
            rustbgpd_rib::RouteOrigin::Ibgp
        };

        // AS_PATH loop detection (RFC 4271 §9.1.2): discard all
        // announcements if our local ASN appears in the AS_PATH.
        // Withdrawals are still processed normally.
        let as_path_loop = parsed.attributes.iter().any(|a| {
            if let PathAttribute::AsPath(as_path) = a {
                as_path.contains_asn(self.config.peer.local_asn)
            } else {
                false
            }
        });
        if as_path_loop {
            // Count rejected announced prefixes (body NLRI + MP_REACH_NLRI)
            let rejected_count = parsed.announced.len()
                + parsed
                    .attributes
                    .iter()
                    .filter_map(|a| match a {
                        PathAttribute::MpReachNlri(mp) => Some(mp.announced.len()),
                        _ => None,
                    })
                    .sum::<usize>();
            debug!(
                peer = %self.peer_label,
                local_asn = self.config.peer.local_asn,
                rejected = rejected_count,
                "AS_PATH loop detected — discarding announcements"
            );
            self.metrics
                .record_as_path_loop_detected(&self.peer_label, rejected_count as u64);

            // Still process withdrawals (body + MP_UNREACH with negotiated-family check)
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            if !loop_withdrawn.is_empty() || !loop_fs_withdrawn.is_empty() {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                });
            }
            self.drive_fsm(Event::UpdateReceived).await;
            return;
        }

        // Route reflector loop detection (RFC 4456 §8):
        // - ORIGINATOR_ID matching our own router-id → loop
        // - Our cluster_id already in CLUSTER_LIST → loop
        //
        // ORIGINATOR_ID must be checked even when we are not operating as an
        // RR ourselves: a non-RR speaker can still receive reflected routes
        // from some other RR in the AS.
        let originator_loop = parsed.attributes.iter().any(|a| {
            matches!(a, PathAttribute::OriginatorId(id) if *id == self.config.peer.local_router_id)
        });
        let cluster_loop = self.config.cluster_id.is_some_and(|cluster_id| {
            parsed
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(ids) if ids.contains(&cluster_id)))
        });
        if originator_loop || cluster_loop {
            let reason = if originator_loop {
                "ORIGINATOR_ID"
            } else {
                "CLUSTER_LIST"
            };
            debug!(
                peer = %self.peer_label,
                reason,
                "Route reflector loop detected — discarding announcements"
            );
            self.metrics.record_rr_loop_detected(&self.peer_label);

            // Still process withdrawals (same pattern as AS_PATH loop)
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            if !loop_withdrawn.is_empty() || !loop_fs_withdrawn.is_empty() {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                });
            }
            self.drive_fsm(Event::UpdateReceived).await;
            return;
        }

        // Filter attributes: strip MP_REACH/MP_UNREACH before storing on routes
        // (they are per-UPDATE framing, not per-route attributes)
        let route_attrs: Vec<PathAttribute> = parsed
            .attributes
            .iter()
            .filter(|a| {
                !matches!(
                    a,
                    PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
                )
            })
            .cloned()
            .collect();

        // Extract communities for policy matching
        let update_ecs: &[rustbgpd_wire::ExtendedCommunity] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let update_communities: &[u32] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);

        // Compute AS_PATH string for policy matching
        let update_large_communities: &[rustbgpd_wire::LargeCommunity] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let aspath_str: String = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p.to_aspath_string()),
                _ => None,
            })
            .unwrap_or_default();
        let aspath_len: usize = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p.len()),
                _ => None,
            })
            .unwrap_or(0);

        // Body NLRI routes (IPv4)
        let mut announced: Vec<Route> = parsed
            .announced
            .iter()
            .filter_map(|entry| {
                let prefix = Prefix::V4(entry.prefix);
                let result = rustbgpd_policy::evaluate_chain(
                    self.import_policy.as_ref(),
                    prefix,
                    update_ecs,
                    update_communities,
                    update_large_communities,
                    &aspath_str,
                    aspath_len,
                    rustbgpd_wire::RpkiValidation::NotFound,
                );
                if result.action != rustbgpd_policy::PolicyAction::Permit {
                    return None;
                }
                let mut attrs = route_attrs.clone();
                let nh_action =
                    rustbgpd_policy::apply_modifications(&mut attrs, &result.modifications);
                let next_hop = resolve_import_nexthop(
                    nh_action.as_ref(),
                    body_next_hop,
                    self.stream.as_ref(),
                    &self.config,
                );
                Some(Route {
                    prefix,
                    next_hop,
                    peer: self.peer_ip,
                    attributes: attrs,
                    received_at: now,
                    origin_type: route_origin,
                    peer_router_id: self
                        .negotiated
                        .as_ref()
                        .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                    is_stale: false,
                    is_llgr_stale: false,
                    path_id: entry.path_id,
                    validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                })
            })
            .collect();

        // Body withdrawn routes (IPv4) — carry path_id for Add-Path peers
        let mut withdrawn: Vec<(Prefix, u32)> = parsed
            .withdrawn
            .iter()
            .map(|e| (Prefix::V4(e.prefix), e.path_id))
            .collect();

        // MP-BGP NLRI from attributes
        // For IPv6 routes, also strip body NEXT_HOP — it's IPv4-specific and
        // would contaminate IPv6 route attributes in mixed UPDATEs.
        let mp_route_attrs: Vec<PathAttribute> = route_attrs
            .iter()
            .filter(|a| !matches!(a, PathAttribute::NextHop(_)))
            .cloned()
            .collect();

        let mut flowspec_announced: Vec<FlowSpecRoute> = Vec::new();
        let mut flowspec_withdrawn: Vec<FlowSpecRule> = Vec::new();

        for attr in &parsed.attributes {
            match attr {
                PathAttribute::MpReachNlri(mp) => {
                    let family = (mp.afi, mp.safi);
                    if !self.negotiated_families.contains(&family) {
                        warn!(
                            peer = %self.peer_label,
                            afi = ?mp.afi,
                            safi = ?mp.safi,
                            "Ignoring MP_REACH_NLRI for non-negotiated family"
                        );
                        continue;
                    }

                    if family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4() {
                        warn!(
                            peer = %self.peer_label,
                            "Ignoring IPv4 MP_REACH_NLRI without negotiated Extended Next Hop"
                        );
                        continue;
                    }

                    if mp.safi == Safi::FlowSpec {
                        // FlowSpec announced routes — no next-hop (NH len = 0)
                        for rule in &mp.flowspec_announced {
                            // Apply import policy using the destination prefix
                            // component (if present) for prefix matching
                            let dest_prefix = rule.destination_prefix();
                            let result = rustbgpd_policy::evaluate_chain(
                                self.import_policy.as_ref(),
                                dest_prefix.unwrap_or(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                                    Ipv4Addr::UNSPECIFIED,
                                    0,
                                ))),
                                update_ecs,
                                update_communities,
                                update_large_communities,
                                &aspath_str,
                                aspath_len,
                                rustbgpd_wire::RpkiValidation::NotFound,
                            );
                            if result.action == rustbgpd_policy::PolicyAction::Permit {
                                let mut attrs = mp_route_attrs.clone();
                                let _nh_action = rustbgpd_policy::apply_modifications(
                                    &mut attrs,
                                    &result.modifications,
                                );
                                flowspec_announced.push(FlowSpecRoute {
                                    rule: rule.clone(),
                                    afi: mp.afi,
                                    peer: self.peer_ip,
                                    attributes: attrs,
                                    received_at: now,
                                    origin_type: route_origin,
                                    peer_router_id: self
                                        .negotiated
                                        .as_ref()
                                        .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                                    is_stale: false,
                                    is_llgr_stale: false,
                                    path_id: 0,
                                });
                            }
                        }
                        continue;
                    }

                    // Unicast routes
                    for entry in &mp.announced {
                        let result = rustbgpd_policy::evaluate_chain(
                            self.import_policy.as_ref(),
                            entry.prefix,
                            update_ecs,
                            update_communities,
                            update_large_communities,
                            &aspath_str,
                            aspath_len,
                            rustbgpd_wire::RpkiValidation::NotFound,
                        );
                        if result.action == rustbgpd_policy::PolicyAction::Permit {
                            let mut attrs = mp_route_attrs.clone();
                            let nh_action = rustbgpd_policy::apply_modifications(
                                &mut attrs,
                                &result.modifications,
                            );
                            let next_hop = resolve_import_nexthop(
                                nh_action.as_ref(),
                                mp.next_hop,
                                self.stream.as_ref(),
                                &self.config,
                            );
                            announced.push(Route {
                                prefix: entry.prefix,
                                next_hop,
                                peer: self.peer_ip,
                                attributes: attrs,
                                received_at: now,
                                origin_type: route_origin,
                                peer_router_id: self
                                    .negotiated
                                    .as_ref()
                                    .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                                is_stale: false,
                                is_llgr_stale: false,
                                path_id: entry.path_id,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                            });
                        }
                    }
                }
                PathAttribute::MpUnreachNlri(mp) => {
                    let family = (mp.afi, mp.safi);
                    if !self.negotiated_families.contains(&family) {
                        continue;
                    }
                    if family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4() {
                        warn!(
                            peer = %self.peer_label,
                            "Ignoring IPv4 MP_UNREACH_NLRI without negotiated Extended Next Hop"
                        );
                        continue;
                    }
                    withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                    flowspec_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                }
                _ => {}
            }
        }

        // 4. Max-prefix enforcement — track via HashSet for accuracy
        for &(prefix, path_id) in &withdrawn {
            self.known_paths.remove(&(prefix, path_id));
        }
        for route in &announced {
            self.known_paths.insert((route.prefix, route.path_id));
        }

        let prefix_count = self.known_prefix_count();
        if let Some(max) = self.config.max_prefixes
            && prefix_count > max as usize
        {
            warn!(
                peer = %self.peer_label,
                count = prefix_count,
                max,
                "max prefix exceeded"
            );
            self.metrics.record_max_prefix_exceeded(&self.peer_label);
            let notif = NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::MAX_PREFIXES,
                bytes::Bytes::new(),
            );
            self.drive_fsm(Event::UpdateValidationError(notif)).await;
            return;
        }

        if !announced.is_empty()
            || !withdrawn.is_empty()
            || !flowspec_announced.is_empty()
            || !flowspec_withdrawn.is_empty()
        {
            let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                peer: self.peer_ip,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
            });
        }

        // 5. Tell FSM about the update (restarts hold timer)
        self.drive_fsm(Event::UpdateReceived).await;
    }
}
