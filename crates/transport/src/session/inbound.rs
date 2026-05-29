use std::sync::Arc;
use std::time::SystemTime;

use super::import_decision_cache::{CachedDecision, ImportDecisionKey};
use super::{
    Afi, AsPath, BgpRole, Event, EvpnRibRoute, EvpnRoute, EvpnRouteKey, FlowSpecRoute,
    FlowSpecRule, Instant, IpAddr, Ipv4Addr, NextHopScope, NotificationCode, NotificationMessage,
    PathAttribute, PeerSession, Prefix, RibUpdate, Route, Safi, cease_subcode, debug, info,
    is_ipv6_link_local, resolve_import_nexthop, warn,
};
use rustbgpd_policy::{
    NextHopAction, PolicyAction, PolicyEvaluation, RouteContext, RouteModifications, RouteType,
};

/// Increment `bgp_policy_routes_total{peer, policy, direction=import,
/// action}` for one import-side chain evaluation. Policy falls back to
/// `"inline"` for anonymous / inline policies; cardinality stays
/// bounded by config.
fn record_import_policy_eval(
    metrics: &rustbgpd_telemetry::BgpMetrics,
    peer_label: &str,
    evaluation: &PolicyEvaluation,
    permitted: &mut u64,
    denied: &mut u64,
) {
    let policy = evaluation.matched_policy.as_deref().unwrap_or("inline");
    let action = match evaluation.action {
        PolicyAction::Permit => {
            *permitted = permitted.saturating_add(1);
            "permit"
        }
        PolicyAction::Deny => {
            *denied = denied.saturating_add(1);
            "deny"
        }
    };
    metrics.record_policy_routes(peer_label, policy, "import", action);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtcState {
    Absent,
    Present(u32),
    MalformedLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtcIngressAction {
    None,
    Add(u32),
    DropUnicastAnnouncements(&'static str),
}

fn otc_state(attrs: &[PathAttribute]) -> OtcState {
    let mut found = OtcState::Absent;
    for attr in attrs {
        match attr {
            PathAttribute::OnlyToCustomer(asn) => found = OtcState::Present(*asn),
            PathAttribute::Unknown(raw)
                if raw.type_code == rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER =>
            {
                if raw.data.len() != 4 {
                    return OtcState::MalformedLength;
                }
                found = OtcState::Present(u32::from_be_bytes([
                    raw.data[0],
                    raw.data[1],
                    raw.data[2],
                    raw.data[3],
                ]));
            }
            _ => {}
        }
    }
    found
}

/// Build the `(otc_value, as_path_string)` pair attached to an
/// [`OtcRouteBlockedEvent`] for the ingress decision sites.
///
/// `otc_value` is `None` on the `malformed_length` path because the
/// attribute could not be decoded (the codec returns
/// `OtcState::MalformedLength` rather than a usable ASN). For both
/// I1 (`ingress_from_customer_rsclient`) and I2
/// (`ingress_peer_mismatch`) the codec returns the present ASN.
///
/// `as_path_string` uses
/// [`rustbgpd_wire::AsPath::to_aspath_string`] so `AS_SET` / confed
/// segments survive the lossless round-trip into the structured
/// event — the proto field is `string`, not `repeated uint32`.
fn otc_event_context(attrs: &[PathAttribute], reason: &'static str) -> (Option<u32>, String) {
    let otc_value = if reason == "malformed_length" {
        None
    } else {
        match otc_state(attrs) {
            OtcState::Present(asn) => Some(asn),
            OtcState::Absent | OtcState::MalformedLength => None,
        }
    };
    let as_path_string = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p.to_aspath_string()),
            _ => None,
        })
        .unwrap_or_default();
    (otc_value, as_path_string)
}

fn otc_ingress_action(
    local_role: Option<BgpRole>,
    remote_asn: Option<u32>,
    attrs: &[PathAttribute],
) -> OtcIngressAction {
    let Some(local_role) = local_role else {
        return OtcIngressAction::None;
    };
    match otc_state(attrs) {
        OtcState::MalformedLength => OtcIngressAction::DropUnicastAnnouncements("malformed_length"),
        OtcState::Present(_) if matches!(local_role, BgpRole::Provider | BgpRole::RouteServer) => {
            OtcIngressAction::DropUnicastAnnouncements("ingress_from_customer_rsclient")
        }
        OtcState::Present(asn)
            if local_role == BgpRole::Peer && remote_asn.is_some_and(|remote| asn != remote) =>
        {
            OtcIngressAction::DropUnicastAnnouncements("ingress_peer_mismatch")
        }
        OtcState::Absent
            if matches!(
                local_role,
                BgpRole::Customer | BgpRole::Peer | BgpRole::RouteServerClient
            ) =>
        {
            remote_asn.map_or(OtcIngressAction::None, OtcIngressAction::Add)
        }
        _ => OtcIngressAction::None,
    }
}

/// Policy-context fields extracted from a route's path attributes in a
/// single pass over the attribute vector. This replaces what used to be
/// eight independent `find_map` / `iter` scans of the same vector on the
/// inbound UPDATE hot path.
///
/// Each field keeps first-match-wins semantics, mirroring the previous
/// `find_map` short-circuit (BGP permits at most one of each well-known
/// attribute; a duplicate is ignored rather than overwriting an earlier
/// occurrence). The four `AS_PATH`-derived surfaces (`as_path`,
/// `as_path_str`, `as_path_len`, `origin_asn`) all come from the same
/// first `AS_PATH` attribute.
struct PolicyAttrSummary<'a> {
    extended_communities: &'a [rustbgpd_wire::ExtendedCommunity],
    communities: &'a [u32],
    large_communities: &'a [rustbgpd_wire::LargeCommunity],
    as_path: Option<&'a AsPath>,
    as_path_str: String,
    as_path_len: usize,
    origin_asn: Option<u32>,
    local_pref: Option<u32>,
    med: Option<u32>,
}

impl<'a> PolicyAttrSummary<'a> {
    fn from_route_attrs(attrs: &'a [PathAttribute]) -> Self {
        let mut extended_communities: Option<&'a [rustbgpd_wire::ExtendedCommunity]> = None;
        let mut communities: Option<&'a [u32]> = None;
        let mut large_communities: Option<&'a [rustbgpd_wire::LargeCommunity]> = None;
        let mut as_path: Option<&'a AsPath> = None;
        let mut local_pref: Option<u32> = None;
        let mut med: Option<u32> = None;

        // First-match-wins guards preserve the prior `find_map` behavior:
        // once a field is set, a later attribute of the same type fails
        // its guard and falls through to `_` rather than overwriting it.
        // Tracking the slices as `Option<&[T]>` keeps presence
        // unambiguous — a duplicate *empty* community must not blank out
        // an earlier populated one (an `is_empty()` sentinel would).
        for attr in attrs {
            match attr {
                PathAttribute::ExtendedCommunities(c) if extended_communities.is_none() => {
                    extended_communities = Some(c.as_slice());
                }
                PathAttribute::Communities(c) if communities.is_none() => {
                    communities = Some(c.as_slice());
                }
                PathAttribute::LargeCommunities(c) if large_communities.is_none() => {
                    large_communities = Some(c.as_slice());
                }
                PathAttribute::AsPath(p) if as_path.is_none() => as_path = Some(p),
                PathAttribute::LocalPref(v) if local_pref.is_none() => local_pref = Some(*v),
                PathAttribute::Med(v) if med.is_none() => med = Some(*v),
                _ => {}
            }
        }

        Self {
            extended_communities: extended_communities.unwrap_or_default(),
            communities: communities.unwrap_or_default(),
            large_communities: large_communities.unwrap_or_default(),
            as_path,
            as_path_str: as_path.map(AsPath::to_aspath_string).unwrap_or_default(),
            as_path_len: as_path.map_or(0, AsPath::len),
            origin_asn: as_path.and_then(AsPath::origin_asn),
            local_pref,
            med,
        }
    }
}

/// The canonical per-family attribute sets for one inbound UPDATE, each
/// behind an `Arc` so the accepted-route loops can SHARE them instead of
/// deep-cloning the attribute vector per NLRI.
///
/// Three variants, derived once from the (MP-filtered) `route_attrs`:
/// - `unicast` — body IPv4: keeps the body `NEXT_HOP`, carries the OTC
///   attribute when ingress policy adds one;
/// - `mp` — `FlowSpec` / EVPN: body `NEXT_HOP` stripped (IPv4-specific; it
///   must not contaminate non-IPv4 routes in mixed UPDATEs), no OTC;
/// - `mp_unicast` — MP unicast (e.g. IPv6): `NEXT_HOP` stripped, OTC kept.
///
/// Fields are `pub` only so the (off-by-default) `bench-internals`
/// feature can exercise the type; the enclosing `session` module is
/// `pub(crate)`, so nothing here is reachable in a normal build.
pub struct RouteAttrBundle {
    pub unicast: Arc<Vec<PathAttribute>>,
    pub mp: Arc<Vec<PathAttribute>>,
    pub mp_unicast: Arc<Vec<PathAttribute>>,
}

impl RouteAttrBundle {
    /// Build the three variants from the MP-filtered base attributes.
    /// `otc_add` is `Some(asn)` when ingress OTC handling appends an
    /// `ONLY_TO_CUSTOMER` attribute (unicast families only).
    ///
    /// Borrows `base` (it stays alive for the policy-summary borrows in
    /// `process_update`); the up-front cost matches the previous code
    /// (`mp` and `mp_unicast` are still one filtered clone each).
    #[must_use]
    pub fn new(base: &[PathAttribute], otc_add: Option<u32>) -> Self {
        let strip_next_hop = |attrs: &[PathAttribute]| -> Vec<PathAttribute> {
            attrs
                .iter()
                .filter(|a| !matches!(a, PathAttribute::NextHop(_)))
                .cloned()
                .collect()
        };

        // `mp` derives from `base` (no OTC). Build it before injecting OTC.
        let mp = strip_next_hop(base);

        let mut unicast = base.to_vec();
        if let Some(asn) = otc_add {
            unicast.push(PathAttribute::OnlyToCustomer(asn));
        }
        let mp_unicast = strip_next_hop(&unicast);

        Self {
            unicast: Arc::new(unicast),
            mp: Arc::new(mp),
            mp_unicast: Arc::new(mp_unicast),
        }
    }
}

/// Produce the stored attribute set for one accepted route, sharing the
/// canonical `Arc` when policy made no modifications (the common case)
/// and deep-cloning + applying only when it did. Mirrors the outbound
/// distribution `CoW` pattern (`crates/rib/src/manager/distribution.rs`).
///
/// When `mods` is empty, `apply_modifications` is skipped entirely — its
/// next-hop action derives solely from `mods.set_next_hop`, so the result
/// is `None`, which `resolve_import_nexthop` already handles.
// Tiny hot-path wrapper called once per accepted NLRI — inline it so the
// no-mods fast path is a branch + `Arc` bump with no call overhead (and so
// the cross-crate microbench measures it faithfully).
#[inline]
#[must_use]
pub fn materialize_attrs(
    canonical: &Arc<Vec<PathAttribute>>,
    mods: &RouteModifications,
) -> (Arc<Vec<PathAttribute>>, Option<NextHopAction>) {
    if mods.is_empty() {
        (Arc::clone(canonical), None)
    } else {
        let mut owned = (**canonical).clone();
        let nh = rustbgpd_policy::apply_modifications(&mut owned, mods);
        (Arc::new(owned), nh)
    }
}

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

    pub(super) fn is_scoped_link_local_peer(&self) -> bool {
        matches!(self.peer_ip, IpAddr::V6(v6) if is_ipv6_link_local(&v6))
            && self.config.peer_interface.is_some()
            && self.config.peer_scope_id.is_some()
    }

    fn link_local_next_hop_scope(&self, next_hop: IpAddr) -> Option<Box<NextHopScope>> {
        match next_hop {
            IpAddr::V6(v6) if is_ipv6_link_local(&v6) => {
                self.link_local_next_hop_scope.clone().map(Box::new)
            }
            _ => None,
        }
    }

    /// Parse an UPDATE message, validate attributes, apply import policy,
    /// enforce max-prefix limit, send routes to RIB, and feed the
    /// appropriate event to the FSM.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn process_update(&mut self, update: rustbgpd_wire::UpdateMessage) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);
        let mut import_policy_routes_permitted = 0_u64;
        let mut import_policy_routes_denied = 0_u64;

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

        let validation_options = rustbgpd_wire::UpdateValidationOptions {
            allow_ipv4_link_local_mp_reach_next_hop: self.is_scoped_link_local_peer()
                && self.use_extended_nexthop_ipv4(),
        };
        if let Err(update_err) = rustbgpd_wire::validate::validate_update_attributes_with_options(
            &parsed.attributes,
            has_nlri,
            has_body_nlri,
            is_ebgp,
            validation_options,
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
                let _ = self
                    .rib_tx
                    .send(RibUpdate::EndOfRib {
                        peer: self.peer_ip,
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                    })
                    .await;
                self.drive_fsm(Event::UpdateReceived).await;
                return;
            }
            // MP EoR: UPDATE with only an empty MP_UNREACH_NLRI (IPv6 unicast, FlowSpec, etc.)
            if parsed.attributes.len() == 1
                && let Some(PathAttribute::MpUnreachNlri(mp)) = parsed.attributes.first()
                && mp.withdrawn.is_empty()
                && mp.flowspec_withdrawn.is_empty()
                && mp.evpn_withdrawn.is_empty()
            {
                info!(
                    peer = %self.peer_label,
                    afi = ?mp.afi,
                    safi = ?mp.safi,
                    "received End-of-RIB"
                );
                let _ = self
                    .rib_tx
                    .send(RibUpdate::EndOfRib {
                        peer: self.peer_ip,
                        afi: mp.afi,
                        safi: mp.safi,
                    })
                    .await;
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
        let policy_route_type = Some(match route_origin {
            rustbgpd_rib::RouteOrigin::Local => RouteType::Local,
            rustbgpd_rib::RouteOrigin::Ibgp => RouteType::Internal,
            rustbgpd_rib::RouteOrigin::Ebgp => RouteType::External,
        });
        let policy_peer_asn = self.negotiated.as_ref().map(|n| n.peer_asn);
        let otc_action = otc_ingress_action(
            self.config.peer.local_role,
            policy_peer_asn,
            &parsed.attributes,
        );
        let otc_drop_unicast_announcements =
            matches!(otc_action, OtcIngressAction::DropUnicastAnnouncements(_));
        if let OtcIngressAction::DropUnicastAnnouncements(reason) = otc_action {
            // Collect every unicast prefix the OTC rule rejected:
            // body NLRI (always IPv4) plus IPv4/IPv6 unicast
            // MP_REACH_NLRI. Other families are out of scope for OTC.
            let mut blocked_prefixes: Vec<String> = parsed
                .announced
                .iter()
                .map(|e| e.prefix.to_string())
                .collect();
            for attr in &parsed.attributes {
                if let PathAttribute::MpReachNlri(mp) = attr
                    && ((mp.afi, mp.safi) == (Afi::Ipv4, Safi::Unicast)
                        || (mp.afi, mp.safi) == (Afi::Ipv6, Safi::Unicast))
                {
                    for entry in &mp.announced {
                        blocked_prefixes.push(entry.prefix.to_string());
                    }
                }
            }
            let rejected = blocked_prefixes.len();

            // An OTC-tagged UPDATE with no announced unicast routes —
            // e.g. malformed-length on a body-NLRI withdrawals-only
            // UPDATE, or any tagged UPDATE that carries only
            // withdrawals or non-unicast MP_REACH — produces no
            // counter bump and no structured event. The
            // OtcRouteBlockedEvent proto contract is "blocks one or
            // more unicast routes", so a zero-count event would be
            // semantically wrong. Withdrawals still flow through the
            // normal path regardless.
            if rejected > 0 {
                warn!(
                    peer = %self.peer_label,
                    reason,
                    rejected,
                    "OTC route-leak rule rejected unicast announcements; withdrawals still processed"
                );
                self.record_otc_routes_blocked(reason, rejected as u64);

                // Publish the structured event AFTER the counter +
                // per-NeighborState scalar update, so a sink that
                // drops (queue_full / closed) can never leave the
                // legacy surfaces inconsistent.
                let (otc_value, as_path_string) = otc_event_context(&parsed.attributes, reason);
                let otc_event = crate::event_sink::OtcRouteBlockedEvent {
                    peer: self.peer_ip,
                    direction: crate::event_sink::OtcDirection::Ingress,
                    reason,
                    prefixes: blocked_prefixes,
                    local_role: self.config.peer.local_role,
                    remote_role: self.negotiated.as_ref().and_then(|n| n.remote_role),
                    otc_value,
                    as_path: as_path_string,
                };
                self.event_sink().publish_otc_route_blocked(&otc_event);
            }
        }

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

            // Still process withdrawals (body + MP_UNREACH with negotiated-family check).
            // Covers unicast, FlowSpec, AND EVPN — the AS_PATH-loop branch must
            // not silently drop withdrawals for any family, or stale EVPN state
            // accumulates downstream until the next session reset / refresh.
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            let mut loop_evpn_withdrawn: Vec<EvpnRouteKey> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                        loop_evpn_withdrawn.extend(mp.evpn_withdrawn.iter().map(EvpnRoute::key));
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            for rule in &loop_fs_withdrawn {
                self.known_flowspec.remove(rule);
            }
            for key in &loop_evpn_withdrawn {
                self.known_evpn.remove(key);
            }
            if !loop_withdrawn.is_empty()
                || !loop_fs_withdrawn.is_empty()
                || !loop_evpn_withdrawn.is_empty()
            {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                    evpn_announced: vec![],
                    evpn_withdrawn: loop_evpn_withdrawn,
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

            // Still process withdrawals (same pattern as AS_PATH loop).
            // Covers unicast, FlowSpec, AND EVPN — the reflected-loop
            // detection must not silently drop withdrawals for any family,
            // or stale state accumulates downstream.
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            let mut loop_evpn_withdrawn: Vec<EvpnRouteKey> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                        loop_evpn_withdrawn.extend(mp.evpn_withdrawn.iter().map(EvpnRoute::key));
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            for rule in &loop_fs_withdrawn {
                self.known_flowspec.remove(rule);
            }
            for key in &loop_evpn_withdrawn {
                self.known_evpn.remove(key);
            }
            if !loop_withdrawn.is_empty()
                || !loop_fs_withdrawn.is_empty()
                || !loop_evpn_withdrawn.is_empty()
            {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                    evpn_announced: vec![],
                    evpn_withdrawn: loop_evpn_withdrawn,
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
        // Canonical per-family attribute sets, each behind an `Arc` so the
        // accepted-route loops below can share them (one `Arc` bump per
        // NLRI) instead of deep-cloning per route when policy makes no
        // modifications. See `RouteAttrBundle` / `materialize_attrs`.
        let otc_add = match otc_action {
            OtcIngressAction::Add(asn) => Some(asn),
            _ => None,
        };
        let attr_bundle = RouteAttrBundle::new(&route_attrs, otc_add);

        // Single pass over the (MP-filtered) attribute vector pulls every
        // policy-context field the RouteContext sites read — replacing
        // what used to be eight independent attribute scans. Built from
        // `route_attrs`, NOT `unicast_route_attrs`: the OTC attribute is
        // appended to the unicast clone only and must not leak into the
        // policy summary (matches pre-refactor behavior). `parsed_as_path`
        // / `origin_asn` feed ASPA (per-family) and RPKI (per-prefix)
        // validation below.
        let PolicyAttrSummary {
            extended_communities: update_ecs,
            communities: update_communities,
            large_communities: update_large_communities,
            as_path_str: aspath_str,
            as_path_len: aspath_len,
            as_path: parsed_as_path,
            origin_asn,
            local_pref: policy_local_pref,
            med: policy_med,
        } = PolicyAttrSummary::from_route_attrs(&route_attrs);

        // Borrow the current RPKI/ASPA validation snapshot for import policy.
        // Cloning is cheap (two Arc::clone). Falls back to NotFound/Unknown
        // when no RPKI is configured.
        let validation = self.validation_rx.as_ref().map(|rx| rx.borrow().clone());

        // Compute ASPA state once per UPDATE for the IPv4-unicast body NLRI
        // surface. Other families compute their own state inside the
        // MP_REACH_NLRI handling below — draft-ietf-sidrops-aspa-
        // verification-25 §6.2 limits verification to IPv4/IPv6 unicast,
        // and `ValidationSnapshot::validate_aspa` returns `Unknown` for
        // every other family.
        //
        // NOTE: draft v25 §5.4 step 2 also requires that the most-recent
        // AS in `AS_PATH` equals the negotiated neighbor ASN, with a
        // transparent-route-server-client exception. rustbgpd does not
        // yet enforce this precondition (no `enforce-first-as`-equivalent
        // exists today); operators relying on ASPA against peers that
        // strip or rewrite the leftmost AS may see misleading verdicts.
        // Tracked as a follow-up.
        let body_aspa_state = validation
            .as_ref()
            .map_or(rustbgpd_wire::AspaValidation::Unknown, |v| {
                v.validate_aspa(parsed_as_path, (Afi::Ipv4, Safi::Unicast))
            });

        let unnumbered_ipv4_body_forbidden = self.is_scoped_link_local_peer();
        if unnumbered_ipv4_body_forbidden
            && (!parsed.announced.is_empty() || !parsed.withdrawn.is_empty())
        {
            warn!(
                peer = %self.peer_label,
                "Ignoring IPv4 body NLRI from scoped link-local peer; RFC 8950 requires MP_REACH_NLRI"
            );
        }

        // Body NLRI routes (IPv4). `import_decisions` collects every
        // evaluation — permit and deny — for the ADR-0073 explain cache.
        // The closure only borrows `self` immutably, so we accumulate
        // here and drain into `self.import_decision_cache` (a `&mut`
        // borrow) after the `.collect()` completes.
        //
        // `explain_enabled` gates the whole snapshot: when explain is
        // disabled this stays a single boolean check per NLRI and the
        // per-route attribute / modification clone never happens
        // (ADR-0073 write-path cost control).
        let explain_enabled = self.import_explain_enabled;
        let mut import_decisions: Vec<(ImportDecisionKey, CachedDecision)> = Vec::new();
        let mut announced: Vec<Route> =
            if unnumbered_ipv4_body_forbidden || otc_drop_unicast_announcements {
                Vec::new()
            } else {
                parsed
                    .announced
                    .iter()
                    .filter_map(|entry| {
                        let prefix = Prefix::V4(entry.prefix);
                        let rpki_state = validation
                            .as_ref()
                            .map_or(rustbgpd_wire::RpkiValidation::NotFound, |v| {
                                v.validate_rpki(&prefix, origin_asn)
                            });
                        let ctx = RouteContext {
                            prefix,
                            next_hop: Some(body_next_hop),
                            extended_communities: update_ecs,
                            communities: update_communities,
                            large_communities: update_large_communities,
                            as_path_str: &aspath_str,
                            as_path_len: aspath_len,
                            validation_state: rpki_state,
                            aspa_state: body_aspa_state,
                            peer_address: Some(self.peer_ip),
                            peer_asn: policy_peer_asn,
                            peer_group: self.config.peer_group.as_deref(),
                            route_type: policy_route_type,
                            evpn_route_type: None,
                            local_pref: policy_local_pref,
                            med: policy_med,
                        };
                        let (result, evaluation) = rustbgpd_policy::evaluate_chain_with_attribution(
                            self.import_policy.as_ref(),
                            &ctx,
                        );
                        record_import_policy_eval(
                            &self.metrics,
                            &self.peer_label,
                            &evaluation,
                            &mut import_policy_routes_permitted,
                            &mut import_policy_routes_denied,
                        );
                        // ADR-0073: record the decision before the
                        // permit gate so denies — the load-bearing
                        // explain case — are captured too. Gated on
                        // `explain_enabled` so a disabled deployment
                        // never pays the attribute / modification clone.
                        // `modifications` is cloned here because the
                        // permit path consumes it via
                        // `apply_modifications` just below.
                        if explain_enabled {
                            import_decisions.push((
                                ImportDecisionKey {
                                    afi: Afi::Ipv4,
                                    safi: Safi::Unicast,
                                    prefix,
                                    path_id: entry.path_id,
                                },
                                CachedDecision {
                                    outcome: result.action.into(),
                                    matched_policy: evaluation.matched_policy.clone(),
                                    rpki: rpki_state,
                                    aspa: body_aspa_state,
                                    pre_policy_attrs: (*attr_bundle.unicast).clone(),
                                    modifications: result.modifications.clone(),
                                    evaluated_at: SystemTime::now(),
                                    policy_generation: self.import_policy_generation,
                                },
                            ));
                        }
                        if result.action != rustbgpd_policy::PolicyAction::Permit {
                            return None;
                        }
                        let (attrs, nh_action) =
                            materialize_attrs(&attr_bundle.unicast, &result.modifications);
                        let next_hop = resolve_import_nexthop(
                            nh_action.as_ref(),
                            body_next_hop,
                            self.read_half.as_ref(),
                            &self.config,
                        );
                        Some(Route {
                            prefix,
                            next_hop,
                            link_local_next_hop: None,
                            next_hop_scope: self.link_local_next_hop_scope(next_hop),
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
                            validation_state: rpki_state,
                            aspa_state: body_aspa_state,
                        })
                    })
                    .collect()
            };

        // Drain the collected import decisions into the per-session
        // explain cache (ADR-0073). Now that the `.collect()` above has
        // released its immutable borrow of `self`, the `&mut
        // self.import_decision_cache` borrow is free.
        for (key, decision) in import_decisions {
            self.import_decision_cache.insert(key, decision);
        }

        // Body withdrawn routes (IPv4) — carry path_id for Add-Path peers
        let mut withdrawn: Vec<(Prefix, u32)> = if unnumbered_ipv4_body_forbidden {
            Vec::new()
        } else {
            parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect()
        };

        // MP-BGP NLRI from attributes. The MP families read the
        // body-NEXT_HOP-stripped variants from `attr_bundle` (`mp` for
        // FlowSpec / EVPN, `mp_unicast` for unicast) — the stripping
        // happens once in `RouteAttrBundle::new`.
        let mut flowspec_announced: Vec<FlowSpecRoute> = Vec::new();
        let mut flowspec_withdrawn: Vec<FlowSpecRule> = Vec::new();
        let mut evpn_announced: Vec<EvpnRibRoute> = Vec::new();
        let mut evpn_withdrawn: Vec<EvpnRouteKey> = Vec::new();

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

                    // ASPA state for this MP_REACH family. Per draft v25 §6.2,
                    // `ValidationSnapshot::validate_aspa` returns `Unknown` for
                    // anything outside IPv4/IPv6 unicast — so FlowSpec and
                    // EVPN announcements below propagate `Unknown` even when
                    // an ASPA table is loaded, without any extra branching.
                    let mp_aspa_state = validation
                        .as_ref()
                        .map_or(rustbgpd_wire::AspaValidation::Unknown, |v| {
                            v.validate_aspa(parsed_as_path, family)
                        });

                    if mp.safi == Safi::FlowSpec {
                        // FlowSpec announced routes — no next-hop (NH len = 0)
                        for rule in &mp.flowspec_announced {
                            // Apply import policy using the destination prefix
                            // component (if present) for prefix matching
                            let dest_prefix = rule.destination_prefix();
                            let fs_prefix = dest_prefix.unwrap_or(Prefix::V4(
                                rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
                            ));
                            let ctx = RouteContext {
                                prefix: fs_prefix,
                                next_hop: None,
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path_len: aspath_len,
                                validation_state: validation
                                    .as_ref()
                                    .map_or(rustbgpd_wire::RpkiValidation::NotFound, |v| {
                                        v.validate_rpki(&fs_prefix, origin_asn)
                                    }),
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                evpn_route_type: None,
                                local_pref: policy_local_pref,
                                med: policy_med,
                            };
                            let (result, evaluation) =
                                rustbgpd_policy::evaluate_chain_with_attribution(
                                    self.import_policy.as_ref(),
                                    &ctx,
                                );
                            record_import_policy_eval(
                                &self.metrics,
                                &self.peer_label,
                                &evaluation,
                                &mut import_policy_routes_permitted,
                                &mut import_policy_routes_denied,
                            );
                            if result.action == rustbgpd_policy::PolicyAction::Permit {
                                // FlowSpec stores an owned `Vec` (not `Arc`),
                                // so it can't share — but still skip the no-op
                                // apply when policy made no modifications.
                                let mut attrs = (*attr_bundle.mp).clone();
                                if !result.modifications.is_empty() {
                                    let _ = rustbgpd_policy::apply_modifications(
                                        &mut attrs,
                                        &result.modifications,
                                    );
                                }
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

                    if mp.safi == Safi::Evpn {
                        // EVPN announced routes — typed TLVs, not prefixes.
                        // Policy context uses a placeholder 0.0.0.0/0 prefix
                        // so RT / ext-community / AS_PATH match clauses work;
                        // match_prefix against the placeholder is effectively
                        // a no-op. RT-based filtering is the expected model.
                        let placeholder_prefix =
                            Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
                        for route in &mp.evpn_announced {
                            let ctx = RouteContext {
                                prefix: placeholder_prefix,
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path_len: aspath_len,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                evpn_route_type: Some(route.route_type()),
                                local_pref: policy_local_pref,
                                med: policy_med,
                            };
                            let (result, evaluation) =
                                rustbgpd_policy::evaluate_chain_with_attribution(
                                    self.import_policy.as_ref(),
                                    &ctx,
                                );
                            record_import_policy_eval(
                                &self.metrics,
                                &self.peer_label,
                                &evaluation,
                                &mut import_policy_routes_permitted,
                                &mut import_policy_routes_denied,
                            );
                            if result.action == rustbgpd_policy::PolicyAction::Permit {
                                // EVPN uses mp.next_hop, not the policy nh_action.
                                let (attrs, _) =
                                    materialize_attrs(&attr_bundle.mp, &result.modifications);
                                evpn_announced.push(EvpnRibRoute {
                                    route: route.clone(),
                                    next_hop: mp.next_hop,
                                    link_local_next_hop: mp.link_local_next_hop,
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
                                });
                            }
                        }
                        continue;
                    }

                    if otc_drop_unicast_announcements {
                        continue;
                    }

                    // Unicast routes
                    for entry in &mp.announced {
                        let mp_rpki_state = validation
                            .as_ref()
                            .map_or(rustbgpd_wire::RpkiValidation::NotFound, |v| {
                                v.validate_rpki(&entry.prefix, origin_asn)
                            });
                        let ctx = RouteContext {
                            prefix: entry.prefix,
                            next_hop: Some(mp.next_hop),
                            extended_communities: update_ecs,
                            communities: update_communities,
                            large_communities: update_large_communities,
                            as_path_str: &aspath_str,
                            as_path_len: aspath_len,
                            validation_state: mp_rpki_state,
                            aspa_state: mp_aspa_state,
                            peer_address: Some(self.peer_ip),
                            peer_asn: policy_peer_asn,
                            peer_group: self.config.peer_group.as_deref(),
                            route_type: policy_route_type,
                            evpn_route_type: None,
                            local_pref: policy_local_pref,
                            med: policy_med,
                        };
                        let (result, evaluation) = rustbgpd_policy::evaluate_chain_with_attribution(
                            self.import_policy.as_ref(),
                            &ctx,
                        );
                        record_import_policy_eval(
                            &self.metrics,
                            &self.peer_label,
                            &evaluation,
                            &mut import_policy_routes_permitted,
                            &mut import_policy_routes_denied,
                        );
                        // ADR-0073 (IPv6 / MP_REACH unicast): record the
                        // decision before the permit gate, gated on
                        // explain_enabled so the clone is skipped when
                        // disabled. Keyed by the MP family (afi from
                        // mp.afi, safi == Unicast here — FlowSpec / EVPN
                        // `continue` above and never reach this loop).
                        if explain_enabled {
                            self.import_decision_cache.insert(
                                ImportDecisionKey {
                                    afi: mp.afi,
                                    safi: mp.safi,
                                    prefix: entry.prefix,
                                    path_id: entry.path_id,
                                },
                                CachedDecision {
                                    outcome: result.action.into(),
                                    matched_policy: evaluation.matched_policy.clone(),
                                    rpki: mp_rpki_state,
                                    aspa: mp_aspa_state,
                                    pre_policy_attrs: (*attr_bundle.mp_unicast).clone(),
                                    modifications: result.modifications.clone(),
                                    evaluated_at: SystemTime::now(),
                                    policy_generation: self.import_policy_generation,
                                },
                            );
                        }
                        if result.action == rustbgpd_policy::PolicyAction::Permit {
                            let (attrs, nh_action) =
                                materialize_attrs(&attr_bundle.mp_unicast, &result.modifications);
                            let next_hop = resolve_import_nexthop(
                                nh_action.as_ref(),
                                mp.next_hop,
                                self.read_half.as_ref(),
                                &self.config,
                            );
                            let link_local_next_hop = if next_hop == mp.next_hop {
                                mp.link_local_next_hop
                            } else {
                                None
                            };
                            announced.push(Route {
                                prefix: entry.prefix,
                                next_hop,
                                link_local_next_hop,
                                next_hop_scope: self.link_local_next_hop_scope(next_hop),
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
                                validation_state: mp_rpki_state,
                                aspa_state: mp_aspa_state,
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
                    evpn_withdrawn.extend(mp.evpn_withdrawn.iter().map(EvpnRoute::key));
                }
                _ => {}
            }
        }

        // ADR-0073: tombstone any cached decision for a withdrawn prefix
        // as WITHDRAWN, so the explain surface distinguishes "seen then
        // withdrawn" from "never seen". Runs here — after the attribute
        // loop — so `withdrawn` already includes both IPv4 body and
        // IPv6 MP_UNREACH prefixes. AFI is derived per-prefix (the vec
        // mixes families); SAFI is unicast on this path. No-op for keys
        // the cache never held; skipped entirely when explain is off.
        if explain_enabled {
            for (prefix, path_id) in &withdrawn {
                let afi = match prefix {
                    Prefix::V4(_) => Afi::Ipv4,
                    Prefix::V6(_) => Afi::Ipv6,
                };
                self.import_decision_cache
                    .mark_withdrawn(&ImportDecisionKey {
                        afi,
                        safi: Safi::Unicast,
                        prefix: *prefix,
                        path_id: *path_id,
                    });
            }
        }

        // 4. Max-prefix enforcement — track via HashSet for accuracy.
        //    Counts unicast unique prefixes + FlowSpec rules + EVPN keys
        //    so a peer can't bypass the cap by flooding a non-unicast
        //    family.
        for &(prefix, path_id) in &withdrawn {
            self.known_paths.remove(&(prefix, path_id));
        }
        for route in &announced {
            self.known_paths.insert((route.prefix, route.path_id));
        }
        for rule in &flowspec_withdrawn {
            self.known_flowspec.remove(rule);
        }
        for route in &flowspec_announced {
            self.known_flowspec.insert(route.rule.clone());
        }
        for key in &evpn_withdrawn {
            self.known_evpn.remove(key);
        }
        for route in &evpn_announced {
            self.known_evpn.insert(route.key());
        }
        self.import_policy_routes_permitted = self
            .import_policy_routes_permitted
            .saturating_add(import_policy_routes_permitted);
        self.import_policy_routes_denied = self
            .import_policy_routes_denied
            .saturating_add(import_policy_routes_denied);

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
            || !evpn_announced.is_empty()
            || !evpn_withdrawn.is_empty()
        {
            let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                peer: self.peer_ip,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            });
        }

        // 5. Tell FSM about the update (restarts hold timer)
        self.drive_fsm(Event::UpdateReceived).await;
    }
}

#[cfg(test)]
mod policy_attr_summary_tests {
    use super::*;
    use rustbgpd_wire::{AsPathSegment, ExtendedCommunity, LargeCommunity};

    fn as_path(asns: Vec<u32>) -> AsPath {
        AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }
    }

    #[test]
    fn empty_attrs_use_defaults() {
        let attrs: Vec<PathAttribute> = Vec::new();
        let s = PolicyAttrSummary::from_route_attrs(&attrs);
        assert!(s.extended_communities.is_empty());
        assert!(s.communities.is_empty());
        assert!(s.large_communities.is_empty());
        assert!(s.as_path.is_none());
        assert_eq!(s.as_path_str, "");
        assert_eq!(s.as_path_len, 0);
        assert_eq!(s.origin_asn, None);
        assert_eq!(s.local_pref, None);
        assert_eq!(s.med, None);
    }

    #[test]
    fn extracts_each_field_in_one_pass() {
        let attrs = vec![
            PathAttribute::Communities(vec![100, 200]),
            PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(1)]),
            PathAttribute::LargeCommunities(vec![LargeCommunity::new(65001, 1, 2)]),
            PathAttribute::AsPath(as_path(vec![65001, 65002])),
            PathAttribute::LocalPref(150),
            PathAttribute::Med(42),
        ];
        let s = PolicyAttrSummary::from_route_attrs(&attrs);
        assert_eq!(s.communities, [100u32, 200].as_slice());
        assert_eq!(s.extended_communities.len(), 1);
        assert_eq!(s.large_communities.len(), 1);
        assert!(s.as_path.is_some());
        // The four AS_PATH-derived surfaces agree because they come from
        // the same first AS_PATH attribute.
        assert_eq!(s.as_path_str, "65001 65002");
        assert_eq!(s.as_path_len, 2);
        assert_eq!(s.origin_asn, Some(65002));
        assert_eq!(s.local_pref, Some(150));
        assert_eq!(s.med, Some(42));
    }

    /// The load-bearing guard for the `find_map` → single-pass change:
    /// first match wins for every attribute type, and a *later empty*
    /// community attribute must not blank out an earlier populated one
    /// (an `is_empty()` presence sentinel would have regressed this).
    #[test]
    fn first_match_wins_and_ignores_later_duplicates() {
        let attrs = vec![
            PathAttribute::Communities(vec![100, 200]),
            PathAttribute::Communities(Vec::new()), // later empty — must be ignored
            PathAttribute::AsPath(as_path(vec![65001])),
            PathAttribute::AsPath(as_path(vec![65002, 65003])), // later — must be ignored
            PathAttribute::LocalPref(100),
            PathAttribute::LocalPref(200), // later — must be ignored
            PathAttribute::Med(5),
            PathAttribute::Med(9), // later — must be ignored
        ];
        let s = PolicyAttrSummary::from_route_attrs(&attrs);
        assert_eq!(
            s.communities,
            [100u32, 200].as_slice(),
            "first populated community must survive a later empty one"
        );
        assert_eq!(s.as_path_str, "65001", "first AS_PATH wins");
        assert_eq!(s.as_path_len, 1);
        assert_eq!(s.origin_asn, Some(65001));
        assert_eq!(s.local_pref, Some(100), "first LOCAL_PREF wins");
        assert_eq!(s.med, Some(5), "first MED wins");
    }
}

#[cfg(test)]
mod route_attr_bundle_tests {
    use super::*;
    use rustbgpd_wire::{AsPath, AsPathSegment, Origin};

    fn base_attrs() -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Communities(vec![100]),
        ]
    }

    fn has_next_hop(attrs: &[PathAttribute]) -> bool {
        attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_)))
    }

    fn has_otc(attrs: &[PathAttribute]) -> bool {
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::OnlyToCustomer(_)))
    }

    #[test]
    fn bundle_variant_shapes_with_otc() {
        let bundle = RouteAttrBundle::new(&base_attrs(), Some(65002));
        // unicast: keeps body NEXT_HOP + carries OTC.
        assert!(has_next_hop(&bundle.unicast));
        assert!(has_otc(&bundle.unicast));
        // mp (FlowSpec/EVPN): NEXT_HOP stripped, NO OTC.
        assert!(!has_next_hop(&bundle.mp));
        assert!(!has_otc(&bundle.mp));
        // mp_unicast: NEXT_HOP stripped, OTC kept.
        assert!(!has_next_hop(&bundle.mp_unicast));
        assert!(has_otc(&bundle.mp_unicast));
    }

    #[test]
    fn bundle_variant_shapes_without_otc() {
        let bundle = RouteAttrBundle::new(&base_attrs(), None);
        assert!(has_next_hop(&bundle.unicast) && !has_otc(&bundle.unicast));
        assert!(!has_next_hop(&bundle.mp) && !has_otc(&bundle.mp));
        assert!(!has_next_hop(&bundle.mp_unicast) && !has_otc(&bundle.mp_unicast));
    }

    #[test]
    fn materialize_shares_arc_when_no_modifications() {
        let bundle = RouteAttrBundle::new(&base_attrs(), None);
        let mods = RouteModifications::default();
        let (attrs, nh) = materialize_attrs(&bundle.unicast, &mods);
        assert!(
            Arc::ptr_eq(&attrs, &bundle.unicast),
            "no-mods path must share the canonical Arc, not deep-clone"
        );
        assert!(nh.is_none(), "nh_action derives from set_next_hop only");
    }

    #[test]
    fn materialize_clones_and_applies_when_modified() {
        let bundle = RouteAttrBundle::new(&base_attrs(), None);
        let mods = RouteModifications {
            set_local_pref: Some(200),
            ..RouteModifications::default()
        };
        let (attrs, nh) = materialize_attrs(&bundle.unicast, &mods);
        assert!(
            !Arc::ptr_eq(&attrs, &bundle.unicast),
            "modified path must own a fresh Arc"
        );
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(200))),
            "set_local_pref modification must be applied"
        );
        assert!(nh.is_none(), "no set_next_hop → no nh_action");
    }
}
