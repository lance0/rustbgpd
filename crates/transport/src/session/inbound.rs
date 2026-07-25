use super::import_decision_cache::{CachedDecision, CachedPolicyContext, ImportDecisionKey};
use super::rejected_routes::RejectedRouteEntry;
use super::{
    Afi, AsPath, BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, BgpRole, Event, EvpnRibRoute,
    EvpnRoute, EvpnRouteKey, FlowSpecKey, FlowSpecRoute, Instant, IpAddr, Ipv4Addr,
    LabeledRibRoute, LabeledRibRouteKey, NextHopScope, NotificationCode, NotificationMessage,
    PathAttribute, PeerSession, Prefix, RibUpdate, Route, RtcRibRoute, RtcRibRouteKey, Safi,
    VpnRibRoute, VpnRibRouteKey, debug, info, is_ipv6_link_local, resolve_import_nexthop, warn,
};
use rustbgpd_policy::{
    NextHopAction, PolicyAction, PolicyEvaluation, RouteContext, RouteFamily, RouteModifications,
    RouteType,
};
use rustbgpd_telemetry::reason_labels::{
    ImportRejectReason, MalformedUpdateDisposition, NextHopOwnershipBlockReason, OtcBlockReason,
    RrLoopReason,
};
use rustbgpd_wire::{AspaValidationContext, ErrorDisposition, ParsedUpdate};
use std::sync::Arc;
use std::time::SystemTime;
/// Canonical `bgp_update_malformed_total` label for a wire-crate
/// RFC 7606 disposition.
fn malformed_disposition_label(disposition: ErrorDisposition) -> MalformedUpdateDisposition {
    match disposition {
        ErrorDisposition::AttributeDiscard => MalformedUpdateDisposition::AttributeDiscard,
        ErrorDisposition::TreatAsWithdraw => MalformedUpdateDisposition::TreatAsWithdraw,
        ErrorDisposition::SessionReset => MalformedUpdateDisposition::SessionReset,
    }
}
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
    // LAN-301: a fail-closed deny also counts on the eval-error
    // aggregate (direction × closed error kind). Error path only.
    if let Some(error) = &evaluation.eval_error {
        metrics.record_policy_eval_error("import", error.kind.label());
    }
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
    DropUnicastAnnouncements(OtcBlockReason),
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
fn bgpls_family_from_safi(safi: Safi) -> Option<BgpLsFamily> {
    match safi {
        Safi::BgpLs => Some(BgpLsFamily::LinkState),
        Safi::BgpLsVpn => Some(BgpLsFamily::LinkStateVpn),
        _ => None,
    }
}
/// The inner IP prefix of a VPN NLRI as an ordinary [`Prefix`], for honest
/// import-policy prefix matching (ADR-0077) — unlike BGP-LS, a VPN route has
/// a real prefix.
fn vpn_inner_prefix(prefix: &rustbgpd_wire::VpnPrefix) -> Prefix {
    match *prefix {
        rustbgpd_wire::VpnPrefix::V4 { addr, len } => {
            Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(addr, len))
        }
        rustbgpd_wire::VpnPrefix::V6 { addr, len } => {
            Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(addr, len))
        }
    }
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
fn otc_event_context(attrs: &[PathAttribute], reason: OtcBlockReason) -> (Option<u32>, String) {
    let otc_value = if reason == OtcBlockReason::MalformedLength {
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
        OtcState::MalformedLength => {
            OtcIngressAction::DropUnicastAnnouncements(OtcBlockReason::MalformedLength)
        }
        OtcState::Present(_) if matches!(local_role, BgpRole::Provider | BgpRole::RouteServer) => {
            OtcIngressAction::DropUnicastAnnouncements(OtcBlockReason::IngressFromCustomerRsclient)
        }
        OtcState::Present(asn)
            if local_role == BgpRole::Peer && remote_asn.is_some_and(|remote| asn != remote) =>
        {
            OtcIngressAction::DropUnicastAnnouncements(OtcBlockReason::IngressPeerMismatch)
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
/// ADR-0107 strict-peer `NEXT_HOP` ownership check for one decoded wire
/// next-hop identity (RFC 7948 §4.8).
///
/// The strict pilot accepts a form only when every address component of
/// its complete wire identity is the advertising session's own address:
///
/// - a global + link-local pair carries two address identities while the
///   session maps to exactly one, so one component is always
///   unverifiable — rejected rather than silently ignoring the
///   companion (ADR-0107 §2);
/// - a link-local next-hop is an identity only together with an
///   interface scope; without a scoped link-local session there is no
///   scope to map it to, so it fails closed regardless of value;
/// - everything else (classic IPv4, IPv6 global, RFC 8950
///   IPv4-over-IPv6) must equal the session address exactly.
///
/// Communities are invisible here by construction: a BLACKHOLE tag
/// cannot bypass the ownership gate (ADR-0107 §5).
fn strict_peer_next_hop_violation(
    session_addr: IpAddr,
    session_is_scoped_link_local: bool,
    next_hop: IpAddr,
    link_local_companion: Option<std::net::Ipv6Addr>,
) -> Option<NextHopOwnershipBlockReason> {
    if link_local_companion.is_some() {
        return Some(NextHopOwnershipBlockReason::UnverifiedLinkLocalCompanion);
    }
    if let IpAddr::V6(v6) = next_hop
        && is_ipv6_link_local(&v6)
        && !session_is_scoped_link_local
    {
        return Some(NextHopOwnershipBlockReason::UnscopedLinkLocal);
    }
    (next_hop != session_addr).then_some(NextHopOwnershipBlockReason::ForeignNextHop)
}
/// Hex rendering of the ENTIRE malformed UPDATE for the RFC 7606 §6
/// debug dump. Never truncated: the message came off the wire, so its
/// size is protocol-bounded (4096 bytes, or 65535 with Extended
/// Messages). Re-encodes the decoded sections — a byte-for-byte
/// reconstruction, since the header is fixed-form and the sections are
/// verbatim copies of the received body.
pub(crate) fn full_update_hex(update: &rustbgpd_wire::UpdateMessage) -> String {
    use std::fmt::Write as _;
    let mut wire = bytes::BytesMut::with_capacity(update.encoded_len());
    // A received message always fits the Extended-Messages bound, so
    // this cannot fail; an empty dump beats a panic on an error path.
    if update.encode_with_limit(&mut wire, u16::MAX).is_err() {
        return String::new();
    }
    let mut out = String::with_capacity(wire.len() * 2);
    for byte in &wire {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
/// Enumerate every NLRI the revised parse recovered from a malformed
/// UPDATE — body IPv4 and each MP family, announcements and
/// withdrawals, with Add-Path path IDs where present — per the
/// RFC 7606 §6 guidance to list the NLRI involved. Renders only what
/// the parse already produced: an MP attribute that was itself
/// malformed is absent here and covered by the full-message hex.
pub(crate) fn involved_nlri(parsed: &ParsedUpdate) -> String {
    fn with_path_id(path_id: u32, rendered: String) -> String {
        if path_id == 0 {
            rendered
        } else {
            format!("{rendered} path-id {path_id}")
        }
    }
    fn section(out: &mut String, label: &str, items: &[String]) {
        if items.is_empty() {
            return;
        }
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(label);
        out.push_str("=[");
        out.push_str(&items.join(", "));
        out.push(']');
    }
    let mut out = String::new();
    section(
        &mut out,
        "ipv4_unicast_announced",
        &parsed
            .announced
            .iter()
            .map(|e| with_path_id(e.path_id, e.prefix.to_string()))
            .collect::<Vec<_>>(),
    );
    section(
        &mut out,
        "ipv4_unicast_withdrawn",
        &parsed
            .withdrawn
            .iter()
            .map(|e| with_path_id(e.path_id, e.prefix.to_string()))
            .collect::<Vec<_>>(),
    );
    for attr in &parsed.attributes {
        let (direction, afi, safi, items) = match attr {
            PathAttribute::MpReachNlri(mp) => (
                "announced",
                mp.afi,
                mp.safi,
                mp.announced
                    .iter()
                    .map(|e| with_path_id(e.path_id, e.prefix.to_string()))
                    .chain(mp.flowspec_announced.iter().map(ToString::to_string))
                    .chain(mp.evpn_announced.iter().map(|r| format!("{r:?}")))
                    .chain(mp.bgpls_announced.iter().map(|r| format!("{r:?}")))
                    .chain(
                        mp.vpn_announced
                            .iter()
                            .map(|e| with_path_id(e.path_id, format!("{:?}", e.nlri))),
                    )
                    .chain(
                        mp.labeled_announced
                            .iter()
                            .map(|e| with_path_id(e.path_id, format!("{:?}", e.nlri))),
                    )
                    .chain(mp.rtc_announced.iter().map(ToString::to_string))
                    .collect::<Vec<_>>(),
            ),
            PathAttribute::MpUnreachNlri(mp) => (
                "withdrawn",
                mp.afi,
                mp.safi,
                mp.withdrawn
                    .iter()
                    .map(|e| with_path_id(e.path_id, e.prefix.to_string()))
                    .chain(mp.flowspec_withdrawn.iter().map(ToString::to_string))
                    .chain(mp.evpn_withdrawn.iter().map(|r| format!("{r:?}")))
                    .chain(mp.bgpls_withdrawn.iter().map(|r| format!("{r:?}")))
                    .chain(
                        mp.vpn_withdrawn
                            .iter()
                            .map(|e| with_path_id(e.path_id, format!("{:?}", e.nlri))),
                    )
                    .chain(
                        mp.labeled_withdrawn
                            .iter()
                            .map(|e| with_path_id(e.path_id, format!("{:?}", e.nlri))),
                    )
                    .chain(mp.rtc_withdrawn.iter().map(ToString::to_string))
                    .collect::<Vec<_>>(),
            ),
            _ => continue,
        };
        let family = format!("{afi:?}_{safi:?}").to_lowercase();
        section(&mut out, &format!("{family}_{direction}"), &items);
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
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
/// `pub(super)` (not private): the explain command handler in
/// `super::commands` reuses this exact extraction to rebuild the
/// evaluation-time `RouteContext` from a cached decision's pre-policy
/// attributes — sharing the extractor (instead of duplicating it) is
/// what guarantees the re-derived statement trace sees the same
/// context fields the live evaluation saw. Visibility-only change;
/// the hot path is untouched.
pub(super) struct PolicyAttrSummary<'a> {
    pub(super) extended_communities: &'a [rustbgpd_wire::ExtendedCommunity],
    pub(super) communities: &'a [u32],
    pub(super) large_communities: &'a [rustbgpd_wire::LargeCommunity],
    as_path: Option<&'a AsPath>,
    pub(super) as_path_str: String,
    pub(super) as_path_len: usize,
    origin_asn: Option<u32>,
    pub(super) local_pref: Option<u32>,
    pub(super) med: Option<u32>,
}
impl<'a> PolicyAttrSummary<'a> {
    /// `needs_as_path_string` gates the `as_path_str` build (String +
    /// per-ASN `to_string` + join): callers pass the session's cached
    /// `import_needs_as_path_string` so an import chain with no
    /// `AS_PATH` regex terms (or no chain at all) never pays for it —
    /// the same `requires_as_path_string` gate the export-side RIB
    /// distribution modules apply. When `false`, `as_path_str` is
    /// empty; `as_path_len` / `origin_asn` are still extracted (cheap,
    /// and RPKI/ASPA need them regardless of policy).
    pub(super) fn from_route_attrs(attrs: &'a [PathAttribute], needs_as_path_string: bool) -> Self {
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
            as_path_str: if needs_as_path_string {
                as_path.map(AsPath::to_aspath_string).unwrap_or_default()
            } else {
                String::new()
            },
            as_path_len: as_path.map_or(0, AsPath::len),
            origin_asn: as_path.and_then(AsPath::origin_asn),
            local_pref,
            med,
        }
    }
    pub(super) fn to_cached_context(&self) -> CachedPolicyContext {
        CachedPolicyContext {
            extended_communities: self.extended_communities.to_vec(),
            communities: self.communities.to_vec(),
            large_communities: self.large_communities.to_vec(),
            as_path: self.as_path.cloned(),
            as_path_len: self.as_path_len,
            origin_asn: self.origin_asn,
            local_pref: self.local_pref,
            med: self.med,
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
    /// Return unicast announcement identities that this session would accept
    /// from the UPDATE's wire surfaces before policy or safety checks.
    fn eligible_unicast_announcements(&self, parsed: &ParsedUpdate) -> Vec<(Prefix, u32)> {
        let mut identities = if self.is_scoped_link_local_peer() {
            Vec::new()
        } else {
            parsed
                .announced
                .iter()
                .map(|entry| (Prefix::V4(entry.prefix), entry.path_id))
                .collect()
        };
        for attr in &parsed.attributes {
            let PathAttribute::MpReachNlri(mp) = attr else {
                continue;
            };
            let family = (mp.afi, mp.safi);
            if mp.safi != Safi::Unicast
                || !matches!(mp.afi, Afi::Ipv4 | Afi::Ipv6)
                || !self.negotiated_families.contains(&family)
                || family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4()
            {
                continue;
            }
            identities.extend(
                mp.announced
                    .iter()
                    .map(|entry| (entry.prefix, entry.path_id)),
            );
        }
        identities
    }

    /// ADR-0107 strict-peer pre-policy gate: return the first announced
    /// unicast wire form whose complete next-hop identity does not belong
    /// to this session, as `(reason, next_hop, link_local_companion)`.
    ///
    /// Only forms the import loops below would accept are inspected —
    /// the same gates as [`Self::eligible_unicast_announcements`]
    /// (negotiated family, IPv4-MP extended next-hop, no body NLRI on a
    /// scoped link-local session). `body_next_hop` is the value the
    /// body-NLRI import loop evaluates: the decoded wire `NEXT_HOP`
    /// when present, else the session's own address — which is
    /// self-consistent by definition. Runs before import policy can
    /// rewrite anything, so a policy rewrite can never launder an
    /// unauthorized wire value (ADR-0107 §3).
    fn next_hop_ownership_violation(
        &self,
        parsed: &ParsedUpdate,
        body_next_hop: IpAddr,
    ) -> Option<(
        NextHopOwnershipBlockReason,
        IpAddr,
        Option<std::net::Ipv6Addr>,
    )> {
        let scoped = self.is_scoped_link_local_peer();
        if !parsed.announced.is_empty()
            && !scoped
            && let Some(reason) =
                strict_peer_next_hop_violation(self.peer_ip, scoped, body_next_hop, None)
        {
            return Some((reason, body_next_hop, None));
        }
        for attr in &parsed.attributes {
            let PathAttribute::MpReachNlri(mp) = attr else {
                continue;
            };
            let family = (mp.afi, mp.safi);
            if mp.announced.is_empty()
                || mp.safi != Safi::Unicast
                || !matches!(mp.afi, Afi::Ipv4 | Afi::Ipv6)
                || !self.negotiated_families.contains(&family)
                || family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4()
            {
                continue;
            }
            if let Some(reason) = strict_peer_next_hop_violation(
                self.peer_ip,
                scoped,
                mp.next_hop,
                mp.link_local_next_hop,
            ) {
                return Some((reason, mp.next_hop, mp.link_local_next_hop));
            }
        }
        None
    }

    /// LAN-472: retain one rejected unicast identity in the bounded
    /// per-session store. AFI derives from the prefix; SAFI is unicast —
    /// retention covers the unicast member-support surface only,
    /// matching the v1 `ExplainImportPolicy` scope.
    fn retain_rejected_route(&mut self, prefix: Prefix, path_id: u32, entry: RejectedRouteEntry) {
        let afi = match prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        };
        self.rejected_routes.insert(
            ImportDecisionKey {
                afi,
                safi: Safi::Unicast,
                prefix,
                path_id,
            },
            entry,
        );
    }

    /// Build a retention entry for a pre-policy gate rejection from the
    /// parsed UPDATE's attributes (LAN-472). Called only after a reject
    /// actually occurred, so the AS-path string build and community
    /// clones cost nothing on the clean hot path. Validation states are
    /// left at their defaults: the gate fired before (and independently
    /// of) RPKI/ASPA evaluation.
    fn gate_reject_entry(
        parsed: &ParsedUpdate,
        reason: ImportRejectReason,
        detail: Option<&str>,
        next_hop: Option<IpAddr>,
    ) -> RejectedRouteEntry {
        let mut as_path = String::new();
        let mut communities: Vec<u32> = Vec::new();
        let mut large_communities: Vec<rustbgpd_wire::LargeCommunity> = Vec::new();
        for attr in &parsed.attributes {
            match attr {
                PathAttribute::AsPath(p) if as_path.is_empty() => {
                    as_path = p.to_aspath_string();
                }
                PathAttribute::Communities(c) if communities.is_empty() => {
                    communities.clone_from(c);
                }
                PathAttribute::LargeCommunities(c) if large_communities.is_empty() => {
                    large_communities.clone_from(c);
                }
                _ => {}
            }
        }
        let mut entry = RejectedRouteEntry {
            reason,
            detail: detail.map(str::to_owned),
            next_hop,
            as_path,
            communities,
            communities_dropped: 0,
            large_communities,
            large_communities_dropped: 0,
            rpki: rustbgpd_wire::RpkiValidation::NotFound,
            aspa: rustbgpd_wire::AspaValidation::Unknown,
            rejected_at: SystemTime::now(),
        };
        // Bound before the caller clones it across every rejected
        // identity, so the clones are ≤ the per-entry budget too.
        entry.enforce_bounds();
        entry
    }

    /// Build the bounded prototype shared by one UPDATE's retained rejects.
    #[allow(clippy::unused_self, reason = "test-only build counter uses self")]
    fn build_rejected_route_prototype(
        &self,
        (as_path, communities, large_communities): (
            Option<&AsPath>,
            &[u32],
            &[rustbgpd_wire::LargeCommunity],
        ),
    ) -> RejectedRouteEntry {
        #[cfg(test)]
        self.rejected_route_prototype_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut prototype = RejectedRouteEntry {
            reason: ImportRejectReason::PolicyReject,
            detail: None,
            next_hop: None,
            as_path: as_path.map(AsPath::to_aspath_string).unwrap_or_default(),
            communities: communities.to_vec(),
            communities_dropped: 0,
            large_communities: large_communities.to_vec(),
            large_communities_dropped: 0,
            rpki: rustbgpd_wire::RpkiValidation::NotFound,
            aspa: rustbgpd_wire::AspaValidation::Unknown,
            rejected_at: SystemTime::now(),
        };
        prototype.enforce_bounds();
        prototype
    }

    /// Deliver a `RoutesReceived` batch to the RIB manager — block, never
    /// drop (ADR-0078). The fast path is a `try_send`; when the channel
    /// is full the saturation counter increments and the session task
    /// parks on `send().await`. Parking here is the contract: the select
    /// loop stops reading the TCP socket, the kernel receive window
    /// fills, and the sender is paced — overload is shed to the party
    /// that can slow down instead of becoming a silently dropped batch
    /// (a permanently missing route or a permanently stale one). The
    /// peer's hold timer stays fed by the writer-owned KEEPALIVE
    /// cadence while parked.
    ///
    /// `Err` means the RIB manager is gone (daemon shutdown) — the
    /// caller should abandon the rest of its turn.
    pub(super) async fn deliver_routes_to_rib(&self, update: RibUpdate) -> Result<(), ()> {
        match self.rib_tx.try_send(update) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(update)) => {
                self.metrics
                    .record_inbound_rib_backpressure(&self.peer_label);
                debug!(
                    peer = %self.peer_label,
                    "RIB channel full; session parks until the RIB drains (TCP backpressure)"
                );
                self.rib_tx.send(update).await.map_err(|_| ())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(()),
        }
    }
    /// Maximum message length we may SEND to this peer: 65535 if the PEER
    /// advertised Extended Messages, otherwise 4096 (RFC 8654 §2 — the
    /// peer's capability governs our outbound sizes). The inbound limit is
    /// governed by OUR advertised capability and lives on the framing
    /// buffer (see the `SessionEstablished` arm in fsm.rs).
    pub(super) fn outbound_max_message_len(&self) -> u16 {
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
    /// Check whether a prefix's address family is among the negotiated families.
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
    pub(super) fn aspa_validation_context(&self) -> AspaValidationContext {
        let local_role = self.config.peer.local_role;
        AspaValidationContext {
            neighbor_asn: local_role.map(|_| {
                self.negotiated
                    .as_ref()
                    .map_or(self.config.peer.remote_asn, |n| n.peer_asn)
            }),
            local_role,
            first_as_check_exempt: matches!(local_role, Some(BgpRole::RouteServerClient)),
        }
    }
    /// Return the received and negotiated ASNs when an IPv4/IPv6-unicast
    /// UPDATE between role-aware, four-octet-AS-capable eBGP speakers fails
    /// the ASPA first-AS precondition. Roleless sessions keep their
    /// compatibility behavior, and an RS-client remains exempt for a
    /// transparent route server / IX.
    pub(super) fn aspa_first_as_mismatch(
        &self,
        four_octet_as: bool,
        is_ebgp: bool,
        has_unicast_announcements: bool,
        attrs: &[PathAttribute],
    ) -> Option<(Option<u32>, u32)> {
        if !four_octet_as || !is_ebgp || !has_unicast_announcements {
            return None;
        }
        let context = self.aspa_validation_context();
        if context.first_as_check_exempt {
            return None;
        }
        let neighbor_asn = context.neighbor_asn?;
        let path = attrs.iter().find_map(|attr| match attr {
            PathAttribute::AsPath(path) => Some(path),
            _ => None,
        })?;
        if path
            .segments
            .iter()
            .any(|segment| matches!(segment, rustbgpd_wire::AsPathSegment::AsSet(_)))
        {
            return None;
        }
        let received_first_as = path.segments.iter().find_map(|segment| match segment {
            rustbgpd_wire::AsPathSegment::AsSequence(asns) => asns.first().copied(),
            rustbgpd_wire::AsPathSegment::AsSet(_) => None,
        });
        (received_first_as != Some(neighbor_asn)).then_some((received_first_as, neighbor_asn))
    }
    /// RFC 7606 treat-as-withdraw primitive: drop every announcement carried
    /// in the UPDATE, withdraw any previously accepted route those
    /// announcements replace, process the explicit withdrawals normally
    /// (unicast, `FlowSpec`, EVPN, BGP-LS, L3VPN, labeled-unicast, and RTC —
    /// no family may accumulate stale state downstream), and leave the
    /// session Established. Shared by the AS_PATH-loop, reflection-loop,
    /// and RFC 7606 malformed-attribute paths.
    #[expect(
        clippy::too_many_lines,
        reason = "one withdraw-conversion pass per address family over the same sequence"
    )]
    async fn treat_update_as_withdraw(
        &mut self,
        parsed: &ParsedUpdate,
        reject_reason: ImportRejectReason,
        reject_detail: Option<&str>,
    ) {
        let rejected_unicast = self.eligible_unicast_announcements(parsed);
        let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
            .withdrawn
            .iter()
            .map(|e| (Prefix::V4(e.prefix), e.path_id))
            .collect();
        let mut loop_fs_withdrawn: Vec<FlowSpecKey> = Vec::new();
        let mut loop_fs_rejected: Vec<FlowSpecKey> = Vec::new();
        let mut loop_evpn_withdrawn: Vec<EvpnRouteKey> = Vec::new();
        let mut loop_evpn_rejected: Vec<EvpnRouteKey> = Vec::new();
        let mut loop_bgpls_withdrawn: Vec<BgpLsRouteKey> = Vec::new();
        let mut loop_bgpls_rejected: Vec<BgpLsRouteKey> = Vec::new();
        let mut loop_l3vpn_withdrawn: Vec<VpnRibRouteKey> = Vec::new();
        let mut loop_l3vpn_rejected: Vec<VpnRibRouteKey> = Vec::new();
        let mut loop_labeled_withdrawn: Vec<LabeledRibRouteKey> = Vec::new();
        let mut loop_labeled_rejected: Vec<LabeledRibRouteKey> = Vec::new();
        let mut loop_rtc_withdrawn: Vec<RtcRibRouteKey> = Vec::new();
        let mut loop_rtc_rejected: Vec<RtcRibRouteKey> = Vec::new();
        for attr in &parsed.attributes {
            if let PathAttribute::MpUnreachNlri(mp) = attr {
                let family = (mp.afi, mp.safi);
                if self.negotiated_families.contains(&family) {
                    loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                    loop_fs_withdrawn.extend(
                        mp.flowspec_withdrawn
                            .iter()
                            .cloned()
                            .map(|rule| FlowSpecKey { afi: mp.afi, rule }),
                    );
                    loop_evpn_withdrawn.extend(mp.evpn_withdrawn.iter().map(EvpnRoute::key));
                    if let Some(bgpls_family) = bgpls_family_from_safi(mp.safi) {
                        loop_bgpls_withdrawn.extend(mp.bgpls_withdrawn.iter().map(|nlri| {
                            BgpLsRouteKey {
                                family: bgpls_family,
                                nlri: nlri.key(),
                                path_id: 0,
                            }
                        }));
                    }
                    if mp.safi == Safi::MplsVpn {
                        loop_l3vpn_withdrawn.extend(mp.vpn_withdrawn.iter().map(|entry| {
                            VpnRibRouteKey {
                                nlri_key: entry.nlri.key(),
                                path_id: entry.path_id,
                            }
                        }));
                    }
                    if mp.safi == Safi::LabeledUnicast {
                        loop_labeled_withdrawn.extend(mp.labeled_withdrawn.iter().map(|entry| {
                            LabeledRibRouteKey {
                                prefix: entry.nlri.key(),
                                path_id: entry.path_id,
                            }
                        }));
                    }
                    if mp.safi == Safi::RtConstrain {
                        loop_rtc_withdrawn.extend(mp.rtc_withdrawn.iter().map(|nlri| {
                            RtcRibRouteKey {
                                nlri: *nlri,
                                path_id: 0,
                            }
                        }));
                    }
                }
            }
            if let PathAttribute::MpReachNlri(mp) = attr
                && let Some(bgpls_family) = bgpls_family_from_safi(mp.safi)
                && self.negotiated_families.contains(&(mp.afi, mp.safi))
            {
                loop_bgpls_rejected.extend(mp.bgpls_announced.iter().map(|nlri| BgpLsRouteKey {
                    family: bgpls_family,
                    nlri: nlri.key(),
                    path_id: 0,
                }));
            }
            // A loop-rejected announcement replaces only an exact route
            // that this session previously accepted.
            if let PathAttribute::MpReachNlri(mp) = attr
                && mp.safi == Safi::MplsVpn
                && self.negotiated_families.contains(&(mp.afi, mp.safi))
            {
                loop_l3vpn_rejected.extend(mp.vpn_announced.iter().map(|entry| VpnRibRouteKey {
                    nlri_key: entry.nlri.key(),
                    path_id: entry.path_id,
                }));
            }
            if let PathAttribute::MpReachNlri(mp) = attr
                && mp.safi == Safi::LabeledUnicast
                && self.negotiated_families.contains(&(mp.afi, mp.safi))
            {
                loop_labeled_rejected.extend(mp.labeled_announced.iter().map(|entry| {
                    LabeledRibRouteKey {
                        prefix: entry.nlri.key(),
                        path_id: entry.path_id,
                    }
                }));
            }
            if let PathAttribute::MpReachNlri(mp) = attr
                && mp.safi == Safi::RtConstrain
                && self.negotiated_families.contains(&(mp.afi, mp.safi))
            {
                loop_rtc_rejected.extend(mp.rtc_announced.iter().map(|nlri| RtcRibRouteKey {
                    nlri: *nlri,
                    path_id: 0,
                }));
            }
            // FlowSpec and EVPN announcements get the same rejected→withdraw
            // conversion as the other MP families: RFC 7606 §2 requires the
            // UPDATE's routes to be treated as withdrawn, so a previously
            // accepted route re-announced here must leave the RIB. The
            // family-specific announced vectors are only populated for their
            // own SAFI, so the negotiated-family check is the only guard.
            if let PathAttribute::MpReachNlri(mp) = attr
                && self.negotiated_families.contains(&(mp.afi, mp.safi))
            {
                loop_fs_rejected.extend(
                    mp.flowspec_announced
                        .iter()
                        .cloned()
                        .map(|rule| FlowSpecKey { afi: mp.afi, rule }),
                );
                loop_evpn_rejected.extend(mp.evpn_announced.iter().map(EvpnRoute::key));
            }
        }
        for &(prefix, path_id) in &loop_withdrawn {
            self.forget_known_path(prefix, path_id);
        }
        for &(prefix, path_id) in &rejected_unicast {
            if self.forget_known_path(prefix, path_id) {
                loop_withdrawn.push((prefix, path_id));
            }
        }
        if self.import_explain_enabled {
            for &(prefix, path_id) in &loop_withdrawn {
                let afi = match prefix {
                    Prefix::V4(_) => Afi::Ipv4,
                    Prefix::V6(_) => Afi::Ipv6,
                };
                self.import_decision_cache
                    .mark_withdrawn(&ImportDecisionKey {
                        afi,
                        safi: Safi::Unicast,
                        prefix,
                        path_id,
                    });
            }
        }
        // LAN-472: the retention store follows the same conversion.
        // Explicit withdrawals (and replaced identities) clear any
        // retained reject first, then every unicast announcement this
        // UPDATE carried is retained under the shared gate reason —
        // same-identity overlap nets to the reject, the current truth.
        if self.reject_retention_enabled {
            if !self.rejected_routes.is_empty() {
                for &(prefix, path_id) in &loop_withdrawn {
                    let afi = match prefix {
                        Prefix::V4(_) => Afi::Ipv4,
                        Prefix::V6(_) => Afi::Ipv6,
                    };
                    self.rejected_routes.remove(&ImportDecisionKey {
                        afi,
                        safi: Safi::Unicast,
                        prefix,
                        path_id,
                    });
                }
            }
            if !rejected_unicast.is_empty() {
                let entry = Self::gate_reject_entry(parsed, reject_reason, reject_detail, None);
                for &(prefix, path_id) in &rejected_unicast {
                    self.retain_rejected_route(prefix, path_id, entry.clone());
                }
            }
            self.metrics
                .set_rejected_routes_retained(&self.peer_label, self.rejected_routes.len());
        }
        for rule in &loop_fs_withdrawn {
            self.known_flowspec.remove(rule);
        }
        for rule in loop_fs_rejected {
            if self.known_flowspec.remove(&rule) {
                loop_fs_withdrawn.push(rule);
            }
        }
        for key in &loop_evpn_withdrawn {
            self.known_evpn.remove(key);
        }
        for key in loop_evpn_rejected {
            if self.known_evpn.remove(&key) {
                loop_evpn_withdrawn.push(key);
            }
        }
        for key in &loop_bgpls_withdrawn {
            self.known_bgpls.remove(key);
        }
        for key in loop_bgpls_rejected {
            if self.known_bgpls.remove(&key) {
                loop_bgpls_withdrawn.push(key);
            }
        }
        for key in &loop_l3vpn_withdrawn {
            self.known_vpn.remove(key);
        }
        for key in loop_l3vpn_rejected {
            if self.known_vpn.remove(&key) {
                loop_l3vpn_withdrawn.push(key);
            }
        }
        for key in &loop_labeled_withdrawn {
            self.known_labeled.remove(key);
        }
        for key in loop_labeled_rejected {
            if self.known_labeled.remove(&key) {
                loop_labeled_withdrawn.push(key);
            }
        }
        for key in &loop_rtc_withdrawn {
            self.known_rtc.remove(key);
        }
        for key in loop_rtc_rejected {
            if self.known_rtc.remove(&key) {
                loop_rtc_withdrawn.push(key);
            }
        }
        // This RFC 7606/loop-rejection path only removes accepted routes and
        // therefore does not call max-prefix enforcement. Publish after its
        // complete accounting transaction and before the first awaited RIB
        // delivery so actor state and gauges cannot diverge on backpressure or
        // channel failure.
        self.sync_max_prefix_capacity_metrics();
        if !loop_withdrawn.is_empty()
            || !loop_fs_withdrawn.is_empty()
            || !loop_evpn_withdrawn.is_empty()
        {
            let refresh_delta = self.capture_routes_refresh_delta(
                &[],
                &loop_withdrawn,
                &[],
                &loop_fs_withdrawn,
                &[],
                &loop_evpn_withdrawn,
            );
            if self
                .deliver_routes_to_rib(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                    evpn_announced: vec![],
                    evpn_withdrawn: loop_evpn_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !loop_bgpls_withdrawn.is_empty() {
            let refresh_delta = self.capture_bgpls_refresh_delta(&[], &loop_bgpls_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::BgpLsRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vec![],
                    withdrawn: loop_bgpls_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !loop_l3vpn_withdrawn.is_empty() {
            let refresh_delta = self.capture_vpn_refresh_delta(&[], &loop_l3vpn_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::VpnRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vec![],
                    withdrawn: loop_l3vpn_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !loop_labeled_withdrawn.is_empty() {
            let refresh_delta = self.capture_labeled_refresh_delta(&[], &loop_labeled_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::LabeledRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vec![],
                    withdrawn: loop_labeled_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !loop_rtc_withdrawn.is_empty() {
            let refresh_delta = self.capture_rtc_refresh_delta(&[], &loop_rtc_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::RtcRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vec![],
                    withdrawn: loop_rtc_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        self.drive_fsm(Event::UpdateReceived).await;
    }
    /// RFC 7606 §6 debugging facility: capture the entire malformed
    /// UPDATE message and list the NLRI involved, for offline analysis.
    /// DEBUG-only by design: a hostile peer can trigger this once per
    /// UPDATE, so it must never land at info/warn where it would spam
    /// operators. The full-message hex is protocol-bounded (4096 bytes,
    /// or 65535 with Extended Messages), so it needs no artificial cap.
    /// The `tracing` macro skips all rendering when DEBUG is disabled.
    fn debug_dump_malformed_update(
        &self,
        update: &rustbgpd_wire::UpdateMessage,
        parsed: &ParsedUpdate,
    ) {
        debug!(
            peer = %self.peer_label,
            nlri_involved = %involved_nlri(parsed),
            update_message_hex = %full_update_hex(update),
            "malformed UPDATE captured in full (RFC 7606 §6 debugging facility)"
        );
    }
    /// Parse an UPDATE message, validate attributes, apply import policy,
    /// enforce max-prefix limit, send routes to RIB, and feed the
    /// appropriate event to the FSM.
    #[expect(
        clippy::too_many_lines,
        reason = "UPDATE handling keeps decode, validation, import policy, RIB enqueue, and FSM side effects ordered"
    )]
    pub(super) async fn process_update(&mut self, update: rustbgpd_wire::UpdateMessage) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);
        let mut import_policy_routes_permitted = 0_u64;
        let mut import_policy_routes_denied = 0_u64;
        // Check if Add-Path receive is negotiated for IPv4 unicast (body NLRI)
        let add_path_ipv4 = self
            .add_path_receive_families
            .contains(&(Afi::Ipv4, Safi::Unicast));
        // 1. Structural decode — RFC 7606 revised error handling: recoverable
        // per-attribute malformations are collected alongside the parse
        // instead of aborting it. `Err` stays reserved for session-reset-class
        // problems (RFC 7606 §3 (j), §5.3): syntactically incorrect NLRI /
        // Withdrawn Routes fields, or a malformed or duplicated
        // MP_REACH_NLRI / MP_UNREACH_NLRI whose NLRI cannot be located.
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);
        let revised = match update.parse_revised(
            four_octet_as,
            !is_ebgp,
            add_path_ipv4,
            &self.add_path_receive_families,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(peer = %self.peer_label, error = %e, "UPDATE decode error");
                // parse_revised reserves Err for session-reset-class
                // malformations (RFC 7606 §3 (j), §5.3).
                self.metrics.record_update_malformed(
                    &self.peer_label,
                    MalformedUpdateDisposition::SessionReset,
                );
                self.drive_fsm(Event::DecodeError(e)).await;
                return;
            }
        };
        let malformed = revised.malformed;
        let parsed = revised.update;
        for m in &malformed {
            warn!(
                peer = %self.peer_label,
                attr_type = m.type_code,
                disposition = m.disposition.as_str(),
                error = %m.error,
                "malformed path attribute (RFC 7606 revised error handling)"
            );
        }
        if !malformed.is_empty() {
            self.debug_dump_malformed_update(&update, &parsed);
        }
        // RFC 7606 §3 (h): when multiple attribute errors exist, the approach
        // with the strongest action wins.
        let mut disposition = malformed.iter().map(|m| m.disposition).max();
        // Observe recoverable BGP-LS NLRI discards (RFC 9552 fault management,
        // PR #616): known NLRIs with out-of-order descriptor TLVs are dropped
        // while the session survives. Fatal framing errors take the Err arm
        // above, so this counter never conflates the two.
        if parsed.bgpls_nlri_discarded > 0 {
            debug!(
                peer = %self.peer_label,
                family = "bgp_ls",
                discarded = parsed.bgpls_nlri_discarded,
                "discarded malformed BGP-LS NLRIs with out-of-order descriptor TLVs"
            );
            self.metrics.record_bgpls_nlri_discarded(
                &self.peer_label,
                u64::from(parsed.bgpls_nlri_discarded),
            );
        }
        // 2. Semantic validation. Two distinct MP_REACH_NLRI facts feed
        // two different consumers and must not be conflated: the
        // attribute validator keys mandatory-attribute rules off
        // attribute PRESENCE (an UPDATE that carries an MP_REACH at all
        // must carry ORIGIN / AS_PATH), while the RFC 7606 §5.2
        // reachability gate below needs NLRI CONTENT — an MP_REACH that
        // encodes zero NLRI provides no reachable NLRI, and its mere
        // presence must not shield a treat-as-withdraw-class error from
        // the mandated session reset (treat-as-withdraw would withdraw
        // nothing).
        let has_mp_reach_attr = parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(_)));
        let mp_reach_carries_nlri = parsed.attributes.iter().any(|a| match a {
            PathAttribute::MpReachNlri(mp) => {
                !mp.announced.is_empty()
                    || !mp.flowspec_announced.is_empty()
                    || !mp.evpn_announced.is_empty()
                    || !mp.bgpls_announced.is_empty()
                    || !mp.vpn_announced.is_empty()
                    || !mp.labeled_announced.is_empty()
                    || !mp.rtc_announced.is_empty()
            }
            _ => false,
        });
        let has_body_nlri = !parsed.announced.is_empty();
        let has_nlri = has_body_nlri || has_mp_reach_attr;
        let validation_options = rustbgpd_wire::UpdateValidationOptions {
            allow_ipv4_link_local_mp_reach_next_hop: self.is_scoped_link_local_peer()
                && self.use_extended_nexthop_ipv4(),
        };
        let mut validation_payload: Option<(u8, Vec<u8>)> = None;
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
                disposition = update_err.disposition.as_str(),
                "UPDATE validation error"
            );
            self.debug_dump_malformed_update(&update, &parsed);
            if update_err.disposition == ErrorDisposition::SessionReset {
                self.metrics.record_update_malformed(
                    &self.peer_label,
                    MalformedUpdateDisposition::SessionReset,
                );
                let notif = NotificationMessage::new(
                    NotificationCode::UpdateMessage,
                    update_err.subcode,
                    bytes::Bytes::from(update_err.data),
                );
                self.drive_fsm(Event::UpdateValidationError(notif)).await;
                return;
            }
            disposition = disposition.max(Some(update_err.disposition));
            validation_payload = Some((update_err.subcode, update_err.data));
        }
        // Apply the strongest RFC 7606 disposition. Attribute-discard needs no
        // action here — the offending attributes were already omitted from
        // `parsed.attributes` and the UPDATE proceeds without them (§2).
        // Treat-as-withdraw removes every route the UPDATE carries while the
        // session stays Established.
        if disposition >= Some(ErrorDisposition::TreatAsWithdraw) {
            // RFC 7606 §5.2: an UPDATE with path attributes but no reachable
            // NLRI encoded gives no confidence that its NLRI was parsed
            // successfully; for any error stronger than attribute-discard the
            // session-reset approach MUST be used instead. "Encoded" means
            // actual NLRI content — an MP_REACH_NLRI attribute carrying zero
            // NLRI counts as no reachable NLRI.
            if parsed.announced.is_empty() && !mp_reach_carries_nlri {
                warn!(
                    peer = %self.peer_label,
                    "treat-as-withdraw with no reachable NLRI — session reset (RFC 7606 §5.2)"
                );
                self.metrics.record_update_malformed(
                    &self.peer_label,
                    MalformedUpdateDisposition::SessionReset,
                );
                if let Some(m) = malformed
                    .iter()
                    .find(|m| m.disposition == ErrorDisposition::TreatAsWithdraw)
                {
                    self.drive_fsm(Event::DecodeError(m.error.clone())).await;
                } else {
                    let (subcode, data) = validation_payload.unwrap_or((
                        rustbgpd_wire::notification::update_subcode::MALFORMED_ATTRIBUTE_LIST,
                        Vec::new(),
                    ));
                    let notif = NotificationMessage::new(
                        NotificationCode::UpdateMessage,
                        subcode,
                        bytes::Bytes::from(data),
                    );
                    self.drive_fsm(Event::UpdateValidationError(notif)).await;
                }
                return;
            }
            warn!(
                peer = %self.peer_label,
                announced = parsed.announced.len(),
                "treat-as-withdraw — withdrawing the routes carried in the malformed UPDATE"
            );
            self.metrics.record_update_malformed(
                &self.peer_label,
                MalformedUpdateDisposition::TreatAsWithdraw,
            );
            self.treat_update_as_withdraw(&parsed, ImportRejectReason::TreatAsWithdraw, None)
                .await;
            return;
        }
        // Weaker than treat-as-withdraw: the only remaining non-clean
        // disposition is attribute-discard — the offending attributes were
        // dropped and the UPDATE proceeds without them.
        if let Some(applied) = disposition {
            self.metrics
                .record_update_malformed(&self.peer_label, malformed_disposition_label(applied));
        }
        // draft-ietf-sidrops-aspa-verification-26 §5: between role-aware,
        // four-octet-AS-capable eBGP speakers, an AS_PATH whose most recently
        // added AS is not the negotiated neighbor AS is semantically invalid
        // and SHALL use RFC 7606 treat-as-withdraw. Section 6.2 scopes ASPA
        // verification to IPv4/IPv6 unicast. Apply this before policy/ASPA
        // state so the disposition cannot depend on an operator policy or
        // cache snapshot.
        let has_unicast_announcements = !parsed.announced.is_empty()
            || parsed.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    PathAttribute::MpReachNlri(mp)
                        if matches!(mp.afi, Afi::Ipv4 | Afi::Ipv6)
                            && mp.safi == Safi::Unicast
                            && !mp.announced.is_empty()
                )
            });
        if let Some((received_first_as, neighbor_asn)) = self.aspa_first_as_mismatch(
            four_octet_as,
            is_ebgp,
            has_unicast_announcements,
            &parsed.attributes,
        ) {
            warn!(
                peer = %self.peer_label,
                received_first_as = ?received_first_as,
                neighbor_asn,
                "ASPA first-AS precondition failed; treating UPDATE as withdraw"
            );
            self.metrics.record_update_malformed(
                &self.peer_label,
                MalformedUpdateDisposition::TreatAsWithdraw,
            );
            self.treat_update_as_withdraw(
                &parsed,
                ImportRejectReason::TreatAsWithdraw,
                Some("aspa_first_as_mismatch"),
            )
            .await;
            return;
        }
        // 3. End-of-RIB detection (RFC 4724 §2). An UPDATE that only became
        // empty because malformed attributes were discarded is junk, not an
        // EoR signal — require a clean decode.
        if parsed.announced.is_empty() && parsed.withdrawn.is_empty() && malformed.is_empty() {
            // IPv4 EoR: empty UPDATE (no NLRI, no withdrawn, no attributes)
            if parsed.attributes.is_empty() {
                info!(peer = %self.peer_label, family = "ipv4_unicast", "received End-of-RIB");
                self.received_eor_families
                    .insert((Afi::Ipv4, Safi::Unicast));
                let _ = self
                    .rib_tx
                    .send(RibUpdate::EndOfRib {
                        peer: self.peer_ip,
                        session_id: self.session_identity.id,
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
                && mp.bgpls_withdrawn.is_empty()
                && mp.vpn_withdrawn.is_empty()
                && mp.labeled_withdrawn.is_empty()
                && mp.rtc_withdrawn.is_empty()
            {
                info!(
                    peer = %self.peer_label,
                    afi = ?mp.afi,
                    safi = ?mp.safi,
                    "received End-of-RIB"
                );
                self.received_eor_families.insert((mp.afi, mp.safi));
                let _ = self
                    .rib_tx
                    .send(RibUpdate::EndOfRib {
                        peer: self.peer_ip,
                        session_id: self.session_identity.id,
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
        let otc_rejected_unicast = if otc_drop_unicast_announcements {
            self.eligible_unicast_announcements(&parsed)
        } else {
            Vec::new()
        };
        if let OtcIngressAction::DropUnicastAnnouncements(reason) = otc_action {
            // Count every unicast prefix the OTC rule rejected: body NLRI
            // (always IPv4) plus IPv4/IPv6 unicast MP_REACH_NLRI. Other
            // families are out of scope for OTC.
            let rejected = parsed.announced.len()
                + parsed
                    .attributes
                    .iter()
                    .filter_map(|attr| {
                        if let PathAttribute::MpReachNlri(mp) = attr
                            && ((mp.afi, mp.safi) == (Afi::Ipv4, Safi::Unicast)
                                || (mp.afi, mp.safi) == (Afi::Ipv6, Safi::Unicast))
                        {
                            Some(mp.announced.len())
                        } else {
                            None
                        }
                    })
                    .sum::<usize>();
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
                    reason = reason.as_str(),
                    rejected,
                    "OTC route-leak rule rejected unicast announcements; withdrawals still processed"
                );
                self.record_otc_routes_blocked(reason, rejected as u64);
                if self.event_sink().wants_otc_route_blocked() {
                    // The prefix strings are event-only payload. Build them
                    // only for sinks that retain structured events; the
                    // counter/log path above remains allocation-light when
                    // event history is disabled.
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
                            blocked_prefixes
                                .extend(mp.announced.iter().map(|entry| entry.prefix.to_string()));
                        }
                    }
                    // Publish the structured event AFTER the counter +
                    // per-NeighborState scalar update, so a sink that drops
                    // (queue_full / closed) can never leave the legacy
                    // surfaces inconsistent.
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
        }
        // ADR-0107: route-server strict-peer NEXT_HOP ownership. Inspects
        // the immutable decoded wire next-hop before import policy can
        // rewrite it (RFC 7948 §4.8). Skipped when OTC already dropped
        // this UPDATE's unicast announcements — the treat-as-withdraw
        // identity sets would be identical.
        let next_hop_ownership_rejection =
            if self.config.next_hop_ownership_strict_peer && !otc_drop_unicast_announcements {
                self.next_hop_ownership_violation(&parsed, body_next_hop)
            } else {
                None
            };
        let ownership_drop_unicast_announcements = next_hop_ownership_rejection.is_some();
        let ownership_rejected_unicast = if ownership_drop_unicast_announcements {
            self.eligible_unicast_announcements(&parsed)
        } else {
            Vec::new()
        };
        if let Some((reason, next_hop, link_local)) = next_hop_ownership_rejection {
            warn!(
                peer = %self.peer_label,
                reason = reason.as_str(),
                next_hop = %next_hop,
                link_local_next_hop = ?link_local,
                rejected = ownership_rejected_unicast.len(),
                prefixes = ?ownership_rejected_unicast,
                "strict-peer next-hop ownership rejected unicast announcements \
                 (ADR-0107); withdrawals still processed"
            );
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
                        PathAttribute::MpReachNlri(mp) => Some(
                            mp.announced.len()
                                + mp.bgpls_announced.len()
                                + mp.vpn_announced.len()
                                + mp.labeled_announced.len()
                                + mp.rtc_announced.len(),
                        ),
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
            // Covers unicast, FlowSpec, EVPN, and BGP-LS — the AS_PATH-loop branch must
            // not silently drop withdrawals for any family, or stale non-unicast state
            // accumulates downstream until the next session reset / refresh.
            self.treat_update_as_withdraw(&parsed, ImportRejectReason::AsPathLoop, None)
                .await;
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
                RrLoopReason::OriginatorId
            } else {
                RrLoopReason::ClusterList
            };
            debug!(
                peer = %self.peer_label,
                reason = reason.as_str(),
                "Route reflector loop detected — discarding announcements"
            );
            self.metrics.record_rr_loop_detected(&self.peer_label);
            // Still process withdrawals (same pattern as AS_PATH loop).
            // Covers unicast, FlowSpec, EVPN, and BGP-LS — the reflected-loop
            // detection must not silently drop withdrawals for any family,
            // or stale state accumulates downstream.
            self.treat_update_as_withdraw(
                &parsed,
                ImportRejectReason::RrLoop,
                Some(reason.as_str()),
            )
            .await;
            return;
        }
        // Normalize the attributes that policy and the RIB are allowed to
        // observe. MP_REACH/MP_UNREACH are per-UPDATE framing, not per-route
        // attributes. RFC 4271 §5.1.5 also requires a LOCAL_PREF received
        // from an external peer to be ignored (rustbgpd has no confederation
        // exception), so strip it before policy context, explain caching, and
        // every family-specific stored-route path. Import policy may still add
        // a locally configured LOCAL_PREF via `materialize_attrs` below.
        //
        // The pre-policy BMP tap deliberately retains the original wire
        // attribute: `process_read_buffer` emits its byte-exact raw UPDATE
        // before calling `process_update`, matching RFC 7854's unprocessed
        // Adj-RIB-In view.
        let route_attrs: Vec<PathAttribute> = parsed
            .attributes
            .iter()
            .filter(|a| {
                !(matches!(
                    a,
                    PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
                ) || is_ebgp && matches!(a, PathAttribute::LocalPref(_)))
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
        let explain_enabled = self.import_explain_enabled;
        let policy_summary =
            PolicyAttrSummary::from_route_attrs(&route_attrs, self.import_needs_as_path_string);
        let cached_policy_context = explain_enabled.then(|| policy_summary.to_cached_context());
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
        } = policy_summary;
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
        // draft v25 §5.4 step 2 also requires the most-recent AS in `AS_PATH`
        // to equal the negotiated neighbor ASN, with a transparent-route-
        // server-client exception. That leftmost-AS precondition is enforced
        // here whenever a local BGP Role is configured (the role-aware
        // context carries the neighbor ASN and the RS-client exemption); the
        // roleless case keeps the legacy behavior and skips it.
        let aspa_context = self.aspa_validation_context();
        let body_aspa_state = validation
            .as_ref()
            .map_or(rustbgpd_wire::AspaValidation::Unknown, |v| {
                v.validate_aspa(parsed_as_path, (Afi::Ipv4, Safi::Unicast), aspa_context)
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
        // per-route context / modification clone never happens
        // (ADR-0073 write-path cost control).
        let mut import_decisions: Vec<(ImportDecisionKey, CachedDecision)> = Vec::new();
        // LAN-472: policy denies retained for the looking-glass reject
        // surface, accumulated here (body-NLRI closure borrows `self`
        // immutably) and drained into the bounded store after the
        // explicit-withdrawal removal pass below. Entry construction
        // happens only on an actual deny, so the clean permit path pays
        // nothing.
        let retention_enabled = self.reject_retention_enabled;
        // One bounded attribute summary per UPDATE. It is initialized on the
        // first actual policy, OTC, or ownership rejection; clean permitted
        // UPDATEs avoid the AS-path render, community copies, and timestamp.
        let reject_proto_attrs = (parsed_as_path, update_communities, update_large_communities);
        let mut reject_proto: Option<RejectedRouteEntry> = None;
        let mut rejected_retained: Vec<(Prefix, u32, RejectedRouteEntry)> = Vec::new();
        // A denied announcement replaces any prior accepted path under the
        // same wire identity; retire it after explicit withdrawals below.
        let mut denied_unicast: Vec<(Prefix, u32)> = Vec::new();
        let mut announced: Vec<Route> = if unnumbered_ipv4_body_forbidden
            || otc_drop_unicast_announcements
            || ownership_drop_unicast_announcements
        {
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
                        prefix: Some(prefix),
                        next_hop: Some(body_next_hop),
                        extended_communities: update_ecs,
                        communities: update_communities,
                        large_communities: update_large_communities,
                        as_path_str: &aspath_str,
                        as_path: parsed_as_path,
                        as_path_len: aspath_len,
                        origin_asn,
                        validation_state: rpki_state,
                        aspa_state: body_aspa_state,
                        peer_address: Some(self.peer_ip),
                        peer_asn: policy_peer_asn,
                        peer_group: self.config.peer_group.as_deref(),
                        route_type: policy_route_type,
                        family: Some(RouteFamily::Ipv4Unicast),
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
                    // never pays the context / modification clone.
                    // `modifications` is cloned here because the
                    // permit path consumes it via
                    // `apply_modifications` just below.
                    if let Some(policy_context) = cached_policy_context.as_ref() {
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
                                policy_context: policy_context.clone(),
                                next_hop: Some(body_next_hop),
                                modifications: result.modifications.clone(),
                                evaluated_at: SystemTime::now(),
                                policy_generation: self.import_policy_generation,
                            },
                        ));
                    }
                    if result.action != rustbgpd_policy::PolicyAction::Permit {
                        if retention_enabled {
                            let proto = reject_proto.get_or_insert_with(|| {
                                self.build_rejected_route_prototype(reject_proto_attrs)
                            });
                            let mut reject_entry = proto.clone();
                            reject_entry.detail.clone_from(&evaluation.matched_policy);
                            reject_entry.next_hop = Some(body_next_hop);
                            reject_entry.rpki = rpki_state;
                            reject_entry.aspa = body_aspa_state;
                            rejected_retained.push((prefix, entry.path_id, reject_entry));
                        }
                        denied_unicast.push((prefix, entry.path_id));
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
                        aspa_context,
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
        let mut flowspec_withdrawn: Vec<FlowSpecKey> = Vec::new();
        let mut denied_flowspec: Vec<FlowSpecKey> = Vec::new();
        let mut evpn_announced: Vec<EvpnRibRoute> = Vec::new();
        let mut evpn_withdrawn: Vec<EvpnRouteKey> = Vec::new();
        let mut policy_denied_evpn: Vec<EvpnRouteKey> = Vec::new();
        let mut bgpls_announced: Vec<BgpLsRibRoute> = Vec::new();
        let mut bgpls_withdrawn: Vec<BgpLsRouteKey> = Vec::new();
        let mut denied_bgpls: Vec<BgpLsRouteKey> = Vec::new();
        let mut vpn_announced: Vec<VpnRibRoute> = Vec::new();
        let mut vpn_withdrawn: Vec<VpnRibRouteKey> = Vec::new();
        let mut denied_vpn: Vec<VpnRibRouteKey> = Vec::new();
        let mut labeled_announced: Vec<LabeledRibRoute> = Vec::new();
        let mut labeled_withdrawn: Vec<LabeledRibRouteKey> = Vec::new();
        let mut denied_labeled: Vec<LabeledRibRouteKey> = Vec::new();
        let mut rtc_announced: Vec<RtcRibRoute> = Vec::new();
        let mut rtc_withdrawn: Vec<RtcRibRouteKey> = Vec::new();
        let mut denied_rtc: Vec<RtcRibRouteKey> = Vec::new();
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
                            v.validate_aspa(parsed_as_path, family, aspa_context)
                        });
                    if mp.safi == Safi::FlowSpec {
                        // FlowSpec announced routes — no next-hop (NH len = 0)
                        for rule in &mp.flowspec_announced {
                            // Apply import policy using the destination prefix
                            // component (if present) for prefix matching.
                            let dest_prefix = rule.destination_prefix();
                            let ctx = RouteContext {
                                prefix: dest_prefix,
                                next_hop: None,
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: validation
                                    .as_ref()
                                    .zip(dest_prefix.as_ref())
                                    .map_or(
                                        rustbgpd_wire::RpkiValidation::NotFound,
                                        |(v, prefix)| v.validate_rpki(prefix, origin_asn),
                                    ),
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                            } else {
                                denied_flowspec.push(FlowSpecKey {
                                    afi: mp.afi,
                                    rule: rule.clone(),
                                });
                            }
                        }
                        continue;
                    }
                    if mp.safi == Safi::Evpn {
                        // EVPN Types 1-4 are prefixless for policy purposes;
                        // Type 5 carries a real IP prefix (RFC 9136).
                        for route in &mp.evpn_announced {
                            let policy_prefix = match route {
                                rustbgpd_wire::EvpnRoute::IpPrefix(t5) => match t5.prefix {
                                    rustbgpd_wire::EvpnIpPrefixValue::V4(p) => Some(Prefix::V4(p)),
                                    rustbgpd_wire::EvpnIpPrefixValue::V6(p) => Some(Prefix::V6(p)),
                                },
                                _ => None,
                            };
                            let ctx = RouteContext {
                                prefix: policy_prefix,
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                            } else {
                                policy_denied_evpn.push(route.key());
                            }
                        }
                        continue;
                    }
                    if let Some(bgpls_family) = bgpls_family_from_safi(mp.safi) {
                        // BGP-LS announced routes — opaque topology objects,
                        // not unicast prefixes. Prefix predicates therefore do
                        // not match; AS_PATH/community/RT predicates still
                        // operate on the real path attributes.
                        for nlri in &mp.bgpls_announced {
                            let ctx = RouteContext {
                                prefix: None,
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                                let (attrs, _) =
                                    materialize_attrs(&attr_bundle.mp, &result.modifications);
                                bgpls_announced.push(BgpLsRibRoute {
                                    family: bgpls_family,
                                    nlri: nlri.clone(),
                                    next_hop: mp.next_hop,
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
                            } else {
                                denied_bgpls.push(BgpLsRouteKey {
                                    family: bgpls_family,
                                    nlri: nlri.key(),
                                    path_id: 0,
                                });
                            }
                        }
                        continue;
                    }
                    if mp.safi == Safi::MplsVpn {
                        // VPNv4/VPNv6 announced routes (RFC 4364 / RFC 4659).
                        // Unlike BGP-LS, the policy context carries the real
                        // inner prefix (ADR-0077 honest policy context).
                        for entry in &mp.vpn_announced {
                            let ctx = RouteContext {
                                prefix: Some(vpn_inner_prefix(&entry.nlri.prefix)),
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                                let (attrs, _) =
                                    materialize_attrs(&attr_bundle.mp, &result.modifications);
                                vpn_announced.push(VpnRibRoute {
                                    nlri: entry.nlri.clone(),
                                    next_hop: mp.next_hop,
                                    // Carry the RFC 4659 two-address IPv6
                                    // link-local half so VPNv6 reflection
                                    // re-emits it (LAN-217).
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
                                    path_id: entry.path_id,
                                });
                            } else {
                                denied_vpn.push(VpnRibRouteKey {
                                    nlri_key: entry.nlri.key(),
                                    path_id: entry.path_id,
                                });
                            }
                        }
                        continue;
                    }
                    if mp.safi == Safi::LabeledUnicast {
                        // Labeled-unicast announced routes (RFC 8277). The
                        // policy context carries the real prefix — a labeled
                        // route IS an IP prefix (ADR-0077 honest policy
                        // context).
                        for entry in &mp.labeled_announced {
                            let ctx = RouteContext {
                                prefix: Some(entry.nlri.prefix),
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                                let (attrs, _) =
                                    materialize_attrs(&attr_bundle.mp, &result.modifications);
                                labeled_announced.push(LabeledRibRoute {
                                    nlri: entry.nlri.clone(),
                                    next_hop: mp.next_hop,
                                    // Carry the RFC 8950 two-address IPv6
                                    // link-local half so labeled IPv6
                                    // reflection re-emits it (LAN-190).
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
                                    path_id: entry.path_id,
                                });
                            } else {
                                denied_labeled.push(LabeledRibRouteKey {
                                    prefix: entry.nlri.key(),
                                    path_id: entry.path_id,
                                });
                            }
                        }
                        continue;
                    }
                    if mp.safi == Safi::RtConstrain {
                        // RT-Constrain announced routes (RFC 4684). Like
                        // BGP-LS, the policy context carries no prefix — an
                        // RT membership NLRI has no IP prefix to match on.
                        for nlri in &mp.rtc_announced {
                            let ctx = RouteContext {
                                prefix: None,
                                next_hop: Some(mp.next_hop),
                                extended_communities: update_ecs,
                                communities: update_communities,
                                large_communities: update_large_communities,
                                as_path_str: &aspath_str,
                                as_path: parsed_as_path,
                                as_path_len: aspath_len,
                                origin_asn,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                                aspa_state: mp_aspa_state,
                                peer_address: Some(self.peer_ip),
                                peer_asn: policy_peer_asn,
                                peer_group: self.config.peer_group.as_deref(),
                                route_type: policy_route_type,
                                // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                                family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                                let (attrs, _) =
                                    materialize_attrs(&attr_bundle.mp, &result.modifications);
                                rtc_announced.push(RtcRibRoute {
                                    nlri: *nlri,
                                    next_hop: mp.next_hop,
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
                            } else {
                                denied_rtc.push(RtcRibRouteKey {
                                    nlri: *nlri,
                                    path_id: 0,
                                });
                            }
                        }
                        continue;
                    }
                    if otc_drop_unicast_announcements || ownership_drop_unicast_announcements {
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
                            prefix: Some(entry.prefix),
                            next_hop: Some(mp.next_hop),
                            extended_communities: update_ecs,
                            communities: update_communities,
                            large_communities: update_large_communities,
                            as_path_str: &aspath_str,
                            as_path: parsed_as_path,
                            as_path_len: aspath_len,
                            origin_asn,
                            validation_state: mp_rpki_state,
                            aspa_state: mp_aspa_state,
                            peer_address: Some(self.peer_ip),
                            peer_asn: policy_peer_asn,
                            peer_group: self.config.peer_group.as_deref(),
                            route_type: policy_route_type,
                            // Typed family from the MP_REACH AFI/SAFI (LAN-295).
                            family: RouteFamily::from_afi_safi(mp.afi, mp.safi),
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
                        if let Some(policy_context) = cached_policy_context.as_ref() {
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
                                    policy_context: policy_context.clone(),
                                    next_hop: Some(mp.next_hop),
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
                                aspa_context,
                            });
                        } else {
                            if retention_enabled {
                                let proto = reject_proto.get_or_insert_with(|| {
                                    self.build_rejected_route_prototype(reject_proto_attrs)
                                });
                                let mut reject_entry = proto.clone();
                                reject_entry.detail.clone_from(&evaluation.matched_policy);
                                reject_entry.next_hop = Some(mp.next_hop);
                                reject_entry.rpki = mp_rpki_state;
                                reject_entry.aspa = mp_aspa_state;
                                rejected_retained.push((entry.prefix, entry.path_id, reject_entry));
                            }
                            denied_unicast.push((entry.prefix, entry.path_id));
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
                    flowspec_withdrawn.extend(
                        mp.flowspec_withdrawn
                            .iter()
                            .cloned()
                            .map(|rule| FlowSpecKey { afi: mp.afi, rule }),
                    );
                    evpn_withdrawn.extend(mp.evpn_withdrawn.iter().map(EvpnRoute::key));
                    if let Some(bgpls_family) = bgpls_family_from_safi(mp.safi) {
                        bgpls_withdrawn.extend(mp.bgpls_withdrawn.iter().map(|nlri| {
                            BgpLsRouteKey {
                                family: bgpls_family,
                                nlri: nlri.key(),
                                path_id: 0,
                            }
                        }));
                    }
                    if mp.safi == Safi::MplsVpn {
                        vpn_withdrawn.extend(mp.vpn_withdrawn.iter().map(|entry| VpnRibRouteKey {
                            nlri_key: entry.nlri.key(),
                            path_id: entry.path_id,
                        }));
                    }
                    if mp.safi == Safi::LabeledUnicast {
                        labeled_withdrawn.extend(mp.labeled_withdrawn.iter().map(|entry| {
                            LabeledRibRouteKey {
                                prefix: entry.nlri.key(),
                                path_id: entry.path_id,
                            }
                        }));
                    }
                    if mp.safi == Safi::RtConstrain {
                        rtc_withdrawn.extend(mp.rtc_withdrawn.iter().map(|nlri| RtcRibRouteKey {
                            nlri: *nlri,
                            path_id: 0,
                        }));
                    }
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
        // 4. Max-prefix enforcement — ordinary unicast uses the compact
        //    prefix set; negotiated Add-Path receive families retain exact
        //    identities plus per-prefix refcounts. Counts unicast unique
        //    prefixes + FlowSpec rules + EVPN keys so a peer can't bypass the
        //    cap by flooding a non-unicast family.
        for &(prefix, path_id) in &withdrawn {
            self.forget_known_path(prefix, path_id);
        }
        // LAN-472: an explicit withdrawal clears any retained reject for
        // the identity — the peer no longer announces it, so "why isn't
        // it accepted?" is moot. Runs before the reject inserts below,
        // so a same-UPDATE withdraw+reject nets to the reject (the
        // current truth). `withdrawn` holds only explicit withdrawals at
        // this point; the rejected identities are appended after.
        if self.reject_retention_enabled && !self.rejected_routes.is_empty() {
            for &(prefix, path_id) in &withdrawn {
                let afi = match prefix {
                    Prefix::V4(_) => Afi::Ipv4,
                    Prefix::V6(_) => Afi::Ipv6,
                };
                self.rejected_routes.remove(&ImportDecisionKey {
                    afi,
                    safi: Safi::Unicast,
                    prefix,
                    path_id,
                });
            }
        }
        // LAN-472: retain the pre-policy safety rejections under their
        // gate reason. One shared entry per gate, derived from the
        // bounded per-UPDATE prototype — the attribute summary is
        // identical across the rejected identities, so each identity
        // clones the ≤ 512 B prototype instead of re-deriving it.
        if retention_enabled {
            if let OtcIngressAction::DropUnicastAnnouncements(otc_reason) = otc_action
                && !otc_rejected_unicast.is_empty()
            {
                let proto = reject_proto
                    .get_or_insert_with(|| self.build_rejected_route_prototype(reject_proto_attrs));
                let mut entry = proto.clone();
                entry.reason = ImportRejectReason::OtcRouteLeak;
                entry.detail = Some(otc_reason.as_str().to_owned());
                for &(prefix, path_id) in &otc_rejected_unicast {
                    self.retain_rejected_route(prefix, path_id, entry.clone());
                }
            }
            if let Some((ownership_reason, violating_next_hop, _)) = next_hop_ownership_rejection
                && !ownership_rejected_unicast.is_empty()
            {
                let proto = reject_proto
                    .get_or_insert_with(|| self.build_rejected_route_prototype(reject_proto_attrs));
                let mut entry = proto.clone();
                entry.reason = ImportRejectReason::NextHopOwnership;
                entry.detail = Some(ownership_reason.as_str().to_owned());
                entry.next_hop = Some(violating_next_hop);
                for &(prefix, path_id) in &ownership_rejected_unicast {
                    self.retain_rejected_route(prefix, path_id, entry.clone());
                }
            }
        }
        // A pre-policy safety rejection replaces any prior accepted route
        // under the same wire identity. Explicit withdrawals above win on
        // overlap; first-seen rejected announcements remain silent.
        for (prefix, path_id) in otc_rejected_unicast {
            if self.forget_known_path(prefix, path_id) {
                withdrawn.push((prefix, path_id));
                if explain_enabled {
                    let afi = match prefix {
                        Prefix::V4(_) => Afi::Ipv4,
                        Prefix::V6(_) => Afi::Ipv6,
                    };
                    self.import_decision_cache
                        .mark_withdrawn(&ImportDecisionKey {
                            afi,
                            safi: Safi::Unicast,
                            prefix,
                            path_id,
                        });
                }
            }
        }
        // ADR-0107 §3: identical replacement semantics for the ownership
        // gate — retire only the exact prior accepted (prefix, path_id)
        // identity; a first-seen rejection emits no withdrawal. Disjoint
        // from the OTC set by construction (the ownership check is
        // skipped when OTC already dropped this UPDATE).
        for (prefix, path_id) in ownership_rejected_unicast {
            if self.forget_known_path(prefix, path_id) {
                withdrawn.push((prefix, path_id));
                if explain_enabled {
                    let afi = match prefix {
                        Prefix::V4(_) => Afi::Ipv4,
                        Prefix::V6(_) => Afi::Ipv6,
                    };
                    self.import_decision_cache
                        .mark_withdrawn(&ImportDecisionKey {
                            afi,
                            safi: Safi::Unicast,
                            prefix,
                            path_id,
                        });
                }
            }
        }
        // `forget_known_path` gates first-seen denies and also deduplicates an
        // explicit withdrawal for the same identity in this UPDATE.
        for (prefix, path_id) in denied_unicast {
            if self.forget_known_path(prefix, path_id) {
                withdrawn.push((prefix, path_id));
            }
        }
        for route in &announced {
            self.remember_known_path(route.prefix, route.path_id);
        }
        // LAN-472: retain the policy denies (body + MP unicast), clear
        // any stale reject for identities accepted this UPDATE, then
        // refresh the gauge once. Empty when retention is disabled.
        for (prefix, path_id, entry) in rejected_retained {
            self.retain_rejected_route(prefix, path_id, entry);
        }
        if self.reject_retention_enabled {
            if !self.rejected_routes.is_empty() {
                for route in &announced {
                    let afi = match route.prefix {
                        Prefix::V4(_) => Afi::Ipv4,
                        Prefix::V6(_) => Afi::Ipv6,
                    };
                    self.rejected_routes.remove(&ImportDecisionKey {
                        afi,
                        safi: Safi::Unicast,
                        prefix: route.prefix,
                        path_id: route.path_id,
                    });
                }
            }
            self.metrics
                .set_rejected_routes_retained(&self.peer_label, self.rejected_routes.len());
        }
        for key in &flowspec_withdrawn {
            self.known_flowspec.remove(key);
        }
        for key in denied_flowspec {
            if self.known_flowspec.remove(&key) {
                flowspec_withdrawn.push(key);
            }
        }
        for route in &flowspec_announced {
            self.known_flowspec.insert(route.selection_key());
        }
        for key in &evpn_withdrawn {
            self.known_evpn.remove(key);
        }
        for key in policy_denied_evpn {
            if self.known_evpn.remove(&key) {
                evpn_withdrawn.push(key);
            }
        }
        for route in &evpn_announced {
            self.known_evpn.insert(route.key());
        }
        for key in &bgpls_withdrawn {
            self.known_bgpls.remove(key);
        }
        for key in denied_bgpls {
            if self.known_bgpls.remove(&key) {
                bgpls_withdrawn.push(key);
            }
        }
        for route in &bgpls_announced {
            self.known_bgpls.insert(route.key());
        }
        for key in &vpn_withdrawn {
            self.known_vpn.remove(key);
        }
        for key in denied_vpn {
            if self.known_vpn.remove(&key) {
                vpn_withdrawn.push(key);
            }
        }
        for route in &vpn_announced {
            // Keyed by (RD+prefix, path_id): under VPN Add-Path each received
            // path counts toward max-prefix separately. Deliberately stricter
            // than unicast's unique-prefix refcount — over-counting tears the
            // session down earlier, never lets a peer bypass the cap.
            self.known_vpn.insert(route.key());
        }
        for key in &labeled_withdrawn {
            self.known_labeled.remove(key);
        }
        for key in denied_labeled {
            if self.known_labeled.remove(&key) {
                labeled_withdrawn.push(key);
            }
        }
        for route in &labeled_announced {
            // Keyed by (prefix, path_id): under labeled Add-Path each
            // received path counts toward max-prefix separately — the same
            // deliberately-strict accounting as the VPN sibling.
            self.known_labeled.insert(route.key());
        }
        for key in &rtc_withdrawn {
            self.known_rtc.remove(key);
        }
        for key in denied_rtc {
            if self.known_rtc.remove(&key) {
                rtc_withdrawn.push(key);
            }
        }
        for route in &rtc_announced {
            self.known_rtc.insert(route.key());
        }
        self.import_policy_routes_permitted = self
            .import_policy_routes_permitted
            .saturating_add(import_policy_routes_permitted);
        self.import_policy_routes_denied = self
            .import_policy_routes_denied
            .saturating_add(import_policy_routes_denied);
        if self.enforce_max_prefix_limits(true).await {
            return;
        }
        if !announced.is_empty()
            || !withdrawn.is_empty()
            || !flowspec_announced.is_empty()
            || !flowspec_withdrawn.is_empty()
            || !evpn_announced.is_empty()
            || !evpn_withdrawn.is_empty()
        {
            let refresh_delta = self.capture_routes_refresh_delta(
                &announced,
                &withdrawn,
                &flowspec_announced,
                &flowspec_withdrawn,
                &evpn_announced,
                &evpn_withdrawn,
            );
            if self
                .deliver_routes_to_rib(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced,
                    withdrawn,
                    flowspec_announced,
                    flowspec_withdrawn,
                    evpn_announced,
                    evpn_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !bgpls_announced.is_empty() || !bgpls_withdrawn.is_empty() {
            let refresh_delta =
                self.capture_bgpls_refresh_delta(&bgpls_announced, &bgpls_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::BgpLsRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: bgpls_announced,
                    withdrawn: bgpls_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !vpn_announced.is_empty() || !vpn_withdrawn.is_empty() {
            let refresh_delta = self.capture_vpn_refresh_delta(&vpn_announced, &vpn_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::VpnRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: vpn_announced,
                    withdrawn: vpn_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !labeled_announced.is_empty() || !labeled_withdrawn.is_empty() {
            let refresh_delta =
                self.capture_labeled_refresh_delta(&labeled_announced, &labeled_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::LabeledRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: labeled_announced,
                    withdrawn: labeled_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
        }
        if !rtc_announced.is_empty() || !rtc_withdrawn.is_empty() {
            let refresh_delta = self.capture_rtc_refresh_delta(&rtc_announced, &rtc_withdrawn);
            if self
                .deliver_routes_to_rib(RibUpdate::RtcRoutesReceived {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    announced: rtc_announced,
                    withdrawn: rtc_withdrawn,
                })
                .await
                .is_err()
            {
                return;
            }
            if let Some(delta) = refresh_delta {
                self.apply_refresh_accounting_delta(delta);
            }
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
        let s = PolicyAttrSummary::from_route_attrs(&attrs, true);
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
        let s = PolicyAttrSummary::from_route_attrs(&attrs, true);
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
        let s = PolicyAttrSummary::from_route_attrs(&attrs, true);
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
#[cfg(test)]
mod next_hop_ownership_tests {
    use super::{NextHopOwnershipBlockReason, strict_peer_next_hop_violation};
    use std::net::{IpAddr, Ipv6Addr};

    const V4_PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
    const V6_PEER: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    const LL_PEER: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

    #[test]
    fn own_addresses_conform() {
        // Classic IPv4, IPv6 global, RFC 8950 IPv4-over-IPv6 (the wire
        // AFI never reaches the identity check — ownership is a pure
        // address comparison), and a scoped link-local session.
        assert_eq!(
            strict_peer_next_hop_violation(V4_PEER, false, V4_PEER, None),
            None
        );
        assert_eq!(
            strict_peer_next_hop_violation(V6_PEER, false, V6_PEER, None),
            None
        );
        assert_eq!(
            strict_peer_next_hop_violation(LL_PEER, true, LL_PEER, None),
            None
        );
    }

    #[test]
    fn foreign_addresses_are_rejected() {
        let other_v4: IpAddr = "192.0.2.99".parse().unwrap();
        let other_v6: IpAddr = "2001:db8::99".parse().unwrap();
        let other_ll: IpAddr = "fe80::99".parse().unwrap();
        for (session, nh, scoped) in [
            (V4_PEER, other_v4, false),
            (V6_PEER, other_v6, false),
            // RFC 8950 session announcing a v4 next-hop it cannot own.
            (V6_PEER, other_v4, false),
            // Same fe80:: space, different host, same interface scope.
            (LL_PEER, other_ll, true),
        ] {
            assert_eq!(
                strict_peer_next_hop_violation(session, scoped, nh, None),
                Some(NextHopOwnershipBlockReason::ForeignNextHop),
                "session {session} must reject foreign next-hop {nh}"
            );
        }
    }

    #[test]
    fn link_local_companion_pair_always_fails_closed() {
        // ADR-0107 §2: the 32-octet global + link-local pair carries two
        // address identities; the session maps to one, so the strict
        // pilot can never verify both — even when one component matches.
        let companion: Ipv6Addr = "fe80::2".parse().unwrap();
        for (session, scoped) in [(V6_PEER, false), (LL_PEER, true)] {
            assert_eq!(
                strict_peer_next_hop_violation(session, scoped, V6_PEER, Some(companion)),
                Some(NextHopOwnershipBlockReason::UnverifiedLinkLocalCompanion),
                "session {session} must fail closed on a paired companion"
            );
        }
    }

    #[test]
    fn link_local_without_session_scope_fails_closed() {
        // A link-local identity is address + interface scope; a session
        // without a scoped link-local identity has no scope to map it
        // to — rejected regardless of the address value.
        assert_eq!(
            strict_peer_next_hop_violation(V6_PEER, false, LL_PEER, None),
            Some(NextHopOwnershipBlockReason::UnscopedLinkLocal)
        );
        assert_eq!(
            strict_peer_next_hop_violation(V4_PEER, false, LL_PEER, None),
            Some(NextHopOwnershipBlockReason::UnscopedLinkLocal)
        );
    }
}
