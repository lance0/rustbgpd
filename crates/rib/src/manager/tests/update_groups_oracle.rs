//! Differential RIB-level oracle for shared update-group distribution.
//!
//! Every scenario runs the real manager with grouping and with the private
//! fallback. Compare ordered per-session/receiver/family/key events and final
//! admitted state; batch boundaries and cross-key order are unconstrained.
//! Explicit peer-scoped recovery intervals use end-state comparison, but every
//! withdrawal must remove a currently admitted key in every interval, and every
//! announce must repeat the value it replaces or equal the key's value at End. Clean
//! promotion, refresh and regroup have no recovery exemption.
//!
//! These normalized RIB values are not final encoded-byte evidence. The
//! transport shared-encoding tests compare shared and private encoding of one
//! envelope; they do not encode grouped and per-peer RIB output.

use std::collections::BTreeMap;

use rustbgpd_policy::{
    CommunityMatch, NeighborSetMatch, NextHopAction, Policy, PolicyAction, PolicyChain,
    PolicyStatement, RouteModifications,
};
use rustbgpd_wire::RtcNlri;

use super::*;
use crate::attr_set::AttrSet;
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
        attributes: AttrSet::new(attributes),
        received_at: crate::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: crate::test_support::session_router_id(IpAddr::V4(src)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: crate::route::AspaContextId::DEFAULT,
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
        next_hop_scope: None,
        peer: IpAddr::V4(src),
        attributes: AttrSet::new(attributes),
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
        attributes: AttrSet::new(vec![
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
/// stack, next hop, source peer, attributes, AFI, path id). Keys/NLRI are `Debug`
/// strings — `VpnRouteKey` has no `Display` and only sort stability
/// matters here.
pub(super) type NormVpnAnnounce = (String, String, IpAddr, IpAddr, Vec<PathAttribute>, u16, u32);

pub(super) type NormEvpnAnnounce = (
    String,
    rustbgpd_wire::EvpnRoute,
    IpAddr,
    Option<std::net::Ipv6Addr>,
    IpAddr,
    Ipv4Addr,
    RouteOrigin,
    Vec<PathAttribute>,
);

/// The closed recovery list from ADR-0099 section F, stated at each schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryPath {
    QueueDeferral,
    InterruptedRegroup,
    SessionRestart,
    PartialEncoderFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryBoundary {
    Begin(RecoveryPath),
    End,
}

#[derive(Debug, Default, PartialEq, Clone)]
pub(super) struct NormMsg {
    /// A transport incarnation started, including the first registration.
    /// Admitted state is connection-scoped, so discard the predecessor's
    /// advertisements before consuming a new dump.
    pub(super) session_start: Option<u64>,
    pub(super) announce: Vec<NormAnnounce>,
    pub(super) withdraw: Vec<(Prefix, u32)>,
    pub(super) end_of_rib: Vec<(Afi, Safi)>,
    pub(super) refresh_markers: Vec<(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype)>,
    pub(super) vpn_announce: Vec<NormVpnAnnounce>,
    pub(super) vpn_withdraw: Vec<(String, u32, u16)>,
    pub(super) evpn_announce: Vec<NormEvpnAnnounce>,
    pub(super) evpn_withdraw: Vec<String>,
    pub(super) recovery: Option<RecoveryBoundary>,
}

pub(super) fn normalize(update: &OutboundRouteUpdate) -> NormMsg {
    // Model source exclusion before comparing RIB events. Attribute preparation
    // and encoded bytes are checked separately by the transport oracle.
    let mut announce: Vec<_> = update
        .announce
        .iter()
        .enumerate()
        .filter(|(_, r)| update.announce_source_exclusion != Some(r.peer))
        .map(|(i, r)| {
            (
                r.prefix,
                r.path_id,
                r.next_hop,
                r.peer,
                r.attributes.to_vec(),
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
                r.attributes.to_vec(),
                r.afi_safi().0 as u16,
                r.path_id,
            )
        })
        .collect();
    vpn_announce.sort_by(|a, b| a.0.cmp(&b.0));
    let mut vpn_withdraw: Vec<_> = update
        .vpn_withdraw
        .iter()
        .map(|key| {
            let afi = match key.nlri_key.prefix {
                VpnPrefix::V4 { .. } => Afi::Ipv4,
                VpnPrefix::V6 { .. } => Afi::Ipv6,
            };
            (format!("{:?}", key.nlri_key), key.path_id, afi as u16)
        })
        .collect();
    vpn_withdraw.sort();
    let mut evpn_announce: Vec<_> = update
        .evpn_announce
        .iter()
        .map(|route| {
            (
                format!("{:?}", route.key()),
                route.route.clone(),
                route.next_hop,
                route.link_local_next_hop,
                route.peer,
                route.peer_router_id,
                route.origin_type,
                route.attributes.to_vec(),
            )
        })
        .collect();
    evpn_announce.sort_by(|a, b| a.0.cmp(&b.0));
    let mut evpn_withdraw: Vec<_> = update
        .evpn_withdraw
        .iter()
        .map(|key| format!("{key:?}"))
        .collect();
    evpn_withdraw.sort();
    NormMsg {
        session_start: None,
        announce,
        withdraw,
        end_of_rib,
        refresh_markers: update.refresh_markers.clone(),
        vpn_announce,
        vpn_withdraw,
        evpn_announce,
        evpn_withdraw,
        recovery: None,
    }
}

pub(super) type Streams = BTreeMap<IpAddr, Vec<NormMsg>>;

type Family = (u16, u8);

/// Incarnation also distinguishes fixture reconnects that reuse a session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SessionKey {
    peer: IpAddr,
    incarnation: usize,
    id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventKey {
    family: Family,
    nlri: String,
    path_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum Announced {
    Unicast(NormAnnounce),
    Vpn(NormVpnAnnounce),
    Evpn(NormEvpnAnnounce),
}

#[derive(Debug, Clone, PartialEq)]
enum KeyEvent {
    Announce(Announced),
    Withdraw,
}

type Admitted = BTreeMap<EventKey, Announced>;

#[derive(Debug, PartialEq)]
struct Marker {
    /// BoRR/EoRR retain their wire subtype; `EoR` has a separate value.
    kind: u16,
    /// Recovery End advances this operation boundary; an old terminal never
    /// seals a later ordinary operation or a newly named retry.
    epoch: usize,
    recovery: Option<RecoveryPath>,
    admitted: Admitted,
    /// Progress binds a normal marker to the same per-key event prefix,
    /// without constraining unrelated keys or packet packing.
    progress: BTreeMap<EventKey, usize>,
}

#[derive(Debug, Default, PartialEq)]
struct Trace {
    events: BTreeMap<(SessionKey, usize, EventKey), Vec<KeyEvent>>,
    markers: BTreeMap<(SessionKey, Family), Vec<Marker>>,
    recovery: BTreeMap<SessionKey, Vec<(RecoveryBoundary, Admitted)>>,
    terminal: BTreeMap<SessionKey, Admitted>,
    /// Announces inside the open recovery interval with the value each one
    /// replaced; checked and drained at End, so always empty between streams.
    recovery_announces: Vec<(EventKey, Announced, Option<Announced>)>,
}

fn unicast_key(prefix: Prefix, path_id: u32) -> EventKey {
    EventKey {
        family: (
            match prefix {
                Prefix::V4(_) => Afi::Ipv4,
                Prefix::V6(_) => Afi::Ipv6,
            } as u16,
            Safi::Unicast as u8,
        ),
        nlri: prefix.to_string(),
        path_id,
    }
}

fn vpn_event_key(nlri: &str, path_id: u32, afi: u16) -> EventKey {
    EventKey {
        family: (afi, Safi::MplsVpn as u8),
        nlri: nlri.to_owned(),
        path_id,
    }
}

fn evpn_event_key(nlri: &str) -> EventKey {
    EventKey {
        family: (Afi::L2Vpn as u16, Safi::Evpn as u8),
        nlri: nlri.to_owned(),
        path_id: 0,
    }
}

fn recovery_family_completed(
    trace: &Trace,
    session: SessionKey,
    epoch: usize,
    family: Family,
) -> bool {
    trace
        .markers
        .get(&(session, family))
        .is_some_and(|markers| {
            markers.iter().any(|marker| {
                marker.epoch == epoch
                    && marker.recovery.is_some()
                    && (marker.kind == 256
                        || marker.kind
                            == u16::from(rustbgpd_wire::RouteRefreshSubtype::EoRR.as_u8()))
            })
        })
}

/// Apply events in transport phase order. Every removal is checked before any
/// recovery relaxation; a replay can never manufacture withdrawal duty.
fn record_event(
    trace: &mut Trace,
    session: SessionKey,
    epoch: usize,
    recovering: Option<RecoveryPath>,
    admitted: &mut Admitted,
    key: EventKey,
    event: KeyEvent,
) {
    assert!(
        recovering.is_none() || !recovery_family_completed(trace, session, epoch, key.family),
        "covered recovery event after terminal in {session:?}, epoch={epoch}: {key:?}"
    );
    match &event {
        KeyEvent::Announce(value) => {
            let replaced = admitted.insert(key.clone(), value.clone());
            if recovering.is_some() {
                trace
                    .recovery_announces
                    .push((key.clone(), value.clone(), replaced));
            }
        }
        KeyEvent::Withdraw => {
            assert!(
                admitted.remove(&key).is_some(),
                "spurious withdrawal in {session:?}, recovery={recovering:?}: {key:?}"
            );
        }
    }
    if recovering.is_none() {
        trace
            .events
            .entry((session, epoch, key))
            .or_default()
            .push(event);
    }
}

fn record_marker(
    trace: &mut Trace,
    session: SessionKey,
    epoch: usize,
    recovering: Option<RecoveryPath>,
    admitted: &Admitted,
    family: Family,
    kind: u16,
) {
    if recovering.is_some() && kind == u16::from(rustbgpd_wire::RouteRefreshSubtype::BoRR.as_u8()) {
        assert!(
            !recovery_family_completed(trace, session, epoch, family),
            "BoRR restarts completed recovery in {session:?}, epoch={epoch}, family={family:?}"
        );
    }
    let progress = if recovering.is_some() {
        BTreeMap::new()
    } else {
        trace
            .events
            .iter()
            .filter(|((s, e, key), _)| *s == session && *e == epoch && key.family == family)
            .map(|((_, _, key), events)| (key.clone(), events.len()))
            .collect()
    };
    trace
        .markers
        .entry((session, family))
        .or_default()
        .push(Marker {
            kind,
            epoch,
            recovery: recovering,
            admitted: admitted
                .iter()
                .filter(|(key, _)| key.family == family)
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            progress,
        });
}

#[expect(
    clippy::too_many_lines,
    reason = "one ordered interpreter checks session, recovery, family events and marker coverage together"
)]
fn trace(streams: &Streams) -> Trace {
    let mut result = Trace::default();
    for (peer, messages) in streams {
        let mut session = SessionKey {
            peer: *peer,
            incarnation: 0,
            id: 0,
        };
        let mut admitted = Admitted::new();
        let mut recovering = None;
        let mut epoch = 0;
        for message in messages {
            if let Some(id) = message.session_start {
                assert!(
                    recovering.is_none(),
                    "session change inside unfinished recovery"
                );
                if session.incarnation != 0 {
                    result
                        .terminal
                        .insert(session, std::mem::take(&mut admitted));
                } else {
                    assert!(
                        admitted.is_empty(),
                        "initial session marker follows route events"
                    );
                }
                session = SessionKey {
                    peer: *peer,
                    incarnation: session.incarnation + 1,
                    id,
                };
                epoch = 0;
            }
            if let Some(boundary) = message.recovery {
                match boundary {
                    RecoveryBoundary::Begin(path) => {
                        assert!(recovering.replace(path).is_none(), "nested recovery");
                    }
                    RecoveryBoundary::End => {
                        assert!(recovering.take().is_some(), "recovery ended without begin");
                        // Only idempotent replay or convergence to the final
                        // value: each announce repeats the value it replaced
                        // or equals the key's state at End.
                        for (key, value, replaced) in result.recovery_announces.drain(..) {
                            assert!(
                                replaced.as_ref() == Some(&value)
                                    || admitted.get(&key) == Some(&value),
                                "non-idempotent recovery announce in {session:?}: {key:?} \
                                 replaced {replaced:?} with {value:?}"
                            );
                        }
                        epoch += 1;
                    }
                }
                result
                    .recovery
                    .entry(session)
                    .or_default()
                    .push((boundary, admitted.clone()));
            }
            // BoRR precedes covered routes. EoRR and EoR follow them.
            for (afi, safi, subtype) in &message.refresh_markers {
                if *subtype == rustbgpd_wire::RouteRefreshSubtype::BoRR {
                    record_marker(
                        &mut result,
                        session,
                        epoch,
                        recovering,
                        &admitted,
                        (*afi as u16, *safi as u8),
                        u16::from(subtype.as_u8()),
                    );
                }
            }
            for (prefix, path_id) in &message.withdraw {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    unicast_key(*prefix, *path_id),
                    KeyEvent::Withdraw,
                );
            }
            for route in &message.announce {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    unicast_key(route.0, route.1),
                    KeyEvent::Announce(Announced::Unicast(route.clone())),
                );
            }
            for key in &message.evpn_withdraw {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    evpn_event_key(key),
                    KeyEvent::Withdraw,
                );
            }
            for (key, path_id, afi) in &message.vpn_withdraw {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    vpn_event_key(key, *path_id, *afi),
                    KeyEvent::Withdraw,
                );
            }
            for route in &message.evpn_announce {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    evpn_event_key(&route.0),
                    KeyEvent::Announce(Announced::Evpn(route.clone())),
                );
            }
            for route in &message.vpn_announce {
                record_event(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &mut admitted,
                    vpn_event_key(&route.0, route.6, route.5),
                    KeyEvent::Announce(Announced::Vpn(route.clone())),
                );
            }
            for (afi, safi, subtype) in &message.refresh_markers {
                if *subtype != rustbgpd_wire::RouteRefreshSubtype::BoRR {
                    record_marker(
                        &mut result,
                        session,
                        epoch,
                        recovering,
                        &admitted,
                        (*afi as u16, *safi as u8),
                        u16::from(subtype.as_u8()),
                    );
                }
            }
            for (afi, safi) in &message.end_of_rib {
                record_marker(
                    &mut result,
                    session,
                    epoch,
                    recovering,
                    &admitted,
                    (*afi as u16, *safi as u8),
                    256,
                );
            }
        }
        assert!(recovering.is_none(), "unfinished recovery for {peer}");
        result.terminal.insert(session, admitted);
    }
    result
}

pub(super) fn assert_route_parity(grouped: &Streams, private: &Streams) {
    assert_eq!(
        trace(grouped),
        trace(private),
        "per-key events, barriers and admitted state differ"
    );
}

fn one_receiver(messages: Vec<NormMsg>) -> Streams {
    let mut stamped = vec![NormMsg {
        session_start: Some(SESSION),
        ..Default::default()
    }];
    stamped.extend(messages);
    [(IpAddr::V4(C), stamped)].into_iter().collect()
}

/// Real outbound values exercise each family, including full VPN label data
/// and EVPN route data. A test-only textual key is never a payload stand-in.
fn family_messages() -> Vec<(NormMsg, NormMsg)> {
    let unicast = ibgp_route(pfx(40, 0), A, 100, vec![]);
    let vpn = vpn_route(vpn_nlri(40, 16000), A, 100, vec![]);
    let evpn = make_evpn_imet(A, 40);
    vec![
        (
            normalize(&OutboundRouteUpdate {
                announce: vec![unicast.clone()].into(),
                ..Default::default()
            }),
            normalize(&OutboundRouteUpdate {
                withdraw: vec![(unicast.prefix, unicast.path_id)],
                ..Default::default()
            }),
        ),
        (
            normalize(&OutboundRouteUpdate {
                vpn_announce: vec![vpn.clone()],
                ..Default::default()
            }),
            normalize(&OutboundRouteUpdate {
                vpn_withdraw: vec![vpn.key()],
                ..Default::default()
            }),
        ),
        (
            normalize(&OutboundRouteUpdate {
                evpn_announce: vec![evpn.clone()],
                ..Default::default()
            }),
            normalize(&OutboundRouteUpdate {
                evpn_withdraw: vec![evpn.key()],
                ..Default::default()
            }),
        ),
    ]
}

#[test]
fn per_key_trace_accepts_cross_key_order_and_packing() {
    let first = ibgp_route(pfx(40, 0), A, 100, vec![]);
    let second = ibgp_route(pfx(41, 0), A, 100, vec![]);
    let packed = one_receiver(vec![normalize(&OutboundRouteUpdate {
        announce: vec![first.clone(), second.clone()].into(),
        ..Default::default()
    })]);
    let reordered = one_receiver(vec![
        normalize(&OutboundRouteUpdate {
            announce: vec![second].into(),
            ..Default::default()
        }),
        normalize(&OutboundRouteUpdate {
            announce: vec![first].into(),
            ..Default::default()
        }),
    ]);
    assert_route_parity(&packed, &reordered);
}

#[test]
fn per_key_trace_rejects_extra_or_transient_normal_events_for_every_family() {
    for (announce, withdraw) in family_messages() {
        let baseline = one_receiver(vec![announce.clone()]);
        for changed in [
            vec![announce.clone(), announce.clone()],
            vec![announce.clone(), withdraw.clone(), announce.clone()],
        ] {
            let changed = one_receiver(changed);
            assert!(std::panic::catch_unwind(|| assert_route_parity(&baseline, &changed)).is_err());
        }
    }
}

#[test]
fn per_key_trace_rejects_unknown_duplicate_and_previous_session_withdrawals() {
    for (announce, withdraw) in family_messages() {
        for invalid in [
            vec![withdraw.clone()],
            vec![announce.clone(), withdraw.clone(), withdraw.clone()],
            vec![
                announce.clone(),
                NormMsg {
                    session_start: Some(SESSION),
                    ..Default::default()
                },
                withdraw.clone(),
            ],
        ] {
            assert!(std::panic::catch_unwind(|| trace(&one_receiver(invalid))).is_err());
        }
    }
    // VPN Add-Path identity remains part of the exact withdrawal key.
    let (announce, mut wrong_path) = family_messages().remove(1);
    wrong_path.vpn_withdraw[0].1 = 99;
    assert!(std::panic::catch_unwind(|| trace(&one_receiver(vec![announce, wrong_path]))).is_err());
}

#[test]
fn per_key_trace_recovery_is_explicit_and_never_relaxes_withdrawal_presence() {
    for path in [
        RecoveryPath::QueueDeferral,
        RecoveryPath::InterruptedRegroup,
        RecoveryPath::SessionRestart,
        RecoveryPath::PartialEncoderFallback,
    ] {
        for (announce, withdraw) in family_messages() {
            let begin = NormMsg {
                recovery: Some(RecoveryBoundary::Begin(path)),
                ..Default::default()
            };
            let end = NormMsg {
                recovery: Some(RecoveryBoundary::End),
                ..Default::default()
            };
            let baseline = one_receiver(vec![announce.clone(), begin.clone(), end.clone()]);
            let replay = one_receiver(vec![
                announce.clone(),
                begin.clone(),
                announce.clone(),
                end.clone(),
            ]);
            assert_route_parity(&baseline, &replay);
            let invalid = one_receiver(vec![begin.clone(), withdraw, end.clone()]);
            assert!(std::panic::catch_unwind(|| trace(&invalid)).is_err());
            let unclosed = one_receiver(vec![begin.clone(), announce.clone()]);
            assert!(std::panic::catch_unwind(|| trace(&unclosed)).is_err());
            let double_end = one_receiver(vec![begin, announce, end.clone(), end]);
            assert!(std::panic::catch_unwind(|| trace(&double_end)).is_err());
        }
    }
}

/// Recovery permits only idempotent replay and convergence to the final value.
/// An intermediate value, or a return to a replaced value, is a per-key
/// transient the private path does not produce and must fail even though
/// both streams agree at End.
#[test]
fn per_key_trace_recovery_rejects_non_idempotent_announces() {
    let unicast: fn(u32) -> NormMsg = |local_pref| {
        normalize(&OutboundRouteUpdate {
            announce: vec![ibgp_route(pfx(40, 0), A, local_pref, vec![])].into(),
            ..Default::default()
        })
    };
    let vpn: fn(u32) -> NormMsg = |local_pref| {
        normalize(&OutboundRouteUpdate {
            vpn_announce: vec![vpn_route(vpn_nlri(40, 16000), A, local_pref, vec![])],
            ..Default::default()
        })
    };
    let begin = NormMsg {
        recovery: Some(RecoveryBoundary::Begin(RecoveryPath::QueueDeferral)),
        ..Default::default()
    };
    let end = NormMsg {
        recovery: Some(RecoveryBoundary::End),
        ..Default::default()
    };
    for value in [unicast, vpn] {
        let window = |inside: &[u32]| {
            let mut messages = vec![value(100), begin.clone()];
            messages.extend(inside.iter().map(|lp| value(*lp)));
            messages.push(end.clone());
            one_receiver(messages)
        };
        let private = window(&[200]);
        // Replaying the admitted value before converging stays permitted.
        assert_route_parity(&window(&[100, 200]), &private);
        assert_route_parity(&window(&[200, 200]), &private);
        // Same End state as the private stream, so only the in-window
        // transient (an unknown value, or a return to a replaced one) fails.
        for invalid in [&[999, 200][..], &[200, 100, 200]] {
            assert!(
                std::panic::catch_unwind(|| assert_route_parity(&window(invalid), &private))
                    .is_err(),
                "non-idempotent recovery announce accepted: {invalid:?}"
            );
        }
    }
}

#[test]
fn per_key_trace_preserves_eor_coverage_and_refresh_barriers() {
    let family = (Afi::Ipv4, Safi::Unicast);
    let (announce, _) = family_messages().remove(0);
    let eor = NormMsg {
        end_of_rib: vec![family],
        ..Default::default()
    };
    let baseline = one_receiver(vec![announce.clone(), eor.clone()]);
    let early = one_receiver(vec![eor.clone(), announce.clone()]);
    assert!(std::panic::catch_unwind(|| assert_route_parity(&baseline, &early)).is_err());
    let marker = |subtype| NormMsg {
        refresh_markers: vec![(family.0, family.1, subtype)],
        ..Default::default()
    };
    let begin = marker(rustbgpd_wire::RouteRefreshSubtype::BoRR);
    let end = marker(rustbgpd_wire::RouteRefreshSubtype::EoRR);
    let covered = one_receiver(vec![begin.clone(), announce.clone(), end.clone()]);
    let outside = one_receiver(vec![announce.clone(), begin, end]);
    assert!(std::panic::catch_unwind(|| assert_route_parity(&covered, &outside)).is_err());
    // Equal marker state is insufficient: an idempotent replay before versus
    // after EoR must still have the same per-key coverage boundary.
    let late_replay = one_receiver(vec![announce.clone(), eor.clone(), announce.clone()]);
    let early_replay = one_receiver(vec![announce.clone(), announce, eor.clone()]);
    assert!(std::panic::catch_unwind(|| assert_route_parity(&late_replay, &early_replay)).is_err());
}

#[test]
fn per_key_trace_recovery_rejects_replay_after_terminal() {
    for ((announce, _), family) in family_messages().into_iter().zip([
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::L2Vpn, Safi::Evpn),
    ]) {
        for enhanced in [false, true] {
            let begin = NormMsg {
                recovery: Some(RecoveryBoundary::Begin(
                    RecoveryPath::PartialEncoderFallback,
                )),
                ..Default::default()
            };
            let end = NormMsg {
                recovery: Some(RecoveryBoundary::End),
                ..Default::default()
            };
            let terminal = if enhanced {
                NormMsg {
                    refresh_markers: vec![(
                        family.0,
                        family.1,
                        rustbgpd_wire::RouteRefreshSubtype::EoRR,
                    )],
                    ..Default::default()
                }
            } else {
                NormMsg {
                    end_of_rib: vec![family],
                    ..Default::default()
                }
            };
            let covered = one_receiver(vec![
                announce.clone(),
                begin.clone(),
                announce.clone(),
                terminal.clone(),
                end.clone(),
            ]);
            let premature = one_receiver(vec![
                announce.clone(),
                begin,
                terminal,
                announce.clone(),
                end,
            ]);
            assert!(
                std::panic::catch_unwind(|| assert_route_parity(&covered, &premature)).is_err(),
                "idempotent recovery replay after terminal must fail: {family:?}, enhanced={enhanced}"
            );
        }
    }
}

#[test]
fn per_key_trace_recovery_borr_cannot_restart_completed_family() {
    let (announce, _) = family_messages().remove(0);
    let family = (Afi::Ipv4, Safi::Unicast);
    let stream = one_receiver(vec![
        announce.clone(),
        NormMsg {
            recovery: Some(RecoveryBoundary::Begin(
                RecoveryPath::PartialEncoderFallback,
            )),
            ..Default::default()
        },
        announce.clone(),
        NormMsg {
            end_of_rib: vec![family],
            ..Default::default()
        },
        NormMsg {
            refresh_markers: vec![(family.0, family.1, rustbgpd_wire::RouteRefreshSubtype::BoRR)],
            ..Default::default()
        },
        announce,
        NormMsg {
            recovery: Some(RecoveryBoundary::End),
            ..Default::default()
        },
    ]);
    assert!(
        std::panic::catch_unwind(|| trace(&stream)).is_err(),
        "BoRR cannot restart terminal phases inside the same recovery operation"
    );
}

#[test]
fn per_key_trace_recovery_allows_preterminal_retries_and_later_operations() {
    for ((announce, _), family) in family_messages().into_iter().zip([
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::L2Vpn, Safi::Evpn),
    ]) {
        for enhanced in [false, true] {
            let begin = NormMsg {
                recovery: Some(RecoveryBoundary::Begin(
                    RecoveryPath::PartialEncoderFallback,
                )),
                ..Default::default()
            };
            let end = NormMsg {
                recovery: Some(RecoveryBoundary::End),
                ..Default::default()
            };
            let terminal = if enhanced {
                NormMsg {
                    refresh_markers: vec![(
                        family.0,
                        family.1,
                        rustbgpd_wire::RouteRefreshSubtype::EoRR,
                    )],
                    ..Default::default()
                }
            } else {
                NormMsg {
                    end_of_rib: vec![family],
                    ..Default::default()
                }
            };
            let stream = |retries| {
                // A preceding normal terminal in the same numeric epoch does
                // not complete a recovery operation that has not begun yet.
                let mut messages = vec![announce.clone(), terminal.clone(), begin.clone()];
                messages.extend(std::iter::repeat_n(announce.clone(), retries));
                messages.extend([terminal.clone(), end.clone()]);
                // Separate normal work may emit the same key after End.
                messages.extend([announce.clone(), terminal.clone()]);
                // A later named retry is also a separate operation.
                messages.extend([
                    begin.clone(),
                    announce.clone(),
                    terminal.clone(),
                    end.clone(),
                ]);
                one_receiver(messages)
            };
            assert_route_parity(&stream(1), &stream(3));
        }
    }
}

#[test]
fn per_key_trace_recovery_completion_is_family_scoped() {
    let mut families = family_messages();
    let (unicast, _) = families.remove(0);
    let (vpn, _) = families.remove(0);
    let stream = |retries| {
        let mut messages = vec![
            unicast.clone(),
            vpn.clone(),
            NormMsg {
                recovery: Some(RecoveryBoundary::Begin(RecoveryPath::QueueDeferral)),
                ..Default::default()
            },
            unicast.clone(),
            NormMsg {
                end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
                ..Default::default()
            },
        ];
        // VPN remains covered by its own later terminal after unicast finishes.
        messages.extend(std::iter::repeat_n(vpn.clone(), retries));
        messages.extend([
            NormMsg {
                end_of_rib: vec![(Afi::Ipv4, Safi::MplsVpn)],
                ..Default::default()
            },
            NormMsg {
                recovery: Some(RecoveryBoundary::End),
                ..Default::default()
            },
        ]);
        one_receiver(messages)
    };
    assert_route_parity(&stream(1), &stream(3));
}

/// `normalize` models transport's own-source exclusion: the excluded
/// member's routes vanish, and every surviving route keeps the next-hop
/// override at its original index, including an override on a route
/// that sits next to an excluded one.
#[test]
fn normalize_excludes_own_source_and_keeps_overrides_aligned() {
    let own = ibgp_route(pfx(1, 0), A, 100, vec![]);
    let other = ibgp_route(pfx(2, 0), B, 100, vec![]);
    let third = ibgp_route(pfx(3, 0), C, 100, vec![]);
    let own_after = ibgp_route(pfx(4, 0), A, 100, vec![]);
    let override_nh = NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    let mut update = OutboundRouteUpdate {
        announce: vec![own.clone(), other.clone(), third.clone(), own_after.clone()].into(),
        next_hop_override: vec![
            Some(NextHopAction::Self_),
            Some(override_nh.clone()),
            None,
            Some(NextHopAction::Self_),
        ]
        .into(),
        announce_source_exclusion: Some(IpAddr::V4(A)),
        ..Default::default()
    };
    let expect = |route: &Route, nh: Option<NextHopAction>| {
        (
            route.prefix,
            route.path_id,
            route.next_hop,
            route.peer,
            route.attributes.to_vec(),
            nh,
        )
    };
    assert_eq!(
        normalize(&update).announce,
        vec![
            expect(&other, Some(override_nh.clone())),
            expect(&third, None)
        ],
        "own-source routes dropped, overrides stay with their routes"
    );
    update.announce_source_exclusion = None;
    assert_eq!(
        normalize(&update).announce,
        vec![
            expect(&own, Some(NextHopAction::Self_)),
            expect(&other, Some(override_nh)),
            expect(&third, None),
            expect(&own_after, Some(NextHopAction::Self_)),
        ],
        "no exclusion keeps every route with its override"
    );
}

/// Fold admitted unicast state, rejecting unknown or duplicate withdrawals.
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
                assert!(
                    table.remove(&(*prefix, *path_id)).is_some(),
                    "spurious unicast withdrawal for {peer}: {prefix}, path {path_id}"
                );
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
            for (key, path, _) in &msg.vpn_withdraw {
                assert_eq!(
                    *path, 0,
                    "VPN oracle scenarios use single-best path identity"
                );
                assert!(
                    table.remove(key).is_some(),
                    "spurious VPN withdrawal for {peer}: {key}"
                );
            }
            for (key, nlri, nh, src, attrs, _, path) in &msg.vpn_announce {
                assert_eq!(
                    *path, 0,
                    "VPN folded scenarios use single-best path identity"
                );
                table.insert(key.clone(), (nlri.clone(), *nh, *src, attrs.clone()));
            }
        }
    }
    state
}

pub(super) struct Oracle {
    tx: mpsc::Sender<RibUpdate>,
    roster: crate::export_roster::ExportRosterReader,
    outs: BTreeMap<IpAddr, mpsc::Receiver<OutboundRouteUpdate>>,
    handle: tokio::task::JoinHandle<()>,
    /// Messages drained so far (incremental collection so the VPN
    /// invariant checker can fold mid-scenario); `finish` drains the
    /// remainder into it and returns the whole stream set.
    collected: Streams,
    /// [`Self::queue`] inserts a FIFO barrier after every update, so queued
    /// route messages never share a distribution window (the reference
    /// side of the cross-message coalescing tests).
    sequential_queue: bool,
}

/// Session features that disqualify a peer from shared single-best staging.
/// The fault corpus varies these only at stamped `PeerUp` boundaries, matching
/// production OPEN negotiation rather than inventing live capability changes.
#[derive(Clone, Debug, Default)]
pub(super) struct OraclePeerFeatures {
    pub(super) add_path_send_max: u32,
    pub(super) negotiated_orf_recv: Vec<(Afi, Safi)>,
    /// RFC 7947 §2.3.2 per-client best-path (ADR-0101). A group-key
    /// bit for unicast-only sessions since the ADR-0126 Phase 3
    /// classifier flip, so the oracle's normal side groups these peers
    /// while the forced side keeps the per-peer correctness oracle.
    pub(super) per_client_best: bool,
}

impl Oracle {
    pub(super) fn spawn(force_ungrouped: bool, cluster_id: Option<Ipv4Addr>) -> Self {
        Self::spawn_configured(force_ungrouped, cluster_id, |_| {})
    }

    /// [`Self::spawn`] with a hook applied to the manager before it runs.
    pub(super) fn spawn_configured(
        force_ungrouped: bool,
        cluster_id: Option<Ipv4Addr>,
        configure: impl FnOnce(&mut RibManager),
    ) -> Self {
        let (tx, rx) = mpsc::channel(512);
        let mut manager =
            RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        configure(&mut manager);
        let roster = manager.export_roster();
        let handle = tokio::spawn(manager.run());
        Self {
            tx,
            roster,
            outs: BTreeMap::new(),
            handle,
            collected: Streams::new(),
            sequential_queue: false,
        }
    }

    /// Make [`Self::queue`] deliver one update at a time.
    pub(super) fn sequential(mut self) -> Self {
        self.sequential_queue = true;
        self
    }

    /// Queue updates back to back without yielding, so the actor finds them
    /// all already queued (route messages among them may share one
    /// distribution window), then quiesce.
    pub(super) async fn queue(&mut self, updates: Vec<RibUpdate>) {
        for update in updates {
            self.tx
                .try_send(update)
                .expect("queued updates fit the primary channel");
            if self.sequential_queue {
                self.quiesce().await;
            }
        }
        self.quiesce().await;
    }

    /// Stage RFC 7947 control-community handling before the peer's `PeerUp`.
    pub(super) async fn set_rs_control(&mut self, peer: Ipv4Addr, rs_control_asn: u32) {
        self.tx
            .send(RibUpdate::SetPeerRsControl {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
                rs_control_asn: Some(rs_control_asn),
            })
            .await
            .unwrap();
    }

    pub(super) async fn peer_up(
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
    #[expect(
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

    #[expect(
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
                per_client_best: features.per_client_best,
                interpret_rfc1997: true,
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
        let msgs = self.collected.entry(IpAddr::V4(peer)).or_default();
        if let Some(mut old_rx) = self.outs.insert(IpAddr::V4(peer), out_rx) {
            while let Ok(update) = old_rx.try_recv() {
                msgs.push(normalize(&update));
            }
        }
        msgs.push(NormMsg {
            session_start: Some(session_id),
            ..NormMsg::default()
        });
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
                validated_with: None,
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
        published_export_rows(&self.tx, &self.roster, None)
            .await
            .iter()
            .map(|row| row.evals)
            .sum()
    }

    /// Export-policy evaluations visible through one installed peer handle.
    /// Grouped peers intentionally alias the same group counter instance, so
    /// summing every per-peer row would multiply one real evaluation by the
    /// number of members and cannot measure a zero-evaluation delta.
    async fn export_policy_evals_for(&mut self, peer: Ipv4Addr) -> u64 {
        published_export_rows(&self.tx, &self.roster, Some(IpAddr::V4(peer)))
            .await
            .iter()
            .map(|row| row.evals)
            .sum()
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
                queued: Arc::default(),
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
            .send(RibUpdate::QueryBestRoutes {
                deadline: full_snapshot_query_deadline(),
                reply: reply_tx,
            })
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

    /// The queued pre-failure update is still a normal admission. Only this
    /// named peer's subsequent targeted retry uses the recovery exception.
    pub(super) async fn drain_before_recovery(
        &mut self,
        peer: Ipv4Addr,
        path: RecoveryPath,
    ) -> OutboundRouteUpdate {
        let update = self.drain_one(peer).await;
        self.begin_recovery(peer, path);
        update
    }

    /// Record a named interval without changing admission or channel capacity.
    pub(super) fn begin_recovery(&mut self, peer: Ipv4Addr, path: RecoveryPath) {
        self.collected
            .entry(IpAddr::V4(peer))
            .or_default()
            .push(NormMsg {
                recovery: Some(RecoveryBoundary::Begin(path)),
                ..Default::default()
            });
    }

    /// Record settlement after the schedule has drained its admitted updates.
    pub(super) fn close_recovery(&mut self, peer: Ipv4Addr) {
        self.collected
            .entry(IpAddr::V4(peer))
            .or_default()
            .push(NormMsg {
                recovery: Some(RecoveryBoundary::End),
                ..Default::default()
            });
    }

    /// Close an explicitly scheduled retry after its actor barrier and retain
    /// all admitted messages before comparing the recovered state.
    pub(super) async fn end_recovery(&mut self, peer: Ipv4Addr) {
        self.quiesce().await;
        self.drain_collected();
        self.close_recovery(peer);
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

    /// Actor-ordered dirty state for one peer, without changing its queue or
    /// route view. Fault schedules use this to mark only actual deferrals.
    pub(super) async fn peer_outbound_dirty(&mut self, peer: Ipv4Addr) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::TestQueryPeerOutboundDirty {
                peer: IpAddr::V4(peer),
                reply: reply_tx,
            })
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
        // Validate every key removal even before a differential comparison.
        let _ = trace(&self.collected);
        self.collected
    }
}

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const D: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const E: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const F: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

fn dataset_prefix_data(prefix: Prefix, permit: bool) -> rustbgpd_policy::datasets::DatasetData {
    use rustbgpd_policy::datasets::DatasetData;
    use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry};
    DatasetData::Prefix(PrefixSet::new(permit.then_some(PrefixSetEntry {
        prefix,
        ge: None,
        le: None,
    })))
}

fn dataset_prefix_policy(
    prefix: Prefix,
    permit: bool,
) -> (Arc<rustbgpd_policy::datasets::DatasetHandle>, PolicyChain) {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetHandle, DatasetKind};
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::SetStore;
    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        dataset_prefix_data(prefix, permit),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled = RpolFile::parse(
        "dataset prefix-set allowed\npolicy p { term t { if route.prefix in allowed { accept } reject } }",
    )
    .expect("dataset policy parses")
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .expect("policy compiles")
    .expect("dataset binding is complete");
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);
    (handle, chain)
}

async fn check_dataset_export_refresh(per_client_best: bool) {
    let prefix = Prefix::V4(pfx(1, 0));
    for force_ungrouped in [true, false] {
        for initially_permitted in [true, false] {
            let (handle, chain) = dataset_prefix_policy(prefix, initially_permitted);
            let mut oracle = Oracle::spawn(force_ungrouped, None);
            oracle.peer_up(A, true, false, None, 64).await;
            for peer in [B, C] {
                oracle
                    .peer_up_families_generation_with_features(
                        peer,
                        SESSION,
                        true,
                        false,
                        Some(chain.clone()),
                        64,
                        ipv4_sendable(),
                        OraclePeerFeatures {
                            per_client_best,
                            ..OraclePeerFeatures::default()
                        },
                    )
                    .await;
            }
            oracle
                .peer_up(
                    D,
                    true,
                    false,
                    Some(permit_all_with(RouteModifications::default())),
                    64,
                )
                .await;
            let group = oracle.group_label(B).await;
            assert_eq!(group.starts_with("group:"), !force_ungrouped);
            assert_eq!(group, oracle.group_label(C).await);
            oracle
                .routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
                .await;
            if per_client_best {
                // B must receive A's runner-up while C receives B's best.
                oracle
                    .routes(B, vec![ibgp_route(pfx(1, 0), B, 200, vec![])], vec![])
                    .await;
            }
            oracle.drain_available();
            let initial = fold(&oracle.collected);
            for peer in [B, C] {
                assert_eq!(
                    initial[&IpAddr::V4(peer)].contains_key(&(prefix, 0)),
                    initially_permitted
                );
            }
            let bystander = oracle.collected[&IpAddr::V4(D)].clone();
            let bystander_evals = oracle.export_policy_evals_for(D).await;
            let prior_evals = oracle.export_policy_evals_for(B).await;

            assert_eq!(
                handle.refresh(dataset_prefix_data(prefix, !initially_permitted)),
                Some(2)
            );
            let (reply, result) = oneshot::channel();
            oracle
                .tx
                .send(RibUpdate::ReevaluatePeerExportPolicies {
                    peers: vec![IpAddr::V4(B), IpAddr::V4(C)],
                    swaps: None,
                    reply,
                })
                .await
                .unwrap();
            result.await.unwrap().unwrap();
            let next_evals = oracle.export_policy_evals_for(B).await;
            assert!(
                next_evals > prior_evals,
                "installed counter instance must keep advancing"
            );
            if !force_ungrouped {
                assert_eq!(
                    next_evals - prior_evals,
                    if per_client_best { 2 } else { 1 },
                    "shared group must be evaluated once, not once per member"
                );
            }
            assert_eq!(oracle.export_policy_evals_for(D).await, bystander_evals);
            let streams = oracle.finish().await;
            assert_eq!(
                streams[&IpAddr::V4(D)],
                bystander,
                "unrelated group was re-emitted"
            );
            let final_state = fold(&streams);
            for peer in [B, C] {
                let advertised = final_state[&IpAddr::V4(peer)].contains_key(&(prefix, 0));
                assert_eq!(
                    advertised, !initially_permitted,
                    "stale dataset verdict: ungrouped={force_ungrouped} pcb={per_client_best} initial={initially_permitted} peer={peer}"
                );
            }
        }
    }
}

#[tokio::test]
async fn dataset_content_refresh_rechecks_grouped_export_verdicts() {
    check_dataset_export_refresh(false).await;
}

#[tokio::test]
async fn dataset_content_refresh_rechecks_per_client_best_export_verdicts() {
    check_dataset_export_refresh(true).await;
}

#[tokio::test]
async fn dataset_content_refresh_missing_target_has_no_effects() {
    let prefix = Prefix::V4(pfx(1, 0));
    let (handle, chain) = dataset_prefix_policy(prefix, true);
    let mut oracle = Oracle::spawn(false, None);
    oracle.peer_up(A, true, false, None, 64).await;
    oracle.peer_up(B, true, false, Some(chain), 64).await;
    oracle
        .routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
        .await;
    oracle.drain_available();
    let before = oracle.collected[&IpAddr::V4(B)].clone();
    let evals = oracle.export_policy_evals_for(B).await;
    handle.refresh(dataset_prefix_data(prefix, false)).unwrap();
    let (reply, result) = oneshot::channel();
    oracle
        .tx
        .send(RibUpdate::ReevaluatePeerExportPolicies {
            peers: vec![IpAddr::V4(B), IpAddr::V4(F)],
            swaps: None,
            reply,
        })
        .await
        .unwrap();
    assert!(matches!(
        result.await.unwrap(),
        Err(crate::update::RibCommandError::NotFound(_))
    ));
    assert_eq!(oracle.export_policy_evals_for(B).await, evals);
    let streams = oracle.finish().await;
    assert_eq!(streams[&IpAddr::V4(B)], before);
}

#[tokio::test]
async fn dataset_content_refresh_rechecks_grouped_vpn_export_verdicts() {
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 210, 1, 0), 24));
    for initially_permitted in [true, false] {
        let (handle, chain) = dataset_prefix_policy(prefix, initially_permitted);
        let mut oracle = Oracle::spawn(false, Some(Ipv4Addr::new(192, 0, 2, 1)));
        oracle
            .peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        for peer in [B, C] {
            oracle
                .peer_up_families(peer, false, true, Some(chain.clone()), 64, vpn_sendable())
                .await;
        }
        assert!(oracle.group_label(B).await.starts_with("group:"));
        assert_eq!(oracle.group_label(B).await, oracle.group_label(C).await);
        oracle
            .vpn_routes(A, vec![vpn_route(vpn_nlri(1, 100), A, 100, vec![])], vec![])
            .await;
        oracle.drain_available();
        let initial = fold_vpn(&oracle.collected);
        for peer in [B, C] {
            assert_eq!(!initial[&IpAddr::V4(peer)].is_empty(), initially_permitted);
        }
        handle
            .refresh(dataset_prefix_data(prefix, !initially_permitted))
            .unwrap();
        let (reply, result) = oneshot::channel();
        oracle
            .tx
            .send(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![IpAddr::V4(B), IpAddr::V4(C)],
                swaps: None,
                reply,
            })
            .await
            .unwrap();
        result.await.unwrap().unwrap();
        let final_state = fold_vpn(&oracle.finish().await);
        for peer in [B, C] {
            assert_eq!(
                final_state[&IpAddr::V4(peer)].is_empty(),
                initially_permitted
            );
        }
    }
}

/// Contents of the three datasets the swap oracle's export chain reads.
#[derive(Clone)]
struct SwapData {
    allowed: Vec<rustbgpd_policy::sets::PrefixSetEntry>,
    blocked: Vec<u32>,
    tagged: Vec<u32>,
}

impl SwapData {
    fn handles(&self) -> [Arc<rustbgpd_policy::datasets::DatasetHandle>; 3] {
        use rustbgpd_policy::datasets::{DatasetHandle, DatasetKind};
        let [allowed, blocked, tagged] = self.data();
        [
            Arc::new(DatasetHandle::new("allowed", DatasetKind::Prefix, allowed)),
            Arc::new(DatasetHandle::new("blocked", DatasetKind::Asn, blocked)),
            Arc::new(DatasetHandle::new("tagged", DatasetKind::Community, tagged)),
        ]
    }

    fn data(&self) -> [rustbgpd_policy::datasets::DatasetData; 3] {
        use rustbgpd_policy::datasets::DatasetData;
        use rustbgpd_policy::sets::{AsnSet, CommunitySet, PrefixSet};
        [
            DatasetData::Prefix(PrefixSet::new(self.allowed.iter().copied())),
            DatasetData::Asn(AsnSet::new(self.blocked.iter().copied())),
            DatasetData::Community(CommunitySet::new(
                self.tagged
                    .iter()
                    .map(|&value| CommunityMatch::Standard { value }),
            )),
        ]
    }
}

fn swap_entry(prefix: Ipv4Prefix, le: Option<u8>) -> rustbgpd_policy::sets::PrefixSetEntry {
    rustbgpd_policy::sets::PrefixSetEntry {
        prefix: Prefix::V4(prefix),
        ge: None,
        le,
    }
}

/// Every oracle route: 10.200.0.0/16 up to /24.
fn swap_all() -> Vec<rustbgpd_policy::sets::PrefixSetEntry> {
    vec![swap_entry(
        Ipv4Prefix::new(Ipv4Addr::new(10, 200, 0, 0), 16),
        Some(24),
    )]
}

fn swap_some(indexes: &[u8]) -> Vec<rustbgpd_policy::sets::PrefixSetEntry> {
    indexes
        .iter()
        .map(|&n| swap_entry(pfx(n, 0), None))
        .collect()
}

fn swap_chain(handles: &[Arc<rustbgpd_policy::datasets::DatasetHandle>; 3]) -> PolicyChain {
    use rustbgpd_policy::datasets::DatasetBindings;
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::SetStore;
    let mut bindings = DatasetBindings::new();
    for handle in handles {
        bindings.insert(Arc::clone(handle));
    }
    let compiled = RpolFile::parse(
        "dataset prefix-set allowed\ndataset asn-set blocked\ndataset community-set tagged\n\
         policy p { term t { if (route.prefix in allowed || route.communities in tagged) \
         && !(route.origin-as in blocked) { accept } reject } }",
    )
    .expect("dataset policy parses")
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .expect("policy compiles")
    .expect("dataset binding is complete");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )])
}

/// A route with `origin` as its `AS_PATH` origin (none: empty path).
fn swap_route(
    n: u8,
    src: Ipv4Addr,
    local_pref: u32,
    origin: Option<u32>,
    community: bool,
) -> Route {
    let mut route = ibgp_route(pfx(n, 0), src, local_pref, vec![]);
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: origin
                .map(|origin| vec![AsPathSegment::AsSequence(vec![65100, origin])])
                .unwrap_or_default(),
        }),
        PathAttribute::LocalPref(local_pref),
    ];
    if community {
        attributes.push(PathAttribute::Communities(vec![0xFDE8_0007]));
    }
    route.attributes = AttrSet::new(attributes);
    route
}

#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent oracle dimensions, each a receiver feature"
)]
struct SwapMode {
    ungrouped: bool,
    per_client_best: bool,
    add_path: bool,
    /// C's channel is full when the re-evaluation arrives, so C is dirty.
    jam: bool,
}

/// Run the oracle topology. `next` swaps every dataset to that content
/// after the initial exchange and re-evaluates B and C, sending the swaps
/// when `with_swaps`; `None` starts from `initial` and never swaps (the
/// reference). Returns the final advertised state and B's export
/// evaluations during the re-evaluation command.
#[expect(
    clippy::too_many_lines,
    reason = "one oracle topology: sessions, routes, swap and recovery in order"
)]
async fn run_swap_case(
    initial: &SwapData,
    next: Option<&SwapData>,
    mode: SwapMode,
    with_swaps: bool,
) -> (FoldedState, u64) {
    let handles = initial.handles();
    let chain = swap_chain(&handles);
    let mut oracle = Oracle::spawn(mode.ungrouped, None);
    oracle.peer_up(A, true, false, None, 64).await;
    oracle.peer_up(E, true, false, None, 64).await;
    for (peer, capacity) in [(B, 64), (C, if mode.jam { 1 } else { 64 })] {
        oracle
            .peer_up_families_generation_with_features(
                peer,
                SESSION,
                true,
                false,
                Some(chain.clone()),
                capacity,
                ipv4_sendable(),
                OraclePeerFeatures {
                    per_client_best: mode.per_client_best,
                    add_path_send_max: if mode.add_path { 4 } else { 0 },
                    ..OraclePeerFeatures::default()
                },
            )
            .await;
    }
    oracle
        .peer_up(
            D,
            true,
            false,
            Some(permit_all_with(RouteModifications::default())),
            64,
        )
        .await;
    if mode.jam {
        let eor = oracle.drain_one(C).await;
        assert!(eor.announce.is_empty());
    }
    let origins = [
        Some(64501),
        Some(64502),
        Some(64503),
        None,
        Some(64501),
        Some(64502),
        Some(64503),
        Some(64504),
    ];
    let from_a = (1..=8)
        .zip(origins)
        .map(|(n, origin)| swap_route(n, A, 200, origin, n == 7))
        .collect();
    oracle.routes(A, from_a, vec![]).await;
    // Runner-up candidates with other origins: per-client-best and Add-Path
    // receivers read them, so an origin swap must reach non-best paths.
    oracle
        .routes(
            E,
            vec![
                swap_route(5, E, 100, Some(64509), false),
                swap_route(6, E, 100, Some(64501), false),
            ],
            vec![],
        )
        .await;
    if !mode.jam {
        oracle.drain_available();
    }
    let mut evals = 0;
    if let Some(next) = next {
        let mut swaps = Vec::new();
        for (handle, data) in handles.iter().zip(next.data()) {
            let prior = handle.pin();
            if handle.refresh(data).is_some() {
                swaps.push(crate::update::DatasetSwap {
                    handle: Arc::clone(handle),
                    prior,
                });
            }
        }
        let before = oracle.export_policy_evals_for(B).await;
        let bystander = oracle.export_policy_evals_for(D).await;
        let (reply, result) = oneshot::channel();
        oracle
            .tx
            .send(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![IpAddr::V4(B), IpAddr::V4(C)],
                swaps: with_swaps.then_some(swaps),
                reply,
            })
            .await
            .unwrap();
        result.await.unwrap().unwrap();
        evals = oracle.export_policy_evals_for(B).await - before;
        assert_eq!(
            oracle.export_policy_evals_for(D).await,
            bystander,
            "bystander re-evaluated"
        );
    }
    if mode.jam {
        oracle
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        oracle.quiesce().await;
        oracle.end_recovery(C).await;
    }
    (fold(&oracle.finish().await), evals)
}

/// How the re-evaluation must have run for a swap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SwapPath {
    /// Bounded, and fewer evaluations than the full pass.
    Narrow,
    /// Bounded, and no route affected: nothing evaluated.
    Empty,
    /// Bounded, every route affected.
    Every,
    /// Not boundable: the full pass ran.
    Full,
}

#[expect(
    clippy::too_many_lines,
    reason = "the swap case table reads best as one list"
)]
async fn check_swap_cases(mode: SwapMode) {
    let base = SwapData {
        allowed: swap_some(&[1, 2]),
        blocked: vec![],
        tagged: vec![],
    };
    let cases = [
        (
            "prefix add",
            base.clone(),
            SwapData {
                allowed: swap_some(&[1, 2, 3, 5]),
                ..base.clone()
            },
            SwapPath::Narrow,
        ),
        (
            "prefix remove",
            SwapData {
                allowed: swap_some(&[1, 2, 3, 4, 5, 6, 7, 8]),
                ..base.clone()
            },
            base.clone(),
            SwapPath::Narrow,
        ),
        (
            "origin add and remove",
            SwapData {
                allowed: swap_all(),
                blocked: vec![64501],
                tagged: vec![],
            },
            SwapData {
                allowed: swap_all(),
                blocked: vec![64502, 64509],
                tagged: vec![],
            },
            SwapPath::Narrow,
        ),
        (
            // p6's best (64502) stays blocked; only its runner-up from E
            // (64501) changes verdict.
            "runner-up origin",
            SwapData {
                allowed: swap_all(),
                blocked: vec![64502],
                tagged: vec![],
            },
            SwapData {
                allowed: swap_all(),
                blocked: vec![64502, 64501],
                tagged: vec![],
            },
            SwapPath::Narrow,
        ),
        (
            "prefix and origin together",
            base.clone(),
            SwapData {
                allowed: swap_some(&[2, 4, 6]),
                blocked: vec![64504, 64502],
                tagged: vec![],
            },
            SwapPath::Narrow,
        ),
        (
            "no route affected",
            base.clone(),
            SwapData {
                allowed: {
                    let mut allowed = swap_some(&[1, 2]);
                    allowed.push(swap_entry(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 99, 0, 0), 24),
                        None,
                    ));
                    allowed
                },
                blocked: vec![64999],
                tagged: vec![],
            },
            SwapPath::Empty,
        ),
        (
            "every route affected",
            SwapData {
                allowed: vec![],
                ..base.clone()
            },
            SwapData {
                allowed: swap_all(),
                ..base.clone()
            },
            SwapPath::Every,
        ),
        (
            "community set",
            base.clone(),
            SwapData {
                tagged: vec![0xFDE8_0007],
                ..base.clone()
            },
            SwapPath::Full,
        ),
    ];
    for (name, initial, next, path) in cases {
        let (bounded, bounded_evals) = run_swap_case(&initial, Some(&next), mode, true).await;
        let (full, full_evals) = run_swap_case(&initial, Some(&next), mode, false).await;
        let (reference, _) = run_swap_case(&next, None, mode, false).await;
        assert_eq!(
            bounded, full,
            "{name} {mode:?}: bounded and full re-evaluation differ"
        );
        assert_eq!(
            full, reference,
            "{name} {mode:?}: full re-evaluation is not exact"
        );
        if mode.jam {
            continue;
        }
        match path {
            SwapPath::Narrow => assert!(
                bounded_evals < full_evals,
                "{name} {mode:?}: {bounded_evals} bounded vs {full_evals} full evaluations"
            ),
            SwapPath::Empty => assert_eq!(bounded_evals, 0, "{name} {mode:?}"),
            SwapPath::Every => assert!(bounded_evals > 0, "{name} {mode:?}"),
            SwapPath::Full => assert_eq!(bounded_evals, full_evals, "{name} {mode:?}"),
        }
    }
}

/// Re-evaluating only the routes a dataset swap affects leaves every
/// receiver with exactly the Adj-RIB-Out the full pass produces, which is
/// in turn the state of a run that started with the new contents.
#[tokio::test]
async fn dataset_swap_bounded_reevaluation_matches_full_pass() {
    for (ungrouped, per_client_best, add_path) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (true, false, true),
    ] {
        check_swap_cases(SwapMode {
            ungrouped,
            per_client_best,
            add_path,
            jam: false,
        })
        .await;
    }
}

/// A member whose channel is full when the swap arrives recovers to the
/// same state on both paths.
#[tokio::test]
async fn dataset_swap_bounded_reevaluation_matches_full_pass_with_dirty_member() {
    tokio::time::pause();
    for ungrouped in [false, true] {
        check_swap_cases(SwapMode {
            ungrouped,
            per_client_best: false,
            add_path: false,
            jam: true,
        })
        .await;
    }
}

/// VPN receivers are outside the bounded path: the swap falls back to the
/// full pass and stays exact.
#[tokio::test]
async fn dataset_swap_with_vpn_receivers_uses_full_pass() {
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 210, 1, 0), 24));
    let run = async |with_swaps: bool| {
        let (handle, chain) = dataset_prefix_policy(prefix, true);
        let mut oracle = Oracle::spawn(false, Some(Ipv4Addr::new(192, 0, 2, 1)));
        oracle
            .peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        for peer in [B, C] {
            oracle
                .peer_up_families(peer, false, true, Some(chain.clone()), 64, vpn_sendable())
                .await;
        }
        oracle
            .vpn_routes(A, vec![vpn_route(vpn_nlri(1, 100), A, 100, vec![])], vec![])
            .await;
        oracle
            .routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        oracle.drain_available();
        let prior = handle.pin();
        handle.refresh(dataset_prefix_data(prefix, false)).unwrap();
        let (reply, result) = oneshot::channel();
        oracle
            .tx
            .send(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![IpAddr::V4(B), IpAddr::V4(C)],
                swaps: with_swaps.then(|| {
                    vec![crate::update::DatasetSwap {
                        handle: Arc::clone(&handle),
                        prior,
                    }]
                }),
                reply,
            })
            .await
            .unwrap();
        result.await.unwrap().unwrap();
        let streams = oracle.finish().await;
        (fold(&streams), fold_vpn(&streams))
    };
    let (unicast, vpn) = run(true).await;
    assert_eq!((unicast, vpn.clone()), run(false).await);
    for peer in [B, C] {
        assert!(vpn[&IpAddr::V4(peer)].is_empty(), "VPN verdict refreshed");
    }
}

/// A swap whose prior is not the handle's immediate predecessor cannot
/// bound the change: exports may reflect an intermediate publication the
/// prior does not show. The full pass runs.
#[tokio::test]
async fn dataset_swap_with_intervening_publication_uses_full_pass() {
    let data = |indexes: &[u8]| {
        SwapData {
            allowed: swap_some(indexes),
            blocked: vec![],
            tagged: vec![],
        }
        .data()
        .into_iter()
        .next()
        .unwrap()
    };
    let handles = SwapData {
        allowed: swap_some(&[1]),
        blocked: vec![],
        tagged: vec![],
    }
    .handles();
    let mut oracle = Oracle::spawn(false, None);
    oracle.peer_up(A, true, false, None, 64).await;
    oracle
        .peer_up(B, true, false, Some(swap_chain(&handles)), 64)
        .await;
    let routes = (1..=2)
        .map(|n| swap_route(n, A, 100, None, false))
        .collect();
    oracle.routes(A, routes, vec![]).await;
    let allowed = &handles[0];
    let stale = allowed.pin();
    let reevaluate = async |oracle: &mut Oracle, swaps| {
        let (reply, result) = oneshot::channel();
        oracle
            .tx
            .send(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![IpAddr::V4(B)],
                swaps,
                reply,
            })
            .await
            .unwrap();
        result.await.unwrap().unwrap();
    };
    // An intermediate publication B already exports.
    allowed.refresh(data(&[1, 2])).unwrap();
    reevaluate(&mut oracle, None).await;
    // Back to the stale prior's content: a diff against it is empty.
    allowed.refresh(data(&[1])).unwrap();
    let swap = crate::update::DatasetSwap {
        handle: Arc::clone(allowed),
        prior: stale,
    };
    reevaluate(&mut oracle, Some(vec![swap])).await;
    let folded = fold(&oracle.finish().await);
    let advertised: BTreeSet<_> = folded[&IpAddr::V4(B)].keys().copied().collect();
    assert_eq!(advertised, BTreeSet::from([(Prefix::V4(pfx(1, 0)), 0)]));
}

pub(super) async fn run_grouped_and_ungrouped<S>(
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

/// The kitchen-sink per-key sequence scenario: initial dump, best change,
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
    assert_route_parity(&grouped, &ungrouped);
    // Sanity: the scenario actually produced traffic.
    assert!(
        grouped.values().any(|msgs| !msgs.is_empty()),
        "scenario must exercise outbound traffic"
    );
}

/// Dirty-member resync (channel-full → tombstones → timer resync).
/// Only C’s scheduled retry may replay announcements. Every withdrawal must
/// remove a key C actually admitted, and the recovered state must match.
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    // The dirty member must have withdrawn the previously admitted p1 on
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

/// A group tombstone for an announce missed during deferral carries no
/// withdrawal duty for that receiver. The admitted p1 remains untouched.
#[tokio::test]
async fn oracle_dirty_missed_announce_then_withdraw_has_no_unknown_tombstone() {
    tokio::time::pause();
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 1).await;
        let eor = o.drain_one(C).await;
        assert_ne!(eor.end_of_rib, Vec::<(Afi, Safi)>::new());
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![], vec![pfx(2, 0)]).await;
        let pending = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(pending.announce.len(), 1);
        assert_eq!(pending.announce[0].prefix, Prefix::V4(pfx(1, 0)));
        tokio::time::advance(Duration::from_secs(2)).await;
        o.end_recovery(C).await;
    };
    let (grouped, private) =
        run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
    assert_route_parity(&grouped, &private);
    let c = &grouped[&IpAddr::V4(C)];
    assert!(c.iter().all(|message| message.withdraw.is_empty()));
    assert!(fold(&grouped)[&IpAddr::V4(C)].contains_key(&(Prefix::V4(pfx(1, 0)), 0)));
}

/// C never receives its own p2. D did admit p2. Both become dirty, so the
/// shared tombstone must withdraw p2 only from D, never fan it out to C.
#[tokio::test]
async fn oracle_dirty_source_excluded_sibling_has_no_shared_tombstone_withdraw() {
    tokio::time::pause();
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 1).await;
        o.peer_up(D, false, true, None, 1).await;
        assert_ne!(o.drain_one(C).await.end_of_rib, Vec::<(Afi, Safi)>::new());
        assert_ne!(o.drain_one(D).await.end_of_rib, Vec::<(Afi, Safi)>::new());
        o.routes(C, vec![ibgp_route(pfx(2, 0), C, 100, vec![])], vec![])
            .await;
        let admitted = o.drain_one(D).await;
        assert_eq!(admitted.announce[0].prefix, Prefix::V4(pfx(2, 0)));
        // p1 fills both channels. p3 then fails for both members.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![ibgp_route(pfx(3, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(C, vec![], vec![pfx(2, 0)]).await;
        for peer in [C, D] {
            let pending = o
                .drain_before_recovery(peer, RecoveryPath::QueueDeferral)
                .await;
            assert_eq!(pending.announce[0].prefix, Prefix::V4(pfx(1, 0)));
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        o.end_recovery(C).await;
        o.end_recovery(D).await;
    };
    let (grouped, private) =
        run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
    assert_route_parity(&grouped, &private);
    let key = (Prefix::V4(pfx(2, 0)), 0);
    assert!(
        grouped[&IpAddr::V4(C)]
            .iter()
            .all(|message| !message.withdraw.contains(&key))
    );
    assert_eq!(
        grouped[&IpAddr::V4(D)]
            .iter()
            .flat_map(|message| &message.withdraw)
            .filter(|withdraw| **withdraw == key)
            .count(),
        1
    );
}

/// RT2 is admitted only by D. A dirty RT1-only sibling must not inherit
/// D's withdrawal duty when the shared table removes that RT2 route.
#[tokio::test]
async fn oracle_dirty_rtc_excluded_sibling_has_no_shared_tombstone_withdraw() {
    tokio::time::pause();
    let scenario = async |o: &mut Oracle| {
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(C, false, true, None, 2, vpn_rtc_sendable())
            .await;
        o.peer_up_families(D, false, true, None, 64, vpn_rtc_sendable())
            .await;
        let dump = o.drain_one(C).await;
        assert!(dump.vpn_announce.is_empty());
        assert_ne!(o.drain_one(C).await.end_of_rib, Vec::<(Afi, Safi)>::new());
        o.rtc_routes(C, vec![rtc_interest(C, 1)]).await;
        o.rtc_routes(D, vec![rtc_default(D)]).await;
        o.vpn_routes(
            A,
            vec![vpn_route(vpn_nlri(2, 200), A, 100, vec![rt_ec(2)])],
            vec![],
        )
        .await;
        // Two RT1 announcements fill C's two slots; id4 is missed.
        for id in [1, 3, 4] {
            o.vpn_routes(
                A,
                vec![vpn_route(
                    vpn_nlri(id, u32::from(id) * 100),
                    A,
                    100,
                    vec![rt_ec(1)],
                )],
                vec![],
            )
            .await;
        }
        o.vpn_routes(A, vec![], vec![vpn_key(2, 200)]).await;
        let first = o.drain_one(C).await;
        assert_eq!(first.vpn_announce[0].key(), vpn_key(1, 100));
        let second = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(second.vpn_announce[0].key(), vpn_key(3, 300));
        tokio::time::advance(Duration::from_secs(2)).await;
        o.end_recovery(C).await;
        o.check_vpn_invariant("RT-excluded sibling recovered").await;
    };
    let (grouped, private) =
        run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
    assert_route_parity(&grouped, &private);
    let key = format!("{:?}", vpn_nlri(2, 200).key());
    assert!(grouped[&IpAddr::V4(C)].iter().all(|message| {
        message
            .vpn_withdraw
            .iter()
            .all(|withdraw| withdraw.0 != key)
    }));
    assert_eq!(
        grouped[&IpAddr::V4(D)]
            .iter()
            .flat_map(|message| &message.vpn_withdraw)
            .filter(|withdraw| withdraw.0 == key)
            .count(),
        1
    );
}

/// A forced refresh deferred by a full channel is retained for retry and
/// marks the peer dirty.
/// Genuine churn can arrive before that retry, so this deliberately exercises
/// the allowed `force && dirty && !best_changed.is_empty()` state: dirty group
/// assembly must include the pass tombstones while force still replays the
/// current table.
#[tokio::test]
async fn oracle_deferred_force_then_churn_converges_to_identical_state() {
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
        // Forced replay waits for channel capacity, retaining force and
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

        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");

        // Source flip ONTO the already-dirty member: C's own route
        // displaces A's as best. C's pass takes the resync arm, which
        // announces table ∖ own-sourced — the displaced p1(A) can only
        // reach the withdraw set via the extras recorded at staging.
        o.routes(C, vec![ibgp_route(pfx(1, 0), C, 200, vec![])], vec![])
            .await;

        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
    assert_route_parity(&grouped, &ungrouped);
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
/// becomes peer-context-dependent) carries its admitted withdrawal duty. The withdrawn key is in neither the
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
            .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
    assert_route_parity(&grouped, &ungrouped);
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

/// The VPN kitchen-sink per-key sequence scenario (update-groups v2 slice
/// 1): initial VPN dump, flood, source-flip X→Y→X, same-peer relabel
/// (ADR-0077 re-advertise), attr mutate, withdraw, split horizon
/// (source inside the group), late joiner replay, RFC 7313 VPN route
/// refresh, member leave, regroup on policy change (content-equal
/// reinstall AND a genuine deny), and a GShut-style forced refresh —
/// grouped vs private per-key VPN event sequences must be identical.
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
    assert_route_parity(&grouped, &ungrouped);
    assert!(
        grouped
            .values()
            .any(|msgs| msgs.iter().any(|m| !m.vpn_announce.is_empty())),
        "scenario must exercise VPN outbound traffic"
    );
}

/// VPN dirty-member resync (channel-full → VPN tombstones → timer
/// resync): only C's named retry may replay announcements. Every withdrawal
/// needs prior admission, recovered state must match, and the missed announce
/// must reach the wire.
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(
            first.vpn_announce.len(),
            1,
            "identity 1 was delivered before the jam"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(
            first.vpn_announce.len(),
            1,
            "identity 1 was delivered before the jam"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        // The adv(m) invariant recomputed from manager state must match
        // the folded emitted streams once the resync has run.
        o.check_vpn_invariant("post source-flip resync").await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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

/// Passes that stage while the member is ALREADY dirty and its channel
/// is still full skip its emission. Their withdrawals ride the staging
/// tombstones and a source flip onto the member rides its extra-withdraw
/// residue, so the resync still folds to the per-peer path's exact
/// state.
#[tokio::test]
async fn oracle_vpn_passes_while_already_dirty_fold_exactly() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up_families(A, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(B, false, true, None, 64, vpn_sendable())
            .await;
        o.peer_up_families(C, false, true, None, 1, vpn_sendable())
            .await;
        let eor = o.drain_one(C).await;
        assert!(eor.vpn_announce.is_empty() && !eor.end_of_rib.is_empty());

        // Identities 1 and 3 land in C's channel (fills it).
        o.vpn_routes(
            A,
            vec![
                vpn_route(vpn_nlri(1, 100), A, 100, vec![]),
                vpn_route(vpn_nlri(3, 300), A, 100, vec![]),
            ],
            vec![],
        )
        .await;
        // Identity 2 announce fails for C → C goes dirty.
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(2, 200), A, 100, vec![])], vec![])
            .await;
        // Already dirty from here on.
        // Source flip ONTO C: the key stays in the group table.
        o.vpn_routes(C, vec![vpn_route(vpn_nlri(1, 100), C, 200, vec![])], vec![])
            .await;
        // Table withdrawal of an admitted identity (tombstone).
        o.vpn_routes(A, vec![], vec![vpn_key(3, 300)]).await;
        // Announce-then-withdraw of a never-admitted identity.
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(4, 400), A, 100, vec![])], vec![])
            .await;
        o.vpn_routes(A, vec![], vec![vpn_key(4, 400)]).await;
        o.vpn_routes(A, vec![vpn_route(vpn_nlri(5, 500), A, 100, vec![])], vec![])
            .await;

        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.vpn_announce.len(), 2, "ids 1+3 preceded the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.check_vpn_invariant("post already-dirty resync").await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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
        !c_final.contains_key(&key(1, 100)),
        "the source flip onto the already-dirty member must be withdrawn"
    );
    assert!(
        !c_final.contains_key(&key(3, 300)),
        "the table withdrawal while dirty must be withdrawn"
    );
    assert!(!c_final.contains_key(&key(4, 400)));
    assert!(c_final.contains_key(&key(2, 200)));
    assert!(c_final.contains_key(&key(5, 500)));
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
    assert_route_parity(&grouped, &ungrouped);
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
    assert_route_parity(&grouped, &ungrouped);
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
    assert_route_parity(&grouped, &ungrouped);
    assert!(
        grouped
            .values()
            .any(|msgs| msgs.iter().any(|m| !m.vpn_announce.is_empty())),
        "scenario must exercise VPN outbound traffic"
    );
}

/// Membership change WHILE dirty (design §2.3): the grouped path skips
/// the delta walk (Φ updated; the pending resync emits against current
/// Φ, withdrawing only Φ-failing keys C previously admitted). Within the
/// named retry interval announcements may replay; final VPN state must converge, the
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
        let second = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(second.vpn_announce.len(), 1, "id 3 was delivered too");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.check_vpn_invariant("post-resync").await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
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

/// A membership widen whose announce-only delta is lost to a full channel
/// has no withdraw duty to carry, so it must mark the member dirty without
/// creating an empty extra-withdraw entry: readers test that map by key.
#[tokio::test]
async fn rtc_announce_only_delta_lost_to_full_channel_leaves_no_extra_withdraw_entry() {
    tokio::time::pause();
    let mut o = Oracle::spawn(false, Some(Ipv4Addr::new(192, 0, 2, 1)));
    o.peer_up_families(A, false, true, None, 64, vpn_sendable())
        .await;
    o.peer_up_families(B, false, true, None, 64, vpn_rtc_sendable())
        .await;
    // C's capacity-2 channel is left holding its initial dump and EoR, so
    // the next send to it fails.
    o.peer_up_families(C, false, true, None, 2, vpn_rtc_sendable())
        .await;
    // Strict-empty membership: the staged route reaches neither B nor C.
    o.vpn_routes(
        A,
        vec![vpn_route(vpn_nlri(1, 100), A, 100, vec![rt_ec(1)])],
        vec![],
    )
    .await;
    let (dirty, _, _, _, _, extra_withdraw_peers) = o.terminal_health().await;
    assert_eq!(
        (dirty, extra_withdraw_peers),
        (0, 0),
        "clean before the widen"
    );

    // C widens to RT1: one announce, no withdraws, and the send fails.
    o.rtc_routes(C, vec![rtc_interest(C, 1)]).await;
    let (dirty, _, _, _, _, extra_withdraw_peers) = o.terminal_health().await;
    assert_eq!(dirty, 1, "the lost delta must leave C dirty for the resync");
    assert_eq!(
        extra_withdraw_peers, 0,
        "an announce-only delta must not create an extra-withdraw entry"
    );
    o.finish().await;
}

/// A member that leaves its group dirty with an empty advertised view has
/// no withdraw duty to carry, so the regroup must not create an empty
/// extra-withdraw entry: readers test that map by key.
#[tokio::test]
async fn dirty_leaver_with_empty_view_leaves_no_extra_withdraw_entry() {
    tokio::time::pause();
    let mut o = Oracle::spawn(false, Some(Ipv4Addr::new(192, 0, 2, 1)));
    o.peer_up(A, false, true, None, 64).await;
    o.peer_up(B, false, true, None, 64).await;
    // C's policy denies the only route, so its group table and advertised
    // view stay empty. Its capacity-1 channel is left holding the initial
    // EoR, so the refresh response below cannot be sent: C goes dirty with
    // nothing advertised and no group tombstones.
    o.peer_up(C, false, true, Some(deny_prefix_chain(pfx(1, 0))), 1)
        .await;
    o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
        .await;
    o.route_refresh(C, Afi::Ipv4, Safi::Unicast).await;
    let (dirty, _, _, _, _, extra_withdraw_peers) = o.terminal_health().await;
    assert_eq!(
        (dirty, extra_withdraw_peers),
        (1, 0),
        "dirty, no residue yet"
    );

    // Regroup while dirty into B's group: the baseline snapshot is empty,
    // and the destination's announce is lost to the still-full channel, so
    // C stays dirty.
    o.replace_policy(C, None).await;
    let (dirty, _, _, _, _, extra_withdraw_peers) = o.terminal_health().await;
    assert_eq!(dirty, 1, "C is still dirty after the regroup");
    assert_eq!(
        extra_withdraw_peers, 0,
        "an empty baseline must not create an extra-withdraw entry"
    );
    o.finish().await;
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

// ---------------------------------------------------------------------
// ADR-0126 Phase 3 pre-flip pins: per-client-best overlap scenarios.
// See the module doc — ungrouped-vs-ungrouped today, the grouping
// equivalence proof after the classifier flip.
// ---------------------------------------------------------------------

/// Community tagged onto a Loc-RIB best so a member chain can deny it:
/// 65000:99 (mirrors the `per_client_best` unit fixtures).
const PCB_DENIED_COMMUNITY: u32 = 0xFDE8_0063;

/// Export chain denying routes tagged 65000:99, permitting the rest.
fn deny_tagged_chain() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![CommunityMatch::Standard {
                value: PCB_DENIED_COMMUNITY,
            }],
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

/// An eBGP route-server candidate: no `LOCAL_PREF`, ranked by AS-path
/// length, optional standard communities.
pub(super) fn rs_route(
    prefix: Ipv4Prefix,
    src: Ipv4Addr,
    asns: Vec<u32>,
    communities: Vec<u32>,
) -> Route {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }),
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
        attributes: AttrSet::new(attributes),
        received_at: crate::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: crate::test_support::session_router_id(IpAddr::V4(src)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: crate::route::AspaContextId::DEFAULT,
    }
}

/// An overlap candidate ranked by AS-path length: rank 1 wins best
/// path, higher ranks lose in order.
pub(super) fn ranked(prefix: Ipv4Prefix, src: Ipv4Addr, rank: u32) -> Route {
    rs_route(prefix, src, vec![65000 + rank; rank as usize], vec![])
}

/// Bring up a per-client-best route-server member (eBGP, no RR).
pub(super) async fn pcb_peer_up(
    o: &mut Oracle,
    peer: Ipv4Addr,
    export_policy: Option<PolicyChain>,
    capacity: usize,
) {
    o.peer_up_families_generation_with_features(
        peer,
        SESSION,
        true,
        false,
        export_policy,
        capacity,
        ipv4_sendable(),
        OraclePeerFeatures {
            per_client_best: true,
            ..OraclePeerFeatures::default()
        },
    )
    .await;
}

/// The member's final advertised source for a prefix in the folded state.
fn folded_src(state: &FoldedState, member: Ipv4Addr, prefix: Ipv4Prefix) -> Option<IpAddr> {
    state
        .get(&IpAddr::V4(member))
        .and_then(|table| table.get(&(Prefix::V4(prefix), 0)))
        .map(|(_, src, _, _)| *src)
}

/// The ordered sequence of announce sources on a member's wire.
fn src_seq(streams: &Streams, member: Ipv4Addr) -> Vec<IpAddr> {
    streams[&IpAddr::V4(member)]
        .iter()
        .flat_map(|msg| &msg.announce)
        .map(|entry| entry.3)
        .collect()
}

/// Steady state under overlap: three members announce p1 with
/// rank-differentiated paths, two announce p2. Each member's stream
/// shows the runner-up substitution — the source of the best receives
/// the second-best candidate, everyone else the best.
#[tokio::test]
async fn oracle_pcb_steady_state_overlap_substitutes_runner_up() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        // p1: three overlapping candidates, ranked A > B > C.
        o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 3)], vec![]).await;
        // p2: two candidates, ranked B > C (A sources nothing).
        o.routes(B, vec![ranked(pfx(2, 0), B, 1)], vec![]).await;
        o.routes(C, vec![ranked(pfx(2, 0), C, 2)], vec![]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    let folded = fold(&grouped);
    // p1: A (source of the best) gets the runner-up; B and C get the best.
    assert_eq!(folded_src(&folded, A, pfx(1, 0)), Some(IpAddr::V4(B)));
    assert_eq!(folded_src(&folded, B, pfx(1, 0)), Some(IpAddr::V4(A)));
    assert_eq!(folded_src(&folded, C, pfx(1, 0)), Some(IpAddr::V4(A)));
    // p2: B (source of the best) gets the runner-up; A and C get the best.
    assert_eq!(folded_src(&folded, A, pfx(2, 0)), Some(IpAddr::V4(B)));
    assert_eq!(folded_src(&folded, B, pfx(2, 0)), Some(IpAddr::V4(C)));
    assert_eq!(folded_src(&folded, C, pfx(2, 0)), Some(IpAddr::V4(B)));
}

/// The winner's source withdraws: the runner-up promotes. The
/// promoted winner's source flips into the former runner-up's slot as
/// an implicit replace; everyone else converges on the promoted
/// winner. No withdraw ever reaches any wire.
///
/// A clean winner promotion must suppress an unchanged runner-up already
/// advertised to the former winner's source; it has no recovery exemption.
#[tokio::test]
async fn oracle_pcb_best_source_withdraw_promotes_runner_up() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 3)], vec![]).await;
        // The winner's source withdraws: B's candidate promotes.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    assert_eq!(src_seq(&grouped, A), vec![IpAddr::V4(B)]);
    assert_eq!(src_seq(&grouped, B), vec![IpAddr::V4(A), IpAddr::V4(C)]);
    assert_eq!(src_seq(&grouped, C), vec![IpAddr::V4(A), IpAddr::V4(B)]);
    let folded = fold(&grouped);
    assert_eq!(
        folded,
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    // A (source of the withdrawn best) holds the promoted winner it
    // already had as the substitution.
    assert_eq!(folded_src(&folded, A, pfx(1, 0)), Some(IpAddr::V4(B)));
    // B — the promoted winner's source — ends on the former
    // runner-up's slot content (C's route).
    assert_eq!(folded_src(&folded, B, pfx(1, 0)), Some(IpAddr::V4(C)));
    // C converges on the promoted winner.
    assert_eq!(folded_src(&folded, C, pfx(1, 0)), Some(IpAddr::V4(B)));
    for member in [A, B, C] {
        assert!(
            grouped[&IpAddr::V4(member)]
                .iter()
                .all(|msg| msg.withdraw.is_empty()),
            "promotion is an implicit replace at path_id 0 — never withdraw+announce"
        );
    }
}

/// An unchanged policy strips its match community, leaving identical Route
/// fields while the separately carried export action changes in both directions.
#[tokio::test]
async fn oracle_action_only_pcb_lane_change_and_promotion() {
    const SELF_TAG: u32 = 0xFDE8_0064;
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let mut policy = permit_all_with(RouteModifications {
                communities_remove: vec![SELF_TAG],
                ..RouteModifications::default()
            });
            let mut tagged = policy.policies[0].policy.entries[0].clone();
            tagged.match_community = vec![CommunityMatch::Standard { value: SELF_TAG }];
            tagged.modifications.set_next_hop = Some(NextHopAction::Self_);
            policy.policies[0].policy.entries.insert(0, tagged);
            let candidate = |use_self: bool| {
                rs_route(
                    pfx(1, 0),
                    B,
                    vec![65002; 2],
                    if use_self { vec![SELF_TAG] } else { vec![] },
                )
            };
            let mut o = Oracle::spawn(force_ungrouped, None);
            for peer in [A, B, C] {
                pcb_peer_up(&mut o, peer, Some(policy.clone()), 64).await;
            }
            assert_eq!(
                o.group_label(A).await.starts_with("group:"),
                !force_ungrouped
            );
            o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
            o.routes(B, vec![candidate(initially_self)], vec![]).await;
            let initial = o.drain_peer_available(A).await;
            let initial: Vec<_> = initial.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(initial.len(), 1);
            let initial = initial[0].clone();
            assert_eq!(initial.5, initially_self.then_some(NextHopAction::Self_));

            // The same policy strips its guard community, so only the
            // separately carried action changes on B's exported candidate.
            o.routes(B, vec![candidate(!initially_self)], vec![]).await;
            let changed = o.drain_peer_available(A).await;
            assert!(changed.iter().all(|msg| msg.withdraw.is_empty()));
            let changed: Vec<_> = changed.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(
                changed.len(),
                1,
                "the changed action must reannounce its key exactly once"
            );
            assert_eq!(
                changed[0].5,
                (!initially_self).then_some(NextHopAction::Self_)
            );
            assert_eq!(
                (
                    &changed[0].0,
                    changed[0].1,
                    changed[0].2,
                    changed[0].3,
                    &changed[0].4
                ),
                (&initial.0, initial.1, initial.2, initial.3, &initial.4)
            );
            o.routes(A, vec![], vec![pfx(1, 0)]).await;
            let promotion = o.drain_peer_available(A).await;
            assert!(
                promotion
                    .iter()
                    .all(|msg| msg.announce.is_empty() && msg.withdraw.is_empty()),
                "promotion must not duplicate the already admitted action"
            );

            // Explicit refresh repeats the now-admitted action, after its
            // ordinary transition and without an intermediate withdrawal.
            o.refresh_outbound(A).await;
            let replay = o.drain_peer_available(A).await;
            let replay: Vec<_> = replay.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(replay.len(), 1);
            let replay = replay[0];
            assert_eq!(replay.5, (!initially_self).then_some(NextHopAction::Self_));
            assert_eq!(
                (&replay.0, replay.1, replay.2, replay.3, &replay.4),
                (&initial.0, initial.1, initial.2, initial.3, &initial.4),
                "the post-policy Route fields stay equal despite the changed action"
            );
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
    }
}

/// One source update changes raw selection rank and policy action together;
/// export normalization hides the rank/tag changes from the Route comparison.
#[tokio::test]
async fn oracle_action_only_same_update_pcb_winner_promotion() {
    const SELF_TAG: u32 = 0xFDE8_0064;
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let mut policy = permit_all_with(RouteModifications {
                set_local_pref: Some(100),
                communities_remove: vec![SELF_TAG],
                ..RouteModifications::default()
            });
            let mut tagged = policy.policies[0].policy.entries[0].clone();
            tagged.match_community = vec![CommunityMatch::Standard { value: SELF_TAG }];
            tagged.modifications.set_next_hop = Some(NextHopAction::Self_);
            policy.policies[0].policy.entries.insert(0, tagged);
            let candidate = |src, local_pref, use_self| {
                let mut route = rs_route(
                    pfx(1, 0),
                    src,
                    vec![65001],
                    if use_self { vec![SELF_TAG] } else { vec![] },
                );
                AttrSet::edit(&mut route.attributes, |attrs| {
                    attrs.push(PathAttribute::LocalPref(local_pref));
                });
                route
            };
            let mut o = Oracle::spawn(force_ungrouped, None);
            for peer in [A, B, C] {
                pcb_peer_up(&mut o, peer, Some(policy.clone()), 64).await;
            }
            assert_eq!(
                o.group_label(A).await.starts_with("group:"),
                !force_ungrouped
            );
            o.routes(A, vec![candidate(A, 150, false)], vec![]).await;
            o.routes(B, vec![candidate(B, 100, initially_self)], vec![])
                .await;
            let initial = o.drain_peer_available(A).await;
            let initial: Vec<_> = initial.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(initial.len(), 1);
            let initial = initial[0].clone();
            assert_eq!(initial.5, initially_self.then_some(NextHopAction::Self_));

            // B becomes winner and flips its action in this one update.
            o.routes(B, vec![candidate(B, 200, !initially_self)], vec![])
                .await;
            let replacement = o.drain_peer_available(A).await;
            assert!(replacement.iter().all(|msg| msg.withdraw.is_empty()));
            let replacement: Vec<_> = replacement.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(
                replacement.len(),
                1,
                "winner promotion must deliver the changed action exactly once"
            );
            assert_eq!(
                replacement[0].5,
                (!initially_self).then_some(NextHopAction::Self_)
            );
            assert_eq!(
                (
                    &replacement[0].0,
                    replacement[0].1,
                    replacement[0].2,
                    replacement[0].3,
                    &replacement[0].4
                ),
                (&initial.0, initial.1, initial.2, initial.3, &initial.4)
            );
            let observer = o.drain_peer_available(C).await;
            let promoted: Vec<_> = observer
                .iter()
                .flat_map(|msg| &msg.announce)
                .filter(|entry| entry.3 == IpAddr::V4(B))
                .collect();
            assert_eq!(promoted.len(), 1, "raw rank must promote B before export");
            let promoted = promoted[0];
            assert_eq!(
                promoted.5,
                (!initially_self).then_some(NextHopAction::Self_)
            );
            assert_eq!(
                (&promoted.0, promoted.1, promoted.2, promoted.3, &promoted.4),
                (&initial.0, initial.1, initial.2, initial.3, &initial.4),
                "the newly winning B Route must equal A's old B substitution"
            );
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
    }
}

/// Register a receiver profile under which every next-hop action encodes the
/// same bytes, overriding the conservative `old == new` trait default.
async fn equivalent_action_profile(o: &mut Oracle, peer: Ipv4Addr) {
    o.tx.send(RibUpdate::SetPeerExportEncoder {
        peer: IpAddr::V4(peer),
        session_id: SESSION,
        encoder: super::exportability::MockExactExportEncoder::equivalent_next_hop_actions(1),
    })
    .await
    .unwrap();
}

/// Under an equivalent profile, PCB groups suppress an action-only change
/// from borrowed prior slots: `delta.prior` toward members that receive the
/// winner, and the lane prior toward the winner's own source.
#[tokio::test]
async fn oracle_action_only_equivalent_profile_pcb_prior_suppression() {
    const SELF_TAG: u32 = 0xFDE8_0064;
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let mut policy = permit_all_with(RouteModifications {
                communities_remove: vec![SELF_TAG],
                ..RouteModifications::default()
            });
            let mut tagged = policy.policies[0].policy.entries[0].clone();
            tagged.match_community = vec![CommunityMatch::Standard { value: SELF_TAG }];
            tagged.modifications.set_next_hop = Some(NextHopAction::Self_);
            policy.policies[0].policy.entries.insert(0, tagged);
            let candidate = |prefix, use_self: bool| {
                rs_route(
                    prefix,
                    B,
                    vec![65002; 2],
                    if use_self { vec![SELF_TAG] } else { vec![] },
                )
            };
            let mut o = Oracle::spawn(force_ungrouped, None);
            for peer in [A, B, C] {
                equivalent_action_profile(&mut o, peer).await;
                pcb_peer_up(&mut o, peer, Some(policy.clone()), 64).await;
            }
            assert_eq!(
                o.group_label(A).await.starts_with("group:"),
                !force_ungrouped
            );

            // B is the only candidate: A and C hold it as the group winner.
            o.routes(B, vec![candidate(pfx(1, 0), initially_self)], vec![])
                .await;
            for peer in [A, C] {
                let initial = o.drain_peer_available(peer).await;
                let initial: Vec<_> = initial.iter().flat_map(|msg| &msg.announce).collect();
                assert_eq!(initial.len(), 1);
                assert_eq!(initial[0].5, initially_self.then_some(NextHopAction::Self_));
            }
            o.routes(B, vec![candidate(pfx(1, 0), !initially_self)], vec![])
                .await;
            for peer in [A, C] {
                assert!(
                    o.drain_peer_available(peer)
                        .await
                        .iter()
                        .all(|msg| msg.announce.is_empty() && msg.withdraw.is_empty()),
                    "an equivalent winner action change must not reach {peer}"
                );
            }

            // A wins the second prefix, so A holds B's route as its lane
            // substitution while C receives A's route.
            o.routes(B, vec![candidate(pfx(2, 0), initially_self)], vec![])
                .await;
            o.routes(A, vec![ranked(pfx(2, 0), A, 1)], vec![]).await;
            let lane = o.drain_peer_available(A).await;
            let lane: Vec<_> = lane.iter().flat_map(|msg| &msg.announce).collect();
            assert!(lane.iter().all(|entry| entry.3 == IpAddr::V4(B)));
            assert_eq!(
                lane.last().map(|entry| entry.5.clone()),
                Some(initially_self.then_some(NextHopAction::Self_))
            );
            o.routes(B, vec![candidate(pfx(2, 0), !initially_self)], vec![])
                .await;
            assert!(
                o.drain_peer_available(A)
                    .await
                    .iter()
                    .all(|msg| msg.announce.is_empty() && msg.withdraw.is_empty()),
                "an equivalent lane action change must not reach the winner's source"
            );
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
    }
}

/// A clean member keeps its regroup baseline when the regroup resync is
/// refused, and that baseline stays the admitted action record while it is
/// dirty. Under an equivalent profile the action-only change is suppressed
/// from that baseline on both the refused and the recovered resync, so only
/// the genuine withdrawal reaches the wire.
#[tokio::test]
async fn oracle_action_only_equivalent_profile_dirty_baseline_suppression() {
    tokio::time::pause();
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let policy = |use_self: bool, regrouped: bool| {
                let mut policy = permit_all_with(RouteModifications {
                    set_next_hop: use_self.then_some(NextHopAction::Self_),
                    ..RouteModifications::default()
                });
                if regrouped {
                    policy.policies[0].policy.entries.insert(
                        0,
                        deny_prefix_chain(pfx(2, 0)).policies[0].policy.entries[0].clone(),
                    );
                }
                policy
            };
            let mut o = Oracle::spawn(force_ungrouped, Some(A));
            for peer in [A, B, C] {
                equivalent_action_profile(&mut o, peer).await;
            }
            o.peer_up(A, false, true, None, 64).await;
            o.peer_up(B, false, true, Some(policy(initially_self, false)), 64)
                .await;
            o.peer_up(C, false, true, Some(policy(initially_self, false)), 2)
                .await;
            o.drain_one(C).await; // Initial End-of-RIB.
            // Both admitted announcements stay queued, filling C's channel.
            o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
                .await;
            o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
                .await;
            // The new policy flips every action and withdraws pfx2. The
            // withdrawal cannot be admitted, so C goes dirty with its baseline.
            o.replace_policy(C, Some(policy(!initially_self, true)))
                .await;
            assert_eq!(
                o.group_label(C).await.starts_with("group:"),
                !force_ungrouped
            );
            // Both queued announcements were admitted before the refusal, so
            // they drain as normal admissions; only the retry that follows
            // runs inside the recovery interval.
            o.drain_one(C).await;
            o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
                .await;
            tokio::time::advance(Duration::from_secs(2)).await;
            o.quiesce().await;
            o.end_recovery(C).await;
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
        for stream in &runs {
            let messages = &stream[&IpAddr::V4(C)];
            let announced: Vec<_> = messages
                .iter()
                .flat_map(|msg| &msg.announce)
                .map(|entry| (entry.0, entry.5.clone()))
                .collect();
            let initial = initially_self.then_some(NextHopAction::Self_);
            assert_eq!(
                announced,
                vec![
                    (Prefix::V4(pfx(1, 0)), initial.clone()),
                    (Prefix::V4(pfx(2, 0)), initial),
                ],
                "the admitted key keeps its equivalent action without a replay"
            );
            let withdrawn: Vec<_> = messages.iter().flat_map(|msg| &msg.withdraw).collect();
            assert_eq!(withdrawn, vec![&(Prefix::V4(pfx(2, 0)), 0)]);
        }
    }
}

/// A new winner's source already holds the standing route it now receives as
/// a substitution. Clean promotion must not reannounce that unchanged value.
#[tokio::test]
async fn oracle_pcb_new_winner_keeps_unchanged_runner_up_without_reannounce() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        o.routes(A, vec![ranked(pfx(1, 0), A, 2)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 3)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 4)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 1)], vec![]).await;
    };
    let (grouped, private) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &private);
    assert_eq!(src_seq(&grouped, A), vec![IpAddr::V4(B), IpAddr::V4(B)]);
    assert_eq!(src_seq(&grouped, B), vec![IpAddr::V4(A)]);
    assert_eq!(src_seq(&grouped, C), vec![IpAddr::V4(A), IpAddr::V4(B)]);
    assert!(
        grouped
            .values()
            .flatten()
            .all(|message| message.withdraw.is_empty())
    );
}

/// Divergence 2: the shared export chain denies the Loc-RIB best, so
/// every member receives the first PERMITTED candidate — with the
/// source substitution on top (the permitted winner's source gets the
/// next permitted candidate).
#[tokio::test]
async fn oracle_pcb_filtered_best_delivers_first_permitted_candidate() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, Some(deny_tagged_chain()), 64).await;
        pcb_peer_up(o, B, Some(deny_tagged_chain()), 64).await;
        pcb_peer_up(o, C, Some(deny_tagged_chain()), 64).await;
        // A's candidate is the Loc-RIB best AND carries the denied tag.
        o.routes(
            A,
            vec![rs_route(
                pfx(1, 0),
                A,
                vec![65001],
                vec![PCB_DENIED_COMMUNITY],
            )],
            vec![],
        )
        .await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 3)], vec![]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    let folded = fold(&grouped);
    // The permitted winner is B's route; B itself walks on to C's.
    assert_eq!(folded_src(&folded, A, pfx(1, 0)), Some(IpAddr::V4(B)));
    assert_eq!(folded_src(&folded, B, pfx(1, 0)), Some(IpAddr::V4(C)));
    assert_eq!(folded_src(&folded, C, pfx(1, 0)), Some(IpAddr::V4(B)));
}

/// Lane-only churn: the best stands while the runner-up candidate
/// changes attributes and then withdraws. Only the best's source (the
/// one member holding the substitution) sees wire deltas; the other
/// members' streams stay at the single initial winner announce.
#[tokio::test]
async fn oracle_pcb_lane_only_churn_reaches_only_the_best_source() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 3)], vec![]).await;
        // Runner-up attribute churn at the same rank: the winner stands.
        let mut tweaked = ranked(pfx(1, 0), B, 2);
        AttrSet::edit(&mut tweaked.attributes, |attrs| {
            attrs.push(PathAttribute::Med(50));
        });
        o.routes(B, vec![tweaked], vec![]).await;
        // Runner-up withdraws: the substitution refills from the third
        // candidate; the winner still stands.
        o.routes(B, vec![], vec![pfx(1, 0)]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    // A (source of the standing best) sees every lane delta: the
    // initial substitution, the attribute churn, the refill from C.
    assert_eq!(
        src_seq(&grouped, A),
        vec![IpAddr::V4(B), IpAddr::V4(B), IpAddr::V4(C)]
    );
    // The non-source members hold the unchanged winner throughout.
    assert_eq!(src_seq(&grouped, B), vec![IpAddr::V4(A)]);
    assert_eq!(src_seq(&grouped, C), vec![IpAddr::V4(A)]);
    for member in [A, B, C] {
        assert!(
            grouped[&IpAddr::V4(member)]
                .iter()
                .all(|msg| msg.withdraw.is_empty()),
            "lane churn under a standing best must never reach a wire as a withdraw"
        );
    }
}

/// Dirty-member resync with overlap (the file's dirty-resync pattern):
/// the jammed member misses both an overlapped announce and the
/// winner's withdrawal-driven promotion; the timer resync must deliver
/// the promoted runner-up and the recovered announce. Folded-state
/// comparison applies only inside C’s explicitly scheduled retry interval.
#[tokio::test]
async fn oracle_pcb_dirty_resync_with_overlap_converges() {
    tokio::time::pause();
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        pcb_peer_up(o, C, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 best from A lands in C's channel (fills it).
        o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
        // The p1 runner-up changes nothing for C (the winner stands);
        // the p2 announce fails against the full channel → C dirty.
        o.routes(
            B,
            vec![ranked(pfx(1, 0), B, 2), ranked(pfx(2, 0), B, 1)],
            vec![],
        )
        .await;
        // The winner's source withdraws WHILE C is dirty: the resync
        // must deliver the promoted runner-up.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;

        // Free the channel and let the resync timer fire.
        let first = o
            .drain_before_recovery(C, RecoveryPath::QueueDeferral)
            .await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
        o.end_recovery(C).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    let folded = fold(&grouped);
    // C converges to the promoted winner and the recovered announce.
    assert_eq!(folded_src(&folded, C, pfx(1, 0)), Some(IpAddr::V4(B)));
    assert_eq!(folded_src(&folded, C, pfx(2, 0)), Some(IpAddr::V4(B)));
    // A (source of the withdrawn best) keeps the substituted runner-up.
    assert_eq!(folded_src(&folded, A, pfx(1, 0)), Some(IpAddr::V4(B)));
    // B's own candidate is all that remains for p1: split horizon.
    assert_eq!(folded_src(&folded, B, pfx(1, 0)), None);
}

/// RFC 2918 route refresh under overlap: refreshing the member that
/// sources the winner must replay the substituted runner-up, not the
/// Loc-RIB best; refreshing a non-source member replays the winner.
#[tokio::test]
async fn oracle_pcb_route_refresh_replays_runner_up_substitution() {
    let scenario = async |o: &mut Oracle| {
        pcb_peer_up(o, A, None, 64).await;
        pcb_peer_up(o, B, None, 64).await;
        pcb_peer_up(o, C, None, 64).await;
        o.routes(A, vec![ranked(pfx(1, 0), A, 1)], vec![]).await;
        o.routes(B, vec![ranked(pfx(1, 0), B, 2)], vec![]).await;
        o.routes(C, vec![ranked(pfx(1, 0), C, 3)], vec![]).await;
        // Refresh the winner's source, then a non-source member.
        o.route_refresh(A, Afi::Ipv4, Safi::Unicast).await;
        o.route_refresh(C, Afi::Ipv4, Safi::Unicast).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_route_parity(&grouped, &ungrouped);
    // A: the initial substitution, then the refresh replay of the SAME
    // substituted runner-up (never A's own winner).
    assert_eq!(src_seq(&grouped, A), vec![IpAddr::V4(B), IpAddr::V4(B)]);
    // C: the initial winner, then the refresh replay of the winner.
    assert_eq!(src_seq(&grouped, C), vec![IpAddr::V4(A), IpAddr::V4(A)]);
    // B was not refreshed: exactly the initial winner announce.
    assert_eq!(src_seq(&grouped, B), vec![IpAddr::V4(A)]);
    for member in [A, B, C] {
        assert!(
            grouped[&IpAddr::V4(member)]
                .iter()
                .all(|msg| msg.withdraw.is_empty()),
            "refresh replay must not withdraw anything"
        );
    }
}

/// All requests are queued before the actor runs. Distinct own-source rows,
/// a different policy group and negotiated private paths retain the same
/// normalized announcements, next hops, withdrawals and refresh markers.
#[tokio::test]
async fn oracle_queued_refresh_cohort_matches_private_replays() {
    for features in [
        OraclePeerFeatures::default(),
        OraclePeerFeatures {
            add_path_send_max: 2,
            ..OraclePeerFeatures::default()
        },
        OraclePeerFeatures {
            negotiated_orf_recv: ipv4_sendable(),
            ..OraclePeerFeatures::default()
        },
        OraclePeerFeatures {
            per_client_best: true,
            ..OraclePeerFeatures::default()
        },
    ] {
        let scenario = async |o: &mut Oracle| {
            for peer in [A, B, C] {
                o.peer_up_families_generation_with_features(
                    peer,
                    SESSION,
                    false,
                    true,
                    None,
                    64,
                    ipv4_sendable(),
                    features.clone(),
                )
                .await;
            }
            o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
                .await;
            o.routes(B, vec![ibgp_route(pfx(2, 0), B, 100, vec![])], vec![])
                .await;
            o.routes(C, vec![ibgp_route(pfx(3, 0), C, 100, vec![])], vec![])
                .await;
            let requests = [A, B, C].map(|peer| RibUpdate::RouteRefreshRequest {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                queued: Arc::default(),
            });
            o.queue(requests.into()).await;
            // A policy mutation is an actual FIFO barrier between otherwise
            // compatible requests; C must observe its new policy afterward.
            o.replace_policy(C, Some(deny_prefix_chain(pfx(1, 0))))
                .await;
            o.queue(
                [A, B, C]
                    .map(|peer| RibUpdate::RouteRefreshRequest {
                        peer: IpAddr::V4(peer),
                        session_id: SESSION,
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        queued: Arc::default(),
                    })
                    .into(),
            )
            .await;
        };
        let (grouped, ungrouped) =
            run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
        assert_route_parity(&grouped, &ungrouped);
        for peer in [A, B, C] {
            assert!(
                grouped[&IpAddr::V4(peer)]
                    .iter()
                    .any(|message| { !message.refresh_markers.is_empty() }),
                "each member received a refresh response"
            );
        }
    }
}

/// Plain single-best groups and private peers preserve their admitted action
/// across a content-changing, behavior-preserving clean regroup.
#[tokio::test]
async fn oracle_action_only_single_best_after_clean_regroup() {
    const SELF_TAG: u32 = 0xFDE8_0064;
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let mut policy = permit_all_with(RouteModifications {
                communities_remove: vec![SELF_TAG],
                ..RouteModifications::default()
            });
            let mut tagged = policy.policies[0].policy.entries[0].clone();
            tagged.match_community = vec![CommunityMatch::Standard { value: SELF_TAG }];
            tagged.modifications.set_next_hop = Some(NextHopAction::Self_);
            policy.policies[0].policy.entries.insert(0, tagged);
            let mut o = Oracle::spawn(force_ungrouped, Some(A));
            o.peer_up(A, false, true, None, 64).await;
            for peer in [B, C] {
                o.peer_up(peer, false, true, Some(policy.clone()), 64).await;
            }
            let candidate = |use_self: bool| {
                ibgp_route(
                    pfx(1, 0),
                    A,
                    100,
                    if use_self { vec![SELF_TAG] } else { vec![] },
                )
            };
            o.routes(A, vec![candidate(initially_self)], vec![]).await;
            let initial = o.drain_peer_available(C).await;
            let initial: Vec<_> = initial.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(initial.len(), 1);
            assert_eq!(initial[0].5, initially_self.then_some(NextHopAction::Self_));
            policy.policies[0].policy.entries.insert(
                0,
                deny_prefix_chain(pfx(9, 0)).policies[0].policy.entries[0].clone(),
            );
            o.replace_policy(C, Some(policy)).await;
            assert_eq!(
                o.group_label(C).await.starts_with("group:"),
                !force_ungrouped
            );
            assert!(
                o.drain_peer_available(C)
                    .await
                    .iter()
                    .all(|msg| msg.announce.is_empty() && msg.withdraw.is_empty()),
                "clean regroup must preserve the old action without replaying it"
            );
            o.routes(A, vec![candidate(!initially_self)], vec![]).await;
            let changed = o.drain_peer_available(C).await;
            assert!(changed.iter().all(|msg| msg.withdraw.is_empty()));
            let changed: Vec<_> = changed.iter().flat_map(|msg| &msg.announce).collect();
            assert_eq!(changed.len(), 1);
            assert_eq!(
                changed[0].5,
                (!initially_self).then_some(NextHopAction::Self_)
            );
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
    }
}

/// A refused action-only replacement must survive a dirty membership move
/// and targeted replay. The old action remains the admitted wire truth until
/// the receiver has room for the replacement.
#[tokio::test]
async fn oracle_action_only_refusal_regroup_and_replay() {
    const SELF_TAG: u32 = 0xFDE8_0064;
    tokio::time::pause();
    for initially_self in [false, true] {
        let mut runs = Vec::new();
        for force_ungrouped in [false, true] {
            let mut policy = permit_all_with(RouteModifications {
                communities_remove: vec![SELF_TAG],
                ..RouteModifications::default()
            });
            let mut tagged = policy.policies[0].policy.entries[0].clone();
            tagged.match_community = vec![CommunityMatch::Standard { value: SELF_TAG }];
            tagged.modifications.set_next_hop = Some(NextHopAction::Self_);
            policy.policies[0].policy.entries.insert(0, tagged);
            let mut o = Oracle::spawn(force_ungrouped, Some(A));
            o.peer_up(A, false, true, None, 64).await;
            o.peer_up(B, false, true, Some(policy.clone()), 64).await;
            o.peer_up(C, false, true, Some(policy.clone()), 1).await;
            o.drain_one(C).await; // Initial End-of-RIB occupies the one-slot queue.
            let candidate = |use_self: bool| {
                ibgp_route(
                    pfx(1, 0),
                    A,
                    100,
                    if use_self { vec![SELF_TAG] } else { vec![] },
                )
            };
            o.routes(A, vec![candidate(initially_self)], vec![]).await;
            // Leave the admitted initial announcement queued to refuse the change.
            o.routes(A, vec![candidate(!initially_self)], vec![]).await;
            let (reply, response) = oneshot::channel();
            o.tx.send(RibUpdate::ExplainAdvertisedRoute {
                peer: IpAddr::V4(C),
                prefix: Prefix::V4(pfx(1, 0)),
                rd: None,
                labeled: false,
                source: None,
                reply,
            })
            .await
            .unwrap();
            let before = response.await.unwrap();
            if force_ungrouped {
                assert!(
                    !before.unwrap().already_advertised,
                    "private state retains the old admitted action"
                );
            } else {
                assert!(
                    matches!(
                        before,
                        Err(crate::update::ExplainAdvertisedRouteError::FailedPrecondition(_))
                    ),
                    "dirty shared desired action is not proof of admission"
                );
            }
            policy.policies[0].policy.entries.insert(
                0,
                peer_context_permit_chain().policies[0].policy.entries[0].clone(),
            );
            o.replace_policy(C, Some(policy)).await;
            assert!(!o.group_label(C).await.starts_with("group:"));
            o.drain_before_recovery(C, RecoveryPath::InterruptedRegroup)
                .await;
            tokio::time::advance(Duration::from_secs(2)).await;
            o.quiesce().await;
            o.end_recovery(C).await;
            let after =
                query_explain_advertised_route(&o.tx, IpAddr::V4(C), Prefix::V4(pfx(1, 0))).await;
            assert!(
                after.already_advertised,
                "recovery admits the replacement action"
            );
            runs.push(o.finish().await);
        }
        assert_route_parity(&runs[0], &runs[1]);
        for stream in &runs {
            let messages = &stream[&IpAddr::V4(C)];
            assert!(messages.iter().all(|msg| msg.withdraw.is_empty()));
            let actions: Vec<_> = messages
                .iter()
                .flat_map(|msg| &msg.announce)
                .map(|entry| entry.5.clone())
                .collect();
            assert_eq!(
                actions,
                vec![
                    initially_self.then_some(NextHopAction::Self_),
                    (!initially_self).then_some(NextHopAction::Self_)
                ]
            );
        }
    }
}
