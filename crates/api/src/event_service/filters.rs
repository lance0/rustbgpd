use std::collections::BTreeSet;
use std::net::IpAddr;

use tonic::Status;

use crate::peer_types::{
    PolicyEvent, SessionEvent, SessionLifecycleEventType, SessionNotificationEventType,
};
use crate::proto;
use crate::rib_service::{parse_route_event_prefix_filter, route_event_afi_filter};
use rustbgpd_rib::RouteEventType;
use rustbgpd_wire::{Afi, Prefix, RouteDistinguisher};

#[derive(Clone)]
pub(super) struct WatchEventsFilter {
    categories: BTreeSet<i32>,
    event_types: BTreeSet<i32>,
    peer: Option<IpAddr>,
    afi: Option<Afi>,
    prefix: Option<Prefix>,
}

impl WatchEventsFilter {
    pub(super) fn matches_route_event(&self, event: &rustbgpd_rib::RouteEvent) -> bool {
        if !self.wants_route_events() {
            return false;
        }

        let event_type = route_event_type_to_bgp_event_type(event.event_type);
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(afi) = self.afi {
            match (afi, event.prefix) {
                (Afi::Ipv4, Prefix::V4(_)) | (Afi::Ipv6, Prefix::V6(_)) => {}
                _ => return false,
            }
        }

        if let Some(peer) = self.peer {
            let matches_current = event.peer == Some(peer);
            let matches_previous = event.previous_peer == Some(peer);
            let matches_target = event.target_peer == Some(peer);
            if !matches_current && !matches_previous && !matches_target {
                return false;
            }
        }

        if let Some(prefix) = self.prefix
            && event.prefix != prefix
        {
            return false;
        }

        true
    }

    pub(super) fn wants_route_events(&self) -> bool {
        (self.categories.is_empty()
            || self
                .categories
                .contains(&(proto::EventCategory::Route as i32)))
            && self.event_types_match_route_category()
    }

    pub(super) fn wants_session_events(&self) -> bool {
        (self.categories.is_empty()
            || self
                .categories
                .contains(&(proto::EventCategory::Session as i32)))
            && self.afi.is_none()
            && self.prefix.is_none()
            && self.event_types_match_session_category()
    }

    pub(super) fn wants_policy_events(&self) -> bool {
        let policy_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Policy as i32));
        let policy_type_allowed = self.event_types_match_policy_category();
        let policy_selected = policy_category_requested
            || (self.categories.is_empty() && !self.event_types.is_empty() && policy_type_allowed);
        policy_selected && self.afi.is_none() && self.prefix.is_none() && policy_type_allowed
    }

    pub(super) fn wants_dataplane_events(&self) -> bool {
        let dataplane_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Dataplane as i32));
        let dataplane_type_allowed = self.event_types_match_dataplane_category();
        let dataplane_selected = dataplane_category_requested
            || (self.categories.is_empty()
                && !self.event_types.is_empty()
                && dataplane_type_allowed);
        dataplane_selected && dataplane_type_allowed
    }

    pub(super) fn matches_dataplane_bgp_event(&self, event: &proto::BgpEvent) -> bool {
        if !self.wants_dataplane_events()
            || event.category != proto::EventCategory::Dataplane as i32
        {
            return false;
        }
        let Ok(event_type) = proto::BgpEventType::try_from(event.event_type) else {
            return false;
        };
        if !dataplane_bgp_event_type_allowed(event_type) {
            return false;
        }
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }

        let has_route_filters = self.peer.is_some() || self.afi.is_some() || self.prefix.is_some();
        if has_route_filters && !dataplane_bgp_event_type_has_route(event_type) {
            return false;
        }

        if let Some(peer) = self.peer
            && event.peer_address.parse::<IpAddr>().ok() != Some(peer)
        {
            return false;
        }
        if let Some(afi) = self.afi {
            match (afi, event.afi_safi) {
                (Afi::Ipv4, value) if value == proto::AddressFamily::Ipv4Unicast as i32 => {}
                (Afi::Ipv6, value) if value == proto::AddressFamily::Ipv6Unicast as i32 => {}
                _ => return false,
            }
        }
        if let Some(prefix) = self.prefix {
            let event_prefix =
                parse_route_event_prefix_filter(&event.prefix, event.prefix_length, self.afi)
                    .ok()
                    .flatten();
            if event_prefix != Some(prefix) {
                return false;
            }
        }

        true
    }

    pub(super) fn wants_evpn_events(&self) -> bool {
        let evpn_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Evpn as i32));
        let evpn_type_allowed = self.event_types_match_evpn_category();
        let evpn_selected = evpn_category_requested
            || (self.categories.is_empty() && !self.event_types.is_empty() && evpn_type_allowed);
        evpn_selected && self.afi.is_none() && self.prefix.is_none() && evpn_type_allowed
    }

    pub(super) fn wants_bfd_events(&self) -> bool {
        // BFD events are peer-scoped but carry no family/prefix, so a
        // family/prefix-filtered request never selects them (like session /
        // EVPN). Opt-in: not part of the default route+session set.
        let bfd_category_requested = self
            .categories
            .contains(&(proto::EventCategory::Bfd as i32));
        let bfd_type_allowed = self.event_types_match_bfd_category();
        let bfd_selected = bfd_category_requested
            || (self.categories.is_empty() && !self.event_types.is_empty() && bfd_type_allowed);
        bfd_selected && self.afi.is_none() && self.prefix.is_none() && bfd_type_allowed
    }

    pub(super) fn matches_bfd_event(&self, event: &proto::BgpEvent) -> bool {
        if !self.wants_bfd_events() || event.category != proto::EventCategory::Bfd as i32 {
            return false;
        }
        let Ok(event_type) = proto::BgpEventType::try_from(event.event_type) else {
            return false;
        };
        if !bfd_bgp_event_type_allowed(event_type) {
            return false;
        }
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }
        if let Some(peer) = self.peer
            && event.peer_address.parse::<IpAddr>().ok() != Some(peer)
        {
            return false;
        }
        true
    }

    pub(super) fn matches_session_event(&self, event: &SessionEvent) -> bool {
        if !self.wants_session_events() {
            return false;
        }

        let (event_type, event_peer) = match event {
            SessionEvent::Lifecycle(event) => (
                session_lifecycle_event_type_to_bgp_event_type(event.event_type),
                event.peer,
            ),
            SessionEvent::Notification(event) => (
                session_notification_event_type_to_bgp_event_type(event.event_type),
                event.peer,
            ),
        };
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(peer) = self.peer
            && event_peer != peer
        {
            return false;
        }

        true
    }

    pub(super) fn matches_policy_event(&self, event: &PolicyEvent) -> bool {
        if !self.wants_policy_events() {
            return false;
        }

        if !self.event_types.is_empty()
            && !self
                .event_types
                .contains(&(proto::BgpEventType::PolicyChanged as i32))
        {
            return false;
        }

        if let Some(peer) = self.peer
            && event.peer != Some(peer)
        {
            return false;
        }

        true
    }

    pub(super) fn matches_evpn_event(&self, event: &rustbgpd_rib::EvpnRouteEvent) -> bool {
        if !self.wants_evpn_events() {
            return false;
        }

        let event_type = route_event_type_to_evpn_bgp_event_type(event.event_type);
        if !self.event_types.is_empty() && !self.event_types.contains(&(event_type as i32)) {
            return false;
        }

        if let Some(peer) = self.peer {
            let matches_current = event.peer == Some(peer);
            let matches_previous = event.previous_peer == Some(peer);
            if !matches_current && !matches_previous {
                return false;
            }
        }

        true
    }

    fn event_types_match_route_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::RouteAdded
                        | proto::BgpEventType::RouteWithdrawn
                        | proto::BgpEventType::RouteBestChanged
                        | proto::BgpEventType::RoutePolicyFiltered
                        | proto::BgpEventType::StreamLagged)
                )
            })
    }

    fn event_types_match_session_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::SessionStateChanged
                        | proto::BgpEventType::SessionEstablished
                        | proto::BgpEventType::SessionLost
                        | proto::BgpEventType::PeerEnabled
                        | proto::BgpEventType::PeerDisabled
                        | proto::BgpEventType::NotificationSent
                        | proto::BgpEventType::NotificationReceived
                        | proto::BgpEventType::StreamLagged)
                )
            })
    }

    fn event_types_match_policy_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::PolicyChanged)
                )
            })
    }

    fn event_types_match_dataplane_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                proto::BgpEventType::try_from(*event_type)
                    .is_ok_and(dataplane_bgp_event_type_allowed)
            })
    }

    fn event_types_match_evpn_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                matches!(
                    proto::BgpEventType::try_from(*event_type),
                    Ok(proto::BgpEventType::EvpnRouteAdded
                        | proto::BgpEventType::EvpnRouteWithdrawn
                        | proto::BgpEventType::EvpnRouteBestChanged
                        | proto::BgpEventType::StreamLagged)
                )
            })
    }

    fn event_types_match_bfd_category(&self) -> bool {
        self.event_types.is_empty()
            || self.event_types.iter().any(|event_type| {
                proto::BgpEventType::try_from(*event_type).is_ok_and(bfd_bgp_event_type_allowed)
            })
    }
}

fn bfd_bgp_event_type_allowed(event_type: proto::BgpEventType) -> bool {
    matches!(
        event_type,
        proto::BgpEventType::BfdSessionUp
            | proto::BgpEventType::BfdSessionDown
            | proto::BgpEventType::BfdSessionStateChanged
            | proto::BgpEventType::StreamLagged
    )
}

fn dataplane_bgp_event_type_allowed(event_type: proto::BgpEventType) -> bool {
    matches!(
        event_type,
        proto::BgpEventType::DataplaneStatusChanged
            | proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
            | proto::BgpEventType::StreamLagged
    )
}

fn dataplane_bgp_event_type_has_route(event_type: proto::BgpEventType) -> bool {
    matches!(
        event_type,
        proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
    )
}

pub(super) struct SessionEventHistoryFilter {
    pub(super) peer: Option<IpAddr>,
    pub(super) event_types: BTreeSet<SessionLifecycleEventType>,
    pub(super) limit: usize,
}

pub(super) struct PolicyEventHistoryFilter {
    pub(super) peer: Option<IpAddr>,
    pub(super) limit: usize,
}

pub(super) struct EvpnEventHistoryFilter {
    pub(super) peer: Option<IpAddr>,
    pub(super) event_types: BTreeSet<RouteEventType>,
    pub(super) route_type: Option<u8>,
    pub(super) rd: Option<RouteDistinguisher>,
    pub(super) limit: usize,
}

pub(super) fn route_event_type_to_bgp_event_type(
    event_type: RouteEventType,
) -> proto::BgpEventType {
    match event_type {
        RouteEventType::Added => proto::BgpEventType::RouteAdded,
        RouteEventType::Withdrawn => proto::BgpEventType::RouteWithdrawn,
        RouteEventType::BestChanged => proto::BgpEventType::RouteBestChanged,
        RouteEventType::PolicyFiltered => proto::BgpEventType::RoutePolicyFiltered,
    }
}

pub(super) fn route_event_type_to_evpn_bgp_event_type(
    event_type: RouteEventType,
) -> proto::BgpEventType {
    match event_type {
        RouteEventType::Added => proto::BgpEventType::EvpnRouteAdded,
        RouteEventType::Withdrawn => proto::BgpEventType::EvpnRouteWithdrawn,
        RouteEventType::BestChanged => proto::BgpEventType::EvpnRouteBestChanged,
        RouteEventType::PolicyFiltered => proto::BgpEventType::Unspecified,
    }
}

fn bgp_event_type_to_session_event_type(
    event_type: proto::BgpEventType,
) -> Option<SessionLifecycleEventType> {
    match event_type {
        proto::BgpEventType::SessionStateChanged => Some(SessionLifecycleEventType::StateChanged),
        proto::BgpEventType::SessionEstablished => Some(SessionLifecycleEventType::Established),
        proto::BgpEventType::SessionLost => Some(SessionLifecycleEventType::Lost),
        proto::BgpEventType::PeerEnabled => Some(SessionLifecycleEventType::PeerEnabled),
        proto::BgpEventType::PeerDisabled => Some(SessionLifecycleEventType::PeerDisabled),
        proto::BgpEventType::Unspecified
        | proto::BgpEventType::RouteAdded
        | proto::BgpEventType::RouteWithdrawn
        | proto::BgpEventType::RouteBestChanged
        | proto::BgpEventType::RoutePolicyFiltered
        | proto::BgpEventType::EvpnRouteAdded
        | proto::BgpEventType::EvpnRouteWithdrawn
        | proto::BgpEventType::EvpnRouteBestChanged
        | proto::BgpEventType::NotificationSent
        | proto::BgpEventType::NotificationReceived
        | proto::BgpEventType::PolicyChanged
        | proto::BgpEventType::DataplaneStatusChanged
        | proto::BgpEventType::DataplaneRouteInstalled
        | proto::BgpEventType::DataplaneRouteWithdrawn
        | proto::BgpEventType::DataplaneRouteFailed
        | proto::BgpEventType::BfdSessionUp
        | proto::BgpEventType::BfdSessionDown
        | proto::BgpEventType::BfdSessionStateChanged
        | proto::BgpEventType::StreamLagged => None,
    }
}

fn parse_category_filter(categories: &[i32]) -> Result<BTreeSet<i32>, Status> {
    let mut parsed = BTreeSet::new();
    for category in categories {
        let category = proto::EventCategory::try_from(*category)
            .map_err(|_| Status::invalid_argument("unknown event category"))?;
        match category {
            proto::EventCategory::Route
            | proto::EventCategory::Session
            | proto::EventCategory::Policy
            | proto::EventCategory::Dataplane
            | proto::EventCategory::Evpn
            | proto::EventCategory::Bfd => {
                parsed.insert(category as i32);
            }
            proto::EventCategory::Unspecified => {
                return Err(Status::invalid_argument(
                    "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
                ));
            }
        }
    }
    Ok(parsed)
}

fn parse_event_type_filter(event_types: &[i32]) -> Result<BTreeSet<i32>, Status> {
    let mut parsed = BTreeSet::new();
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        match event_type {
            proto::BgpEventType::RouteAdded
            | proto::BgpEventType::RouteWithdrawn
            | proto::BgpEventType::RouteBestChanged
            | proto::BgpEventType::RoutePolicyFiltered
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
            | proto::BgpEventType::NotificationSent
            | proto::BgpEventType::NotificationReceived
            | proto::BgpEventType::PolicyChanged
            | proto::BgpEventType::DataplaneStatusChanged
            | proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
            | proto::BgpEventType::EvpnRouteAdded
            | proto::BgpEventType::EvpnRouteWithdrawn
            | proto::BgpEventType::EvpnRouteBestChanged
            | proto::BgpEventType::BfdSessionUp
            | proto::BgpEventType::BfdSessionDown
            | proto::BgpEventType::BfdSessionStateChanged
            | proto::BgpEventType::StreamLagged => {
                parsed.insert(event_type as i32);
            }
            proto::BgpEventType::Unspecified => {
                return Err(Status::invalid_argument(
                    "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
                ));
            }
        }
    }
    Ok(parsed)
}

fn parse_session_event_type_filter(
    event_types: &[i32],
) -> Result<BTreeSet<SessionLifecycleEventType>, Status> {
    let mut parsed = BTreeSet::new();
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        if event_type == proto::BgpEventType::Unspecified {
            return Err(Status::invalid_argument(
                "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
            ));
        }
        let Some(session_type) = bgp_event_type_to_session_event_type(event_type) else {
            return Err(Status::invalid_argument(
                "ListSessionEvents only supports session event types",
            ));
        };
        parsed.insert(session_type);
    }
    Ok(parsed)
}

fn parse_policy_event_type_filter(event_types: &[i32]) -> Result<(), Status> {
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        match event_type {
            proto::BgpEventType::PolicyChanged => {}
            proto::BgpEventType::Unspecified => {
                return Err(Status::invalid_argument(
                    "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
                ));
            }
            proto::BgpEventType::RouteAdded
            | proto::BgpEventType::RouteWithdrawn
            | proto::BgpEventType::RouteBestChanged
            | proto::BgpEventType::RoutePolicyFiltered
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
            | proto::BgpEventType::NotificationSent
            | proto::BgpEventType::NotificationReceived
            | proto::BgpEventType::DataplaneStatusChanged
            | proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
            | proto::BgpEventType::EvpnRouteAdded
            | proto::BgpEventType::EvpnRouteWithdrawn
            | proto::BgpEventType::EvpnRouteBestChanged
            | proto::BgpEventType::BfdSessionUp
            | proto::BgpEventType::BfdSessionDown
            | proto::BgpEventType::BfdSessionStateChanged
            | proto::BgpEventType::StreamLagged => {
                return Err(Status::invalid_argument(
                    "ListPolicyEvents only supports policy event types",
                ));
            }
        }
    }
    Ok(())
}

fn parse_evpn_event_type_filter(event_types: &[i32]) -> Result<BTreeSet<RouteEventType>, Status> {
    let mut parsed = BTreeSet::new();
    for event_type in event_types {
        let event_type = proto::BgpEventType::try_from(*event_type)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        match event_type {
            proto::BgpEventType::EvpnRouteAdded => {
                parsed.insert(RouteEventType::Added);
            }
            proto::BgpEventType::EvpnRouteWithdrawn => {
                parsed.insert(RouteEventType::Withdrawn);
            }
            proto::BgpEventType::EvpnRouteBestChanged => {
                parsed.insert(RouteEventType::BestChanged);
            }
            proto::BgpEventType::Unspecified => {
                return Err(Status::invalid_argument(
                    "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
                ));
            }
            proto::BgpEventType::RouteAdded
            | proto::BgpEventType::RouteWithdrawn
            | proto::BgpEventType::RouteBestChanged
            | proto::BgpEventType::RoutePolicyFiltered
            | proto::BgpEventType::SessionStateChanged
            | proto::BgpEventType::SessionEstablished
            | proto::BgpEventType::SessionLost
            | proto::BgpEventType::PeerEnabled
            | proto::BgpEventType::PeerDisabled
            | proto::BgpEventType::NotificationSent
            | proto::BgpEventType::NotificationReceived
            | proto::BgpEventType::PolicyChanged
            | proto::BgpEventType::DataplaneStatusChanged
            | proto::BgpEventType::DataplaneRouteInstalled
            | proto::BgpEventType::DataplaneRouteWithdrawn
            | proto::BgpEventType::DataplaneRouteFailed
            | proto::BgpEventType::BfdSessionUp
            | proto::BgpEventType::BfdSessionDown
            | proto::BgpEventType::BfdSessionStateChanged
            | proto::BgpEventType::StreamLagged => {
                return Err(Status::invalid_argument(
                    "ListEvpnEvents only supports EVPN event types",
                ));
            }
        }
    }
    Ok(parsed)
}

fn parse_evpn_route_type_filter(route_type: u32) -> Result<Option<u8>, Status> {
    if route_type == 0 {
        return Ok(None);
    }
    let route_type = u8::try_from(route_type)
        .map_err(|_| Status::invalid_argument("EVPN route_type_filter must be 1..=5"))?;
    if (1..=5).contains(&route_type) {
        Ok(Some(route_type))
    } else {
        Err(Status::invalid_argument(
            "EVPN route_type_filter must be 1..=5",
        ))
    }
}

fn parse_evpn_rd_filter(rd: &str) -> Result<Option<RouteDistinguisher>, Status> {
    if rd.is_empty() {
        return Ok(None);
    }
    rd.parse::<RouteDistinguisher>()
        .map(Some)
        .map_err(|e| Status::invalid_argument(format!("invalid EVPN rd_filter: {e}")))
}

pub(super) fn session_lifecycle_event_type_to_bgp_event_type(
    event_type: SessionLifecycleEventType,
) -> proto::BgpEventType {
    match event_type {
        SessionLifecycleEventType::StateChanged => proto::BgpEventType::SessionStateChanged,
        SessionLifecycleEventType::Established => proto::BgpEventType::SessionEstablished,
        SessionLifecycleEventType::Lost => proto::BgpEventType::SessionLost,
        SessionLifecycleEventType::PeerEnabled => proto::BgpEventType::PeerEnabled,
        SessionLifecycleEventType::PeerDisabled => proto::BgpEventType::PeerDisabled,
    }
}

pub(super) fn session_notification_event_type_to_bgp_event_type(
    event_type: SessionNotificationEventType,
) -> proto::BgpEventType {
    match event_type {
        SessionNotificationEventType::Sent => proto::BgpEventType::NotificationSent,
        SessionNotificationEventType::Received => proto::BgpEventType::NotificationReceived,
    }
}

pub(super) fn parse_watch_events_filter(
    req: &proto::WatchEventsRequest,
) -> Result<WatchEventsFilter, Status> {
    let categories = parse_category_filter(&req.categories)?;
    let event_types = parse_event_type_filter(&req.event_types)?;
    let afi = route_event_afi_filter(req.afi_safi)?;
    let prefix = parse_route_event_prefix_filter(&req.prefix, req.prefix_length, afi)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(WatchEventsFilter {
        categories,
        event_types,
        peer,
        afi,
        prefix,
    })
}

pub(super) fn parse_list_session_events_filter(
    req: &proto::ListSessionEventsRequest,
) -> Result<SessionEventHistoryFilter, Status> {
    let event_types = parse_session_event_type_filter(&req.event_types)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(SessionEventHistoryFilter {
        peer,
        event_types,
        limit: req.limit as usize,
    })
}

pub(super) fn parse_list_policy_events_filter(
    req: &proto::ListPolicyEventsRequest,
) -> Result<PolicyEventHistoryFilter, Status> {
    parse_policy_event_type_filter(&req.event_types)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(PolicyEventHistoryFilter {
        peer,
        limit: req.limit as usize,
    })
}

pub(super) fn parse_list_evpn_events_filter(
    req: &proto::ListEvpnEventsRequest,
) -> Result<EvpnEventHistoryFilter, Status> {
    let event_types = parse_evpn_event_type_filter(&req.event_types)?;
    let peer = if req.neighbor_address.is_empty() {
        None
    } else {
        Some(
            req.neighbor_address
                .parse::<IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?,
        )
    };

    Ok(EvpnEventHistoryFilter {
        peer,
        event_types,
        route_type: parse_evpn_route_type_filter(req.route_type_filter)?,
        rd: parse_evpn_rd_filter(&req.rd_filter)?,
        limit: req.limit as usize,
    })
}
