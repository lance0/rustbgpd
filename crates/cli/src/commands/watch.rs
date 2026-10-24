use crate::connection::{Connection, read_rpc};
use crate::error::CliError;
use crate::output::{self, JsonRouteEvent, outln};
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddressFamily, BgpEvent, BgpEventType, EventCategory, EvpnRouteEntry, ListEvpnEventsRequest,
    ListPolicyEventsRequest, ListRouteEventsRequest, ListSessionEventsRequest, RouteEvent,
    RouteEventType, StreamLagEvent, WatchEventsRequest,
};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use std::net::IpAddr;

pub struct EventsWatchOptions {
    pub categories: Vec<String>,
    pub neighbor: Option<String>,
    pub family: Option<i32>,
    pub prefix: Option<String>,
    pub event_types: Vec<String>,
    pub backfill: u32,
    pub json: bool,
}

/// Render route-event peers in the scoped `fe80::1%eth0` form from the
/// interfaces the daemon recorded with the event.
fn scope_route_event(event: &mut RouteEvent) {
    use crate::commands::neighbor::scope_address;
    scope_address(&mut event.peer_address, &event.peer_interface);
    scope_address(
        &mut event.previous_peer_address,
        &event.previous_peer_interface,
    );
    scope_address(&mut event.target_peer_address, &event.target_peer_interface);
}

/// Render a stream event's neighbors in scoped form: the payload carries
/// the interfaces, which also scope the envelope's addresses.
pub(crate) fn scope_bgp_event(event: &mut BgpEvent) {
    use crate::commands::neighbor::scope_address;
    use crate::proto::bgp_event::Payload;
    match &mut event.payload {
        Some(Payload::Route(route)) => {
            scope_address(&mut event.peer_address, &route.peer_interface);
            scope_address(
                &mut event.previous_peer_address,
                &route.previous_peer_interface,
            );
            scope_address(&mut event.target_peer_address, &route.target_peer_interface);
            scope_route_event(route);
        }
        Some(Payload::Session(session)) => {
            scope_address(&mut event.peer_address, &session.peer_interface);
            scope_address(&mut session.peer_address, &session.peer_interface);
        }
        Some(Payload::Notification(notification)) => {
            scope_address(&mut event.peer_address, &notification.peer_interface);
            scope_address(&mut notification.peer_address, &notification.peer_interface);
        }
        Some(Payload::Policy(policy)) => {
            scope_address(&mut event.peer_address, &policy.peer_interface);
            scope_address(&mut policy.peer_address, &policy.peer_interface);
        }
        Some(Payload::DataplaneRoute(route)) => {
            scope_address(&mut event.peer_address, &route.peer_interface);
            scope_address(&mut route.peer_address, &route.peer_interface);
        }
        Some(Payload::Bfd(session)) => {
            scope_address(&mut event.peer_address, &session.peer_interface);
            scope_address(&mut session.peer_address, &session.peer_interface);
        }
        Some(Payload::Evpn(route)) => {
            scope_address(&mut event.peer_address, &route.peer_interface);
            scope_address(
                &mut event.previous_peer_address,
                &route.previous_peer_interface,
            );
            scope_address(&mut route.peer_address, &route.peer_interface);
            scope_address(
                &mut route.previous_peer_address,
                &route.previous_peer_interface,
            );
            if let Some(current) = route.route.as_mut() {
                scope_address(&mut current.peer_address, &route.peer_interface);
            }
            if let Some(previous) = route.previous_route.as_mut() {
                scope_address(&mut previous.peer_address, &route.previous_peer_interface);
            }
        }
        _ => {}
    }
}

fn format_event_type(t: i32) -> &'static str {
    match RouteEventType::try_from(t) {
        Ok(RouteEventType::Added) => "added",
        Ok(RouteEventType::Withdrawn) => "withdrawn",
        Ok(RouteEventType::BestChanged) => "best_changed",
        Ok(RouteEventType::PolicyFiltered) => "policy_filtered",
        _ => "unknown",
    }
}

fn json_event(event: &RouteEvent) -> JsonRouteEvent {
    JsonRouteEvent {
        event_id: event.event_id,
        event_type: format_event_type(event.event_type).to_string(),
        prefix: format!("{}/{}", event.prefix, event.prefix_length),
        peer_address: event.peer_address.clone(),
        previous_peer_address: event.previous_peer_address.clone(),
        target_peer_address: event.target_peer_address.clone(),
        afi_safi: output::format_family(event.afi_safi).to_string(),
        timestamp: event.timestamp.clone(),
        timestamp_unix_seconds: timestamp_unix_seconds(&event.timestamp),
        path_id: event.path_id,
        missed_count: 0,
        reason: event.reason.clone(),
    }
}

/// Event timestamps travel as decimal Unix seconds in a string field. JSON
/// keeps that string and adds this numeric form; `None` (JSON `null`) means
/// the daemon sent something other than integer seconds.
pub(crate) fn timestamp_unix_seconds(raw: &str) -> Option<u64> {
    raw.parse().ok()
}

/// Human event lines use the same RFC 3339 UTC rendering as
/// `config history`; a non-numeric value is shown as received.
fn human_timestamp(raw: &str) -> String {
    timestamp_unix_seconds(raw)
        .and_then(super::config::format_unix_utc)
        .unwrap_or_else(|| raw.to_string())
}

fn print_event(event: &RouteEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&json_event(event))?;
        return Ok(());
    }
    outln!("{}", format_route_event_line(event))?;
    Ok(())
}

fn format_route_event_line(event: &RouteEvent) -> String {
    let prefix = format!("{}/{}", event.prefix, event.prefix_length);
    let path_id_str = if event.path_id > 0 {
        format!(" path_id={}", event.path_id)
    } else {
        String::new()
    };
    let event_id_str = if event.event_id > 0 {
        format!(" id={}", event.event_id)
    } else {
        String::new()
    };
    let previous_peer = if event.previous_peer_address.is_empty() {
        String::new()
    } else {
        format!(" previous={}", event.previous_peer_address)
    };
    let target_peer = if event.target_peer_address.is_empty() {
        String::new()
    } else {
        format!(" target={}", event.target_peer_address)
    };
    let reason = if event.reason.is_empty() {
        String::new()
    } else {
        format!(" reason={}", event.reason)
    };
    format!(
        "[{}] {} {} from {}{}{}{}{}{}",
        human_timestamp(&event.timestamp),
        output::colored_event_type(format_event_type(event.event_type)),
        prefix,
        event.peer_address,
        previous_peer,
        target_peer,
        reason,
        path_id_str,
        event_id_str,
    )
}

fn parse_bgp_event_type(s: &str) -> Result<i32, CliError> {
    match s {
        "added" | "route_added" => Ok(BgpEventType::RouteAdded as i32),
        "withdrawn" | "route_withdrawn" => Ok(BgpEventType::RouteWithdrawn as i32),
        "best_changed" | "route_best_changed" => Ok(BgpEventType::RouteBestChanged as i32),
        "policy_filtered" | "route_policy_filtered" => Ok(BgpEventType::RoutePolicyFiltered as i32),
        "state_changed" | "session_state_changed" => Ok(BgpEventType::SessionStateChanged as i32),
        "established" | "session_established" => Ok(BgpEventType::SessionEstablished as i32),
        "lost" | "session_lost" => Ok(BgpEventType::SessionLost as i32),
        "peer_enabled" => Ok(BgpEventType::PeerEnabled as i32),
        "peer_disabled" => Ok(BgpEventType::PeerDisabled as i32),
        "peer_added" => Ok(BgpEventType::PeerAdded as i32),
        "peer_removed" => Ok(BgpEventType::PeerRemoved as i32),
        "max_prefix_warning" => Ok(BgpEventType::MaxPrefixWarning as i32),
        "notification_sent" => Ok(BgpEventType::NotificationSent as i32),
        "notification_received" => Ok(BgpEventType::NotificationReceived as i32),
        "policy_changed" => Ok(BgpEventType::PolicyChanged as i32),
        "dataplane_status_changed" | "dataplane_changed" => {
            Ok(BgpEventType::DataplaneStatusChanged as i32)
        }
        "dataplane_route_installed" | "fib_installed" => {
            Ok(BgpEventType::DataplaneRouteInstalled as i32)
        }
        "dataplane_route_withdrawn" | "fib_withdrawn" => {
            Ok(BgpEventType::DataplaneRouteWithdrawn as i32)
        }
        "dataplane_route_failed" | "fib_failed" => Ok(BgpEventType::DataplaneRouteFailed as i32),
        "evpn_added" | "evpn_route_added" => Ok(BgpEventType::EvpnRouteAdded as i32),
        "evpn_withdrawn" | "evpn_route_withdrawn" => Ok(BgpEventType::EvpnRouteWithdrawn as i32),
        "evpn_best_changed" | "evpn_route_best_changed" => {
            Ok(BgpEventType::EvpnRouteBestChanged as i32)
        }
        "bfd_up" | "bfd_session_up" => Ok(BgpEventType::BfdSessionUp as i32),
        "bfd_down" | "bfd_session_down" => Ok(BgpEventType::BfdSessionDown as i32),
        "bfd_state_changed" | "bfd_session_state_changed" => {
            Ok(BgpEventType::BfdSessionStateChanged as i32)
        }
        "stream_lagged" | "lagged" => Ok(BgpEventType::StreamLagged as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event type {other:?}; expected {}",
            EventTypeScope::All.expected()
        ))),
    }
}

/// Canonical `--type` spelling of every event type `parse_bgp_event_type`
/// accepts. Help, completions, and error messages derive from this list.
const BGP_EVENT_TYPE_NAMES: &[&str] = &[
    "added",
    "withdrawn",
    "best_changed",
    "policy_filtered",
    "state_changed",
    "established",
    "lost",
    "peer_added",
    "peer_removed",
    "peer_enabled",
    "peer_disabled",
    "max_prefix_warning",
    "notification_sent",
    "notification_received",
    "policy_changed",
    "dataplane_status_changed",
    "dataplane_route_installed",
    "dataplane_route_withdrawn",
    "dataplane_route_failed",
    "evpn_added",
    "evpn_withdrawn",
    "evpn_best_changed",
    "bfd_up",
    "bfd_down",
    "bfd_state_changed",
    "stream_lagged",
];

/// The event types one `--type` filter accepts.
#[derive(Clone, Copy)]
pub(crate) enum EventTypeScope {
    All,
    Session,
    Policy,
    Evpn,
}

impl EventTypeScope {
    fn accepts(self, event_type: BgpEventType) -> bool {
        match self {
            Self::All => true,
            Self::Session => matches!(
                event_type,
                BgpEventType::SessionStateChanged
                    | BgpEventType::SessionEstablished
                    | BgpEventType::SessionLost
                    | BgpEventType::PeerEnabled
                    | BgpEventType::PeerDisabled
                    | BgpEventType::PeerAdded
                    | BgpEventType::PeerRemoved
                    | BgpEventType::MaxPrefixWarning
            ),
            Self::Policy => event_type == BgpEventType::PolicyChanged,
            Self::Evpn => matches!(
                event_type,
                BgpEventType::EvpnRouteAdded
                    | BgpEventType::EvpnRouteWithdrawn
                    | BgpEventType::EvpnRouteBestChanged
            ),
        }
    }

    /// Canonical names this scope accepts, in help order.
    pub(crate) fn names(self) -> impl Iterator<Item = &'static str> {
        BGP_EVENT_TYPE_NAMES.iter().copied().filter(move |name| {
            parse_bgp_event_type(name)
                .ok()
                .and_then(|value| BgpEventType::try_from(value).ok())
                .is_some_and(|event_type| self.accepts(event_type))
        })
    }

    fn expected(self) -> String {
        let names: Vec<_> = self.names().collect();
        match names.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{}, or {last}", rest.join(", ")),
            _ => names.join(""),
        }
    }

    fn parse(self, s: &str, label: &str) -> Result<i32, CliError> {
        let event_type = parse_bgp_event_type(s)?;
        match BgpEventType::try_from(event_type) {
            Ok(accepted) if self.accepts(accepted) => Ok(event_type),
            _ => Err(CliError::Argument(format!(
                "unsupported {label} event type {s:?}; expected {}",
                self.expected()
            ))),
        }
    }
}

fn parse_session_bgp_event_type(s: &str) -> Result<i32, CliError> {
    EventTypeScope::Session.parse(s, "session")
}

fn parse_policy_bgp_event_type(s: &str) -> Result<i32, CliError> {
    EventTypeScope::Policy.parse(s, "policy")
}

fn parse_evpn_bgp_event_type(s: &str) -> Result<i32, CliError> {
    EventTypeScope::Evpn.parse(s, "EVPN")
}

fn parse_event_category(s: &str) -> Result<i32, CliError> {
    match s {
        "route" => Ok(EventCategory::Route as i32),
        "session" => Ok(EventCategory::Session as i32),
        "policy" => Ok(EventCategory::Policy as i32),
        "dataplane" => Ok(EventCategory::Dataplane as i32),
        "evpn" => Ok(EventCategory::Evpn as i32),
        "bfd" => Ok(EventCategory::Bfd as i32),
        other => Err(CliError::Argument(format!(
            "unsupported event category {other:?}; expected route, session, policy, dataplane, evpn, or bfd"
        ))),
    }
}

fn bgp_event_type_is_route(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::RouteAdded
            | BgpEventType::RouteWithdrawn
            | BgpEventType::RouteBestChanged)
    )
}

fn bgp_event_type_is_dataplane_route(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::DataplaneRouteInstalled)
            | Ok(BgpEventType::DataplaneRouteWithdrawn)
            | Ok(BgpEventType::DataplaneRouteFailed)
    )
}

fn validate_route_only_filters(
    categories: &[i32],
    event_types: &[i32],
    family: Option<i32>,
    prefix: Option<&str>,
) -> Result<(), CliError> {
    let route_category_selected =
        categories.is_empty() || categories.contains(&(EventCategory::Route as i32));
    let route_type_selected =
        event_types.is_empty() || event_types.iter().copied().any(bgp_event_type_is_route);
    let dataplane_category_selected =
        categories.is_empty() || categories.contains(&(EventCategory::Dataplane as i32));
    let dataplane_type_selected = event_types.is_empty()
        || event_types
            .iter()
            .copied()
            .any(bgp_event_type_is_dataplane_route);
    if !((route_category_selected && route_type_selected)
        || (dataplane_category_selected && dataplane_type_selected))
        && (family.is_some() || prefix.is_some())
    {
        return Err(CliError::Argument(
            "--family and --prefix require route or dataplane route events; remove them or select a compatible category/type"
                .into(),
        ));
    }
    Ok(())
}

fn bgp_event_type_json_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "route_added",
        Ok(BgpEventType::RouteWithdrawn) => "route_withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "route_best_changed",
        Ok(BgpEventType::RoutePolicyFiltered) => "route_policy_filtered",
        Ok(BgpEventType::SessionStateChanged) => "session_state_changed",
        Ok(BgpEventType::SessionEstablished) => "session_established",
        Ok(BgpEventType::SessionLost) => "session_lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::PeerAdded) => "peer_added",
        Ok(BgpEventType::PeerRemoved) => "peer_removed",
        Ok(BgpEventType::MaxPrefixWarning) => "max_prefix_warning",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
        Ok(BgpEventType::DataplaneRouteInstalled) => "dataplane_route_installed",
        Ok(BgpEventType::DataplaneRouteWithdrawn) => "dataplane_route_withdrawn",
        Ok(BgpEventType::DataplaneRouteFailed) => "dataplane_route_failed",
        Ok(BgpEventType::EvpnRouteAdded) => "evpn_route_added",
        Ok(BgpEventType::EvpnRouteWithdrawn) => "evpn_route_withdrawn",
        Ok(BgpEventType::EvpnRouteBestChanged) => "evpn_route_best_changed",
        Ok(BgpEventType::BfdSessionUp) => "bfd_session_up",
        Ok(BgpEventType::BfdSessionDown) => "bfd_session_down",
        Ok(BgpEventType::BfdSessionStateChanged) => "bfd_session_state_changed",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn bgp_event_type_display_label(event_type: i32) -> &'static str {
    match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best_changed",
        Ok(BgpEventType::RoutePolicyFiltered) => "policy_filtered",
        Ok(BgpEventType::SessionStateChanged) => "state_changed",
        Ok(BgpEventType::SessionEstablished) => "established",
        Ok(BgpEventType::SessionLost) => "lost",
        Ok(BgpEventType::PeerEnabled) => "peer_enabled",
        Ok(BgpEventType::PeerDisabled) => "peer_disabled",
        Ok(BgpEventType::PeerAdded) => "peer_added",
        Ok(BgpEventType::PeerRemoved) => "peer_removed",
        Ok(BgpEventType::MaxPrefixWarning) => "max_prefix_warning",
        Ok(BgpEventType::NotificationSent) => "notification_sent",
        Ok(BgpEventType::NotificationReceived) => "notification_received",
        Ok(BgpEventType::PolicyChanged) => "policy_changed",
        Ok(BgpEventType::DataplaneStatusChanged) => "dataplane_status_changed",
        Ok(BgpEventType::DataplaneRouteInstalled) => "dataplane_route_installed",
        Ok(BgpEventType::DataplaneRouteWithdrawn) => "dataplane_route_withdrawn",
        Ok(BgpEventType::DataplaneRouteFailed) => "dataplane_route_failed",
        Ok(BgpEventType::EvpnRouteAdded) => "evpn_added",
        Ok(BgpEventType::EvpnRouteWithdrawn) => "evpn_withdrawn",
        Ok(BgpEventType::EvpnRouteBestChanged) => "evpn_best_changed",
        Ok(BgpEventType::BfdSessionUp) => "bfd_up",
        Ok(BgpEventType::BfdSessionDown) => "bfd_down",
        Ok(BgpEventType::BfdSessionStateChanged) => "bfd_state_changed",
        Ok(BgpEventType::StreamLagged) => "stream_lagged",
        _ => "unknown",
    }
}

fn evpn_route_type_label(t: u32) -> &'static str {
    match t {
        1 => "ead",
        2 => "mac-ip",
        3 => "imet",
        4 => "es",
        5 => "ip-prefix",
        6 => "smet",
        _ => "unknown",
    }
}

fn event_category_json_label(category: i32) -> &'static str {
    match EventCategory::try_from(category) {
        Ok(EventCategory::Route) => "route",
        Ok(EventCategory::Session) => "session",
        Ok(EventCategory::Policy) => "policy",
        Ok(EventCategory::Dataplane) => "dataplane",
        Ok(EventCategory::Evpn) => "evpn",
        Ok(EventCategory::Bfd) => "bfd",
        _ => "unknown",
    }
}

struct JsonEventPrefix<'a>(&'a BgpEvent);

impl Serialize for JsonEventPrefix<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.prefix.is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.collect_str(&format_args!("{}/{}", self.0.prefix, self.0.prefix_length))
        }
    }
}

struct JsonAddressFamily(i32);

impl Serialize for JsonAddressFamily {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0 == AddressFamily::Unspecified as i32 {
            serializer.serialize_none()
        } else {
            serializer.serialize_str(output::format_family(self.0))
        }
    }
}

struct JsonEvpnRouteEntry<'a>(&'a EvpnRouteEntry);

impl Serialize for JsonEvpnRouteEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let route = self.0;
        // Keys are emitted in flattened alphabetical order to match the
        // pre-#515 serde_json::Value (BTreeMap) byte output. Locked by
        // `direct_bgp_event_json_matches_legacy_value` — keep sorted.
        let mut map = serializer.serialize_map(Some(
            17 + usize::from(route.prefix_sid.is_some()) + usize::from(route.smet.is_some()),
        ))?;
        map.serialize_entry("as_path", &route.as_path)?;
        map.serialize_entry("communities", &route.communities)?;
        map.serialize_entry("esi", &route.esi)?;
        map.serialize_entry("ethernet_tag", &route.ethernet_tag)?;
        map.serialize_entry("extended_communities", &route.extended_communities)?;
        map.serialize_entry("gateway", &route.gateway)?;
        map.serialize_entry("ip", &route.ip)?;
        map.serialize_entry("label", &route.label)?;
        map.serialize_entry("label2", &route.label2)?;
        map.serialize_entry("mac", &route.mac)?;
        map.serialize_entry("next_hop", &route.next_hop)?;
        map.serialize_entry("peer", &route.peer_address)?;
        map.serialize_entry("prefix", &route.prefix)?;
        if let Some(view) = &route.prefix_sid {
            map.serialize_entry("prefix_sid", &output::prefix_sid_json(view))?;
        }
        map.serialize_entry("rd", &route.rd)?;
        map.serialize_entry("route_type", &route.route_type)?;
        map.serialize_entry("route_type_name", evpn_route_type_label(route.route_type))?;
        if let Some(view) = &route.smet {
            map.serialize_entry("smet", &super::evpn::smet_json(view))?;
        }
        map.serialize_entry("tunnel_type", &route.tunnel_type)?;
        map.end()
    }
}

struct JsonOptionalEvpnRouteEntry<'a>(Option<&'a EvpnRouteEntry>);

impl Serialize for JsonOptionalEvpnRouteEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(route) => JsonEvpnRouteEntry(route).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

struct JsonBgpEvent<'a>(&'a BgpEvent);

impl Serialize for JsonBgpEvent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use crate::proto::bgp_event::Payload;
        let event = self.0;
        let payload = event.payload.as_ref();
        let event_id = route_event_id(event).filter(|id| *id > 0);
        // Keys are emitted in a single flattened alphabetical sequence so the
        // streamed bytes match the pre-#515 serde_json::Value (BTreeMap) output
        // exactly — envelope and payload keys interleave by key, not
        // envelope-first. Conditional/payload keys are emitted in their sorted
        // position. Locked by `direct_bgp_event_json_matches_legacy_value`;
        // keep this list sorted and add new keys at their alphabetical slot.
        let mut map = serializer.serialize_map(None)?;
        if let Some(Payload::Policy(policy)) = payload {
            map.serialize_entry("affected_peer_count", &policy.affected_peer_count)?;
        }
        if let Some(Payload::DataplaneRoute(route)) = payload {
            map.serialize_entry("action", &route.action)?;
        }
        map.serialize_entry("afi_safi", &JsonAddressFamily(event.afi_safi))?;
        map.serialize_entry("category", event_category_json_label(event.category))?;
        if let Some(Payload::Notification(notification)) = payload {
            map.serialize_entry("code", &notification.code)?;
        }
        if let Some(Payload::Notification(notification)) = payload {
            map.serialize_entry("description", &notification.description)?;
        }
        if let Some(Payload::Notification(notification)) = payload {
            map.serialize_entry("direction", &notification.direction)?;
        }
        if let Some(event_id) = event_id {
            map.serialize_entry("event_id", &event_id)?;
        }
        map.serialize_entry("event_type", bgp_event_type_json_label(event.event_type))?;
        if let Some(Payload::Dataplane(dataplane)) = payload {
            map.serialize_entry("failed", &dataplane.failed)?;
        }
        if let Some(Payload::Dataplane(dataplane)) = payload {
            map.serialize_entry("installed", &dataplane.installed)?;
        }
        if let Some(Payload::DataplaneRoute(route)) = payload {
            map.serialize_entry("metric", &route.metric)?;
        }
        if let Some(Payload::StreamLag(lag)) = payload {
            map.serialize_entry("missed_count", &lag.missed_count)?;
        }
        if let Some(Payload::Session(session)) = payload {
            map.serialize_entry("new_state", &session.new_state)?;
        }
        if let Some(Payload::DataplaneRoute(route)) = payload {
            map.serialize_entry("next_hop", &route.next_hop)?;
        }
        if let Some(Payload::Session(session)) = payload {
            map.serialize_entry("old_state", &session.old_state)?;
        }
        if let Some(Payload::Policy(policy)) = payload {
            map.serialize_entry("operation", &policy.operation)?;
        }
        map.serialize_entry("peer_address", &event.peer_address)?;
        map.serialize_entry("prefix", &JsonEventPrefix(event))?;
        map.serialize_entry("previous_peer_address", &event.previous_peer_address)?;
        if let Some(Payload::Evpn(evpn)) = payload {
            map.serialize_entry(
                "previous_route",
                &JsonOptionalEvpnRouteEntry(evpn.previous_route.as_ref()),
            )?;
        }
        if let Some(Payload::Evpn(evpn)) = payload {
            map.serialize_entry("rd", &evpn.rd)?;
        }
        match payload {
            Some(Payload::Session(session)) => map.serialize_entry("reason", &session.reason)?,
            Some(Payload::Notification(notification)) => {
                map.serialize_entry("reason", &notification.reason)?;
            }
            Some(Payload::Policy(policy)) => map.serialize_entry("reason", &policy.reason)?,
            Some(Payload::DataplaneRoute(route)) => {
                map.serialize_entry("reason", &route.reason)?;
            }
            Some(Payload::Evpn(evpn)) => map.serialize_entry("reason", &evpn.reason)?,
            Some(Payload::StreamLag(lag)) => map.serialize_entry("reason", &lag.reason)?,
            _ => {}
        }
        if let Some(Payload::Dataplane(dataplane)) = payload {
            map.serialize_entry("rejected", &dataplane.rejected)?;
        }
        if let Some(Payload::Evpn(evpn)) = payload {
            map.serialize_entry("route", &JsonOptionalEvpnRouteEntry(evpn.route.as_ref()))?;
        }
        if let Some(Payload::Evpn(evpn)) = payload {
            map.serialize_entry("route_key", &evpn.route_key)?;
        }
        if let Some(Payload::Evpn(evpn)) = payload {
            map.serialize_entry("route_type", &evpn.route_type)?;
            map.serialize_entry("route_type_name", evpn_route_type_label(evpn.route_type))?;
        }
        match payload {
            Some(Payload::Session(session)) => {
                map.serialize_entry("session_role", &session.session_role)?;
            }
            Some(Payload::Notification(notification)) => {
                map.serialize_entry("session_role", &notification.session_role)?;
            }
            _ => {}
        }
        map.serialize_entry("severity", output::format_severity(event.severity))?;
        if let Some(Payload::Notification(notification)) = payload {
            map.serialize_entry("shutdown_reason", &notification.shutdown_reason)?;
        }
        match payload {
            Some(Payload::Dataplane(dataplane)) => {
                map.serialize_entry("source", &dataplane.source)?;
            }
            Some(Payload::DataplaneRoute(route)) => {
                map.serialize_entry("source", &route.source)?;
            }
            _ => {}
        }
        if let Some(Payload::StreamLag(lag)) = payload {
            map.serialize_entry(
                "source_category",
                event_category_json_label(lag.source_category),
            )?;
        }
        if let Some(Payload::Notification(notification)) = payload {
            map.serialize_entry("subcode", &notification.subcode)?;
        }
        map.serialize_entry("summary", &event.summary)?;
        if let Some(Payload::DataplaneRoute(route)) = payload {
            map.serialize_entry("table_id", &route.table_id)?;
        }
        if let Some(Payload::DataplaneRoute(route)) = payload {
            map.serialize_entry("table_name", &route.table_name)?;
        }
        if let Some(Payload::Policy(policy)) = payload {
            map.serialize_entry("target", &policy.target)?;
        }
        map.serialize_entry("target_peer_address", &event.target_peer_address)?;
        if let Some(Payload::Policy(policy)) = payload {
            map.serialize_entry("target_type", &policy.target_type)?;
        }
        map.serialize_entry("timestamp", &event.timestamp)?;
        map.serialize_entry(
            "timestamp_unix_seconds",
            &timestamp_unix_seconds(&event.timestamp),
        )?;
        map.end()
    }
}

pub(crate) fn bgp_event_json_value(event: &BgpEvent) -> Result<serde_json::Value, CliError> {
    Ok(serde_json::to_value(JsonBgpEvent(event))?)
}

#[cfg(test)]
fn json_bgp_event(event: &BgpEvent) -> serde_json::Value {
    bgp_event_json_value(event).expect("serializing BGP event JSON should be infallible")
}

fn route_event_id(event: &BgpEvent) -> Option<u64> {
    match event.payload.as_ref() {
        Some(crate::proto::bgp_event::Payload::Route(route)) => Some(route.event_id),
        _ => None,
    }
}

fn format_bgp_event_line(event: &BgpEvent) -> String {
    let event_id = route_event_id(event)
        .filter(|id| *id > 0)
        .map_or_else(String::new, |id| format!(" id={id}"));
    let mut line = format!(
        "[{}] {} {}{}",
        human_timestamp(&event.timestamp),
        output::colored_event_type(bgp_event_type_display_label(event.event_type)),
        event.summary,
        event_id
    );
    if let Some(crate::proto::bgp_event::Payload::Evpn(evpn)) = &event.payload {
        for (label, route) in [("current", &evpn.route), ("previous", &evpn.previous_route)] {
            if let Some(view) = route.as_ref().and_then(|route| route.prefix_sid.as_ref()) {
                line.push_str(&format!(" {label}: {}", output::prefix_sid_summary(view)));
            }
            if let Some(view) = route.as_ref().and_then(|route| route.smet.as_ref()) {
                line.push_str(&format!(" {label}: {}", super::evpn::smet_summary(view)));
            }
        }
    }
    line
}

fn print_bgp_event(event: &BgpEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&JsonBgpEvent(event))?;
        return Ok(());
    }

    outln!("{}", format_bgp_event_line(event))?;
    Ok(())
}

fn json_route_stream_lag_event(event: &BgpEvent, lag: &StreamLagEvent) -> JsonRouteEvent {
    JsonRouteEvent {
        event_id: 0,
        event_type: bgp_event_type_display_label(event.event_type).to_string(),
        prefix: String::new(),
        peer_address: String::new(),
        previous_peer_address: String::new(),
        target_peer_address: String::new(),
        afi_safi: output::format_family(event.afi_safi).to_string(),
        timestamp: event.timestamp.clone(),
        timestamp_unix_seconds: timestamp_unix_seconds(&event.timestamp),
        path_id: 0,
        missed_count: lag.missed_count,
        reason: lag.reason.clone(),
    }
}

fn json_route_watch_event(event: &BgpEvent) -> Result<serde_json::Value, CliError> {
    match event.payload.as_ref() {
        Some(crate::proto::bgp_event::Payload::Route(route)) => {
            Ok(serde_json::to_value(json_event(route))?)
        }
        Some(crate::proto::bgp_event::Payload::StreamLag(lag)) => Ok(serde_json::to_value(
            json_route_stream_lag_event(event, lag),
        )?),
        _ => bgp_event_json_value(event),
    }
}

fn print_route_watch_event(event: &BgpEvent, json: bool) -> Result<(), CliError> {
    if json {
        output::print_json_line(&json_route_watch_event(event)?)?;
        return Ok(());
    }

    if let Some(crate::proto::bgp_event::Payload::Route(route)) = event.payload.as_ref() {
        print_event(route, false)?;
    } else {
        print_bgp_event(event, false)?;
    }
    Ok(())
}

fn is_route_event_type(event_type: i32) -> bool {
    matches!(
        BgpEventType::try_from(event_type),
        Ok(BgpEventType::RouteAdded)
            | Ok(BgpEventType::RouteWithdrawn)
            | Ok(BgpEventType::RouteBestChanged)
            | Ok(BgpEventType::RoutePolicyFiltered)
    )
}

fn route_event_type_to_bgp_event_type(event_type: i32) -> i32 {
    match RouteEventType::try_from(event_type) {
        Ok(RouteEventType::Added) => BgpEventType::RouteAdded as i32,
        Ok(RouteEventType::Withdrawn) => BgpEventType::RouteWithdrawn as i32,
        Ok(RouteEventType::BestChanged) => BgpEventType::RouteBestChanged as i32,
        Ok(RouteEventType::PolicyFiltered) => BgpEventType::RoutePolicyFiltered as i32,
        _ => BgpEventType::Unspecified as i32,
    }
}

fn wants_route_events(categories: &[i32], event_types: &[i32]) -> bool {
    (categories.is_empty() || categories.contains(&(EventCategory::Route as i32)))
        && (event_types.is_empty() || event_types.iter().copied().any(is_route_event_type))
}

fn route_history_event_matches_types(event: &RouteEvent, event_types: &[i32]) -> bool {
    event_types.is_empty()
        || event_types.contains(&route_event_type_to_bgp_event_type(event.event_type))
}

fn route_history_request_limit(backfill: u32, event_types: &[i32]) -> u32 {
    if event_types.is_empty() { backfill } else { 0 }
}

fn route_event_to_bgp_event(event: RouteEvent) -> BgpEvent {
    let event_type = route_event_type_to_bgp_event_type(event.event_type);
    let event_label = match BgpEventType::try_from(event_type) {
        Ok(BgpEventType::RouteAdded) => "added",
        Ok(BgpEventType::RouteWithdrawn) => "withdrawn",
        Ok(BgpEventType::RouteBestChanged) => "best changed",
        Ok(BgpEventType::RoutePolicyFiltered) => "policy filtered",
        _ => "changed",
    };
    let summary = format!(
        "route {event_label} {}/{}",
        event.prefix, event.prefix_length
    );
    let summary = if event_type == BgpEventType::RoutePolicyFiltered as i32 {
        format!(
            "{summary} target={} reason={}",
            event.target_peer_address, event.reason
        )
    } else {
        summary
    };

    BgpEvent {
        timestamp: event.timestamp.clone(),
        timestamp_unix_ms: event.timestamp_unix_ms,
        category: EventCategory::Route as i32,
        event_type,
        severity: crate::proto::EventSeverity::Info as i32,
        peer_address: event.peer_address.clone(),
        previous_peer_address: event.previous_peer_address.clone(),
        prefix: event.prefix.clone(),
        prefix_length: event.prefix_length,
        afi_safi: event.afi_safi,
        summary,
        target_peer_address: event.target_peer_address.clone(),
        payload: Some(crate::proto::bgp_event::Payload::Route(event)),
    }
}

fn parse_optional_prefix_filter(
    prefix: Option<String>,
    family: Option<i32>,
) -> Result<(String, u32), CliError> {
    let Some(prefix) = prefix else {
        return Ok((String::new(), 0));
    };
    let (addr, length) = output::parse_prefix_addr(&prefix).map_err(CliError::Argument)?;
    match (family, addr) {
        (Some(f), IpAddr::V4(_)) if f == AddressFamily::Ipv6Unicast as i32 => {
            return Err(CliError::Argument(
                "--prefix family does not match --family".into(),
            ));
        }
        (Some(f), IpAddr::V6(_)) if f == AddressFamily::Ipv4Unicast as i32 => {
            return Err(CliError::Argument(
                "--prefix family does not match --family".into(),
            ));
        }
        _ => {}
    }
    Ok((addr.to_string(), length))
}

fn validate_event_filter_categories(
    categories: &[i32],
    neighbor: &Option<String>,
    family: Option<i32>,
    prefix: &Option<String>,
) -> Result<(), CliError> {
    if categories.is_empty() {
        return Ok(());
    }

    let wants_route = categories.contains(&(EventCategory::Route as i32));
    let wants_session = categories.contains(&(EventCategory::Session as i32));
    let wants_dataplane = categories.contains(&(EventCategory::Dataplane as i32));
    let wants_evpn = categories.contains(&(EventCategory::Evpn as i32));
    // PolicyChanged entries scope by peer when the mutation targets one
    // neighbor; --neighbor narrows to those.
    let wants_policy = categories.contains(&(EventCategory::Policy as i32));
    if !wants_route && !wants_dataplane && (family.is_some() || prefix.is_some()) {
        return Err(CliError::Argument(
            "--family and --prefix require --category route or --category dataplane".into(),
        ));
    }
    if !wants_route
        && !wants_session
        && !wants_dataplane
        && !wants_evpn
        && !wants_policy
        && neighbor.is_some()
    {
        return Err(CliError::Argument(
            "--neighbor requires --category route, --category session, --category dataplane, --category evpn, or --category policy"
                .into(),
        ));
    }

    Ok(())
}

pub fn validate_events_watch_filter(
    categories: &[String],
    event_types: &[String],
) -> Result<(), CliError> {
    let categories = categories
        .iter()
        .map(String::as_str)
        .map(parse_event_category)
        .collect::<Result<Vec<_>, _>>()?;
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    validate_category_event_types(&categories, &event_types)
}

fn validate_category_event_types(categories: &[i32], event_types: &[i32]) -> Result<(), CliError> {
    if event_types.is_empty() {
        return Ok(());
    }
    let categories = categories.iter().fold(0, |mask, value| {
        mask | category_mask(EventCategory::try_from(*value).expect("parsed category"))
    });
    let categories = if categories == 0 { 0x3f } else { categories };
    let event_types = event_types.iter().fold(0, |mask, value| {
        mask | live_event_type_mask(BgpEventType::try_from(*value).expect("parsed event type"))
    });
    if categories & event_types != 0 {
        Ok(())
    } else {
        Err(CliError::Argument(
            "event category/type filters have no possible intersection for the live WatchEvents stream"
                .into(),
        ))
    }
}

fn category_mask(category: EventCategory) -> u8 {
    match category {
        EventCategory::Unspecified => 0,
        EventCategory::Route => 1,
        EventCategory::Session => 2,
        EventCategory::Policy => 4,
        EventCategory::Dataplane => 8,
        EventCategory::Evpn => 16,
        EventCategory::Bfd => 32,
    }
}

fn live_event_type_mask(event_type: BgpEventType) -> u8 {
    match event_type {
        BgpEventType::Unspecified => 0,
        BgpEventType::RouteAdded
        | BgpEventType::RouteWithdrawn
        | BgpEventType::RouteBestChanged
        | BgpEventType::RoutePolicyFiltered => 1,
        BgpEventType::SessionStateChanged
        | BgpEventType::SessionEstablished
        | BgpEventType::SessionLost
        | BgpEventType::PeerEnabled
        | BgpEventType::PeerDisabled
        | BgpEventType::PeerAdded
        | BgpEventType::PeerRemoved
        | BgpEventType::MaxPrefixWarning
        | BgpEventType::NotificationSent
        | BgpEventType::NotificationReceived => 2,
        BgpEventType::PolicyChanged => 4,
        BgpEventType::DataplaneStatusChanged
        | BgpEventType::DataplaneRouteInstalled
        | BgpEventType::DataplaneRouteWithdrawn
        | BgpEventType::DataplaneRouteFailed => 8,
        BgpEventType::EvpnRouteAdded
        | BgpEventType::EvpnRouteWithdrawn
        | BgpEventType::EvpnRouteBestChanged => 16,
        BgpEventType::BfdSessionUp
        | BgpEventType::BfdSessionDown
        | BgpEventType::BfdSessionStateChanged => 32,
        BgpEventType::StreamLagged => 1 | 2 | 8 | 16 | 32,
    }
}

pub async fn run(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_events(WatchEventsRequest {
            categories: vec![EventCategory::Route as i32],
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            ..Default::default()
        })
        .await?
        .into_inner();

    while let Some(mut event) = stream.message().await? {
        scope_bgp_event(&mut event);
        print_route_watch_event(&event, json)?;
    }
    Ok(())
}

pub async fn events_watch(
    connection: Connection,
    options: EventsWatchOptions,
) -> Result<(), CliError> {
    validate_events_watch_filter(&options.categories, &options.event_types)?;
    let EventsWatchOptions {
        categories,
        neighbor,
        family,
        prefix,
        event_types,
        backfill,
        json,
    } = options;

    let categories = categories
        .iter()
        .map(String::as_str)
        .map(parse_event_category)
        .collect::<Result<Vec<_>, _>>()?;
    validate_event_filter_categories(&categories, &neighbor, family, &prefix)?;
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let route_events_requested = wants_route_events(&categories, &event_types);
    if backfill > 0 && !route_events_requested {
        return Err(CliError::Argument(
            "--backfill requires a route-capable event stream".into(),
        ));
    }
    validate_route_only_filters(&categories, &event_types, family, prefix.as_deref())?;
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;

    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut stream = client
        .watch_events(WatchEventsRequest {
            categories,
            event_types: event_types.clone(),
            neighbor_address: neighbor.clone().unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            prefix: prefix.clone(),
            prefix_length,
        })
        .await?
        .into_inner();

    let mut last_backfilled_route_event_id = 0;
    if backfill > 0 {
        let mut rib_client =
            RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
        let response = read_rpc(
            "ListRouteEvents",
            rib_client.list_route_events(ListRouteEventsRequest {
                neighbor_address: neighbor.unwrap_or_default(),
                afi_safi: family.unwrap_or(0),
                // Ask for the full bounded ring only when local type
                // filtering could otherwise shrink the requested window.
                limit: route_history_request_limit(backfill, &event_types),
                prefix,
                prefix_length,
            }),
        )
        .await?
        .into_inner();
        let mut events = response
            .events
            .into_iter()
            .filter(|event| route_history_event_matches_types(event, &event_types))
            .collect::<Vec<_>>();
        if events.len() > backfill as usize {
            events.drain(0..events.len() - backfill as usize);
        }
        for event in events {
            last_backfilled_route_event_id = last_backfilled_route_event_id.max(event.event_id);
            let mut event = route_event_to_bgp_event(event);
            scope_bgp_event(&mut event);
            print_bgp_event(&event, json)?;
        }
    }

    while let Some(mut event) = stream.message().await? {
        if last_backfilled_route_event_id > 0
            && route_event_id(&event).is_some_and(|id| id <= last_backfilled_route_event_id)
        {
            continue;
        }
        scope_bgp_event(&mut event);
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

/// LAN-329 empty-state convention: JSON list output is never empty
/// (`[]` parses where the non-empty NDJSON event lines also parse
/// line-wise); human output names what was absent.
fn write_empty_json_history(writer: &mut dyn std::io::Write) -> Result<(), CliError> {
    output::write_serialized_json_line(writer, "[]")
}

fn print_empty_history(json: bool, what: &str) -> Result<(), CliError> {
    if json {
        let stdout = std::io::stdout();
        write_empty_json_history(&mut stdout.lock())?;
    } else {
        outln!("No {what} events recorded")?;
    }
    Ok(())
}

pub async fn history(
    connection: Connection,
    neighbor: Option<String>,
    family: Option<i32>,
    prefix: Option<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let (prefix, prefix_length) = parse_optional_prefix_filter(prefix, family)?;

    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = read_rpc(
        "ListRouteEvents",
        client.list_route_events(ListRouteEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            afi_safi: family.unwrap_or(0),
            limit,
            prefix,
            prefix_length,
        }),
    )
    .await?
    .into_inner();

    if response.events.is_empty() {
        print_empty_history(json, "route")?;
        return Ok(());
    }
    for mut event in response.events {
        scope_route_event(&mut event);
        print_event(&event, json)?;
    }
    Ok(())
}

pub async fn session_history(
    connection: Connection,
    neighbor: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_session_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = read_rpc(
        "ListSessionEvents",
        client.list_session_events(ListSessionEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
        }),
    )
    .await?
    .into_inner();

    if response.events.is_empty() {
        print_empty_history(json, "session")?;
        return Ok(());
    }
    for mut event in response.events {
        scope_bgp_event(&mut event);
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

pub async fn policy_history(
    connection: Connection,
    neighbor: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_policy_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = read_rpc(
        "ListPolicyEvents",
        client.list_policy_events(ListPolicyEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
        }),
    )
    .await?
    .into_inner();

    if response.events.is_empty() {
        print_empty_history(json, "policy")?;
        return Ok(());
    }
    for mut event in response.events {
        scope_bgp_event(&mut event);
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

pub async fn evpn_history(
    connection: Connection,
    neighbor: Option<String>,
    route_type: Option<u32>,
    rd: Option<String>,
    event_types: Vec<String>,
    limit: u32,
    json: bool,
) -> Result<(), CliError> {
    let event_types = event_types
        .iter()
        .map(String::as_str)
        .map(parse_evpn_bgp_event_type)
        .collect::<Result<Vec<_>, _>>()?;
    let mut client =
        EventServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = read_rpc(
        "ListEvpnEvents",
        client.list_evpn_events(ListEvpnEventsRequest {
            neighbor_address: neighbor.unwrap_or_default(),
            event_types,
            limit,
            route_type_filter: route_type.unwrap_or(0),
            rd_filter: rd.unwrap_or_default(),
        }),
    )
    .await?
    .into_inner();

    if response.events.is_empty() {
        print_empty_history(json, "EVPN")?;
        return Ok(());
    }
    for event in response.events {
        print_bgp_event(&event, json)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use prost::Message;
    use std::sync::atomic::Ordering;

    #[test]
    fn empty_json_history_preserves_exact_bytes() {
        let mut bytes = Vec::new();
        write_empty_json_history(&mut bytes).unwrap();
        assert_eq!(bytes, b"[]\n");
    }

    struct FailAfter {
        remaining: usize,
    }

    impl std::io::Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            let written = bytes.len().min(self.remaining);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn empty_json_history_partial_broken_pipe_returns_io_error() {
        let error = write_empty_json_history(&mut FailAfter { remaining: 1 }).unwrap_err();
        assert!(
            matches!(error, CliError::Io(ref error) if error.kind() == std::io::ErrorKind::BrokenPipe)
        );
    }

    struct FlushFailure;

    impl std::io::Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failed"))
        }
    }

    #[test]
    fn empty_json_history_flush_failure_returns_io_error() {
        let error = write_empty_json_history(&mut FlushFailure).unwrap_err();
        assert!(matches!(error, CliError::Io(_)));
    }

    #[tokio::test]
    async fn ordinary_watch_events_is_one_shot() {
        let watch_server = spawn_mock_server(None).await;
        watch_server
            .state
            .watch_events_clean_end
            .store(true, Ordering::SeqCst);
        events_watch(
            connect(&watch_server.addr, None).await.unwrap(),
            EventsWatchOptions {
                categories: vec![],
                event_types: vec![],
                neighbor: None,
                family: None,
                prefix: None,
                backfill: 0,
                json: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            watch_server.state.watch_events_calls.load(Ordering::SeqCst),
            1
        );
    }

    // Frozen reference: builds the `serde_json::Value` exactly as the pre-#515
    // code did (serde_json::json! base + per-payload object inserts; BTreeMap
    // sorts keys on serialize). The streaming `JsonBgpEvent` serializer must
    // produce byte-identical output to this; `direct_bgp_event_json_matches_legacy_value`
    // asserts it. Do NOT "modernize" this helper — its whole value is being a
    // fixed snapshot of the shipped contract so the direct serializer and this
    // reference fail loudly if they drift.
    fn legacy_json_evpn_route_entry(route: &EvpnRouteEntry) -> serde_json::Value {
        serde_json::json!({
            "route_type": route.route_type,
            "route_type_name": evpn_route_type_label(route.route_type),
            "rd": route.rd,
            "esi": route.esi,
            "ethernet_tag": route.ethernet_tag,
            "mac": route.mac,
            "ip": route.ip,
            "prefix": route.prefix,
            "gateway": route.gateway,
            "label": route.label,
            "label2": route.label2,
            "next_hop": route.next_hop,
            "peer": route.peer_address,
            "as_path": route.as_path,
            "communities": route.communities,
            "extended_communities": route.extended_communities,
            "tunnel_type": route.tunnel_type,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "verbatim frozen snapshot of the pre-#515 JSON builder"
    )]
    fn legacy_json_bgp_event(event: &BgpEvent) -> serde_json::Value {
        let mut value = serde_json::json!({
            "timestamp": event.timestamp,
            "category": match EventCategory::try_from(event.category) {
                Ok(EventCategory::Route) => "route",
                Ok(EventCategory::Session) => "session",
                Ok(EventCategory::Policy) => "policy",
                Ok(EventCategory::Dataplane) => "dataplane",
                Ok(EventCategory::Evpn) => "evpn",
                Ok(EventCategory::Bfd) => "bfd",
                _ => "unknown",
            },
            "event_type": bgp_event_type_json_label(event.event_type),
            "severity": output::format_severity(event.severity),
            "peer_address": event.peer_address,
            "previous_peer_address": event.previous_peer_address,
            "target_peer_address": event.target_peer_address,
            "prefix": if event.prefix.is_empty() {
                String::new()
            } else {
                format!("{}/{}", event.prefix, event.prefix_length)
            },
            "afi_safi": if event.afi_safi == AddressFamily::Unspecified as i32 {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(output::format_family(event.afi_safi).to_string())
            },
            "summary": event.summary,
        });
        if let Some(object) = value.as_object_mut()
            && let Some(event_id) = route_event_id(event).filter(|id| *id > 0)
        {
            object.insert(
                "event_id".to_string(),
                serde_json::Value::Number(event_id.into()),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::Session(session)) = event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "old_state".to_string(),
                serde_json::Value::String(session.old_state.clone()),
            );
            object.insert(
                "new_state".to_string(),
                serde_json::Value::String(session.new_state.clone()),
            );
            object.insert(
                "session_role".to_string(),
                serde_json::Value::String(session.session_role.clone()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(session.reason.clone()),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::Notification(notification)) =
            event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "direction".to_string(),
                serde_json::Value::String(notification.direction.clone()),
            );
            object.insert(
                "code".to_string(),
                serde_json::Value::Number(notification.code.into()),
            );
            object.insert(
                "subcode".to_string(),
                serde_json::Value::Number(notification.subcode.into()),
            );
            object.insert(
                "description".to_string(),
                serde_json::Value::String(notification.description.clone()),
            );
            object.insert(
                "session_role".to_string(),
                serde_json::Value::String(notification.session_role.clone()),
            );
            object.insert(
                "shutdown_reason".to_string(),
                serde_json::Value::String(notification.shutdown_reason.clone()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(notification.reason.clone()),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::Policy(policy)) = event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "operation".to_string(),
                serde_json::Value::String(policy.operation.clone()),
            );
            object.insert(
                "target_type".to_string(),
                serde_json::Value::String(policy.target_type.clone()),
            );
            object.insert(
                "target".to_string(),
                serde_json::Value::String(policy.target.clone()),
            );
            object.insert(
                "affected_peer_count".to_string(),
                serde_json::Value::Number(policy.affected_peer_count.into()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(policy.reason.clone()),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::Dataplane(dataplane)) = event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "source".to_string(),
                serde_json::Value::String(dataplane.source.clone()),
            );
            object.insert(
                "installed".to_string(),
                serde_json::Value::from(dataplane.installed),
            );
            object.insert(
                "rejected".to_string(),
                serde_json::Value::from(dataplane.rejected),
            );
            object.insert(
                "failed".to_string(),
                serde_json::Value::from(dataplane.failed),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::DataplaneRoute(route)) =
            event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "source".to_string(),
                serde_json::Value::String(route.source.clone()),
            );
            object.insert(
                "action".to_string(),
                serde_json::Value::String(route.action.clone()),
            );
            object.insert(
                "table_name".to_string(),
                serde_json::Value::String(route.table_name.clone()),
            );
            object.insert(
                "table_id".to_string(),
                serde_json::Value::from(route.table_id),
            );
            object.insert("metric".to_string(), serde_json::Value::from(route.metric));
            object.insert(
                "next_hop".to_string(),
                serde_json::Value::String(route.next_hop.clone()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(route.reason.clone()),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::Evpn(evpn)) = event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "route_type".to_string(),
                serde_json::Value::Number(evpn.route_type.into()),
            );
            object.insert(
                "route_type_name".to_string(),
                serde_json::Value::String(evpn_route_type_label(evpn.route_type).to_string()),
            );
            object.insert("rd".to_string(), serde_json::Value::String(evpn.rd.clone()));
            object.insert(
                "route_key".to_string(),
                serde_json::Value::String(evpn.route_key.clone()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(evpn.reason.clone()),
            );
            object.insert(
                "route".to_string(),
                evpn.route
                    .as_ref()
                    .map_or(serde_json::Value::Null, legacy_json_evpn_route_entry),
            );
            object.insert(
                "previous_route".to_string(),
                evpn.previous_route
                    .as_ref()
                    .map_or(serde_json::Value::Null, legacy_json_evpn_route_entry),
            );
        }
        if let Some(crate::proto::bgp_event::Payload::StreamLag(lag)) = event.payload.as_ref()
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "source_category".to_string(),
                serde_json::Value::String(
                    match EventCategory::try_from(lag.source_category) {
                        Ok(EventCategory::Route) => "route",
                        Ok(EventCategory::Session) => "session",
                        Ok(EventCategory::Policy) => "policy",
                        Ok(EventCategory::Dataplane) => "dataplane",
                        Ok(EventCategory::Evpn) => "evpn",
                        Ok(EventCategory::Bfd) => "bfd",
                        _ => "unknown",
                    }
                    .to_string(),
                ),
            );
            object.insert(
                "missed_count".to_string(),
                serde_json::Value::Number(lag.missed_count.into()),
            );
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(lag.reason.clone()),
            );
        }
        value
    }

    #[test]
    fn smet_event_preserves_current_and_previous_identity_and_raw_flags() {
        for (source, group, originator) in [
            ("*", "*", "192.0.2.9"),
            ("192.0.2.1", "239.1.1.1", "2001:db8::9"),
            ("2001:db8::1", "ff3e::1", "192.0.2.9"),
        ] {
            let route = |flags| EvpnRouteEntry {
                route_type: 6,
                rd: "65000:100".into(),
                ethernet_tag: "7".into(),
                smet: Some(Box::new(crate::proto::EvpnSmetView {
                    source: Some(crate::commands::evpn::parse_smet_address(source).unwrap()),
                    group: Some(crate::commands::evpn::parse_smet_address(group).unwrap()),
                    originator_ip: originator.into(),
                    flags,
                })),
                ..Default::default()
            };
            let event = BgpEvent {
                payload: Some(crate::proto::bgp_event::Payload::Evpn(
                    crate::proto::EvpnRouteEvent {
                        route_type: 6,
                        route: Some(route(0xe5)),
                        previous_route: Some(route(0x80)),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };
            let value = bgp_event_json_value(&event).unwrap();
            assert_eq!(value["route_type_name"], "smet");
            for (key, flags) in [("route", 229), ("previous_route", 128)] {
                assert_eq!(value[key]["route_type_name"], "smet");
                assert_eq!(value[key]["rd"], "65000:100");
                assert_eq!(value[key]["ethernet_tag"], "7");
                assert_eq!(
                    value[key]["smet"],
                    serde_json::json!({
                        "source": source, "group": group, "originator_ip": originator, "flags": flags
                    })
                );
            }
            let text = format_bgp_event_line(&event);
            for (label, flags) in [("current", "e5"), ("previous", "80")] {
                assert!(text.contains(&format!(
                    "{label}: source={source} group={group} originator_ip={originator} flags=0x{flags}"
                )), "{text}");
            }
        }
    }

    #[test]
    fn evpn_event_prefix_sid_keeps_current_and_previous_views() {
        let route = crate::proto::EvpnRouteEntry {
            prefix_sid: Some(Box::new(
                crate::proto::PrefixSidView::decode(
                    crate::test_support::mock_prefix_sid()
                        .encode_to_vec()
                        .as_slice(),
                )
                .unwrap(),
            )),
            ..Default::default()
        };
        let event = BgpEvent {
            payload: Some(crate::proto::bgp_event::Payload::Evpn(
                crate::proto::EvpnRouteEvent {
                    route: Some(route.clone()),
                    previous_route: Some(route),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        let value = bgp_event_json_value(&event).unwrap();
        for key in ["route", "previous_route"] {
            assert_eq!(value[key]["prefix_sid"]["raw_value"], "deadbeef");
            assert_eq!(
                value[key]["prefix_sid"]["services"][0]["sids"][0]["endpoint_behavior"],
                65535
            );
        }
        let text = format_bgp_event_line(&event);
        assert!(text.contains("current: prefix-sid flags=0xe0"));
        assert!(text.contains("previous: prefix-sid flags=0xe0"));
    }

    #[test]
    fn direct_bgp_event_json_matches_legacy_value() {
        use crate::proto::bgp_event::Payload;
        fn envelope(category: EventCategory, afi_safi: i32) -> BgpEvent {
            BgpEvent {
                timestamp: "2026-06-15T00:00:00Z".to_string(),
                timestamp_unix_ms: 0,
                category: category as i32,
                event_type: BgpEventType::PolicyChanged as i32,
                severity: crate::proto::EventSeverity::Warning as i32,
                peer_address: "10.0.0.2".to_string(),
                previous_peer_address: "10.0.0.9".to_string(),
                prefix: "203.0.113.0".to_string(),
                prefix_length: 24,
                afi_safi,
                summary: "summary text".to_string(),
                target_peer_address: "10.0.0.3".to_string(),
                payload: None,
            }
        }
        let ipv4 = AddressFamily::Ipv4Unicast as i32;
        let unspec = AddressFamily::Unspecified as i32;
        let evpn_entry = || crate::proto::EvpnRouteEntry {
            route_type: 2,
            rd: "65000:1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            as_path: vec![65001, 65002],
            communities: vec![100],
            extended_communities: vec![1],
            ..Default::default()
        };

        let mut cases: Vec<(&str, BgpEvent)> = Vec::new();
        cases.push(("none_with_id", envelope(EventCategory::Route, ipv4)));
        cases.push(("none_no_id_unspec", envelope(EventCategory::Route, unspec)));
        cases.push(("route", {
            let mut e = envelope(EventCategory::Route, ipv4);
            e.payload = Some(Payload::Route(crate::proto::RouteEvent {
                event_id: 42,
                ..Default::default()
            }));
            e
        }));
        cases.push(("session", {
            let mut e = envelope(EventCategory::Session, ipv4);
            e.payload = Some(Payload::Session(crate::proto::SessionEvent {
                old_state: "idle".to_string(),
                new_state: "established".to_string(),
                session_role: "rr-client".to_string(),
                reason: "manual".to_string(),
                ..Default::default()
            }));
            e
        }));
        cases.push(("notification", {
            let mut e = envelope(EventCategory::Session, unspec);
            e.payload = Some(Payload::Notification(crate::proto::NotificationEvent {
                direction: "outbound".to_string(),
                code: 6,
                subcode: 2,
                description: "cease".to_string(),
                session_role: "rr-client".to_string(),
                shutdown_reason: "admin".to_string(),
                reason: "manual".to_string(),
                ..Default::default()
            }));
            e
        }));
        cases.push(("policy", {
            let mut e = envelope(EventCategory::Policy, ipv4);
            e.payload = Some(Payload::Policy(crate::proto::PolicyEvent {
                operation: "apply".to_string(),
                target_type: "neighbor".to_string(),
                target: "10.0.0.2".to_string(),
                affected_peer_count: 3,
                reason: "reshape".to_string(),
                ..Default::default()
            }));
            e
        }));
        cases.push(("dataplane", {
            let mut e = envelope(EventCategory::Dataplane, ipv4);
            e.payload = Some(Payload::Dataplane(crate::proto::DataplaneEvent {
                source: "fib".to_string(),
                installed: 10,
                rejected: 1,
                failed: 2,
            }));
            e
        }));
        cases.push(("dataplane_route", {
            let mut e = envelope(EventCategory::Dataplane, ipv4);
            e.payload = Some(Payload::DataplaneRoute(crate::proto::DataplaneRouteEvent {
                source: "fib".to_string(),
                action: "add".to_string(),
                table_name: "main".to_string(),
                table_id: 254,
                metric: 100,
                next_hop: "10.0.0.1".to_string(),
                reason: "installed".to_string(),
                ..Default::default()
            }));
            e
        }));
        cases.push(("evpn_with_routes", {
            let mut e = envelope(EventCategory::Evpn, ipv4);
            e.payload = Some(Payload::Evpn(crate::proto::EvpnRouteEvent {
                route_type: 2,
                rd: "65000:1".to_string(),
                route_key: "key".to_string(),
                reason: "origin".to_string(),
                route: Some(evpn_entry()),
                previous_route: Some(evpn_entry()),
                ..Default::default()
            }));
            e
        }));
        cases.push(("evpn_no_route", {
            let mut e = envelope(EventCategory::Evpn, ipv4);
            e.payload = Some(Payload::Evpn(crate::proto::EvpnRouteEvent {
                route_type: 3,
                rd: "65000:2".to_string(),
                route_key: "key2".to_string(),
                reason: "withdraw".to_string(),
                route: None,
                previous_route: None,
                ..Default::default()
            }));
            e
        }));
        cases.push(("stream_lag", {
            let mut e = envelope(EventCategory::Session, ipv4);
            e.payload = Some(Payload::StreamLag(crate::proto::StreamLagEvent {
                source_category: EventCategory::Session as i32,
                missed_count: 5,
                reason: "backpressure".to_string(),
            }));
            e
        }));
        cases.push(("bfd", {
            let mut e = envelope(EventCategory::Bfd, ipv4);
            e.payload = Some(Payload::Bfd(crate::proto::BfdSessionEvent::default()));
            e
        }));

        for (label, event) in cases {
            let direct = serde_json::to_string(&JsonBgpEvent(&event))
                .expect("direct serialize should succeed");
            // The numeric timestamp is the one field added since the
            // snapshot; everything else must still byte-match it.
            let mut legacy = legacy_json_bgp_event(&event);
            legacy["timestamp_unix_seconds"] = timestamp_unix_seconds(&event.timestamp).into();
            let legacy = serde_json::to_string(&legacy).expect("legacy serialize should succeed");
            assert_eq!(
                direct, legacy,
                "streamed JSON must byte-match the pre-#515 output for {label}"
            );
        }
    }

    #[test]
    fn json_route_event_includes_event_id() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: 1,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            timestamp_unix_ms: 1000,
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_id"], 42);
    }

    #[test]
    fn backfill_route_detection_requires_route_capable_filter() {
        assert!(wants_route_events(&[], &[]));
        assert!(wants_route_events(
            &[EventCategory::Route as i32],
            &[BgpEventType::RouteAdded as i32]
        ));
        assert!(!wants_route_events(
            &[EventCategory::Session as i32],
            &[BgpEventType::SessionEstablished as i32]
        ));
        assert!(!wants_route_events(
            &[],
            &[BgpEventType::SessionEstablished as i32]
        ));
    }

    #[test]
    fn route_history_event_type_filter_matches_route_aliases() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: 3,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            timestamp_unix_ms: 1000,
            previous_peer_address: "10.0.0.2".to_string(),
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 7,
            reason: String::new(),
        };

        assert!(route_history_event_matches_types(
            &event,
            &[BgpEventType::RouteBestChanged as i32]
        ));
        assert!(!route_history_event_matches_types(
            &event,
            &[BgpEventType::RouteAdded as i32]
        ));
    }

    #[test]
    fn route_history_event_converts_to_bgp_event_shape() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: 1,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            timestamp_unix_ms: 1000,
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
        };

        let event = route_event_to_bgp_event(event);
        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_added");
        assert_eq!(value["summary"], "route added 203.0.113.0/24");
        assert_eq!(value["event_id"], 42);
    }

    #[test]
    fn policy_filtered_route_event_json_includes_target_peer_and_reason() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: RouteEventType::PolicyFiltered as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            timestamp_unix_ms: 1000,
            previous_peer_address: String::new(),
            target_peer_address: "10.0.0.2".to_string(),
            path_id: 9,
            event_id: 42,
            reason: "policy_denied".to_string(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "policy_filtered");
        assert_eq!(value["peer_address"], "10.0.0.1");
        assert_eq!(value["target_peer_address"], "10.0.0.2");
        assert_eq!(value["reason"], "policy_denied");

        let bgp_event = route_event_to_bgp_event(event);
        let value = json_bgp_event(&bgp_event);
        assert_eq!(value["event_type"], "route_policy_filtered");
        assert_eq!(value["target_peer_address"], "10.0.0.2");
        assert_eq!(
            value["summary"],
            "route policy filtered 203.0.113.0/24 target=10.0.0.2 reason=policy_denied"
        );
    }

    #[test]
    fn parse_policy_filtered_route_event_aliases() {
        assert_eq!(
            parse_bgp_event_type("policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert_eq!(
            parse_bgp_event_type("route_policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert!(is_route_event_type(
            BgpEventType::RoutePolicyFiltered as i32
        ));
    }

    #[test]
    fn bgp_event_text_route_events_include_event_id() {
        let event = route_event_to_bgp_event(RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: RouteEventType::Added as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "1".to_string(),
            timestamp_unix_ms: 1000,
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 42,
            reason: String::new(),
        });

        assert!(format_bgp_event_line(&event).ends_with(" id=42"));
    }

    #[test]
    fn validate_event_filter_categories_accepts_policy_with_address() {
        // OTC events ride on EVENT_CATEGORY_POLICY and are peer-
        // scoped. The CLI must not reject the natural shape
        // `--category policy --neighbor 10.0.0.2` before the
        // request even reaches the EHM auto-route.
        validate_event_filter_categories(
            &[EventCategory::Policy as i32],
            &Some("10.0.0.2".to_string()),
            None,
            &None,
        )
        .expect("--neighbor must be allowed on --category policy");
        let err = validate_event_filter_categories(
            &[EventCategory::Bfd as i32],
            &Some("10.0.0.2".to_string()),
            None,
            &None,
        )
        .expect_err("a peer filter needs a peer-scoped category");
        assert!(
            err.to_string()
                .starts_with("--neighbor requires --category"),
            "{err}"
        );
    }

    #[test]
    fn route_history_request_limit_only_expands_when_type_filtering() {
        assert_eq!(route_history_request_limit(5, &[]), 5);
        assert_eq!(
            route_history_request_limit(5, &[BgpEventType::RouteAdded as i32]),
            0
        );
    }

    #[test]
    fn bgp_event_display_labels_match_route_event_coloring_labels() {
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteAdded as i32),
            "added"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteWithdrawn as i32),
            "withdrawn"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::RouteBestChanged as i32),
            "best_changed"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::PolicyChanged as i32),
            "policy_changed"
        );
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::EvpnRouteAdded as i32),
            "evpn_added"
        );
    }

    #[test]
    fn parse_bgp_event_type_accepts_aliases_and_rejects_unknown() {
        assert_eq!(
            parse_bgp_event_type("added").unwrap(),
            BgpEventType::RouteAdded as i32
        );
        assert_eq!(
            parse_bgp_event_type("route_added").unwrap(),
            BgpEventType::RouteAdded as i32
        );
        assert_eq!(
            parse_bgp_event_type("session_established").unwrap(),
            BgpEventType::SessionEstablished as i32
        );
        assert_eq!(
            parse_bgp_event_type("dataplane_changed").unwrap(),
            BgpEventType::DataplaneStatusChanged as i32
        );
        assert_eq!(
            parse_bgp_event_type("dataplane_route_installed").unwrap(),
            BgpEventType::DataplaneRouteInstalled as i32
        );
        assert_eq!(
            parse_bgp_event_type("fib_failed").unwrap(),
            BgpEventType::DataplaneRouteFailed as i32
        );
        assert_eq!(
            parse_bgp_event_type("evpn_best_changed").unwrap(),
            BgpEventType::EvpnRouteBestChanged as i32
        );
        assert_eq!(
            parse_bgp_event_type("policy_filtered").unwrap(),
            BgpEventType::RoutePolicyFiltered as i32
        );
        assert!(parse_bgp_event_type("not_an_event").is_err());
    }

    #[test]
    fn event_type_names_cover_every_event_type_once() {
        let mut named: Vec<i32> = BGP_EVENT_TYPE_NAMES
            .iter()
            .map(|name| {
                parse_bgp_event_type(name)
                    .unwrap_or_else(|_| panic!("listed event type {name} does not parse"))
            })
            .collect();
        named.sort_unstable();
        let variants: Vec<i32> = (0..=i32::from(u8::MAX))
            .filter(|value| {
                BgpEventType::try_from(*value)
                    .is_ok_and(|event_type| event_type != BgpEventType::Unspecified)
            })
            .collect();
        assert_eq!(named, variants, "one canonical --type name per event type");
    }

    #[test]
    fn scoped_event_type_errors_list_the_scope() {
        let error = parse_session_bgp_event_type("added")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "expected state_changed, established, lost, peer_added, peer_removed, \
                 peer_enabled, peer_disabled, or max_prefix_warning"
            ),
            "{error}"
        );
        let error = parse_policy_bgp_event_type("added")
            .unwrap_err()
            .to_string();
        assert!(error.ends_with("expected policy_changed"), "{error}");
        let error = parse_bgp_event_type("nope").unwrap_err().to_string();
        assert!(
            error.contains("policy_filtered") && error.ends_with(", or stream_lagged"),
            "{error}"
        );
    }

    #[test]
    fn parse_bfd_category_and_event_types() {
        // The API already filters BFD events; the CLI must accept the `bfd`
        // category and the bfd_* event types (and their aliases) so
        // `rbgp events watch --category bfd` works.
        assert_eq!(
            parse_event_category("bfd").unwrap(),
            EventCategory::Bfd as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_up").unwrap(),
            BgpEventType::BfdSessionUp as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_session_down").unwrap(),
            BgpEventType::BfdSessionDown as i32
        );
        assert_eq!(
            parse_bgp_event_type("bfd_state_changed").unwrap(),
            BgpEventType::BfdSessionStateChanged as i32
        );
        // Round-trips through the display + JSON labels.
        assert_eq!(
            bgp_event_type_display_label(BgpEventType::BfdSessionUp as i32),
            "bfd_up"
        );
        assert_eq!(
            bgp_event_type_json_label(BgpEventType::BfdSessionStateChanged as i32),
            "bfd_session_state_changed"
        );
    }

    #[test]
    fn parse_evpn_bgp_event_type_accepts_only_evpn_route_events() {
        assert_eq!(
            parse_evpn_bgp_event_type("evpn_added").unwrap(),
            BgpEventType::EvpnRouteAdded as i32
        );
        assert!(parse_evpn_bgp_event_type("added").is_err());
        assert!(parse_evpn_bgp_event_type("dataplane_changed").is_err());
    }

    #[test]
    fn parse_policy_bgp_event_type_accepts_only_policy_changed() {
        assert_eq!(
            parse_policy_bgp_event_type("policy_changed").unwrap(),
            BgpEventType::PolicyChanged as i32
        );
        assert!(parse_policy_bgp_event_type("established").is_err());
        assert!(parse_policy_bgp_event_type("dataplane_changed").is_err());
    }

    #[test]
    fn parse_event_category_accepts_supported_categories_only() {
        assert_eq!(
            parse_event_category("route").unwrap(),
            EventCategory::Route as i32
        );
        assert_eq!(
            parse_event_category("session").unwrap(),
            EventCategory::Session as i32
        );
        assert_eq!(
            parse_event_category("policy").unwrap(),
            EventCategory::Policy as i32
        );
        assert_eq!(
            parse_event_category("dataplane").unwrap(),
            EventCategory::Dataplane as i32
        );
        assert_eq!(
            parse_event_category("evpn").unwrap(),
            EventCategory::Evpn as i32
        );
        assert!(parse_event_category("bmp").is_err());
    }

    #[test]
    fn parse_optional_prefix_filter_validates_family_and_splits_prefix() {
        let (prefix, length) = parse_optional_prefix_filter(
            Some("203.0.113.0/24".to_string()),
            Some(AddressFamily::Ipv4Unicast as i32),
        )
        .unwrap();
        assert_eq!(prefix, "203.0.113.0");
        assert_eq!(length, 24);

        let err = parse_optional_prefix_filter(
            Some("2001:db8::/64".to_string()),
            Some(AddressFamily::Ipv4Unicast as i32),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--prefix family"));
    }

    #[test]
    fn json_route_event_omits_empty_optional_fields() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_id: 0,
            event_type: crate::proto::RouteEventType::Added as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "192.0.2.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "123".to_string(),
            timestamp_unix_ms: 123_000,
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "added");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["peer_address"], "192.0.2.1");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert!(value.get("previous_peer_address").is_none());
        assert!(value.get("path_id").is_none());
        assert!(value.get("missed_count").is_none());
        assert!(value.get("reason").is_none());
    }

    #[test]
    fn json_route_event_includes_previous_peer_and_path_id() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_id: 0,
            event_type: crate::proto::RouteEventType::BestChanged as i32,
            prefix: "2001:db8::".to_string(),
            prefix_length: 64,
            peer_address: "2001:db8::1".to_string(),
            afi_safi: AddressFamily::Ipv6Unicast as i32,
            timestamp: "123".to_string(),
            timestamp_unix_ms: 123_000,
            previous_peer_address: "2001:db8::2".to_string(),
            target_peer_address: String::new(),
            path_id: 17,
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "best_changed");
        assert_eq!(value["prefix"], "2001:db8::/64");
        assert_eq!(value["previous_peer_address"], "2001:db8::2");
        assert_eq!(value["path_id"], 17);
    }

    #[test]
    fn json_bgp_event_route_includes_common_route_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::RouteBestChanged as i32,
            severity: 1,
            peer_address: "192.0.2.1".to_string(),
            previous_peer_address: "192.0.2.2".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "route best changed 203.0.113.0/24".to_string(),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_best_changed");
        assert_eq!(value["severity"], "info");
        assert_eq!(value["peer_address"], "192.0.2.1");
        assert_eq!(value["previous_peer_address"], "192.0.2.2");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["summary"], "route best changed 203.0.113.0/24");
    }

    /// A best-path move on one link-local address keeps the two interfaces
    /// distinct in the envelope and both retained route bodies.
    #[test]
    fn evpn_events_render_current_and_previous_scoped_neighbors() {
        use crate::proto::bgp_event::Payload;
        let source = || EvpnRouteEntry {
            peer_address: "fe80::1".into(),
            ..Default::default()
        };
        let mut event = BgpEvent {
            peer_address: "fe80::1".into(),
            previous_peer_address: "fe80::1".into(),
            payload: Some(Payload::Evpn(crate::proto::EvpnRouteEvent {
                peer_address: "fe80::1".into(),
                previous_peer_address: "fe80::1".into(),
                peer_interface: "eth1".into(),
                previous_peer_interface: "eth0".into(),
                route: Some(source()),
                previous_route: Some(source()),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut event);
        assert_eq!(event.peer_address, "fe80::1%eth1");
        assert_eq!(event.previous_peer_address, "fe80::1%eth0");
        let Some(Payload::Evpn(payload)) = event.payload else {
            panic!("EVPN event")
        };
        assert_eq!(payload.peer_address, "fe80::1%eth1");
        assert_eq!(payload.previous_peer_address, "fe80::1%eth0");
        assert_eq!(payload.route.unwrap().peer_address, "fe80::1%eth1");
        assert_eq!(payload.previous_route.unwrap().peer_address, "fe80::1%eth0");
    }

    /// The daemon reports a scoped neighbor as a bare address plus its
    /// interface; rbgp keeps printing `address%interface` for session and
    /// policy events, envelope and payload alike.
    #[test]
    fn session_and_policy_events_render_the_scoped_neighbor() {
        use crate::proto::bgp_event::Payload;
        let mut session = BgpEvent {
            peer_address: "fe80::1".to_string(),
            payload: Some(Payload::Session(crate::proto::SessionEvent {
                peer_address: "fe80::1".to_string(),
                peer_interface: "eth0".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut session);
        assert_eq!(session.peer_address, "fe80::1%eth0");
        let Some(Payload::Session(payload)) = &session.payload else {
            panic!("expected session payload");
        };
        assert_eq!(payload.peer_address, "fe80::1%eth0");

        let mut policy = BgpEvent {
            peer_address: "192.0.2.1".to_string(),
            payload: Some(Payload::Policy(crate::proto::PolicyEvent {
                peer_address: "192.0.2.1".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut policy);
        assert_eq!(policy.peer_address, "192.0.2.1");
    }

    #[test]
    fn bfd_and_dataplane_route_events_render_the_scoped_neighbor() {
        use crate::proto::bgp_event::Payload;
        let mut bfd = BgpEvent {
            peer_address: "fe80::1".to_string(),
            payload: Some(Payload::Bfd(crate::proto::BfdSessionEvent {
                peer_address: "fe80::1".to_string(),
                peer_interface: "eth0".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut bfd);
        assert_eq!(bfd.peer_address, "fe80::1%eth0");
        let Some(Payload::Bfd(payload)) = &bfd.payload else {
            panic!("expected BFD payload");
        };
        assert_eq!(payload.peer_address, "fe80::1%eth0");

        let mut route = BgpEvent {
            peer_address: "fe80::1".to_string(),
            payload: Some(Payload::DataplaneRoute(crate::proto::DataplaneRouteEvent {
                peer_address: "fe80::1".to_string(),
                peer_interface: "eth0".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut route);
        assert_eq!(route.peer_address, "fe80::1%eth0");
        let Some(Payload::DataplaneRoute(payload)) = &route.payload else {
            panic!("expected dataplane route payload");
        };
        assert_eq!(payload.peer_address, "fe80::1%eth0");

        let mut numbered = BgpEvent {
            peer_address: "192.0.2.1".to_string(),
            payload: Some(Payload::Bfd(crate::proto::BfdSessionEvent {
                peer_address: "192.0.2.1".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        scope_bgp_event(&mut numbered);
        assert_eq!(numbered.peer_address, "192.0.2.1");
    }

    #[test]
    fn json_bgp_event_session_uses_null_family() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::SessionEstablished as i32,
            severity: 1,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "session established".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Session(
                crate::proto::SessionEvent {
                    event_type: BgpEventType::SessionEstablished as i32,
                    peer_address: "10.0.0.1".to_string(),
                    timestamp: "1".to_string(),
                    old_state: "OpenConfirm".to_string(),
                    new_state: "Established".to_string(),
                    session_role: "primary".to_string(),
                    reason: "session established".to_string(),
                    peer_interface: String::new(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_bgp_event_stream_lag_includes_missed_count() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::StreamLagged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "route event stream lagged; missed 7 event(s)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::StreamLag(
                crate::proto::StreamLagEvent {
                    source_category: EventCategory::Route as i32,
                    missed_count: 7,
                    reason: "route event stream lagged; missed 7 event(s)".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["event_type"], "stream_lagged");
        assert_eq!(value["severity"], "warning");
        assert_eq!(value["source_category"], "route");
        assert_eq!(value["missed_count"], 7);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_route_watch_stream_lag_uses_route_event_shape() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::StreamLagged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "route event stream lagged; missed 7 event(s)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::StreamLag(
                crate::proto::StreamLagEvent {
                    source_category: EventCategory::Route as i32,
                    missed_count: 7,
                    reason: "route event stream lagged; missed 7 event(s)".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_route_watch_event(&event).unwrap();
        assert_eq!(value["event_type"], "stream_lagged");
        assert_eq!(value["missed_count"], 7);
        assert_eq!(
            value["reason"],
            "route event stream lagged; missed 7 event(s)"
        );
        assert!(value.get("category").is_none());
        assert!(value.get("severity").is_none());
    }

    #[test]
    fn json_bgp_event_notification_includes_code_and_direction() {
        let event = BgpEvent {
            timestamp: "2".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::NotificationSent as i32,
            severity: 2,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "BGP NOTIFICATION sent for peer 10.0.0.1: 6/7 (Connection Collision Resolution)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Notification(
                crate::proto::NotificationEvent {
                    event_type: BgpEventType::NotificationSent as i32,
                    peer_address: "10.0.0.1".to_string(),
                    timestamp: "2".to_string(),
                    direction: "sent".to_string(),
                    code: 6,
                    subcode: 7,
                    description: "Connection Collision Resolution".to_string(),
                    session_role: "primary".to_string(),
                    shutdown_reason: String::new(),
                    reason: "BGP NOTIFICATION sent for peer 10.0.0.1: 6/7 (Connection Collision Resolution)".to_string(),
                    peer_interface: String::new(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["event_type"], "notification_sent");
        assert_eq!(value["direction"], "sent");
        assert_eq!(value["code"], 6);
        assert_eq!(value["subcode"], 7);
        assert_eq!(value["description"], "Connection Collision Resolution");
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_bgp_event_policy_includes_mutation_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Policy as i32,
            event_type: BgpEventType::PolicyChanged as i32,
            severity: 1,
            summary: "policy set policy audit-policy".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Policy(
                crate::proto::PolicyEvent {
                    event_type: BgpEventType::PolicyChanged as i32,
                    operation: "set".to_string(),
                    target_type: "policy".to_string(),
                    target: "audit-policy".to_string(),
                    affected_peer_count: 2,
                    timestamp: "1".to_string(),
                    reason: "policy set policy audit-policy".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "policy");
        assert_eq!(value["event_type"], "policy_changed");
        assert_eq!(value["operation"], "set");
        assert_eq!(value["target_type"], "policy");
        assert_eq!(value["target"], "audit-policy");
        assert_eq!(value["affected_peer_count"], 2);
    }

    #[test]
    fn event_filter_rejects_route_filters_without_route_or_dataplane_category() {
        let categories = vec![EventCategory::Session as i32, EventCategory::Policy as i32];
        let err = validate_event_filter_categories(
            &categories,
            &None,
            Some(AddressFamily::Ipv4Unicast as i32),
            &None,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route or --category dataplane"));

        let err = validate_event_filter_categories(
            &categories,
            &None,
            None,
            &Some("203.0.113.0/24".to_string()),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--category route or --category dataplane"));
    }

    #[test]
    fn event_filter_allows_peer_for_session_dataplane_category() {
        let categories = vec![
            EventCategory::Session as i32,
            EventCategory::Dataplane as i32,
        ];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
    }

    #[test]
    fn event_filter_allows_peer_for_evpn_category() {
        let categories = vec![EventCategory::Evpn as i32];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
    }

    #[test]
    fn event_filter_allows_peer_for_dataplane_route_events() {
        let categories = vec![EventCategory::Dataplane as i32];
        validate_event_filter_categories(&categories, &Some("10.0.0.1".to_string()), None, &None)
            .unwrap();
    }

    #[test]
    fn json_bgp_event_dataplane_includes_summary_counts() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Dataplane as i32,
            event_type: BgpEventType::DataplaneStatusChanged as i32,
            severity: 2,
            afi_safi: AddressFamily::Unspecified as i32,
            summary: "dataplane fib status changed".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Dataplane(
                crate::proto::DataplaneEvent {
                    source: "fib".to_string(),
                    installed: 2,
                    rejected: 1,
                    failed: 1,
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "dataplane");
        assert_eq!(value["event_type"], "dataplane_status_changed");
        assert_eq!(value["source"], "fib");
        assert_eq!(value["installed"], 2);
        assert_eq!(value["rejected"], 1);
        assert_eq!(value["failed"], 1);
        assert!(value["afi_safi"].is_null());
    }

    #[test]
    fn json_bgp_event_dataplane_route_includes_route_fields() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Dataplane as i32,
            event_type: BgpEventType::DataplaneRouteFailed as i32,
            severity: 2,
            peer_address: "10.0.0.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "dataplane fib route failed 203.0.113.0/24".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::DataplaneRoute(
                crate::proto::DataplaneRouteEvent {
                    source: "fib".to_string(),
                    action: "failed".to_string(),
                    table_name: "blue".to_string(),
                    table_id: 100,
                    metric: 20,
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.1".to_string(),
                    peer_address: "10.0.0.1".to_string(),
                    peer_interface: String::new(),
                    timestamp: "1".to_string(),
                    reason: "install_failed:permission denied".to_string(),
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "dataplane");
        assert_eq!(value["event_type"], "dataplane_route_failed");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["source"], "fib");
        assert_eq!(value["action"], "failed");
        assert_eq!(value["table_name"], "blue");
        assert_eq!(value["table_id"], 100);
        assert_eq!(value["metric"], 20);
        assert_eq!(value["next_hop"], "192.0.2.1");
        assert_eq!(value["reason"], "install_failed:permission denied");
    }

    #[test]
    fn json_bgp_event_evpn_includes_route_key_and_payloads() {
        let event = BgpEvent {
            timestamp: "1".to_string(),
            category: EventCategory::Evpn as i32,
            event_type: BgpEventType::EvpnRouteBestChanged as i32,
            severity: 1,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.3".to_string(),
            afi_safi: AddressFamily::L2vpnEvpn as i32,
            summary: "EVPN route best changed mac".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Evpn(
                crate::proto::EvpnRouteEvent {
                    event_type: BgpEventType::EvpnRouteBestChanged as i32,
                    peer_address: "10.0.0.2".to_string(),
                    previous_peer_address: "10.0.0.3".to_string(),
                    timestamp: "1".to_string(),
                    route_type: 2,
                    rd: "65000:100".to_string(),
                    route_key: "type=2 rd=65000:100 mac=aa:bb:cc:dd:ee:ff".to_string(),
                    route: Some(EvpnRouteEntry {
                        route_type: 2,
                        rd: "65000:100".to_string(),
                        mac: "aa:bb:cc:dd:ee:ff".to_string(),
                        peer_address: "10.0.0.2".to_string(),
                        ..Default::default()
                    }),
                    previous_route: None,
                    reason: "EVPN route best changed mac".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "evpn");
        assert_eq!(value["event_type"], "evpn_route_best_changed");
        assert_eq!(value["route_type"], 2);
        assert_eq!(value["route_type_name"], "mac-ip");
        assert_eq!(value["rd"], "65000:100");
        assert_eq!(
            value["route_key"],
            "type=2 rd=65000:100 mac=aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(value["route"]["mac"], "aa:bb:cc:dd:ee:ff");
        assert!(value["previous_route"].is_null());
    }

    #[test]
    fn route_only_filters_reject_policy_only_category() {
        let categories = vec![EventCategory::Policy as i32];
        let err = validate_route_only_filters(&categories, &[], None, Some("203.0.113.0/24"))
            .unwrap_err();
        assert!(err.to_string().contains("route or dataplane route events"));
    }

    #[test]
    fn route_only_filters_allow_mixed_route_policy_category() {
        let categories = vec![EventCategory::Route as i32, EventCategory::Policy as i32];
        validate_route_only_filters(&categories, &[], None, Some("203.0.113.0/24")).unwrap();
    }

    #[test]
    fn route_only_filters_reject_policy_type_without_route_type() {
        let event_types = vec![BgpEventType::PolicyChanged as i32];
        let err = validate_route_only_filters(&[], &event_types, None, Some("203.0.113.0/24"))
            .unwrap_err();
        assert!(err.to_string().contains("route or dataplane route events"));
    }

    #[test]
    fn route_only_filters_allow_mixed_route_policy_types() {
        let event_types = vec![
            BgpEventType::RouteAdded as i32,
            BgpEventType::PolicyChanged as i32,
        ];
        validate_route_only_filters(&[], &event_types, None, Some("203.0.113.0/24")).unwrap();
    }

    #[test]
    fn live_filter_matrix_is_exhaustive() {
        for raw in 0..=100 {
            let Ok(event_type) = BgpEventType::try_from(raw) else {
                continue;
            };
            let live = match raw {
                1..=4 => 1,
                10..=16 | 20..=21 | 53 => 2,
                22 => 4,
                30..=33 => 8,
                40..=42 => 16,
                50..=52 => 32,
                100 => 1 | 2 | 8 | 16 | 32,
                0 => 0,
                _ => unreachable!("known enum value covered"),
            };
            assert_eq!(live_event_type_mask(event_type), live);
        }
        let policy = [EventCategory::Policy as i32];
        assert!(validate_category_event_types(&policy, &[22, 100]).is_ok());
        assert!(validate_category_event_types(&[1, 2], &[1]).is_ok());
        assert!(validate_category_event_types(&policy, &[100]).is_err());
    }

    #[test]
    fn json_route_event_shape_is_stable() {
        let event = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: crate::proto::RouteEventType::BestChanged as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "123".to_string(),
            timestamp_unix_ms: 123_000,
            path_id: 7,
            event_id: 0,
            target_peer_address: String::new(),
            reason: String::new(),
        };

        let value = serde_json::to_value(json_event(&event)).unwrap();
        assert_eq!(value["event_type"], "best_changed");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["peer_address"], "10.0.0.2");
        assert_eq!(value["previous_peer_address"], "10.0.0.1");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["timestamp"], "123");
        assert_eq!(value["path_id"], 7);
        assert_eq!(value["timestamp_unix_seconds"], 123);
    }

    #[test]
    fn json_bgp_event_route_shape_is_stable() {
        let event = BgpEvent {
            timestamp: "123".to_string(),
            category: EventCategory::Route as i32,
            event_type: BgpEventType::RouteWithdrawn as i32,
            severity: crate::proto::EventSeverity::Warning as i32,
            peer_address: "10.0.0.2".to_string(),
            previous_peer_address: "10.0.0.1".to_string(),
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            summary: "route withdrawn 203.0.113.0/24".to_string(),
            ..Default::default()
        };

        let value = json_bgp_event(&event);
        assert_eq!(value["category"], "route");
        assert_eq!(value["event_type"], "route_withdrawn");
        assert_eq!(value["severity"], "warning");
        assert_eq!(value["peer_address"], "10.0.0.2");
        assert_eq!(value["previous_peer_address"], "10.0.0.1");
        assert_eq!(value["prefix"], "203.0.113.0/24");
        assert_eq!(value["afi_safi"], "ipv4_unicast");
        assert_eq!(value["summary"], "route withdrawn 203.0.113.0/24");
        assert_eq!(value["timestamp"], "123");
        assert_eq!(value["timestamp_unix_seconds"], 123);
    }

    /// Golden human lines: the epoch string renders as RFC 3339 UTC in text,
    /// while JSON keeps the string and adds the same instant as a number.
    /// A value that is not integer seconds is shown as received and has no
    /// numeric form.
    /// The text line for a scoped BFD event prints the daemon's summary,
    /// which names the peer as `fe80::1%eth0`.
    #[test]
    fn bfd_event_line_renders_the_scoped_peer() {
        let event = BgpEvent {
            timestamp: "1790132714".to_string(),
            category: EventCategory::Bfd as i32,
            event_type: BgpEventType::BfdSessionUp as i32,
            peer_address: "fe80::1".to_string(),
            summary: "bfd fe80::1%eth0 Init → Up (none)".to_string(),
            payload: Some(crate::proto::bgp_event::Payload::Bfd(
                crate::proto::BfdSessionEvent {
                    peer_address: "fe80::1".to_string(),
                    peer_interface: "eth0".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        assert_eq!(
            format_bgp_event_line(&event),
            "[2026-09-23T03:05:14Z] bfd_up bfd fe80::1%eth0 Init → Up (none)"
        );
    }

    #[test]
    fn event_timestamps_render_rfc3339_in_text_and_epoch_in_json() {
        let session = BgpEvent {
            timestamp: "1790132714".to_string(),
            category: EventCategory::Session as i32,
            event_type: BgpEventType::SessionStateChanged as i32,
            summary: "session state changed for peer 198.51.100.2: connect -> active".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_bgp_event_line(&session),
            "[2026-09-23T03:05:14Z] state_changed session state changed for peer \
             198.51.100.2: connect -> active"
        );
        let json = json_bgp_event(&session);
        assert_eq!(json["timestamp"], "1790132714");
        assert_eq!(json["timestamp_unix_seconds"], 1_790_132_714_u64);

        let route = RouteEvent {
            peer_interface: Default::default(),
            previous_peer_interface: Default::default(),
            target_peer_interface: Default::default(),
            event_type: RouteEventType::Added as i32,
            prefix: "203.0.113.0".to_string(),
            prefix_length: 24,
            peer_address: "10.0.0.1".to_string(),
            afi_safi: AddressFamily::Ipv4Unicast as i32,
            timestamp: "0".to_string(),
            timestamp_unix_ms: 0,
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            path_id: 0,
            event_id: 3,
            reason: String::new(),
        };
        assert_eq!(
            format_route_event_line(&route),
            "[1970-01-01T00:00:00Z] added 203.0.113.0/24 from 10.0.0.1 id=3"
        );
        let json = serde_json::to_value(json_event(&route)).unwrap();
        assert_eq!(json["timestamp"], "0");
        assert_eq!(json["timestamp_unix_seconds"], 0);

        let odd = BgpEvent {
            timestamp: "not-a-number".to_string(),
            event_type: BgpEventType::PeerAdded as i32,
            summary: "peer 198.51.100.2 added".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_bgp_event_line(&odd),
            "[not-a-number] peer_added peer 198.51.100.2 added"
        );
        assert!(json_bgp_event(&odd)["timestamp_unix_seconds"].is_null());

        // Past year 9999 the text falls back to the value as received, while
        // JSON still carries the exact number.
        let far = BgpEvent {
            timestamp: u64::MAX.to_string(),
            event_type: BgpEventType::PeerAdded as i32,
            summary: "peer 198.51.100.2 added".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_bgp_event_line(&far),
            "[18446744073709551615] peer_added peer 198.51.100.2 added"
        );
        assert_eq!(json_bgp_event(&far)["timestamp_unix_seconds"], u64::MAX);
    }

    #[test]
    fn session_history_type_parser_rejects_route_types() {
        assert_eq!(
            parse_session_bgp_event_type("established").unwrap(),
            BgpEventType::SessionEstablished as i32
        );
        assert_eq!(
            parse_session_bgp_event_type("peer_added").unwrap(),
            BgpEventType::PeerAdded as i32
        );
        assert_eq!(
            parse_session_bgp_event_type("peer_removed").unwrap(),
            BgpEventType::PeerRemoved as i32
        );
        assert_eq!(
            parse_session_bgp_event_type("max_prefix_warning").unwrap(),
            BgpEventType::MaxPrefixWarning as i32
        );
        assert!(parse_session_bgp_event_type("added").is_err());
    }
}
