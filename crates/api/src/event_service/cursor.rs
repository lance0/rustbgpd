//! `SubscribeFromEvent` handler helpers (ADR-0072).
//!
//! The tonic service method in `event_service.rs` is a thin
//! adapter that:
//!
//! 1. Confirms an [`EventHistoryHandle`] is available (otherwise
//!    `Status::failed_precondition`).
//! 2. Confirms EHM is not in pass-through mode (same status).
//! 3. Parses the proto request into a [`ProtoFilter`] + the cursor
//!    semantics (`from_event_id = None | Some(0) | Some(N > 0)`).
//! 4. Resolves the live retention floor via
//!    [`EventHistoryHandle::oldest_retained_event_id`] — the gap
//!    signal must be computed against the actual stored MIN, not
//!    a cached atomic, to stay race-free against retention.
//! 5. Spawns a drain task that:
//!    - Emits a leading `StreamLagEvent` if the requested cursor
//!      is older than the retained floor.
//!    - Forwards each committed event, post-filters on the
//!      dimensions the cursor's `SubscribeFilter` doesn't cover
//!      (multi-category, `event_types`, `afi_safi`, `prefix_length`),
//!      decodes the `Proto`-codec payload to `BgpEvent`, stamps
//!      the envelope `event_id` from the `CommittedEvent`, and
//!      mirrors the durable id into the nested `RouteEvent.event_id`
//!      back-compat field for route-only consumers.

use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;

use prost::Message;
use rustbgpd_event_history::{
    Category, CommittedEvent, EventHistoryError, EventHistoryHandle, EventSubscriptionItem,
    PayloadCodec, SubscribeFilter, SubscribeRequest,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::Afi;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{debug, warn};

use crate::proto;
use crate::rib_service::parse_route_event_prefix_filter;

/// Output capacity for the cursor handler's gRPC-side channel.
/// Small relative to EHM's internal broadcast capacity because
/// gRPC backpressure dominates throughput here; a slow client
/// backpressures this per-subscriber stream. If that backpressure
/// makes the underlying EHM broadcast receiver fall behind, the
/// stream emits `BGP_EVENT_TYPE_STREAM_LAGGED`.
const OUTPUT_CAPACITY: usize = 256;

/// Pre-parsed, normalised view of `SubscribeFromEventRequest`.
///
/// `categories`, `event_types`, and `prefix_length` enforce the
/// repeated / scalar dimensions in the handler's post-filter step
/// because the underlying `SubscribeFilter` only models the
/// indexable cursor-side subset.
#[derive(Debug, Clone)]
pub(crate) struct ProtoFilter {
    categories: Vec<proto::EventCategory>,
    event_types: Vec<proto::BgpEventType>,
    neighbor: Option<IpAddr>,
    afi_safi: Option<proto::AddressFamily>,
    prefix: String,
    prefix_length: u32,
}

impl ProtoFilter {
    /// Parse the proto request into a normalised filter. Returns
    /// `Status::invalid_argument` for malformed IP / enum values.
    pub(crate) fn from_request(req: &proto::SubscribeFromEventRequest) -> Result<Self, Status> {
        let categories = parse_categories(&req.categories)?;
        let event_types = parse_event_types(&req.event_types)?;
        validate_durable_category_event_types(&categories, &event_types)?;
        let neighbor = if req.neighbor_address.is_empty() {
            None
        } else {
            Some(IpAddr::from_str(&req.neighbor_address).map_err(|e| {
                Status::invalid_argument(format!(
                    "neighbor_address {:?} is not a valid IP: {e}",
                    req.neighbor_address
                ))
            })?)
        };
        let afi_safi = parse_address_family(req.afi_safi)?;
        let prefix = parse_prefix_filter(&req.prefix, req.prefix_length, afi_safi)?;
        Ok(Self {
            categories,
            event_types,
            neighbor,
            afi_safi,
            prefix,
            prefix_length: req.prefix_length,
        })
    }

    /// Narrow the proto filter into the cursor-side
    /// [`SubscribeFilter`] where the storage layer can index the
    /// query. A single-category filter is the only multi-field
    /// optimisation worth exploiting here; everything else is
    /// post-filtered in [`Self::matches_committed`].
    pub(crate) fn cursor_subset(&self) -> SubscribeFilter {
        SubscribeFilter {
            category: if self.categories.len() == 1 {
                map_proto_category(self.categories[0])
            } else {
                None
            },
            peer: self.neighbor,
            prefix: if self.prefix.is_empty() {
                None
            } else {
                Some(self.prefix.clone())
            },
            rd: None,
        }
    }

    /// Apply the post-filter dimensions that the cursor's
    /// `SubscribeFilter` doesn't cover: multi-category,
    /// `event_types`, `afi_safi`, `prefix_length`. Returns `true`
    /// when the committed event passes all set filters.
    pub(crate) fn matches_committed(&self, evt: &CommittedEvent) -> bool {
        if !self.categories.is_empty() {
            let want: Vec<Category> = self
                .categories
                .iter()
                .filter_map(|c| map_proto_category(*c))
                .collect();
            if !want.contains(&evt.envelope.category) {
                return false;
            }
        }

        if let Some(prefix_length) = (self.prefix_length > 0).then_some(self.prefix_length)
            && !envelope_prefix_length_matches(evt.envelope.prefix.as_ref(), prefix_length)
        {
            return false;
        }

        if let Some(want) = self.afi_safi {
            let want_label = want.as_str_name().to_lowercase();
            if evt.envelope.afi_safi.as_deref() != Some(want_label.as_str()) {
                return false;
            }
        }

        // `event_types` is handled inside the per-event decode
        // because we don't carry the proto event-type i32 on the
        // envelope itself — `envelope.event_type` is a label
        // string from the producer, not a stable wire enum.
        // The caller (run_drain) post-checks against the decoded
        // BgpEvent's event_type field.
        true
    }

    /// Whether the supplied decoded `BgpEvent` passes the
    /// `event_types` filter. Empty `event_types` is wildcard.
    pub(crate) fn matches_event_type(&self, event: &proto::BgpEvent) -> bool {
        if self.event_types.is_empty() {
            return true;
        }
        let Ok(t) = proto::BgpEventType::try_from(event.event_type) else {
            return false;
        };
        self.event_types.contains(&t)
    }
}

fn validate_durable_category_event_types(
    categories: &[proto::EventCategory],
    event_types: &[proto::BgpEventType],
) -> Result<(), Status> {
    if event_types.is_empty() {
        return Ok(());
    }
    let categories = categories
        .iter()
        .fold(0, |mask, category| mask | category_mask(*category));
    let categories = if categories == 0 { 0x3f } else { categories };
    let event_types = event_types.iter().fold(0, |mask, event_type| {
        mask | durable_event_type_mask(*event_type)
    });
    if categories & event_types != 0 {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "event category/type filters have no possible intersection for SubscribeFromEvent",
        ))
    }
}

fn category_mask(category: proto::EventCategory) -> u8 {
    match category {
        proto::EventCategory::Unspecified => 0,
        proto::EventCategory::Route => 1,
        proto::EventCategory::Session => 2,
        proto::EventCategory::Policy => 4,
        proto::EventCategory::Dataplane => 8,
        proto::EventCategory::Evpn => 16,
        proto::EventCategory::Bfd => 32,
    }
}

fn durable_event_type_mask(event_type: proto::BgpEventType) -> u8 {
    match event_type {
        proto::BgpEventType::Unspecified => 0,
        proto::BgpEventType::RouteAdded
        | proto::BgpEventType::RouteWithdrawn
        | proto::BgpEventType::RouteBestChanged
        | proto::BgpEventType::RoutePolicyFiltered => 1,
        proto::BgpEventType::SessionStateChanged
        | proto::BgpEventType::SessionEstablished
        | proto::BgpEventType::SessionLost
        | proto::BgpEventType::PeerEnabled
        | proto::BgpEventType::PeerDisabled
        | proto::BgpEventType::PeerAdded
        | proto::BgpEventType::PeerRemoved
        | proto::BgpEventType::NotificationSent
        | proto::BgpEventType::NotificationReceived => 2,
        proto::BgpEventType::PolicyChanged | proto::BgpEventType::OtcRouteBlocked => 4,
        proto::BgpEventType::DataplaneStatusChanged
        | proto::BgpEventType::DataplaneRouteInstalled
        | proto::BgpEventType::DataplaneRouteWithdrawn
        | proto::BgpEventType::DataplaneRouteFailed => 8,
        proto::BgpEventType::EvpnRouteAdded
        | proto::BgpEventType::EvpnRouteWithdrawn
        | proto::BgpEventType::EvpnRouteBestChanged => 16,
        proto::BgpEventType::BfdSessionUp
        | proto::BgpEventType::BfdSessionDown
        | proto::BgpEventType::BfdSessionStateChanged => 32,
        proto::BgpEventType::StreamLagged => 0x3f,
    }
}

fn parse_categories(raw: &[i32]) -> Result<Vec<proto::EventCategory>, Status> {
    let mut categories = Vec::with_capacity(raw.len());
    for value in raw {
        let category = proto::EventCategory::try_from(*value)
            .map_err(|_| Status::invalid_argument("unknown event category"))?;
        if category == proto::EventCategory::Unspecified {
            return Err(Status::invalid_argument(
                "EVENT_CATEGORY_UNSPECIFIED is not a valid filter",
            ));
        }
        categories.push(category);
    }
    Ok(categories)
}

fn parse_event_types(raw: &[i32]) -> Result<Vec<proto::BgpEventType>, Status> {
    let mut event_types = Vec::with_capacity(raw.len());
    for value in raw {
        let event_type = proto::BgpEventType::try_from(*value)
            .map_err(|_| Status::invalid_argument("unknown event type"))?;
        if event_type == proto::BgpEventType::Unspecified {
            return Err(Status::invalid_argument(
                "BGP_EVENT_TYPE_UNSPECIFIED is not a valid filter",
            ));
        }
        event_types.push(event_type);
    }
    Ok(event_types)
}

fn parse_address_family(value: i32) -> Result<Option<proto::AddressFamily>, Status> {
    let family = proto::AddressFamily::try_from(value)
        .map_err(|_| Status::invalid_argument("unknown address family"))?;
    Ok((family != proto::AddressFamily::Unspecified).then_some(family))
}

fn parse_prefix_filter(
    prefix: &str,
    prefix_length: u32,
    afi_safi: Option<proto::AddressFamily>,
) -> Result<String, Status> {
    let afi = match afi_safi {
        Some(proto::AddressFamily::Ipv4Unicast) => Some(Afi::Ipv4),
        Some(proto::AddressFamily::Ipv6Unicast) => Some(Afi::Ipv6),
        Some(_) if !prefix.is_empty() => {
            return Err(Status::invalid_argument(
                "prefix filters support only IPv4/IPv6 unicast address families",
            ));
        }
        _ => None,
    };

    let parsed = parse_route_event_prefix_filter(prefix, prefix_length, afi)?;
    Ok(parsed.map_or_else(String::new, |p| p.to_string()))
}

/// Parse a proto `EventCategory` into the storage-side `Category`
/// enum. All six categories — route, session, policy, EVPN, BFD,
/// and dataplane — are produced through EHM when
/// `[event_history].enabled = true`.
fn map_proto_category(c: proto::EventCategory) -> Option<Category> {
    match c {
        proto::EventCategory::Route => Some(Category::Route),
        proto::EventCategory::Session => Some(Category::Session),
        proto::EventCategory::Policy => Some(Category::Policy),
        proto::EventCategory::Evpn => Some(Category::Evpn),
        proto::EventCategory::Bfd => Some(Category::Bfd),
        proto::EventCategory::Dataplane => Some(Category::Dataplane),
        proto::EventCategory::Unspecified => None,
    }
}

fn envelope_prefix_length_matches(prefix: Option<&String>, want: u32) -> bool {
    let Some(p) = prefix else { return false };
    let Some(slash_pos) = p.rfind('/') else {
        return false;
    };
    p[slash_pos + 1..]
        .parse::<u32>()
        .is_ok_and(|got| got == want)
}

/// Build the leading `BgpEvent` carrying a `StreamLagEvent` that
/// signals "the client cursor was older than the retained floor."
///
/// The category on the lag event is `Unspecified` because the gap
/// spans the global committed stream — not any particular source
/// category. `missed_count` is computed against the global stream
/// too, not the filtered subset, so collectors do not interpret
/// `missed_count` as "events of the requested type missed".
pub(crate) fn build_cursor_gap_event(requested_from: u64, oldest_retained: u64) -> proto::BgpEvent {
    let missed_count = oldest_retained.saturating_sub(requested_from.saturating_add(1));
    let reason = format!(
        "cursor older than retained history; \
         requested_from_event_id={requested_from} \
         oldest_retained_event_id={oldest_retained}"
    );
    proto::BgpEvent {
        timestamp: String::new(),
        category: proto::EventCategory::Unspecified as i32,
        event_type: proto::BgpEventType::StreamLagged as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address: String::new(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: reason.clone(),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::StreamLag(
            proto::StreamLagEvent {
                source_category: proto::EventCategory::Unspecified as i32,
                missed_count,
                reason,
            },
        )),
    }
}

fn build_live_lag_event(missed_count: u64) -> proto::BgpEvent {
    let reason =
        format!("durable event live stream lagged; missed_committed_events={missed_count}");
    proto::BgpEvent {
        timestamp: String::new(),
        category: proto::EventCategory::Unspecified as i32,
        event_type: proto::BgpEventType::StreamLagged as i32,
        severity: proto::EventSeverity::Warning as i32,
        peer_address: String::new(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary: reason.clone(),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::StreamLag(
            proto::StreamLagEvent {
                source_category: proto::EventCategory::Unspecified as i32,
                missed_count,
                reason,
            },
        )),
    }
}

/// Map an [`EventHistoryError`] back into a tonic [`Status`] suitable
/// for returning to a gRPC client.
pub(crate) fn map_ehm_err_to_status(err: EventHistoryError) -> Status {
    match err {
        EventHistoryError::PassThrough => Status::failed_precondition(
            "event history in pass-through mode; durable cursor unavailable \
             — see [event_history].required + the bgp_event_outbox_degraded gauge",
        ),
        other => Status::internal(format!("event history error: {other}")),
    }
}

/// Decode the byte payload of a `CommittedEvent` (codec
/// [`PayloadCodec::Proto`]) into a [`proto::BgpEvent`]. Returns
/// `None` and increments the drop counter on decode failure.
///
/// Opaque-codec payloads can't be served on the wire — we log and
/// drop them. In practice the only producers writing opaque
/// payloads are crate tests; production producers always use
/// `PayloadCodec::Proto`.
fn decode_payload_as_bgp_event(
    committed: &CommittedEvent,
    metrics: &BgpMetrics,
) -> Option<proto::BgpEvent> {
    match committed.envelope.payload_codec {
        PayloadCodec::Proto => match proto::BgpEvent::decode(&committed.envelope.payload[..]) {
            Ok(event) => Some(event),
            Err(e) => {
                metrics.record_event_outbox_drop(
                    committed.envelope.category.as_str(),
                    "decode_failure",
                );
                metrics.mark_event_outbox_degraded();
                warn!(
                    error = %e,
                    event_id = committed.event_id,
                    category = committed.envelope.category.as_str(),
                    "SubscribeFromEvent: failed to decode payload as BgpEvent; dropping",
                );
                None
            }
        },
        PayloadCodec::Opaque => {
            metrics.record_event_outbox_drop(committed.envelope.category.as_str(), "opaque_codec");
            metrics.mark_event_outbox_degraded();
            debug!(
                event_id = committed.event_id,
                category = committed.envelope.category.as_str(),
                "SubscribeFromEvent: opaque-codec payload skipped (no wire shape)",
            );
            None
        }
    }
}

/// Stamp `BgpEvent.event_id` (envelope-level) and mirror it into
/// the nested back-compat `RouteEvent.event_id` field on the wire
/// when the payload is a route event. Per ADR-0072 the durable id
/// is the authoritative cursor source for `SubscribeFromEvent`;
/// the nested `RouteEvent.event_id` exists only for back-compat
/// with route-only consumers, and on this RPC it carries the
/// durable id (not the legacy process-local id).
fn stamp_durable_ids(event: &mut proto::BgpEvent, durable_event_id: u64) {
    event.event_id = Some(durable_event_id);
    if let Some(proto::bgp_event::Payload::Route(ref mut r)) = event.payload {
        r.event_id = durable_event_id;
    }
}

/// Drive a subscribed cursor stream to the gRPC client.
///
/// Spawns its own task and returns immediately; the caller wraps
/// `out_rx` in a [`ReceiverStream`] and returns it as the tonic
/// response. The task exits when the subscriber's output channel
/// closes (gRPC client disconnect, server drop) or when EHM's
/// drain task signals end-of-stream.
async fn run_drain(
    filter: ProtoFilter,
    cursor: Option<u64>,
    mut committed_rx: mpsc::Receiver<EventSubscriptionItem>,
    out_tx: mpsc::Sender<Result<proto::BgpEvent, Status>>,
    metrics: BgpMetrics,
) {
    // Forward committed events. Retention-gap detection happens
    // inside EHM's replay task and arrives here as
    // `EventSubscriptionItem::RetentionGap(missed)`; submitting the
    // floor read + first chunk read as one storage op makes the gap
    // signal race-free against retention. Live broadcast lag arrives
    // as `EventSubscriptionItem::Lagged(missed)`.
    while let Some(item) = committed_rx.recv().await {
        let committed = match item {
            EventSubscriptionItem::Event(committed) => committed,
            EventSubscriptionItem::Lagged(missed) => {
                let lag = build_live_lag_event(missed);
                if out_tx.send(Ok(lag)).await.is_err() {
                    return;
                }
                continue;
            }
            EventSubscriptionItem::RetentionGap(missed) => {
                let from = cursor.unwrap_or(0);
                let oldest_retained = from.saturating_add(missed.saturating_add(1));
                let lag = build_cursor_gap_event(from, oldest_retained);
                metrics.record_event_outbox_cursor_gap();
                if out_tx.send(Ok(lag)).await.is_err() {
                    return;
                }
                continue;
            }
        };
        if !filter.matches_committed(&committed) {
            continue;
        }
        let Some(mut event) = decode_payload_as_bgp_event(&committed, &metrics) else {
            continue;
        };
        if !filter.matches_event_type(&event) {
            continue;
        }
        stamp_durable_ids(&mut event, committed.event_id);
        if out_tx.send(Ok(event)).await.is_err() {
            return;
        }
    }
}

/// Stream type returned by [`subscribe`]. Aliased to keep the
/// public signature inside the workspace clippy threshold.
pub(crate) type SubscribeFromEventStream =
    Pin<Box<dyn Stream<Item = Result<proto::BgpEvent, Status>> + Send + 'static>>;

fn parse_filter_when_available(
    pass_through: bool,
    request: &proto::SubscribeFromEventRequest,
) -> Result<ProtoFilter, Status> {
    if pass_through {
        return Err(Status::failed_precondition(
            "event history in pass-through mode; durable cursor unavailable",
        ));
    }
    ProtoFilter::from_request(request)
}

/// Public entry point called by the tonic handler. Performs the
/// availability checks, the subscribe, and spawns the drain task.
/// Non-async because the underlying handle's `subscribe_from_event`
/// is non-async (the EHM-side 3-step handoff must run without
/// yielding between subscribe-then-watermark-then-spawn).
pub(crate) fn subscribe(
    handle: &EventHistoryHandle,
    request: &proto::SubscribeFromEventRequest,
    metrics: BgpMetrics,
) -> Result<SubscribeFromEventStream, Status> {
    let filter = parse_filter_when_available(handle.state().pass_through(), request)?;
    let cursor = request.from_event_id;

    let subscribe_req = SubscribeRequest {
        from_event_id: cursor,
        filter: filter.cursor_subset(),
        output_capacity: OUTPUT_CAPACITY,
    };
    let subscription = handle
        .subscribe_from_event(subscribe_req)
        .map_err(map_ehm_err_to_status)?;
    let committed_rx = subscription.into_receiver();

    let (out_tx, out_rx) = mpsc::channel(OUTPUT_CAPACITY);
    tokio::spawn(run_drain(filter, cursor, committed_rx, out_tx, metrics));

    Ok(Box::pin(ReceiverStream::new(out_rx)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_request_rejects_unknown_category() {
        let err = ProtoFilter::from_request(&proto::SubscribeFromEventRequest {
            categories: vec![999],
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn from_request_rejects_unspecified_event_type() {
        let err = ProtoFilter::from_request(&proto::SubscribeFromEventRequest {
            event_types: vec![proto::BgpEventType::Unspecified as i32],
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn from_request_normalizes_prefix_to_storage_key() {
        let filter = ProtoFilter::from_request(&proto::SubscribeFromEventRequest {
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(filter.prefix, "10.0.0.0/24");
        assert_eq!(
            filter.cursor_subset().prefix.as_deref(),
            Some("10.0.0.0/24")
        );
    }

    #[test]
    fn from_request_rejects_unknown_address_family() {
        let err = ProtoFilter::from_request(&proto::SubscribeFromEventRequest {
            afi_safi: 999,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn durable_event_type_matrix_is_exhaustive() {
        for raw in 0..=100 {
            let Ok(event_type) = proto::BgpEventType::try_from(raw) else {
                continue;
            };
            let expected = match raw {
                1..=4 => 1,
                10..=16 | 20..=21 => 2,
                22..=23 => 4,
                30..=33 => 8,
                40..=42 => 16,
                50..=52 => 32,
                100 => 0x3f,
                0 => 0,
                _ => unreachable!("known enum value covered"),
            };
            assert_eq!(
                durable_event_type_mask(event_type),
                expected,
                "{event_type:?}"
            );
        }
    }

    #[test]
    fn availability_precedes_impossible_filter_validation() {
        let request = proto::SubscribeFromEventRequest {
            categories: vec![proto::EventCategory::Session as i32],
            event_types: vec![proto::BgpEventType::OtcRouteBlocked as i32],
            ..Default::default()
        };
        let unavailable = parse_filter_when_available(true, &request).unwrap_err();
        assert_eq!(unavailable.code(), tonic::Code::FailedPrecondition);
        let available = parse_filter_when_available(false, &request).unwrap_err();
        assert_eq!(available.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn durable_mixed_sets_accept_any_intersection() {
        let request = proto::SubscribeFromEventRequest {
            categories: vec![
                proto::EventCategory::Route as i32,
                proto::EventCategory::Session as i32,
            ],
            event_types: vec![proto::BgpEventType::RouteAdded as i32],
            ..Default::default()
        };
        ProtoFilter::from_request(&request).expect("one compatible category/type pair is enough");
    }
}
