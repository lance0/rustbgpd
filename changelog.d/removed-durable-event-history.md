### Removed

- Removed the optional durable event history and everything built on it:
  the `[event_history]` config section and its `events.db` store,
  `EventService.SubscribeFromEvent` and `SubscribeFromEventRequest`, the
  envelope field `BgpEvent.event_id` (`RouteEvent.event_id` stays),
  `rbgp events watch --from-event-id`, the `examples/event-bridge` sample,
  and the `event_history_changed` key in config diff JSON. The protobuf
  field numbers and names are reserved. The bounded in-memory session,
  policy, route and EVPN histories behind `ListSessionEvents`,
  `ListPolicyEvents`, `ListRouteEvents` and `ListEvpnEvents`, and the live
  `WatchEvents` stream, are unchanged. The daemon no longer links SQLite.
- Removed the `bgp_event_outbox_committed_total`,
  `bgp_event_outbox_dropped_total`, `bgp_event_outbox_queue_depth`,
  `bgp_event_outbox_db_size_bytes`,
  `bgp_event_outbox_retention_evicted_total`,
  `bgp_event_outbox_latest_event_id`,
  `bgp_event_outbox_open_failures_total`, `bgp_event_outbox_degraded`,
  `bgp_event_outbox_storage_failed` and `bgp_event_outbox_cursor_gap_total`
  metric families, the `BgpEventOutboxDegraded` and
  `BgpEventOutboxStorageFailed` alert rules, and the event outbox panels of
  the overview dashboard.
- Removed the `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED` event type and its
  `OtcRouteBlockedEvent` payload, which only the durable event history ever
  delivered, together with `rbgp events watch --type otc_route_blocked`.
  The `bgp_otc_routes_blocked_total{peer,reason}` counter, the per-neighbor
  `otc_routes_blocked` count and the OTC log lines are unchanged.
