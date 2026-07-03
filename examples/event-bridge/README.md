# event-bridge — reference external-collector bridge (ADR-0072)

This example demonstrates the operator-facing pattern for
consuming `rustbgpd`'s **durable event outbox** over gRPC and
forwarding events to an external system (Kafka, NATS, Vector,
journald, a SIEM ingestion endpoint, etc.).

It is a **reference skeleton**, not a maintained bus connector —
development/example status only. It is not part of the default
`cargo build`, the release tarballs, or any container image; it
builds only with `--workspace` or an explicit `-p event-bridge`.
Real deployments fork this and replace the stdout writer with the
operator's preferred sink. The patterns to preserve are:

1. **Subscribe with a durable cursor.** Pass the last
   `event_id` your sink confirmed durable as `--from-event-id`.
2. **Advance the cursor only after the downstream sink confirms
   durability.** This skeleton's stdout flush is a stand-in for
   that confirmation; a real sink uses its own ack mechanism.
3. **Treat `StreamLagEvent` as a gap signal, not a stream end.**
   When the daemon emits one as the leading frame, your collector
   has lost events older than the daemon's retention floor. Alert
   on the `bgp_event_outbox_cursor_gap_total` daemon metric.
4. **Use `timestamp`, not `event_id`, for causal joins across
   event categories.** The `event_id` is order-of-arrival at EHM,
   not order-of-occurrence at the producer. See ADR-0072 "Global
   ordering semantic."

## Build + run

```sh
cargo run --release -p event-bridge -- \
    --addr http://127.0.0.1:50051 \
    --from-event-id 0 \
    --category route,session,policy \
    > /tmp/events.ndjson
```

Each line of stdout is one JSON object:

```json
{"event_id":42,"timestamp":"1748305280","category":"route",
 "event_type":"BGP_EVENT_TYPE_ROUTE_ADDED","severity":"info",
 "peer":"10.0.0.1","previous_peer":"","target_peer":"",
 "prefix":"10.1.0.0","prefix_length":24,"afi_safi":"ipv4_unicast",
 "summary":"route added 10.1.0.0/24",
 "payload":{"type":"route","prefix":"10.1.0.0",
            "prefix_length":24,"afi_safi":1,"peer":"10.0.0.1",
            "previous_peer":"","target_peer":"","path_id":0,
            "reason":"","event_id":42}}
```

## Failure modes worth handling

- **`FAILED_PRECONDITION` on subscribe**: the daemon was started
  with `[event_history].enabled = false`, or EHM dropped into
  pass-through mode at runtime. Legacy `WatchEvents` /
  `WatchRoutes` still work; durable cursor replay does not.

- **Cursor older than retention floor**: the stream's first frame
  is a `StreamLagEvent` with `missed_count` over the global
  committed stream (not your filtered subset). Your wrapper should
  log + alert and continue. To prevent it, size `[event_history]
  .max_events` and `max_bytes` for your worst-case collector
  reconnect SLA, monitor `bgp_event_outbox_cursor_gap_total`, and
  reconnect promptly after a sink outage.

- **Dataplane events not in the durable outbox in v1**: this release wires
  route + EVPN + session-lifecycle + session-notification + policy
  + BFD through EHM. Dataplane events stay live-only. Empty
  categories on `SubscribeFromEvent` selects all **retained**
  categories — dataplane is silently absent. See ADR-0072
  "Producer set in v1".

## Plugging in a real sink

Replace the `stdout.write_all` loop with your sink's publish call.
Wait for the sink's ack before advancing your persisted
`last_seen_event_id`. A typical Kafka-style pattern:

```rust
producer.send(topic, &payload).await?;          // sink publish
producer.flush_timeout(Duration::from_secs(5)).await?; // ack
state.set_last_seen(event.event_id.unwrap_or(0))?;     // persist
```

For NATS JetStream, the durable-consumer ack on `msg.ack()` is
the equivalent confirmation step. Use the operator's existing
persistence mechanism for `last_seen_event_id`; the daemon does
not provide one.
