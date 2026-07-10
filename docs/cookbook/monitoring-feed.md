# Controller / monitoring feed (BMP trio, events, MRT)

**When this is you:** a controller, analytics pipeline, or NOC stack
needs to see what this daemon sees — pre-policy, post-policy, and
Loc-RIB route streams into BMP collectors, a durable event feed your
bridge can replay after a restart, periodic MRT table archives, and a
Grafana dashboard on top. rustbgpd exports the full BMP monitoring
trio on one exporter (RFC 7854 Adj-RIB-In, RFC 8671 Adj-RIB-Out as
byte-exact wire PDUs, RFC 9069 Loc-RIB), selectable per collector.

**Proven by:** [M24](../RECEIPTS.md#interop-labs--pr-gated-interopyml)
(BMP Initiation / PeerUp / RouteMonitoring ordering vs a BMP receiver)
and M81 (the trio plus BMPv4, validated against three independent
decoders at once: pmacct, gobmp, and tshark). Config shape derived
from
[`tests/interop/configs/rustbgpd-m81-bmp-rr.toml`](../../tests/interop/configs/rustbgpd-m81-bmp-rr.toml)
and [`examples/route-collector/`](../../examples/route-collector/).

## Config

The example is an RR that also feeds the monitoring stack; the same
`[bmp]` / `[event_history]` / `[mrt]` blocks bolt onto any of the
other recipes unchanged.

```toml
[global]
asn = 65000
router_id = "10.255.0.1"
listen_port = 179
cluster_id = "10.255.0.1"

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

# Durable event outbox (ADR-0072): restart-safe replay cursor for
# SubscribeFromEvent. Opt-in — it costs memory/CPU at scale, which is
# why it is off by default. Enable it here because replay is the
# point of this deployment.
[event_history]
enabled = true

# Periodic MRT TABLE_DUMP_V2 snapshots — readable by bgpdump, BGPKIT,
# and the RouteViews/RIPE RIS toolchains.
[mrt]
output_dir = "/var/lib/rustbgpd/mrt"
dump_interval = 3600
compress = true
file_prefix = "feed"

[bmp]
sys_name = "rustbgpd-feed"
sys_descr = "fabric RR monitoring feed"

# Production collector: BMP v3 (the default), all three RIB views.
# When a collector connects it receives a chunked dump of the current
# table state followed by End-of-RIB, then deltas (RFC 9069 §"on
# connect" behavior — no daemon restart needed to attach a collector).
[[bmp.collectors]]
address = "10.20.0.10:1790"
reconnect_interval = 5
monitor = ["rib_in_pre", "rib_out_post", "loc_rib"]

# Optional second collector with BMPv4 TLV framing + the Path Marking
# TLV. Caveat, stated plainly: BMPv4 code points are pre-IANA drafts
# (draft-ietf-grow-bmp-tlv / draft-ietf-grow-bmp-path-marking-tlv) and
# may renumber; current pmacct releases discard tlv-20-framed v4 Route
# Monitoring messages. Keep production collectors on v3 (the default);
# point v4 only at tooling that tracks the drafts (M81 validated the
# v4 bytes with tshark 4.4).
#[[bmp.collectors]]
#address = "10.20.0.11:1790"
#reconnect_interval = 5
#version = 4
#monitor = ["rib_in_pre", "rib_out_post", "loc_rib"]

[[neighbors]]
address = "10.0.0.11"
remote_asn = 65000
description = "pe-1"
hold_time = 90
route_reflector_client = true
families = ["ipv4_unicast", "ipv6_unicast", "l3vpn_ipv4_unicast"]

[[neighbors]]
address = "10.0.1.2"
remote_asn = 65000
description = "pe-2"
hold_time = 90
route_reflector_client = true
families = ["ipv4_unicast", "ipv6_unicast", "l3vpn_ipv4_unicast"]
```

## Verify

```console
$ export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
$ rbgp health
$ rbgp neighbor
```

**BMP:** on the collector you should see Initiation, one PeerUp per
established peer per view, the chunked table dump, End-of-RIB, then
live RouteMonitoring deltas. From the daemon side the collector
connection state is visible in the logs (`log_format = "json"`) and
the BMP metrics below.

**Event replay (the bridge contract):** live tail plus durable replay
from a cursor. `--from-event-id 0` replays everything retained, then
tails; your bridge persists the last `event_id` it processed and
resumes from there after either side restarts:

```console
$ rbgp events watch --from-event-id 0
$ rbgp events watch --category route,session --from-event-id 41236
```

The same contract over raw gRPC is
`EventService.SubscribeFromEvent` — see
[`examples/event-bridge/`](../../examples/event-bridge/) for a
complete bridge (gRPC → JSON lines) you can pipe into Kafka, NATS,
or Vector. rustbgpd deliberately is not an event bus; the outbox is
a bounded SQLite WAL store with a monotonic cursor
([ADR-0072](../adr/0072-durable-event-history.md)).

**MRT:** force a dump and inspect it with your usual tooling:

```console
$ rbgp mrt-dump
$ ls /var/lib/rustbgpd/mrt/
feed.20260703.120001.123456789.mrt.gz
```

**Looking glass (optional):** for an Alice-LG-style frontend, run the
[`examples/birdwatcher-adapter/`](../../examples/birdwatcher-adapter/)
against a gRPC TCP listener. (The in-daemon
`[global.telemetry.looking_glass]` server has been removed.)

## Watch

Import the overview dashboard per [`GRAFANA.md`](../GRAFANA.md); the
BMP / event-outbox row is populated once the features above are
configured. Key series:

| Metric | Meaning |
|--------|---------|
| `bgp_event_outbox_degraded` | 1 = outbox DB failed and was quarantined; replay unavailable until operator restart |
| `bmp_collector_drops_total` | messages dropped toward a slow/disconnected collector |
| `bmp_source_drops_total` | route-monitoring events dropped at the source tap under backpressure |
| `bmp_replay_attempts_total` | PeerUp-cache replays on collector reconnect |
| `bgp_rib_outbound_registered_peers` | feed coverage: peers whose routes the views carry |

## Failure modes

**`SubscribeFromEvent` / `rbgp events watch --from-event-id` returns
`FAILED_PRECONDITION`.** The daemon is running with
`[event_history].enabled = false` (the default). Enable it and
restart — the outbox fields are restart-required.

**The bridge missed events during a burst.** Live streams emit
`stream_lagged` warnings when a bounded source dropped events for a
slow consumer. That is the signal to resume via the durable cursor
(`--from-event-id <last-processed>`) rather than the live ring.

**A BMP collector shows nothing after a network blip.** The daemon
redials every `reconnect_interval` seconds and replays the full state
dump on reconnect; check the collector-side listener first, then the
daemon log for the collector's connection state transitions.

**pmacct rejects the v4 stream (`BMPv4 BGP PDU TLV != 1`).** Known and
expected — see the caveat in the config above. Move that collector to
`version = 3` (or drop the `version` key; 3 is the default).

**The events DB was corrupted by a crash.** The bad file is renamed
`events.db.stale`, the daemon continues (pass-through) unless
`[event_history].required = true`, and `bgp_event_outbox_degraded`
latches to 1 until an operator restart. Details:
[`CONFIGURATION.md` §event_history](../CONFIGURATION.md#event_history).
