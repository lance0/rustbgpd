# rustbgpd-bmp

BMP exporter implementing RFC 7854, with RFC 8671 (post-policy
Adj-RIB-Out) and RFC 9069 (Loc-RIB) route monitoring and BMPv4
per-collector TLV framing.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- Six BMP message types: Initiation, Peer Up, Peer Down, Route
  Monitoring, Stats Report, Termination (Route Mirroring is out of
  scope)
- Per-collector async TCP client with automatic reconnect and backoff
- Fan-out manager distributes events to all connected collectors
- Peer Up replay on collector reconnect
- Periodic Stats Reports for each peer carry the RFC 7854 Adj-RIB-In route
  count (type 7); when available, they also carry the RFC 8671 post-policy
  Adj-RIB-Out total (type 15) and per-(AFI, SAFI) counts (type 17); types 15/17
  are omitted when unavailable rather than reported as false zero. RFC 9972
  post-policy Adj-RIB-In gauges (types 20/21/23) cover negotiated IPv4/IPv6
  unicast and are omitted when effective unicast Add-Path receive is active.
  Type 22 reports exact retained policy rejections for those negotiated
  families, including under Add-Path; it is omitted when rejected-route
  retention is disabled or a capacity eviction makes the retained set
  incomplete. Types 35/36/37 report exact post-policy RPKI Invalid, Valid, and
  NotFound path counts per negotiated IPv4/IPv6-unicast family, including
  Add-Path identities; they are omitted until a VRP table is authoritative.
- RFC 8671 post-policy Adj-RIB-Out route monitoring (O=1/L=1)
- RFC 9069 Loc-RIB route monitoring + Loc-RIB Stats Report (peer type 3),
  with a resumable cursor-based Loc-RIB dump
- BMPv4 per-collector TLV framing (draft-ietf-grow-bmp-tlv-21). Path Marking
  is temporarily unavailable until its draft receives a non-colliding type.
- Per-collector monitoring-scope selection (Adj-RIB-In / Adj-RIB-Out / Loc-RIB)
- Coordinated Termination on daemon shutdown

## Architecture

`BmpManager` receives every `BmpEvent` variant through an `mpsc` channel:
`PeerUp`, `PeerDown`, `RouteMonitoring`, `StatsReport`,
`LocRibRouteMonitoring`, and `LocRibStats`.

`BmpManager` encodes events and distributes to per-collector `BmpClient`
tasks. Zero overhead when no collectors are configured.

## License

MIT OR Apache-2.0
