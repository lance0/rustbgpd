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
- Periodic Stats Report (Adj-RIB-In route count)
- RFC 8671 post-policy Adj-RIB-Out route monitoring (O=1/L=1)
- RFC 9069 Loc-RIB route monitoring + Loc-RIB Stats Report (peer type 3),
  with a resumable cursor-based Loc-RIB dump
- BMPv4 per-collector TLV framing (draft-ietf-grow-bmp-tlv), including the
  Path Marking TLV
- Per-collector monitoring-scope selection (Adj-RIB-In / Adj-RIB-Out / Loc-RIB)
- Coordinated Termination on daemon shutdown

## Architecture

The transport layer captures raw BGP PDUs and emits `BmpEvent` variants
(PeerUp, PeerDown, RouteMonitoring) through an `mpsc` channel.
`BmpManager` encodes events and distributes to per-collector `BmpClient`
tasks. Zero overhead when no collectors are configured.

## License

MIT OR Apache-2.0
