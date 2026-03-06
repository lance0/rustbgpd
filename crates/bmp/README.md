# rustbgpd-bmp

BMP exporter implementing RFC 7854 (BGP Monitoring Protocol).

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- All 6 BMP message types: Initiation, Peer Up, Peer Down, Route
  Monitoring, Stats Report, Termination
- Per-collector async TCP client with automatic reconnect and backoff
- Fan-out manager distributes events to all connected collectors
- Peer Up replay on collector reconnect
- Periodic Stats Report (Adj-RIB-In route count)
- Coordinated Termination on daemon shutdown

## Architecture

The transport layer captures raw BGP PDUs and emits `BmpEvent` variants
(PeerUp, PeerDown, RouteMonitoring) through an `mpsc` channel.
`BmpManager` encodes events and distributes to per-collector `BmpClient`
tasks. Zero overhead when no collectors are configured.

## License

MIT OR Apache-2.0
