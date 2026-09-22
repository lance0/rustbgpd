### Changed

- Log events name a BGP peer's address in one event field, `peer`. Events
  from the peer manager, reload and the TCP listener used three other names,
  which are renamed: `address` to `peer` (peer-manager lifecycle and policy
  events, and the reload `neighbor added`, `neighbor changed`,
  `neighbor removed` and `neighbor hot-applied in place` events), `peer_addr` to `peer` (peer-manager inbound
  connections, session notifications and dynamic-peer dead-lettering), and
  `peer_ip` to `peer` (inbound connection admission and the listener's
  `inbound TCP connection` event). Peer-manager events that logged a peer as
  `addr` (graceful-shutdown toggles, export-knob refresh and daemon-shutdown
  teardown) also use `peer`. The session span field `peer_addr` is unchanged.
  **Operator-visible:** a log pipeline or alert that selects on the old
  field names must select on `peer`. Two events that are not about a BGP
  peer move off peer-like names: the gRPC `grpc_tls_client_certificate`
  and `grpc_tls_client_certificate_expiry` events rename `peer_addr` to
  `client`, and the metrics endpoint's `metrics connection error` event
  renames `peer` to `client`. The `adding peer from config` and
  shutdown-time `rejecting inbound BGP connection` events now log `peer` as
  the bare address instead of `address:port`.
- Smaller log-format changes that follow the same convention: `esi` fields
  now use the `01:02:…` text form everywhere, instead of a Debug byte array
  or struct in EVPN segment, projection and dataplane-reconcile events; VRF
  route `prefix` fields in dataplane-reconcile events and the blackhole
  kernel-drift event use the prefix text form instead of Debug output;
  dataplane-reconcile errors are logged as `error` instead of `e`; and the
  two startup policy-resolution failures log the error as an `error` field
  instead of in the message. Events from a BGP session's connect path and
  socket writer now carry the session's `peer` span, so the per-peer
  `RUST_LOG` span filter and `log_level` also select them.
