### Upgrade notes

- Bare IPv6 link-local neighbor selectors stop working: a gRPC client that
  sends `fe80::1` as a neighbor address now gets `INVALID_ARGUMENT` and must
  send `fe80::1%eth0` or the structured address and interface. Numbered
  neighbors are unaffected. Page tokens from an earlier daemon expire on
  restart as before.
- New `peer_interface` response fields are additive. Binary protobuf clients
  ignore them; strict ProtoJSON consumers that reject unknown fields must be
  updated before they read responses from this release.
