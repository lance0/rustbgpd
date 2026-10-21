### Upgrade notes

- Bare IPv6 link-local neighbor selectors stop working: a gRPC client that
  sends `fe80::1` as a neighbor address now gets `INVALID_ARGUMENT` and must
  send `fe80::1%eth0` or the structured address and interface. Numbered
  neighbors are unaffected. Page tokens from an earlier daemon expire on
  restart as before.
- New `peer_interface` response fields are additive. Binary protobuf clients
  ignore them; strict ProtoJSON consumers that reject unknown fields must be
  updated before they read responses from this release.
- Session, notification and policy events (`WatchEvents`,
  `ListSessionEvents`, `ListPolicyEvents`) now carry a scoped neighbor's bare
  address in `peer_address`, on the payload and the `BgpEvent` envelope, with
  its interface in the payload's new `peer_interface`. They used to put
  `address%interface` in `peer_address`; a consumer matching that string must
  join the two fields instead. `rbgp` output is unchanged.
- gNMI `Get` and `Subscribe` paths key an IPv6 link-local neighbor as
  `neighbor-address=fe80::1%eth0`, and render that key and the
  `state/neighbor-address` leaf in the same scoped form. A bare link-local
  key is now `INVALID_ARGUMENT`; numbered neighbors are unchanged.
