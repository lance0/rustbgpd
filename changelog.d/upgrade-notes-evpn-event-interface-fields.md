### Upgrade notes

- Update strict ProtoJSON event consumers to accept `peerInterface` and
  `previousPeerInterface` on `EvpnRouteEvent`. These additive fields (protobuf
  numbers 11 and 12) identify the current and previous neighbor's interface.
  Binary protobuf clients remain wire-compatible; ProtoJSON decoders that
  reject unknown fields need updated bindings or unknown-field handling.
