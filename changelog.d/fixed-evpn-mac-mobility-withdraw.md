### Fixed

- An EVPN VTEP now withdraws its Type 2 route when another segment
  advertises the same MAC with a higher MAC Mobility sequence, or with an
  equal sequence from a lower PE IP (RFC 7432 §15). It used to raise its
  own sequence above every such route, so two VTEPs advertising one MAC
  raised each other's sequence on every UPDATE exchange and peers
  reinstalled the MAC on each one. The sequence now rises only when the
  MAC is learned on a local port. A withdrawn MAC that is still local is
  advertised again once the contender is gone. See
  [operations](../docs/reference/operations.md).
