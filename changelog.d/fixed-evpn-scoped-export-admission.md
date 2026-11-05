### Fixed

- EVPN export attribute sharing now distinguishes unnumbered receivers that
  use the same link-local address on different interfaces. Equal policy
  outcomes from single-route updates share one allocation across those peers;
  repeated processing of one receiver still leaves its unique outcome uninterned.
