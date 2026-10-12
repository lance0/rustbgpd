### Fixed

- An EVPN Type 1 Ethernet A-D route with an all-zero ESI no longer resets the
  session. A single-homed VPWS per-EVI route carries ESI 0 (RFC 8214 §4), so a
  reflector now accepts and reflects it unchanged; the per-ES form is accepted
  too. A Type 4 Ethernet Segment route with an all-zero ESI names no
  multihomed segment (RFC 7432 §8.1.1) and is now handled as RFC 7606
  treat-as-withdraw for its UPDATE instead of a session reset.
  **Operator-visible:** a VPWS PE advertising single-homed services no longer
  flaps its route-reflector session and every family on it; a zero-ESI Type 4
  counts as `bgp_update_malformed_total{disposition="treat_as_withdraw"}`.
