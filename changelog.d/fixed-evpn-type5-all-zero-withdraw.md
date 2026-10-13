### Fixed

- An EVPN Type 5 route announced with a zero ESI, a zero gateway IP, a zero
  label and no Router's MAC Extended Community is now treat-as-withdraw
  (RFC 9136 §3.2) instead of being accepted and reflected. A Router's MAC
  community carrying an all-zero MAC counts as absent. The same route with a
  non-zero Router's MAC, or with any non-zero label or VNI, is still
  accepted. As with the other EVPN treat-as-withdraw rules, the whole
  UPDATE's routes are withdrawn and the session stays up.
  **Operator-visible:** such an UPDATE counts as
  `bgp_update_malformed_total{disposition="treat_as_withdraw"}`.
