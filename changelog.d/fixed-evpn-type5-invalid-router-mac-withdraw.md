### Fixed

- An EVPN Type 5 route announced with a multicast or broadcast Router's MAC
  (the EVPN Router's MAC Extended Community) is now treat-as-withdraw, as
  RFC 9136 requires, instead of being accepted and reflected. This applies
  whatever the route's ESI, gateway IP and label. A unicast Router's MAC,
  globally or locally administered, is still accepted, and a Type 2 route
  carrying the community is unaffected. As with the other EVPN
  treat-as-withdraw rules, the whole UPDATE's routes are withdrawn and the
  session stays up.
  **Operator-visible:** such an UPDATE counts as
  `bgp_update_malformed_total{disposition="treat_as_withdraw"}`.
