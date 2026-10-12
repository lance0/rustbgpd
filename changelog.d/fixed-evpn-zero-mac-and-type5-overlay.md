### Fixed

- An EVPN Type 2 route with MAC Address Length 0 no longer resets the
  session. RFC 9135 §9.1.1 makes it treat-as-withdraw: its UPDATE withdraws
  its other routes, and the route itself is dropped. Because the MAC Address
  Length is part of the route key (RFC 7432 §7.2), it never removes the
  peer's 48-bit route for the same MAC, in an announcement or a withdrawal,
  and it is never reflected. A Type 5 route announced with both a non-zero
  ESI and a non-zero gateway IP is now treat-as-withdraw (RFC 9136 §3.2)
  instead of being accepted and reflected. An `MP_UNREACH_NLRI` whose EVPN
  routes were all dropped, including unsupported route types, is no longer
  mistaken for End-of-RIB.
  **Operator-visible:** both cases count as
  `bgp_update_malformed_total{disposition="treat_as_withdraw"}` when
  announced; the session stays up.
