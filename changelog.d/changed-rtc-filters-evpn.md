### Changed

- RT-Constrain (RFC 4684) membership now filters EVPN export as well as
  VPNv4/VPNv6. A peer that negotiated both RT-Constrain and L2VPN EVPN
  receives only the EVPN routes whose Route Targets fall inside its
  advertised membership (RFC 7432 §7.10); Type 4 Ethernet Segment routes
  match on their ES-Import Route Target (RFC 7432 §7.6). A membership
  change announces or withdraws the affected EVPN routes without a session
  reset, and `rbgp evpn explain` reports the `rt_membership` gate. Peers
  that did not negotiate RT-Constrain stay unfiltered, and there is no new
  configuration.
  **Operator-visible:** a reflector client that negotiates RT-Constrain and
  EVPN now receives no EVPN routes until it advertises RT membership, and
  then only the tenants it asked for; the default (zero-length) membership
  restores the unfiltered feed. Before this change, such a peer received
  every EVPN route the export policy permitted.
