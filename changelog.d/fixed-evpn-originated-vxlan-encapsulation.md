### Fixed

- EVPN routes the VTEP originates from `[[evpn_instances]]` and
  `[[ethernet_segments]]` now carry the BGP Encapsulation extended community
  for VXLAN (tunnel type 8), as
  [RFC 8365 §5.1.3](https://www.rfc-editor.org/rfc/rfc8365.html#section-5.1.3)
  requires. This covers Type 2 MAC and MAC+IP routes (including SVI MACs),
  Type 3 IMET, Type 1 EAD-per-ES and EAD-per-EVI, and Type 4 ES routes, for
  VLAN-based instances and VLAN-aware bundle members alike. Previously only
  native Type 5 origination and `InjectionService/AddEvpnRoute` attached it.
  **Operator-visible:** peers that require a matching encapsulation before
  installing a route now accept these routes, and `rbgp evpn` shows
  `encap=vxlan` on them.
