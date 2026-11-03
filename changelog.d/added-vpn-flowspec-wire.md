### Added

- The `l3vpn_ipv4_flowspec` family (IPv4 VPN FlowSpec, AFI 1 / SAFI 134,
  RFC 8955 §8) can be listed in `families` and `required_families`. It is
  advertised in OPEN only when configured and never with Add-Path. This first
  slice of [ADR-0146](../docs/adr/0146-vpn-flowspec.md) adds the wire codec
  and negotiation only: received VPN FlowSpec rules are decoded, then
  discarded before the Adj-RIB-In and counted in
  `bgp_vpn_flowspec_nlri_discarded_total{peer}`. They are never stored,
  reflected or validated, and the daemon never sends a ROUTE-REFRESH for the
  family. Originating VPN FlowSpec rules needs later slices; IPv6 VPN
  FlowSpec (AFI 2 / SAFI 134) stays unsupported.
- `rustbgpd-wire` 0.28.0 adds `Safi::FlowSpecVpn`, the `VpnFlowSpecRule`
  NLRI type with `decode_vpn_flowspec_nlri` and
  `try_encode_vpn_flowspec_nlri`, and the `vpn_flowspec_announced` and
  `vpn_flowspec_withdrawn` fields on `MpReachNlri` and `MpUnreachNlri`, a
  breaking change for code that builds those structs. `rustbgpd-fsm` 0.15.0
  and `rustbgpd-rpki` 0.10.0 move to the new wire line. These crate versions
  are prepared, not published.
