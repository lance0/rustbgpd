### Fixed

- A route carried in `MP_REACH_NLRI` no longer has a classic `NEXT_HOP`
  attribute next to it in eBGP exports of IPv6 unicast routes, BMP Loc-RIB VPN
  announcements or MRT EVPN RIB entries (RFC 4760 §3). An import policy that
  set a specific IPv4 next hop added that attribute to IPv6 unicast, VPN and
  EVPN routes. Locally originated EVPN routes stored one too, as `0.0.0.0`
  for an IPv6 VTEP. The next hop is now encoded only in `MP_REACH_NLRI`.
  **Operator-visible:** `InjectionService.AddPath` rejects an IPv6 prefix
  with an IPv4 `next_hop` with `INVALID_ARGUMENT`. IPv6 unicast
  `MP_REACH_NLRI` has no encoding for an IPv4 next hop. An IPv4 prefix with an
  IPv6 next hop (RFC 8950) is still accepted.
