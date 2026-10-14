### Fixed

- `rbgp doctor` now checks the `peer.<address>.inbound_prefix_bound` warning
  per negotiated family. A bound on one family no longer satisfies the check
  for another, so an eBGP peer with only an IPv4 bound that also negotiates
  IPv6, or only a VPN bound that also negotiates unicast, now warns. The
  aggregate `max_prefixes` still covers every family. The detail names each
  unbounded family and the keys that would bound it; see the
  [doctor reference](../docs/reference/operations.md).
  **Operator-visible:** peers that passed with a partial bound turn yellow;
  the check name and the advisory exit status 0 are unchanged.
