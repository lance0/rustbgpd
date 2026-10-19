### Added

- `InjectionService.AddPath` accepts an unspecified next hop (`0.0.0.0` or
  `::`) as next-hop self, resolved per session at export to the session's
  local address (IPv6: the neighbor's `local_ipv6_nexthop`, else the
  session's local IPv6 address) on eBGP, iBGP and route-server-client
  sessions. This is the default next hop of many RTBH controllers. An IPv6
  route with no local IPv6 next hop on a session is refused for that peer
  with the exact-export reason `missing_ipv6_next_hop` instead of being sent
  with `::`, and `[[fib_tables]]` rejects the route with the new reason
  `next_hop_unspecified`. `AddPathResponse.outcome` reports `CREATED`,
  `REPLACED` or `UNCHANGED` against the previous local route, and
  `DeletePathRequest.allow_missing` returns `OK` with outcome `NOT_PRESENT`
  for an absent route, mirroring the FlowSpec controller contract. The
  [API reference](../docs/reference/api.md#unicast-injection-contract)
  documents the contract, restart re-injection and the transports for
  clients without TLS support.
