### Added

- `bgp_rib_outbound_owed_drain_step_seconds{scope}`: the duration of one
  owed-route drain step toward one receiver on the RIB actor, with `scope`
  `cursor` (IPv4 or IPv6 unicast owed whole), `keyed` (a receiver's owed
  routes) or `whole` (one whole-family pass of another family). Bucket
  edges include 50 ms and 250 ms. See the
  [metric reference](../docs/reference/operations.md).
