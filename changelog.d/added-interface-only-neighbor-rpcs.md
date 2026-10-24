### Added

- `AddNeighbor` and `DeleteNeighbor` add and delete interface-only neighbors
  at runtime. An empty `address` with an `interface` names the neighbor, and
  `remote_asn_mode` `EXTERNAL`/`INTERNAL` is carried on the add. A
  `SetPeerGroup` edit that changes an interface-only member's session
  settings rebinds that member instead of being refused. See
  [interface-only neighbors](../docs/reference/api.md#interface-only-neighbors).
  **Operator-visible:** the first interface-only neighbor added without
  `CAP_NET_RAW` or the link monitor, and a static link-local add whose
  address a learned endpoint holds, return `FAILED_PRECONDITION` with nothing
  changed. Deleting an interface-only neighbor's bound peer by address now
  returns `FAILED_PRECONDITION` naming the interface selector, instead of
  asking for a restart.
