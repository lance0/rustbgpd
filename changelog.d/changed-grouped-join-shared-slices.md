### Changed

- Grouped initial unicast dumps now clone routes directly into their final
  shared announcement slices after filtering borrowed group entries. This
  avoids a temporary vector of route shells and its full copy during peer
  rejoin, while preserving source exclusion, route-server control rewrites,
  next-hop overrides, and exact-export admission.
