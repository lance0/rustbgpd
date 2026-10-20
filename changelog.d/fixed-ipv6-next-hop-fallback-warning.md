### Fixed

- An export policy that sets an IPv6 next hop for IPv4 routes toward a peer
  without Extended Next Hop logs one warning per peer per export pass, or one
  per update group (`update_group = true`) when the group shares an encode,
  with the first affected prefix and the route count, instead of one warning
  per route. Exact-export probes no longer log it.
