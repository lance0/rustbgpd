### Changed

- Every gRPC request field that selects a neighbor by address now requires
  the scope of an IPv6 link-local address, as `fe80::1%eth0` or as the bare
  address plus the request's interface field. A bare link-local selector
  returns `INVALID_ARGUMENT` naming the scoped neighbors configured on that
  address, even when only one neighbor uses it; a scope on a numbered address
  is also `INVALID_ARGUMENT`. The scope is part of page-token identity.
  Numbered selectors are unchanged. RFC 4007 permits a default zone; rustbgpd
  deliberately requires the scope so a selector keeps its meaning when another
  neighbor shares the address.
  **Operator-visible:** `rbgp` sends link-local neighbors in scoped form, and
  prints the scoped form from the daemon's interface fields in every unicast
  route view, explanation and route-event view, including the unscoped
  best-route listing and history.
