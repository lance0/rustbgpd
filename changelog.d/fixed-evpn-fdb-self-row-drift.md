### Fixed

- The EVPN dataplane now restores a remote-MAC VXLAN self row that is
  deleted out of band while its bridge master row stays. Previously the
  reconciler treated a row with no destination as matching the route,
  so unicast frames to that MAC fell back to the VXLAN port's flood
  entries, if it had any, until the route changed.
  **Operator-visible:** a `bridge fdb replace … self dst …` written
  without `extern_learn` over a rustbgpd-owned row is now treated as an
  operator takeover, as an unmarked static master row already was.
  rustbgpd relinquishes the row, counts it in the foreign-state counters,
  and leaves it in place on withdrawal and shutdown instead of rewriting
  it.
