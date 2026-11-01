### Fixed

- `bgp_unnumbered_ra_conflicts_total` is now exact however far the peer
  manager falls behind Router Advertisement discovery. A foreign router's
  first binding beside an Established peer learned from an inbound
  connection was counted by the peer manager from the binding change, which
  the coalesced discovery queue could replace before delivery. Discovery now
  learns the Established peer's address and raises that conflict itself. An
  RA from the Established peer's own address is no longer counted as a
  conflict while a foreign router holds the binding.
