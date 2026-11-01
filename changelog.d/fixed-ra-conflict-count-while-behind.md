### Fixed

- `bgp_unnumbered_ra_conflicts_total` no longer depends on how far the peer
  manager falls behind Router Advertisement discovery. A foreign router's
  first binding beside an Established peer learned from an inbound
  connection was counted by the peer manager from the binding change, which
  the coalesced discovery queue could replace before delivery. Discovery now
  learns the Established peer's address and counts each other live source
  once, including one whose RA arrived before it learned of the peer. A
  foreign router whose RA arrives and expires before discovery learns of the
  Established peer is not counted. An RA from the Established peer's own
  address is no longer counted as a conflict while a foreign router holds
  the binding.
