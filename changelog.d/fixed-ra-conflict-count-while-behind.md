### Fixed

- `bgp_unnumbered_ra_conflicts_total` no longer depends on how far the peer
  manager falls behind Router Advertisement discovery. A foreign router's
  first binding beside an Established peer learned from an inbound
  connection was counted by the peer manager from the binding change, which
  the coalesced discovery queue could replace before delivery. Discovery now
  learns the Established peer's address and counts each router once: when a
  conflict first names it, or, for one whose RA arrived before discovery
  learned of the peer, when it does. Only a foreign router that was
  discovery's first binding can go uncounted: one that expired before
  discovery learned of the peer with no conflict naming it, or one named
  only beside another foreign router, which that conflict counted instead.
  Once discovery knows the peer, an RA from the peer's own address is not a
  conflict. Before that, the peer's RA beside a foreign binding still
  raises one, and that conflict counts the foreign router.
