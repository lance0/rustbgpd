### Fixed

- Bound the actor stall when one receiver's advertised EVPN or labeled-unicast
  table grows past about 115k routes. The table now splits into shards instead
  of rehashing every route inside one insert. The worst single insert at 1M
  routes falls from about 190 ms to about 26 ms. Smaller tables keep their
  previous layout and memory use.
