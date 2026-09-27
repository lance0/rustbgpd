### Fixed

- Resolve EVPN ties independently of RIB iteration order. When one remote PE
  advertises an Ethernet Segment under several route distinguishers with
  different DF Election parameters, the route with the lowest RD now supplies
  that PE's DF candidate. Remote MAC and MAC/IP routes from the same VTEP at
  the same mobility sequence now resolve by RD, then ESI, Ethernet Tag, host
  IP and label. Previously the winner, and with it the elected DF, aliasing
  group, sticky bit and ESI, depended on hash-map order.
