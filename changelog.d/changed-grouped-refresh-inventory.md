### Changed

- A ROUTE-REFRESH response to an update-group member no longer walks the
  Loc-RIB and every Adj-RIB-In to build a prefix inventory before replaying
  the group table. Like a grouped join, it scopes that inventory to the
  group's recorded residue and the peer's own residue, which is all a grouped
  replay consults. A refresh for a family other than IPv4 or IPv6 unicast no
  longer builds the unicast inventory at all. The response's routes,
  End-of-RIB, BoRR/EoRR markers and `PolicyFiltered` events are unchanged.
