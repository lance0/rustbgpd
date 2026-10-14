### Fixed

- Re-announce unicast routes when an unchanged export policy switches between
  `set_next_hop = "self"` and the received next hop while removing the attributes
  that selected that action. Private and grouped peers, including per-client-best
  winner promotion, now retain the admitted action through refused sends and
  regroup recovery. Actions that produce identical bytes for the peer do not
  cause an extra announcement.
- Grouped unicast export explain returns `FAILED_PRECONDITION` while a dirty
  peer has no admitted baseline, instead of reporting a refused next-hop
  action as already advertised. Retry after its resync completes.
