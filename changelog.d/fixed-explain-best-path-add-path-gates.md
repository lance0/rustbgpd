### Fixed

- A peer-scoped `ExplainBestPath` (`rbgp rib --prefix P --explain
  --explain-peer PEER` on an Add-Path peer) now applies the same route-server
  control community, LLGR-stale and conditional-advertisement gates as live
  staging. A candidate one of those gates kept off the wire used to be
  reported with a non-zero `advertised_path_id`, as if the peer received it.
