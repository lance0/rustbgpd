### Fixed

- A peer-scoped `ExplainBestPath` (`rbgp rib --prefix P --explain
  --explain-peer PEER` on an Add-Path peer) now applies the peer's
  Address-Prefix ORF filter and the RFC 5291 §6 initial refresh gate, as
  live staging does. For an ORF-denied prefix, or a family still waiting for
  the peer's first ROUTE-REFRESH, candidates used to be reported with
  non-zero `advertised_path_id`s although the peer was sent none of them.
