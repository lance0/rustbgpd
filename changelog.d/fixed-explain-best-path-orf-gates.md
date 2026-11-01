### Fixed

- A peer-scoped `ExplainBestPath` (`rbgp rib --prefix P --explain
  --explain-peer PEER` on an Add-Path peer) now applies the peer's
  Address-Prefix ORF filter, the RFC 5291 §6 initial refresh gate, RFC 9234
  OTC egress and the outbound prefix limit, as live staging does. Candidates
  those gates withhold used to be reported with non-zero
  `advertised_path_id`s. The IDs are the next staging decision: an ORF filter
  pushed with DEFER takes effect at the prefix's next change or the next
  ROUTE-REFRESH.
