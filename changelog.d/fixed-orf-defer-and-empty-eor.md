### Fixed

- An Address-Prefix ORF update with When-to-refresh `DEFER` no longer lifts
  the RFC 5291 §6 initial-advertisement gate. Only a plain ROUTE-REFRESH or an
  `IMMEDIATE` ORF opens a gated family, so selection release and outbound
  churn no longer send a table the peer has not asked for.
- A family withheld from an ORF peer now gets its empty End-of-RIB at
  selection release instead of waiting for that family's ROUTE-REFRESH. When
  a withheld ORF-gated family becomes sendable on a fresh non-GR peer, the
  empty End-of-RIB queued at session start is the only initial marker, however
  full the outbound queue was; the table follows the peer's refresh.
