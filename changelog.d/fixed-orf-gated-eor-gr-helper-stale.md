### Fixed

- Hold an Address Prefix ORF family's initial End-of-RIB behind its gated
  table toward a peer whose previous session advertised Graceful Restart, so
  it does not delete the routes it kept stale from that session before the
  peer's ROUTE-REFRESH brings them back. Previously the End-of-RIB went out at
  once and the peer dropped every stale route of the family, RTBH routes
  included, until the filtered table arrived. Peers that are neither GR
  restarters nor possible stale-route holders keep immediate End-of-RIB
  unless another hold applies.
  **Operator-visible:** every End-of-RIB held for an ORF-gated table now has
  a 60-second ORF hold cap. At that cap, a family for which no plain
  ROUTE-REFRESH or IMMEDIATE ORF request has arrived releases its marker to
  the ordinary pending queue. Selection deferral or replay grace may still
  hold it. A family whose table refresh is already queued keeps its marker
  behind that refresh's table, even past the cap.
  Queued updates and pending resynchronization can delay transmission after
  every hold ends, so the cap is not a deadline for End-of-RIB delivery or
  remote stale-route removal. See the
  [GR-helper RTBH limitation](../docs/reference/known-issues.md#open-issues).
