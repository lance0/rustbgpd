### Fixed

- A peer that stops reading no longer lets its session's outbound writer
  queue gigabytes of encoded UPDATEs. Each session's writer now holds at most
  about 640 KiB of unwritten bytes; at that budget the session stops taking
  outbound work from the RIB and resumes as the peer reads, so the RIB's
  outbound row credit bounds what waits behind it. Reaching the budget never
  tears the session down; a peer that stops reading altogether is still
  closed by the RFC 9687 send hold timer.
  **Operator-visible:** new gauges `bgp_peer_outbound_writer_bytes{peer}`,
  `bgp_outbound_writer_bytes`, `bgp_rib_outbound_credit_rows` and
  `bgp_rib_outbound_operations_live`, and
  `bgp_outbound_commit_refusals_total` is exported at zero for every
  registered peer (see the
  [operations reference](../docs/reference/operations.md)).
