### Fixed

- A peer that stops reading no longer lets its session's outbound writer
  queue gigabytes of encoded UPDATEs. Once a session's writer holds about
  640 KiB of unwritten bytes, the session stops taking outbound work from the
  RIB and resumes as the peer reads, so the RIB's outbound row credit bounds
  what waits behind it. The writer can exceed the budget by one admission
  step (at most 2,048 UPDATEs). A peer that keeps reading, however slowly, is
  not torn down; one that stops reading altogether is still closed by the
  RFC 9687 send hold timer or, with `send_hold_time = 0`, by the admission
  deadline (Cease/8). Slow-peer detection also counts the writer's unwritten
  bytes, since the byte budget now holds a lagging peer's queue well below
  its frame threshold.
  **Operator-visible:** new gauges `bgp_peer_outbound_writer_bytes{peer}`,
  `bgp_outbound_writer_bytes`, `bgp_rib_outbound_credit_rows` and
  `bgp_rib_outbound_operations_live`, and
  `bgp_outbound_commit_refusals_total` is exported at zero for every
  registered peer (see the
  [operations reference](../docs/reference/operations.md)).
