### Fixed

- A session whose inbound UPDATEs are held by a full RIB ingest channel
  keeps draining routes to its peer, enforces its hold timer and acts on
  shutdown at once. Before, the whole session task waited for the RIB, so a
  saturated RIB stopped outbound delivery for every peer, filling each
  per-peer outbound queue, and delayed a closing session's Cease. Inbound
  backpressure is unchanged: the session still stops reading its socket
  until the RIB accepts the held batch, and delivers its messages in order
  ([ADR-0078](../docs/adr/0078-inbound-rib-backpressure.md)).
  **Operator-visible:** `bgp_hold_timer_rearmed_pending_input_total` can now
  rise while the RIB is saturated, and a peer that sends nothing for the
  hold time is expired even while its session is waiting on the RIB.
