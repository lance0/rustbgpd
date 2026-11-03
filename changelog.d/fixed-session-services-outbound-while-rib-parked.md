### Fixed

- A session whose inbound UPDATEs are held by a full RIB ingest channel
  keeps draining routes to its peer, enforces its hold timer and acts on
  shutdown at once. Before, the whole session task waited for the RIB, so a
  saturated RIB stopped outbound delivery for every peer, filling each
  per-peer outbound queue, and delayed a closing session's Cease. Inbound
  backpressure is unchanged: the session still stops reading its socket
  until the RIB accepts the held batch, and delivers its messages in order
  ([ADR-0078](../docs/adr/0078-inbound-rib-backpressure.md)).
  **Operator-visible:** a session whose RIB admission stays blocked for
  about three hold times is now closed with Cease/Out of Resources (6/8) as
  a local overload. Within one wait the first hold expiry is deferred, and
  the second only for newly read bytes, so
  `bgp_hold_timer_rearmed_pending_input_total` can rise while the RIB is
  saturated. `bgp_inbound_rib_backpressure_total` now counts park episodes:
  a route batch held behind a full channel, not every batch that queues
  behind it.
