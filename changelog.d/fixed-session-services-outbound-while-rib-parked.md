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
  rise while the RIB is saturated. A peer that sends nothing is expired
  within two hold times even while its session waits on the RIB: input
  pending in the read buffer renews the hold time once, and further
  renewals need newly received bytes. `bgp_inbound_rib_backpressure_total`
  now counts park episodes: a route batch held behind a full channel, not
  every batch that queues behind it.
