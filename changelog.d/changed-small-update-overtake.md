### Changed

- The RIB admits a small unicast UPDATE (at most 16 routes) ahead of other
  sessions' queued session-down, session-up and table messages, so an
  unrelated peer's change no longer waits for a flap's whole fan-out. With
  700 route-server clients and 50 of them flapping at once, such an UPDATE
  waited behind every queued session end or member table: 7 key pages behind
  8 session ends and 31 behind 32 in the work-count test, now 1 behind 8, 32
  or 50. A session's own messages keep their order, as do all messages for
  one prefix; End-of-RIB, refresh, ORF updates, policy changes, injected
  routes, queries, a draining expiry timer and a first-group build keep
  strict arrival order for everything behind them. The queue also keeps
  strict arrival order throughout while a conditional advertisement is
  defined or any outbound prefix limit is configured. See
  [RIB lifecycle](../docs/reference/rib-lifecycle.md#overview).
  **Operator-visible:** `bgp_rib_inbound_overtake_total{seam}` counts these
  admissions by seam (`departure`, `drain`, `receive`), and
  `bgp_rib_ingest_channel_depth` can now read up to 1,024 above the channel
  capacity, because it includes the messages read ahead.
