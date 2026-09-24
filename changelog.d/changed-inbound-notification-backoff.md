### Changed

- The escalating reconnect wait after consecutive NOTIFICATION teardowns now
  also covers a configured neighbor that reconnects to rustbgpd. Previously
  an inbound connection during the wait was accepted at once and replaced the
  waiting session with a fresh one whose streak started at zero, so a
  neighbor that always dialled in never backed off. From the second
  consecutive NOTIFICATION teardown, an inbound connection during the wait is
  now closed without an OPEN, as RFC 4271 §8.2.2 refuses connections in
  Idle, and a pending collision candidate is dropped instead of promoted. An
  accepted inbound connection or a promoted candidate keeps the replaced
  session's streak. Dynamic neighbors are unchanged.
  **Operator-visible:** such drops are counted as
  `bgp_inbound_connections_dropped_total{reason="notification_backoff"}` and
  logged, at most once per second, with the streak and the remaining wait.
  A neighbor that can only connect inbound re-establishes when the wait ends.
  See the
  [operations guide](../docs/reference/operations.md#debugging-a-session-that-wont-establish).
