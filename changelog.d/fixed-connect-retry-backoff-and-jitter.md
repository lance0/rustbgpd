### Fixed

- Unanswered dials and peer TCP drops now back off. A dial that gets no answer
  (SYNs dropped, no RST) doubles the ConnectRetry interval from
  `connect_retry_secs` on each miss, up to 300 s, instead of redialing at the
  base interval forever. A peer that drops TCP without a NOTIFICATION in
  OpenConfirm or Established joins the reconnect streak that NOTIFICATION
  teardowns use, with the same 300 s cap and the same reset after five
  minutes Established. The ConnectRetry timer and the Idle reconnect wait are
  now jittered to 75–100% of their value each time they are set, as RFC 4271
  §10 recommends, so peers no longer retry in lockstep after a shared outage.
  See [RFC notes](../docs/reference/rfc-notes.md).
  **Operator-visible:** `Reconnect In` and `reconnect_in_seconds` can read up
  to 25% below the doubled wait, and repeated peer TCP drops can now hold
  inbound connections and count as
  `bgp_inbound_connections_dropped_total{reason="notification_backoff"}`.
