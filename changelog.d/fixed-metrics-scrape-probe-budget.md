### Fixed

- A slow or stuck `/metrics` render can no longer keep the telemetry listener
  from answering `/livez` and `/readyz`. Scrapes queued behind one render could
  previously occupy all 64 listener connections and wait without a deadline.
  Now at most 56 scrapes wait on a render, a scrape over that cap is rejected
  at once, and a caller's wait is bounded at 5 s; the render itself is not
  cancelled and holds its slot until it finishes.
  **Operator-visible:** `/metrics` returns `503` when 56 scrapes are already
  waiting or the 5 s wait expires, and `GetMetrics` returns
  `DEADLINE_EXCEEDED` when that wait expires. See
  [HTTP probes](../docs/reference/operations.md#http-probes).
