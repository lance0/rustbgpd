### Fixed

- A slow or stuck `/metrics` render can no longer stop the telemetry listener
  from answering `/livez` and `/readyz`. Scrapes queued behind one render could
  previously occupy all 64 listener connections and wait without a deadline.
  Now at most 56 scrapes are in flight, which always leaves room for probes.
  Waiting for and running a render is bounded at 5 s.
  **Operator-visible:** `/metrics` returns `503` when 56 scrapes are already in
  flight or the render deadline passes, and `GetMetrics` returns
  `DEADLINE_EXCEEDED` past that deadline. See
  [HTTP probes](../docs/reference/operations.md#http-probes).
