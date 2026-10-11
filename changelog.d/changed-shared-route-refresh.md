### Changed

- Compatible, already queued unicast route-refresh requests share one bounded
  replay inventory and announcement encoding. Each peer retains its own source
  exclusion, export checks, prefix limits, refresh markers and retry state.
  In the measured 200-peer IPv4 route-reflector shape with 400,000 prefixes,
  50 concurrent refreshes completed in 0.257–0.295 s instead of 10.469–11.019 s;
  round-end daemon RSS was 3–19 MiB higher in matched rounds. See the
  [dated A/B receipt](../docs/perf/shared-route-refresh-2026-10-11.md) for scope.
