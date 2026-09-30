### Changed

- `GetHealth` now fails with `UNAVAILABLE` instead of `INTERNAL` when the
  peer manager or the RIB misses the 200 ms core-probe deadline. A closed
  actor channel, a dropped reply, a stalled transition and daemon-wide faults
  still return `INTERNAL`. `rbgp doctor` retries `GetHealth` once, after one
  second, on `UNAVAILABLE`: a healthy retry reports `daemon.healthy` as a
  warning that names the first miss, and a second miss is still a failure.
  A single probe miss while a reload settles therefore no longer fails
  doctor with exit 2. See the
  [health check](../docs/reference/api.md#health-check) reference.
  **Operator-visible:** `rbgp health` reports such a miss as `temporarily
  unavailable: ...` rather than `daemon error: ...`; its exit status is
  unchanged. Clients that treat `INTERNAL` from `GetHealth` as the only
  failure code should also handle `UNAVAILABLE`.
