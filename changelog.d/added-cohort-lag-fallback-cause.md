### Added

- `bgp_rib_paced_fallback_total` has a new `cause` value, `cohort_lag`: a
  joiner fell 64 pages behind the Loc-RIB scan it shares with the other
  joiners of its update group, because its writer stayed full while theirs
  drained, and left that scan. It normally rescans on its own in pages and
  is not counted; the cause counts for the `initial_replay` job when it
  cannot. See the
  [paced-job fallbacks](../docs/reference/operations.md#paced-job-fallbacks)
  reference. **Operator-visible:** a dashboard or alert that lists `cause`
  values needs the new one.
