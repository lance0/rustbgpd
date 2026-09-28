### Changed

- With RPKI or ASPA configured, the RIB no longer repeats the origin and
  path validation a peer session already ran against the same cache
  snapshot. Each route batch now carries the snapshots its session used,
  and the RIB re-validates only against a table that changed in between,
  so verdicts are unchanged. Cache updates still revalidate stored routes
  as before.
