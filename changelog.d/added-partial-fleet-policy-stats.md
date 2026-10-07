### Added

- Fleet import policy counters support opt-in partial results during peer churn:
  `GetPolicyStats.allow_partial` and the CLI's `--allow-partial` option retain
  usable import/both rows and identify exited sessions in
  `incomplete_peer_addresses`. Default requests still fail whole; deadlines,
  unavailable counters, stopped owners, export and dataset errors remain errors.
