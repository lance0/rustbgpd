### Fixed

- Bound temporary export-policy rejection inventories by candidate identities
  during initial export, refresh, incremental distribution and policy replay.
  Dedicated RIB readiness queries can run between candidate transfers, set
  rebuilds and cleanup while route counts and rejected-path events stay exact.
