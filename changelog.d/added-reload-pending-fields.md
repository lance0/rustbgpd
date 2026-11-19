### Added

- Config diffs and SIGHUP errors name individual restart-required RPKI, BMP
  and MRT fields. Credential values, free-form BMP text and MRT paths are
  redacted. `rbgp config last-reload` and the `GetLastSighupReload` RPC
  list the fields observed to require a restart. The versioned CLI JSON
  envelope advances to `rbgp-json/1.5`.
