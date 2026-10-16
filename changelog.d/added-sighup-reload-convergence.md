### Added

- `rbgp config last-reload`, its `--json` output and `GetLastSighupReload`
  now report the outbound convergence of a `complete` SIGHUP reload:
  `converging` with the number of peers still awaiting an outbound resync and
  the oldest one's age, `converged` once none remain, or `applied` when the
  RIB has not answered within two seconds. The counts come from the RIB's
  outbound-dirty set, the state behind `bgp_rib_outbound_dirty_peers`.
  `rbgp doctor` warns when a complete reload is still converging after 60
  seconds. The reload acknowledgement itself is unchanged. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
