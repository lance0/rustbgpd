### Added

- `rbgp config last-reload`, its `--json` output and `GetLastSighupReload`
  now report the RIB-side outbound convergence of a `complete` SIGHUP
  reload: `converging` with the number of peers whose RIB outbound resync is
  still pending and the oldest one's age, `converged` once none is pending,
  or `applied` when the RIB has not answered within two seconds. `converged`
  does not confirm that peers received the view; transport processing and
  socket writes may still be pending. The counts come from the RIB's
  outbound-dirty set, the state behind `bgp_rib_outbound_dirty_peers`.
  `rbgp doctor` warns when a complete reload is still converging after 60
  seconds. The reload acknowledgement itself is unchanged. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
