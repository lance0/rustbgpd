### Added

- The reloadstall flapstorm harness takes `--flap-rounds N` (default 3) and,
  with `RELOADSTALL_HEAP_METRICS_ADDR`, logs the daemon's jemalloc allocated,
  active, resident and mapped bytes after each round. The IXP matrix
  (`FLAP_ROUNDS`) and headline campaign (`MATRIX_FLAP_ROUNDS`) pass the
  round count through, and the headline summary extracts the heap values.
