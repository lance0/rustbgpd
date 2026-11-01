### Fixed

- `rbgp --help` and `rbgp doctor --help` now describe exit code `0` as "no
  red checks": a run with yellow warnings but no red check also exits `0`, as
  the [operations reference](../docs/reference/operations.md) already stated.
  The exit codes themselves are unchanged.
