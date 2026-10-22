### Fixed

- Report disabled IPv6, missing or unusable link-local addresses, and unsafe
  RA default-route acceptance on neighbor interfaces at startup, during runtime,
  in `--check`, and in local `rbgp doctor` diagnostics. Plain checks remain
  advisory; `--strict` fails on warnings. Count RA/RS send failures by errno
  class and warn once per interface link generation.
- Keep monitoring running interface-only ports after reload, and avoid local
  namespace probes in doctor when the daemon connection is unavailable.
