### Fixed

- A slow RIB no longer stops the daemon in these steps:
  publishing route-flap dampening owners after a SIGHUP reload, config
  transaction or neighbor change; a hot update that changes a neighbor's
  export policy chain or confirms an IPv6 unlock, including a peer-group
  edit that hot-applies to its members. Each step gave the RIB five
  seconds, both to accept the request into a busy queue and to answer it.
  After that it fenced `known_divergence` or `acknowledgement_lost` and
  exited 70, although the RIB was still working and nothing could be
  rolled back cleanly. The steps now wait for the RIB, serving readiness
  meanwhile. The wait is bounded by the operation's
  [settlement watchdog](../docs/how-to/settlement-watchdog.md) budget and,
  for API-owned changes, by the existing ten-minute dispatch bound.
