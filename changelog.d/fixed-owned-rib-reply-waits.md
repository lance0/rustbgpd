### Fixed

- A slow RIB no longer stops the daemon after a SIGHUP reload, config
  transaction or neighbor change that publishes route-flap dampening owners,
  or during a hot update that changes a neighbor's export policy chain or
  confirms an IPv6 unlock, including a peer-group edit that hot-applies to
  its members. These steps waited at most five seconds for the RIB's answer
  and then fenced `known_divergence` or `acknowledgement_lost` and exited 70,
  although the RIB was still completing the work. They now wait for the
  answer, serving readiness meanwhile, bounded by the operation's
  [settlement watchdog](../docs/how-to/settlement-watchdog.md) budget and,
  for API-owned changes, the existing ten-minute dispatch bound.
