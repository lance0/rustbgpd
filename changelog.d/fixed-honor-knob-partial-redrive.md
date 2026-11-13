### Fixed

- A SIGHUP with an unchanged config file now retries the EBGP peers that a
  previous `honor_graceful_shutdown` or `honor_blackhole` step left behind.
  Fixing the cause and sending SIGHUP again (or running `rbgp reload`) is
  enough: the step runs again with the unchanged knob value, retargets only
  the peers whose installed chains differ or that still owe a Route Refresh,
  and is receipted applied once they acknowledge. A peer that still fails is
  named again in a `known_partial` receipt. Previously only a
  generation-route reload, a knob change or a restart retried them. See
  [Honor-knob partial apply](../docs/reference/reload-matrix.md#honor-knob-partial-apply).
