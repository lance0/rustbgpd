### Fixed

- A SIGHUP that changes `honor_graceful_shutdown` or `honor_blackhole` and
  leaves some EBGP peers behind now settles as `known_partial` instead of
  `complete`. A peer is left behind when its chains could not be resolved,
  its session did not acknowledge the new chains, or it took them but still
  owes the Route Refresh that re-evaluates its `Adj-RIB-In` (a rejected
  refresh or an unanswered session state query). `rbgp config last-reload`
  and `GetLastSighupReload` name each such peer under the
  `honor_graceful_shutdown.apply` or `honor_blackhole.apply` bucket, and
  `rbgp doctor` warns on the partial reload. The knob is still installed
  and the rest of the reload still applies. A no-op SIGHUP does not retry
  those peers; see
  [Honor-knob partial apply](../docs/reference/reload-matrix.md#honor-knob-partial-apply)
  for the triggers that do.
