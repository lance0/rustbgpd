### Fixed

- A SIGHUP that changes `honor_graceful_shutdown` or `honor_blackhole` and
  leaves some EBGP peers on their prior import and export chains now settles
  as `known_partial` instead of `complete`. Such peers can remain after a
  session-side policy update timeout, a failed Route Refresh, an RFC 8212
  qualification failure or an unresolvable chain. `rbgp config last-reload`
  and `GetLastSighupReload` name each such peer under the
  `honor_graceful_shutdown.apply` or `honor_blackhole.apply` bucket, and
  `rbgp doctor` warns on the partial reload. The knob
  is still installed and the rest of the reload still applies. Those peers
  are retargeted by the next reload that takes the generation route, by
  reverting and re-setting the knob, or by a restart; see
  [Honor-knob partial apply](../docs/reference/reload-matrix.md#honor-knob-partial-apply).
