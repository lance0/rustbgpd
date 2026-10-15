### Fixed

- Clearing a peer's outbound state now fences advertised-view page tokens for
  every family with committed rows, not only EVPN. A continuation therefore
  returns `ABORTED` instead of an empty final page.
- The whole-graph ORR topology reads built without configured vantages now
  exclude BGP-LS families whose selection is still deferred, matching the
  topology that vantages use.
