### Fixed

- Remove a peer's `bgp_peer_update_group` sample when its outbound session
  registration ends, including peer-down and graceful-restart teardown.
  Departed peers no longer report a stale update-group id in metrics.
