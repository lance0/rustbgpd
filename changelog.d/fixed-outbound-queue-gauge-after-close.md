### Fixed

- `bgp_peer_outbound_queue_depth` now returns to 0 when a peer's connection
  closes, including after the Cease/Out of Resources teardown or an aborted
  write. It previously kept the last backlog sample, and an administratively
  stopped peer could show a queue that no longer existed.
