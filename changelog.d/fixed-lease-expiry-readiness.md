### Fixed

- An injection lease expiry batch now runs under the same readiness ownership
  as a source peer-down, so `/readyz` keeps answering while a large batch of
  expired owners' routes is withdrawn instead of waiting for the batch to
  finish. Its readiness waits record under the `peer_teardown` seam.
