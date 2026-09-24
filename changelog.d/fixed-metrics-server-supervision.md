### Fixed

- The metrics/readiness HTTP server is now supervised like the gRPC and BGP
  listeners. Previously, if its task ended after startup (for example when
  its listening socket became unusable), the daemon kept running with no
  `/metrics`, `/readyz` or `/livez` and logged only one ERROR line.
  **Operator-visible:** such an exit now logs `metrics/readiness server exited
  unexpectedly`, runs the coordinated peer teardown and exits 1, so
  `Restart=on-failure` restarts the daemon. A daemon without `prometheus_addr`
  is unchanged.
