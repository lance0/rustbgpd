### Added

- Opt-in alpha `/dp-readyz` on the telemetry HTTP listener via
  `[global.telemetry].dataplane_readiness = true`. The separate probe observes
  startup, progress, closure and unavailability of configured FIB and EVPN
  workers without changing core readiness or watchdog behavior. It does not
  promise forwarding or route convergence; see the
  [probe contract](../docs/reference/operations.md#http-probes).
