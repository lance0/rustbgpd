### Fixed

- Service dedicated RIB readiness queries at the existing checkpoints inside
  timer-driven dirty-route recovery. **Operator-visible:** core readiness can
  progress during a recovering peer's full-table replay using the existing
  readiness deadline.
