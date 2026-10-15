### Fixed

- Service dedicated RIB readiness queries during OLD-state recovery capture
  triggered by normal route ingestion. **Operator-visible:** core readiness
  progresses through the existing capture checkpoints while ordinary queries
  and mutations remain queued, using the existing readiness deadline.
