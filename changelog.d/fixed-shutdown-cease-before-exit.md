### Fixed

- Daemon shutdown, including fail-stop after a component failure, no longer
  exits before an Established session's Cease/Administrative Shutdown
  NOTIFICATION is written. A session now finishes only after its writer has
  flushed the NOTIFICATION, within the existing per-peer shutdown deadline.
  **Operator-visible:** peers see an administrative shutdown instead of a bare
  TCP close, which a peer could treat as a failure and start Graceful Restart
  retention or wait out its hold timer.
