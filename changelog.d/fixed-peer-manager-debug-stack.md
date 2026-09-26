### Fixed

- Reduce the peer-manager event loop's debug-build stack use during SIGHUP
  reloads by polling public command dispatch separately. Command ordering,
  cancellation, and shutdown behavior remain unchanged.
