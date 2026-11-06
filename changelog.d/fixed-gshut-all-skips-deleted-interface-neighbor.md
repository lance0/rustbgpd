### Fixed

- An all-peers RFC 8326 graceful-shutdown set no longer reaches an
  interface-only neighbor that configuration has deleted while its BFD
  cleanup is still pending. Before, a neighbor re-added on that interface
  before the cleanup finished started in graceful shutdown although it was
  not configured when the set ran.
