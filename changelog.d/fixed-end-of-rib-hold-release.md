### Fixed

- An End-of-RIB that waited behind a forced outbound resync, or behind the
  planned-restart grace window of an interface-only neighbor removed from the
  configuration, is now sent when that hold clears. It used to stay queued
  until the next resync tick, up to one second later. The marker still
  follows the routes it covers.
