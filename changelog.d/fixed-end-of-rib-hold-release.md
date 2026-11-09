### Fixed

- An End-of-RIB that waited behind a forced outbound resync is now sent
  when that resync is admitted. It used to stay queued until the next
  resync tick, up to one second later. An End-of-RIB that waits only for
  routes owed to a slow receiver is sent as soon as those routes are sent
  or withdrawn at the source, and an operator outbound replay no longer
  leaves a second End-of-RIB for a family it covered. The marker still
  follows the routes it covers.
