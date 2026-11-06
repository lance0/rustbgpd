### Fixed

- A static Graceful Restart neighbor rebuilt inside a planned restart's
  window, by a SIGHUP or a peer-group change, now keeps advertising the RFC
  4724 Restart State bit. Before, the rebuilt session sent Restart State 0
  while the neighbor stayed a selection-deferral waiter, so the peer could
  wait for our End-of-RIB while we waited for its, and deferral held until
  the selection-deferral timer. A static neighbor deleted and re-added inside
  the window still sends Restart State 0.
