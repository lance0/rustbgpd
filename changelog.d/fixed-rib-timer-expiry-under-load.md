### Fixed

- The graceful-restart stale timer, the LLGR stale timer, the enhanced
  route refresh window and the startup selection-deferral timer now fire
  under sustained inbound traffic. Each waited for the RIB's inbound queue
  to empty before expiring, so a continuously busy RIB could keep stale
  routes, an open refresh window or deferred route selection alive past
  the deadline indefinitely. Each timer now processes only the updates
  already queued when it fell due, then fires.
  **Operator-visible:** under load, stale routes from a peer that does not
  return are swept at the restart or Long-Lived Stale Time instead of
  after the load subsides.
