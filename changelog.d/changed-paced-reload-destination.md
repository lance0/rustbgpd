### Changed

- During an export-policy reload or rollback, eligible single-best unicast
  peers can continue processing route updates while the RIB builds the new
  group's export table. The old policy remains in effect until commit. For
  peers still receiving their initial routes, the reload withdraws only
  routes already advertised to that peer.
