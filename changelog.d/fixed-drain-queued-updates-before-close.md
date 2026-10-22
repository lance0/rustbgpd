### Fixed

- An administrative stop, reset or daemon shutdown now sends the outbound
  UPDATEs the RIB had already queued for the session before its Cease,
  within the existing close flush budget. Previously updates still waiting
  in the session's queue when the close arrived were dropped, so EVPN
  withdraws that shutdown drains just before closing sessions could miss the
  peer, and a Graceful Restart peer could keep those routes as stale.
