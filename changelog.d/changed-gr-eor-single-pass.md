### Changed

- Consolidate unicast graceful-restart End-of-RIB cleanup into one route
  classification pass, preserving stale Add-Path removal and local LLGR
  community cleanup.
