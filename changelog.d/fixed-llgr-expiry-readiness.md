### Fixed

- Service RIB readiness queries throughout LLGR stale-time expiry: the purge,
  selection, distribution, ORR rebuild and attribute reclamation now run under
  the same readiness owner as LLGR promotion, instead of holding readiness
  until the whole sweep finished.
