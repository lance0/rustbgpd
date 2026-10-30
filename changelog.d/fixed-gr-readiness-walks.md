### Fixed

- Service RIB readiness queries throughout graceful-restart entry, End-of-RIB
  stale resolution (from both the GR and the LLGR phase) and GR expiry
  without LLGR. Marking, clearing and purging retained routes, re-selection,
  distribution and attribute reclamation now run under the same readiness
  owner as LLGR promotion and expiry, instead of holding readiness until the
  whole table had been walked.
