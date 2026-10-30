### Fixed

- Service RIB readiness queries throughout LLGR promotion, non-LLGR family
  cleanup, selection and attribute reclamation. Bound local stale-tag growth
  by hash shard and reserve affected-route inventories before filling them,
  while preserving route counts, local community ownership and family timers.
  When ORR is configured, the BGP-LS topology rebuild, SPF and replaced-state
  cleanup also service readiness queries.
