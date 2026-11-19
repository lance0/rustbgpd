### Changed

- When the first member of an eligible unicast update group joins a RIB with
  at least 10,000 best routes, the RIB can install unrelated updates while it
  builds the group table. The initial member replay follows publication of
  the complete table. This applies to plain single-best unicast groups with
  no export policy or peer-specific export controls.
  A policy change that needs the same unfinished table keeps the old policy
  in effect until the table is ready and earlier route updates have reached
  distribution. A cold registration can reclaim an unused table left by a
  completed policy preparation.
