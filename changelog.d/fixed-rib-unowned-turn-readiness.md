### Fixed

- The RIB now answers readiness probes during several actor turns that
  could walk a whole table without serving them: a BGP-LS UPDATE (selection
  against every Adj-RIB-In, not only the ORR rebuild), retiring or pruning an
  exact-export rejection of a FlowSpec, BGP-LS or RT-Constrain route (which
  walks that family in every Adj-RIB-In), a slow-peer isolation change or a
  conditional-advertisement attachment change that regroups a peer, and a
  session teardown that retires the last member's update-group table.
  **Operator-visible:** the readiness endpoint stays answered through these
  turns; the turns themselves are not shorter, and routes and wire output
  are unchanged.
