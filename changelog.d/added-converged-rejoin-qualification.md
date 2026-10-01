### Added

- The reloadstall harness has an opt-in GR-helper reconnect qualification
  cell that proves retained source routes and fresh survivor coverage before
  measuring each joiner's exact table and EoR completion. Source replay follows
  the measurement, with reconnect-source refresh replies held behind the same
  guarded boundary; readiness, survivor integrity, and GR settlement are checked.
