### Added

- `NeighborState` gains `admin_state`, which says whether the daemon holds a
  neighbor down and which owner did: an operator disable, the configured
  `admin_down`, a max-prefix shutdown latch, or the latch after repeated
  session task crashes. `rbgp neighbor` and the TUI show a held-down neighbor
  as `Idle (Admin)`, `Idle (PfxCt)` or `Idle (Crash)`, the detail view adds
  `Admin State`, and JSON adds `admin_state`; `state` keeps its value. Outside
  a latch, the detail view labels the retained error `Error Before Disable`,
  because it predates the hold. `rbgp doctor` reports a latched neighbor as a
  stuck peer that names the latch and its last error, not as
  administratively disabled. The new field and enum amend the pinned pre-v1
  `NeighborService` stable-surface inventory additively. The opt-in
  `rbgp-json` envelope advances to version 1.3 for this additive field. See
  [Administrative state](../docs/reference/api.md#administrative-state).
