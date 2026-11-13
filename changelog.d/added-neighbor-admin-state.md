### Added

- `NeighborState` gains `admin_state`, which says whether the daemon holds a
  neighbor down and which owner did: an operator disable, the configured
  `admin_down`, a max-prefix shutdown latch, or a dampening capacity disable.
  `rbgp neighbor` shows a held-down neighbor as `Idle (Admin)` or
  `Idle (PfxCt)`, the detail view adds `Admin State`, and JSON adds
  `admin_state`; `state` keeps its value. Outside a max-prefix latch, the
  detail view labels the retained error `Error Before Disable`, because it
  predates the hold. The new field and enum amend the pinned pre-v1
  `NeighborService` stable-surface inventory additively. The opt-in
  `rbgp-json` envelope advances to version 1.3 for this additive field. See
  [Administrative state](../docs/reference/api.md#administrative-state).
