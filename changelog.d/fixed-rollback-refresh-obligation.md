### Fixed

- A policy rollback whose Route Refresh failed no longer reports an exact
  restore while the Loc-RIB may hold routes the restored import policy denies.
  Once a peer's session has taken the candidate import chain, UPDATEs it
  receives are evaluated under that chain, and only a Route Refresh under the
  restored chain re-evaluates them. A peer whose export step was still pending
  in a batched or cohort reload, or whose own forward refresh was refused
  before any family was requested, was treated as untouched: when the reload
  then rolled back and that peer's rollback Route Refresh failed, the rollback
  dropped the refresh obligation and reported full compensation, and a route
  accepted under the candidate policy stayed in the Loc-RIB and was exported.
  The rollback now keeps the obligation armed and reports the restore as
  inexact.
  **Operator-visible:** such a reload now fails as `known_divergence` and the
  daemon fences and exits 70 instead of logging a clean rollback; a
  configuration transaction with the same failure fences the same way. A peer
  that did not negotiate Route Refresh is unchanged: its import edit is
  rejected and rolled back cleanly. See
  [the settlement watchdog](../docs/how-to/settlement-watchdog.md).
