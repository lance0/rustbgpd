### Fixed

- A live import policy edit (SIGHUP, gRPC policy mutation, or in-place
  neighbor update) for an Established peer that did not negotiate Route
  Refresh is now rejected before any session is modified. Previously the
  candidate chain was hot-applied, the refresh failed and the edit was
  rolled back and reported as cleanly restored, while UPDATEs received in
  between stayed accepted under the candidate chain.
  **Operator-visible:** such an edit now fails as a failed precondition with
  nothing changed (`policy_preflight_rejected`); the daemon log names the peer
  and the remedy. To change that peer's import policy, disable the neighbor,
  which withdraws its routes, apply the edit, then enable it. An
  `honor_graceful_shutdown` or `honor_blackhole` toggle likewise leaves such a
  peer on its prior import chain, reported as a failed peer, until the
  neighbor is disabled and re-enabled. See the
  [reload matrix](../docs/reference/reload-matrix.md).
