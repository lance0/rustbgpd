### Added

- Replay-complete signal for the planned-restart End-of-RIB grace window:
  list injection controllers in `[global] gr_eor_replay_owners`, and each
  calls the new `InjectionService.MarkReplayComplete(owner, incarnation)`
  after it replays its desired state into the current daemon incarnation.
  The held End-of-RIB is released as soon as every listed controller has
  signalled, counted as
  `bgp_gr_eor_grace_released_total{peer,reason="replay_complete"}`; the
  window's deadline still releases it otherwise, with a WARN log naming the
  controllers that never signalled. The signal is ordered behind the
  controller's earlier injections, so the window closes the gap when every
  listed controller signals before the deadline. A stale incarnation is
  `FAILED_PRECONDITION` with `ErrorInfo` reason `INCARNATION_MISMATCH`. The
  RPC is `operator_only` and outside the v1 inventory. An empty list keeps
  the timer-only window.
- `rustbgpd-gobgp-bridge` signals replay complete as `gobgp-bridge` after a
  post-restart reconcile pass finishes without a failure. See
  [the configuration reference](../docs/reference/configuration.md#planned-restart-end-of-rib-grace-window).
