### Changed

- `rbgp gshut` and `SetGracefulShutdown` now return once the live sessions
  have accepted the toggle, instead of after every acknowledging peer's
  outbound routes were re-advertised. The re-advertisement follows in the
  background, one peer at a time, so the peers' own route updates, including
  withdrawals, are no longer held behind every replay; a slow or failed
  refresh is logged (`graceful-shutdown outbound refreshes complete` with
  its counts, and a warning per failed peer) instead of failing the command.
