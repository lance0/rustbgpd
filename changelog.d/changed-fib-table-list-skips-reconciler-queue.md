### Changed

- `ListFibTables` (`rbgp fib-table list`) no longer sends a `GetTables` query
  to the FIB reconciler. It serves the committed table set and checks only
  whether the reconciler's command channel is open, so concurrent reads can no
  longer fill the command queue that `SetFibTable` and `DeleteFibTable` use.
  `runtime_available = true` now means the reconciler was started and its
  command channel is open; it is not a responsiveness guarantee. Use the
  mutation response and `ListFibRoutes` for the actual apply outcome. A closed
  channel still returns retryable `UNAVAILABLE`, and a reconciler that never
  started still reports `runtime_available = false`.
  **Operator-visible:** against a wedged reconciler whose channel is still
  open, `rbgp fib-table list` now returns the committed tables immediately
  instead of waiting up to ten minutes for the `GetTables` deadline.
