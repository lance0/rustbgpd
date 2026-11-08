### Security

- `TestPolicy` and `ComparePolicy` (`rbgp policy test` and
  `rbgp policy compare`) now evaluate route pages on the blocking pool
  instead of the async runtime that serves BGP sessions and other RPCs, and
  bound the reads that set up the walk and the walk itself at 60 s after
  the compile, after which the request returns `DEADLINE_EXCEEDED` with the
  number of routes it evaluated. The CLI waits long enough for the
  daemon's compile and walk bounds to report first. The two
  dry-run slots per API listener now cover evaluation as well as the
  compile, so a third concurrent request returns `RESOURCE_EXHAUSTED` while
  two walks run. Previously a costly candidate over a large table held one
  async worker per request for the length of the walk.
  **Operator-visible:** a whole-table dry run that needs more than 60 s must
  be narrowed with `--limit`, `--neighbor` or `--family`
  ([API reference](../docs/reference/api.md)).
- `TestPolicy` rejects `show_changes` above 1,000 with `INVALID_ARGUMENT`,
  matching `show_rejected` and `max_samples`, so one request can no longer
  return a rendered diff for every route in the table. `rbgp policy test`
  rejects `--show-changes` above 1000 before sending.
