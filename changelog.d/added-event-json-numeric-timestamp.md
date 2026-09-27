### Added

- `rbgp -j events …` and `rbgp -j watch` records carry
  `timestamp_unix_seconds`, the event time as a JSON number, next to the
  existing `timestamp` string, which is unchanged. The
  [CLI guide](../crates/cli/README.md#events-and-control) also records that
  session events spell `old_state`/`new_state` in the FSM's snake_case
  vocabulary while `rbgp neighbor` uses the display form; neither field is
  re-cased.
