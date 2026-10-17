### Added

- `rbgp policy check` works as a CI and editor gate. Every check now computes
  the static lints, and `--deny-lints[=LINT,...]` fails the check with exit
  code 4 on the named lints (or all of them), after the existing 1, 2 and 3.
  Without the flag, lints stay warnings and exit codes are unchanged.
  `--fail-on-empty` exits 2 when the file and its imports define no tests.
  `-j` output is now the versioned `rbgp-policy-check/1.0` document; a new
  `findings` array locates each compile error and lint by file, line and
  column, with a stable code, severity, label and notes. Existing keys,
  including the message-only `diagnostics` strings, keep their shape. See
  [the CLI reference](../crates/cli/README.md#policy-check-as-a-ci-and-editor-gate).
