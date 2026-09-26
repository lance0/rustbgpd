### Changed

- `rbgp policy chain set-import`, `set-export`, `clear-import` and
  `clear-export` now require `--global` or `--neighbor`, and `rbgp gshut`
  requires `--all` or `--neighbor`. Omitting the scope is a usage error
  (exit 2) that names both choices and sends nothing to the daemon; the
  previous release selected the global chain or every peer and printed a
  deprecation warning. The confirmation prompt and `--yes` are unchanged. See
  the [operations reference](../docs/reference/operations.md).
  **Operator-visible:** scripts that still omit the scope now fail instead of
  changing the global chain or toggling graceful shutdown on every peer; add
  `--global` or `--all` to keep the daemon-wide behavior.
