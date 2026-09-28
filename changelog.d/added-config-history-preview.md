### Added

- `rbgp config diff --history N` previews a retained rollback with the existing
  redacted transaction plan and source-provenance checks, without changing daemon
  state. Missing, unreadable, metadata-only, or source-mismatched history fails
  closed. The new outside-v1 `PreviewConfigRollback` RPC requires
  `sensitive_read` access; older daemons fail safely without attempting rollback.
