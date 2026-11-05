### Fixed

- Preserve withdrawals when a receiver with deferred private routes leaves an
  update group after an export-policy change, including when recovery capture
  reaches its limit.
- Defer private route updates before staging when grouped updates fill a
  receiver's outbound channel, avoiding unnecessary whole-peer recovery.
