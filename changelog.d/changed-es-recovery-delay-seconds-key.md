### Changed

- The `[[ethernet_segments]]` link-drain hold-off key is now
  `recovery_delay_seconds`, matching the other `_seconds` timer keys. The
  earlier spelling `recovery_delay_secs` is still accepted as an alias, so
  existing configs load unchanged.
  **Operator-visible:** the JSON Schema, reference docs, and validation
  errors use `recovery_delay_seconds`. See the
  [configuration reference](../docs/reference/configuration.md).
