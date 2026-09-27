### Added

- `[global.telemetry] log_format = "text"` writes human-readable log lines
  instead of JSON. The `lab` starter profile (`rustbgpd --init-config lab`)
  now uses it, so the quickstart's foreground run is readable; the `edge` and
  `route-server` profiles and existing configs keep `"json"`. The format is
  startup-only: a reload keeps the running format. See the
  [configuration reference](../docs/reference/configuration.md).
