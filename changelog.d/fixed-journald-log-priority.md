### Fixed

- When stdout is a journal stream (`JOURNAL_STREAM` names it), each log
  line starts with its level's syslog priority (`ERROR` 3, `WARN` 4,
  `INFO` 6, `DEBUG`/`TRACE` 7) in both the JSON and text formats.
  journald stores that priority, so `journalctl -u rustbgpd -p warning`
  shows the daemon's warnings and errors; previously every line was stored
  at `info`. Output to a terminal, file or pipe is unchanged. See
  [Troubleshooting](../docs/how-to/deployment.md#troubleshooting).
